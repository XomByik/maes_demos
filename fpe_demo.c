#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include "libs/micro_aes.h"

// Helper function to convert hex string to binary data
// Returns 0 on success, -1 on error (invalid format or length)
int hex_to_bin(const char *hex, uint8_t *bin, size_t bin_len) {
    if (hex == NULL || bin == NULL) {
         fprintf(stderr, "Error: NULL pointer passed to hex_to_bin.\n");
         return -1;
    }
    size_t hex_len = strlen(hex);
    // Check if hex string length is exactly double the binary length
    if (hex_len != bin_len * 2) {
        // Allow empty string if bin_len is 0
        if (!(bin_len == 0 && hex_len == 0)) {
             fprintf(stderr, "Error: Hex string length (%zu) must be (%zu), double the expected binary length (%zu).\n", hex_len, bin_len*2, bin_len);
             return -1;
        }
    }
    if (bin_len == 0) {
        return 0; // Nothing to convert
    }

    for (size_t i = 0; i < bin_len; ++i) {
        // Ensure the characters being read are valid hex digits
        if (!isxdigit((unsigned char)hex[i * 2]) || !isxdigit((unsigned char)hex[i * 2 + 1])) {
             fprintf(stderr, "Error: Invalid non-hex character encountered in string '%s' at index %zu.\n", hex, i*2);
             return -1;
        }
        unsigned int byte_val;
        if (sscanf(hex + i * 2, "%2x", &byte_val) != 1) {
             fprintf(stderr, "Error: sscanf failed to parse hex byte from '%s' at index %zu.\n", hex, i*2);
             return -1; // Should not happen if isxdigit passed, but check anyway
        }
        bin[i] = (uint8_t)byte_val; // Cast to uint8_t
    }
    return 0; // Indicate success
}

// --- Configuration Check ---
#ifndef FF_X
#error "FF_X macro (1 for FF1, 3 for FF3-1) must be defined during compilation."
#endif

#if FF_X != 1 && FF_X != 3
#error "Invalid value for FF_X. Must be 1 or 3."
#endif

// --- Helper Functions (Copied from other demos) ---

// Simple strdup implementation
static char* my_strdup(const char* s) {
    if (s == NULL) return NULL;
    size_t len = strlen(s) + 1;
    char* new_s = malloc(len);
    if (new_s == NULL) return NULL;
    return memcpy(new_s, s, len);
}

// Trim leading/trailing whitespace from a string (modifies the string in place)
static char* trim(char* str) {
    if (str == NULL) return NULL;
    char *end;
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return str;
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    return str;
}

// --- FPE Test Vector Structure ---
typedef struct {
    char *count_str;
    char *method_str;
    char *alphabet_str;
    char *key_hex;
    char *tweak_hex;
    char *pt_str;
    char *expected_ct_str;
} FPE_Test_Vector;

// Function to free memory allocated for a test vector
static void free_fpe_vector(FPE_Test_Vector *vector) {
    free(vector->count_str);
    free(vector->method_str);
    free(vector->alphabet_str);
    free(vector->key_hex);
    free(vector->tweak_hex);
    free(vector->pt_str);
    free(vector->expected_ct_str);
    // Reset pointers to NULL after freeing
    memset(vector, 0, sizeof(FPE_Test_Vector));
}

// --- Test Execution Function ---
static int run_fpe_test(const FPE_Test_Vector *vector) {
    // Basic validation of the vector structure pointers
    if (!vector || !vector->count_str || !vector->method_str || !vector->alphabet_str ||
        !vector->key_hex || !vector->tweak_hex || !vector->pt_str || !vector->expected_ct_str) {
        fprintf(stderr, "Chyba: Neplatny ukazovatel v strukture testovacieho vektora.\n");
        return 0;
    }

    printf("--- Test Pripad: %s ---\n", vector->count_str);

    // --- Input Validation and Preparation ---

    // 1. Check if the method matches the compiled method
    #if FF_X == 1
        const char* compiled_method_local = "FF1"; // Use local variable name
    #elif FF_X == 3
        const char* compiled_method_local = "FF3"; // Assuming FF3-1 is represented as FF3 in files
    #endif
    if (strcmp(vector->method_str, compiled_method_local) != 0) { // Use local variable
        printf("Varovanie: Test preskoceny. Metoda v subore (%s) nezodpoveda skompilovanej metode (%s).\n",
               vector->method_str, compiled_method_local); // Use local variable
        printf("-------------------------------------\n");
        return 0; // Skip test, but don't count as failure in main summary
    }

    // 2. Check if the alphabet is the default decimal one (limitation of this demo)
    const char* default_alphabet = "0123456789";
    if (strcmp(vector->alphabet_str, default_alphabet) != 0) {
        printf("Varovanie: Test preskoceny. Abeceda v subore ('%s') nie je podporovana tymto demo programom (podporuje len '%s').\n",
               vector->alphabet_str, default_alphabet);
        printf("-------------------------------------\n");
        return 0; // Skip test
    }

    // 3. Get lengths and validate
    size_t key_hex_len = strlen(vector->key_hex);
    size_t tweak_hex_len = strlen(vector->tweak_hex);
    size_t pt_len = strlen(vector->pt_str);
    size_t expected_ct_len = strlen(vector->expected_ct_str);

    if (pt_len != expected_ct_len) {
         printf("Chyba: Dlzka PT (%zu) a ocakavaneho CT (%zu) sa nezhoduju.\n", pt_len, expected_ct_len);
         printf("-------------------------------------\n");
         return 0;
    }

    size_t key_len = key_hex_len / 2;
    size_t tweak_len = tweak_hex_len / 2;

    if (key_hex_len % 2 != 0 || (key_len != 16 && key_len != 24 && key_len != 32)) {
        printf("Chyba: Neplatna dlzka kluca (%zu hex znakov / %zu bajtov). Očakava sa 16, 24 alebo 32 bajtov.\n", key_hex_len, key_len);
        printf("-------------------------------------\n");
        return 0;
    }
    if (tweak_hex_len % 2 != 0) {
        printf("Chyba: Neplatna dlzka tweak-u (%zu hex znakov) - musi byt parna.\n", tweak_hex_len);
        printf("-------------------------------------\n");
        return 0;
    }
    #if FF_X == 3
        if (tweak_len != FF3_TWEAK_LEN) {
             printf("Chyba: Neplatna dlzka tweak-u pre FF3-1 (%zu bajtov). Očakava sa %d bajtov.\n", tweak_len, FF3_TWEAK_LEN);
             printf("-------------------------------------\n");
             return 0;
        }
    #endif // FF_X == 3

    // 4. Allocate memory
    uint8_t *key = malloc(key_len);
    uint8_t *tweak = malloc(tweak_len > 0 ? tweak_len : 1); // Allocate at least 1 byte if tweak is empty
    char *actual_ct_str = malloc(pt_len + 1);
    char *decrypted_pt_str = malloc(pt_len + 1);

    if (!key || !tweak || !actual_ct_str || !decrypted_pt_str) {
        fprintf(stderr, "Chyba: Alokacia pamate zlyhala.\n");
        free(key); free(tweak); free(actual_ct_str); free(decrypted_pt_str);
        printf("-------------------------------------\n");
        return 0;
    }

    // 5. Convert hex inputs to binary
    if (hex_to_bin(vector->key_hex, key, key_len) != 0) {
        free(key); free(tweak); free(actual_ct_str); free(decrypted_pt_str);
        printf("-------------------------------------\n");
        return 0;
    }
    if (tweak_len > 0 && hex_to_bin(vector->tweak_hex, tweak, tweak_len) != 0) {
        free(key); free(tweak); free(actual_ct_str); free(decrypted_pt_str);
        printf("-------------------------------------\n");
        return 0;
    }

    // --- Print Inputs ---
    printf("Vstupy:\n");
    printf("  Metoda    : %s\n", vector->method_str);
    printf("  Abeceda   : %s\n", vector->alphabet_str);
    printf("  Kluc      : %s (%zu bajtov)\n", vector->key_hex, key_len);
    printf("  Tweak     : %s (%zu bajtov)\n", vector->tweak_hex, tweak_len);
    printf("  Plaintext : %s (%zu znakov)\n", vector->pt_str, pt_len);

    // --- Encryption ---
    printf("\nVystupy (Sifrovanie):\n");
    char enc_status;
    #if FF_X == 3
        enc_status = AES_FPE_encrypt(key, tweak, vector->pt_str, pt_len, actual_ct_str);
    #else // FF1
        enc_status = AES_FPE_encrypt(key, tweak, tweak_len, vector->pt_str, pt_len, actual_ct_str);
    #endif

    int enc_match = 0;
    if (enc_status == NO_ERROR_RETURNED) {
        printf("  Sifrovanie: USPESNE\n");
        printf("    Ocakavane CT : %s\n", vector->expected_ct_str);
        printf("    Vypocitane CT: %s\n", actual_ct_str);
        enc_match = (strcmp(vector->expected_ct_str, actual_ct_str) == 0);
        printf("    Zhoda        : %s\n", enc_match ? "ANO" : "NIE");
    } else {
        printf("  Sifrovanie: ZLYHALO (status: %d)\n", enc_status);
        printf("    Ocakavane CT : %s\n", vector->expected_ct_str);
        printf("    Vypocitane CT: (nedostupne)\n");
        printf("    Zhoda        : NIE\n");
        enc_match = 0;
    }

    // --- Decryption ---
    printf("\nVystupy (Desifrovanie):\n");
    int dec_match = 0;
    if (enc_status == NO_ERROR_RETURNED) { // Only attempt decryption if encryption succeeded
        char dec_status;
        #if FF_X == 3
            dec_status = AES_FPE_decrypt(key, tweak, actual_ct_str, pt_len, decrypted_pt_str);
        #else // FF1
            dec_status = AES_FPE_decrypt(key, tweak, tweak_len, actual_ct_str, pt_len, decrypted_pt_str);
        #endif

        if (dec_status == NO_ERROR_RETURNED) {
            printf("  Desifrovanie: USPESNE\n");
            printf("    Ocakavane PT : %s\n", vector->pt_str);
            printf("    Vypocitane PT: %s\n", decrypted_pt_str);
            dec_match = (strcmp(vector->pt_str, decrypted_pt_str) == 0);
            printf("    Zhoda        : %s\n", dec_match ? "ANO" : "NIE");
        } else {
            printf("  Desifrovanie: ZLYHALO (status: %d)\n", dec_status);
            printf("    Ocakavane PT : %s\n", vector->pt_str);
            printf("    Vypocitane PT: (nedostupne)\n");
            printf("    Zhoda        : NIE\n");
            dec_match = 0;
        }
    } else {
        printf("  Desifrovanie: Preskocene (sifrovanie zlyhalo)\n");
        dec_match = 0; // Decryption implicitly fails if encryption failed
    }

    // --- Cleanup and Result ---
    free(key);
    free(tweak);
    free(actual_ct_str);
    free(decrypted_pt_str);

    int overall_success = enc_match && dec_match;
    printf("\nCelkovy vysledok testu: %s\n", overall_success ? "PRESLO" : "ZLYHALO");
    printf("-------------------------------------\n");
    return overall_success;
}

// --- Main Function ---
int main(void) {
    int passed_count = 0;
    int total_processed = 0; // Count tests that were actually run (not skipped)
    int file_parsed_count = 0; // Count vectors parsed from file

    printf("AES-FPE Demo (Nacitanie zo suboru)\n");
    printf("===========================================\n");

    // Define compiled_method here for use in main's scope
    #if FF_X == 1
        const char* compiled_method = "FF1";
    #elif FF_X == 3
        const char* compiled_method = "FF3";
    #endif

    // Zistenie velkosti kluca a vyber suboru
    #if AES___ == 256
        const int aes_bits = 256;
        #if FF_X == 1
            const char* test_vectors_file = "test_vectors/ff1_256.txt";
            const char* mode_name = "FF1";
        #else // FF_X == 3
            const char* test_vectors_file = "test_vectors/ff3_256.txt";
            const char* mode_name = "FF3-1";
        #endif
        printf("Program skompilovany pre AES-256, rezim %s\n", mode_name);
    #elif AES___ == 192
        const int aes_bits = 192;
        #if FF_X == 1
            const char* test_vectors_file = "test_vectors/ff1_192.txt";
            const char* mode_name = "FF1";
        #else // FF_X == 3
            const char* test_vectors_file = "test_vectors/ff3_192.txt";
            const char* mode_name = "FF3-1";
        #endif
        printf("Program skompilovany pre AES-192, rezim %s\n", mode_name);
    #else // Default to 128
        const int aes_bits = 128;
        #if FF_X == 1
            const char* test_vectors_file = "test_vectors/ff1_128.txt";
            const char* mode_name = "FF1";
        #else // FF_X == 3
            const char* test_vectors_file = "test_vectors/ff3_128.txt";
            const char* mode_name = "FF3-1";
        #endif
        printf("Program skompilovany pre AES-128, rezim %s\n", mode_name);
    #endif
    (void)aes_bits; // Suppress unused variable warning if not used elsewhere

    FILE *fp;
    char line[1024]; // Buffer for reading lines

    printf("Pouziva sa testovaci subor: %s\n", test_vectors_file);
    fp = fopen(test_vectors_file, "r");
    if (!fp) {
        perror("Nepodarilo sa otvorit subor s testovacimi vektormi");
        return 1;
    }

    FPE_Test_Vector current_vector = {0}; // Initialize all pointers to NULL
    int vector_data_present = 0; // Flag to indicate if we have started parsing a vector

    while (fgets(line, sizeof(line), fp)) {
        char* trimmed_line = trim(line);
        size_t len = strlen(trimmed_line);

        if (len == 0 || trimmed_line[0] == '#') { // Empty line or comment
             // If we have accumulated data for a vector, process it
            if (vector_data_present && current_vector.key_hex && current_vector.tweak_hex && // Check tweak_hex is not NULL
                current_vector.pt_str && current_vector.expected_ct_str &&
                current_vector.method_str && current_vector.alphabet_str)
            {
                file_parsed_count++;
                int result = run_fpe_test(&current_vector);
                // Only increment processed count if the test wasn't skipped due to alphabet/method mismatch
                 if (strcmp(current_vector.alphabet_str, "0123456789") == 0 &&
                     strcmp(current_vector.method_str, compiled_method) == 0) {
                     if (result) { // run_fpe_test returns 1 for pass, 0 for fail
                         passed_count++;
                     }
                     total_processed++;
                 }
                free_fpe_vector(&current_vector);
                vector_data_present = 0;
            }
            continue;
        }

        if (strncmp(trimmed_line, "Count = ", 8) == 0) {
            // If we encounter a new Count, process the previous vector if ready
             if (vector_data_present && current_vector.key_hex && current_vector.tweak_hex && // Check tweak_hex is not NULL
                 current_vector.pt_str && current_vector.expected_ct_str &&
                 current_vector.method_str && current_vector.alphabet_str)
             {
                 file_parsed_count++;
                 int result = run_fpe_test(&current_vector);
                 if (strcmp(current_vector.alphabet_str, "0123456789") == 0 &&
                     strcmp(current_vector.method_str, compiled_method) == 0) {
                     if (result) {
                         passed_count++;
                     }
                     total_processed++;
                 }
                 free_fpe_vector(&current_vector);
            }
            // Start new vector
            vector_data_present = 1;
            current_vector.count_str = my_strdup(trimmed_line);
            // Initialize potentially missing fields to empty strings
            current_vector.tweak_hex = my_strdup(""); // Initialize tweak to empty
            if (!current_vector.count_str || !current_vector.tweak_hex) {
                 fprintf(stderr, "Chyba alokacie pamate pri starte vektora %s\n", trimmed_line);
                 // Handle allocation error appropriately, e.g., exit or skip
                 if (current_vector.tweak_hex) free(current_vector.tweak_hex);
                 if (current_vector.count_str) free(current_vector.count_str);
                 vector_data_present = 0; // Don't process this vector
                 continue;
            }
        } else if (vector_data_present && strncmp(trimmed_line, "Method = ", 9) == 0) {
            free(current_vector.method_str);
            current_vector.method_str = my_strdup(trimmed_line + 9);
        } else if (vector_data_present && strncmp(trimmed_line, "Alphabet = ", 11) == 0) {
            free(current_vector.alphabet_str);
            current_vector.alphabet_str = my_strdup(trimmed_line + 11);
        } else if (vector_data_present && strncmp(trimmed_line, "Key = ", 6) == 0) {
            free(current_vector.key_hex);
            current_vector.key_hex = my_strdup(trimmed_line + 6);
        } else if (vector_data_present && strncmp(trimmed_line, "Tweak = ", 8) == 0) {
            free(current_vector.tweak_hex); // Free the default ""
            current_vector.tweak_hex = my_strdup(trimmed_line + 8);
            if (!current_vector.tweak_hex) { /* Handle allocation error */ }
        } else if (vector_data_present && strncmp(trimmed_line, "PT = ", 5) == 0) {
             free(current_vector.pt_str);
             current_vector.pt_str = my_strdup(trimmed_line + 5);
        } else if (vector_data_present && strncmp(trimmed_line, "CT = ", 5) == 0) {
             free(current_vector.expected_ct_str);
             current_vector.expected_ct_str = my_strdup(trimmed_line + 5);
        }
        // Add checks for allocation failures after each my_strdup if necessary
    }

    // Process the last vector if it exists
    if (vector_data_present && current_vector.key_hex && current_vector.tweak_hex && // Check tweak_hex is not NULL
        current_vector.pt_str && current_vector.expected_ct_str &&
        current_vector.method_str && current_vector.alphabet_str)
    {
        file_parsed_count++;
        int result = run_fpe_test(&current_vector);
         if (strcmp(current_vector.alphabet_str, "0123456789") == 0 &&
             strcmp(current_vector.method_str, compiled_method) == 0) {
             if (result) {
                 passed_count++;
             }
             total_processed++;
         }
        free_fpe_vector(&current_vector);
    }

    fclose(fp);

    printf("\n=======================\n");
    printf("Zhrnutie testov:\n");
    printf("  Nacitanych vektorov: %d\n", file_parsed_count);
    printf("  Spracovanych vektorov (spravna metoda/abeceda): %d\n", total_processed);
    printf("  Uspesnych testov: %d / %d\n", passed_count, total_processed);
    printf("=======================\n");

    // Return 0 if all processed tests passed, 1 otherwise
    // Handle case where total_processed might be 0 if all tests were skipped
    if (total_processed == 0) {
        return (file_parsed_count > 0) ? 1 : 0; // Return error if vectors were parsed but none processed, 0 if file was empty/irrelevant
    }
    return (passed_count == total_processed) ? 0 : 1;
}