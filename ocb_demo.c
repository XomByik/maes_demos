#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include "libs/micro_aes.h"

#define OCB_TAG_LEN 16 // Standard OCB tag length is 128 bits (16 bytes)

// --- Pomocne funkcie ---

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

// Konvertuje bajty na hex retazec
void bytesToHex(const uint8_t *bytes, size_t len, char *hex) {
    if (bytes == NULL || hex == NULL) return;
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + i * 2, "%02x", bytes[i]);
    }
    hex[len * 2] = '\0'; // Null-terminate the string
}

// Vlastna implementacia strdup ak je potrebna
char* my_strdup(const char* s) {
    if (s == NULL) return NULL;
    size_t len = strlen(s) + 1;
    char* new_s = malloc(len);
    if (new_s == NULL) return NULL;
    memcpy(new_s, s, len);
    return new_s;
}

// Odstrani biele znaky zo zaciatku a konca retazca
char *trim(char *str) {
    if (str == NULL) return NULL;
    char *end;
    // Trim leading space
    while(isspace((unsigned char)*str)) str++;
    if(*str == 0) // All spaces?
        return str;
    // Trim trailing space
    end = str + strlen(str) - 1;
    while(end > str && isspace((unsigned char)*end)) end--;
    *(end+1) = 0;
    return str;
}

// Porovna dve bajtove polia a vypise vysledok v hex formate
int compareAndPrintHex(const char *title, const uint8_t *expected, const uint8_t *actual, size_t len) {
    // Allocate enough space for hex strings + null terminator
    char *expected_hex = malloc(len * 2 + 1);
    char *actual_hex = malloc(len * 2 + 1);
    if (!expected_hex || !actual_hex) {
        fprintf(stderr, "Chyba alokacie pamate pre hex retazce\n");
        free(expected_hex);
        free(actual_hex);
        return 0; // Indicate failure
    }

    bytesToHex(expected, len, expected_hex);
    bytesToHex(actual, len, actual_hex);

    int match = (len == 0 || memcmp(expected, actual, len) == 0);

    printf("%s:\n", title);
    printf("  Ocakavane : %s (%zu bajtov)\n", expected_hex, len);
    printf("  Vypocitane: %s (%zu bajtov)\n", actual_hex, len);
    printf("  Zhoda     : %s\n", match ? "ANO" : "NIE");

    free(expected_hex);
    free(actual_hex);
    return match;
}


// --- Struktura pre testovacie vektory ---

typedef struct {
    char *key_hex;
    char *nonce_hex;
    char *a_hex; // Associated Data
    char *p_hex; // Plaintext
    char *c_hex; // Ciphertext + Tag
} OCB_Test_Vector;

// Deklaracia funkcie pre uvolnenie pamate
void freeTestVectors(OCB_Test_Vector *vectors, int count);

// --- Nacitanie testovacich vektorov ---

int loadTestVectors(const char *filename, OCB_Test_Vector **vectors, int *vector_count) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        printf("Chyba pri otvarani suboru s testovacimi vektormi: %s\n", filename);
        return 0;
    }

    char line[2048];
    int count = 0;
    int capacity = 10;
    *vectors = malloc(sizeof(OCB_Test_Vector) * capacity);
    if (!*vectors) {
        fclose(fp);
        printf("Chyba alokacie pamate pre vektory\n");
        return 0;
    }
    memset(*vectors, 0, sizeof(OCB_Test_Vector) * capacity);

    OCB_Test_Vector current_vector = {0};
    char *global_key_hex = NULL; // Store the global key

    while (fgets(line, sizeof(line), fp)) {
        char* trimmed_line = trim(line);

        // Skip comments and empty lines initially
        if (strlen(trimmed_line) == 0 || trimmed_line[0] == '#') {
            continue;
        }

        // Parse global Key first
        if (global_key_hex == NULL && strncmp(trimmed_line, "K : ", 4) == 0) {
             global_key_hex = my_strdup(trim(trimmed_line + 4));
             if (!global_key_hex) {
                 printf("Chyba alokacie pamate pre globalny kluc\n");
                 fclose(fp);
                 free(*vectors);
                 *vectors = NULL;
                 return 0;
             }
             continue; // Move to the next line after finding the key
        }

        // Start of a new vector block
        if (strncmp(trimmed_line, "N:", 2) == 0 || strncmp(trimmed_line, "N : ", 4) == 0) {
            // If a vector was being processed, save it first
            if (current_vector.nonce_hex != NULL && current_vector.c_hex != NULL) {
                 if (capacity <= count) {
                     capacity *= 2;
                     OCB_Test_Vector *temp = realloc(*vectors, sizeof(OCB_Test_Vector) * capacity);
                     if (!temp) {
                         printf("Chyba realokacie pamate pre vektory\n");
                         free(current_vector.nonce_hex);
                         free(current_vector.a_hex);
                         free(current_vector.p_hex);
                         free(current_vector.c_hex);
                         freeTestVectors(*vectors, count);
                         *vectors = NULL;
                         free(global_key_hex);
                         fclose(fp);
                         return 0;
                     }
                     *vectors = temp;
                 }
                 // Assign the global key
                 current_vector.key_hex = my_strdup(global_key_hex);
                 if (!current_vector.key_hex) {
                      printf("Chyba alokacie pamate pre kluc vektora\n");
                      // Cleanup
                      free(current_vector.nonce_hex);
                      free(current_vector.a_hex);
                      free(current_vector.p_hex);
                      free(current_vector.c_hex);
                      freeTestVectors(*vectors, count);
                      *vectors = NULL;
                      free(global_key_hex);
                      fclose(fp);
                      return 0;
                 }
                 (*vectors)[count] = current_vector;
                 count++;
                 memset(&current_vector, 0, sizeof(OCB_Test_Vector)); // Reset for the next vector
            }

            // Parse the new Nonce
            free(current_vector.nonce_hex); // Free previous if any (should not happen here)
            current_vector.nonce_hex = my_strdup(trim(trimmed_line + (strncmp(trimmed_line, "N : ", 4) == 0 ? 4 : 2)));
            if (!current_vector.nonce_hex) { /* Handle allocation error */ }

        } else if (strncmp(trimmed_line, "A:", 2) == 0 || strncmp(trimmed_line, "A : ", 4) == 0) {
            free(current_vector.a_hex);
            const char* value_start = trim(trimmed_line + (strncmp(trimmed_line, "A : ", 4) == 0 ? 4 : 2));
            if (strlen(value_start) > 0) {
                current_vector.a_hex = my_strdup(value_start);
                 if (!current_vector.a_hex) { /* Handle allocation error */ }
            } else {
                current_vector.a_hex = NULL; // Handle empty A field
            }
        } else if (strncmp(trimmed_line, "P:", 2) == 0 || strncmp(trimmed_line, "P : ", 4) == 0) {
            free(current_vector.p_hex);
             const char* value_start = trim(trimmed_line + (strncmp(trimmed_line, "P : ", 4) == 0 ? 4 : 2));
            if (strlen(value_start) > 0) {
                current_vector.p_hex = my_strdup(value_start);
                 if (!current_vector.p_hex) { /* Handle allocation error */ }
            } else {
                 current_vector.p_hex = NULL; // Handle empty P field
            }
        } else if (strncmp(trimmed_line, "C:", 2) == 0 || strncmp(trimmed_line, "C : ", 4) == 0) {
            free(current_vector.c_hex);
            current_vector.c_hex = my_strdup(trim(trimmed_line + (strncmp(trimmed_line, "C : ", 4) == 0 ? 4 : 2)));
             if (!current_vector.c_hex) { /* Handle allocation error */ }
        }
    }

    // Handle the very last vector read from the file
    if (current_vector.nonce_hex != NULL && current_vector.c_hex != NULL) {
        if (capacity <= count) {
            capacity++;
            OCB_Test_Vector *temp = realloc(*vectors, sizeof(OCB_Test_Vector) * capacity);
            if (!temp) {
                printf("Chyba realokacie pamate pre posledny vektor\n");
                free(current_vector.nonce_hex);
                free(current_vector.a_hex);
                free(current_vector.p_hex);
                free(current_vector.c_hex);
                freeTestVectors(*vectors, count);
                *vectors = NULL;
                free(global_key_hex);
                fclose(fp);
                return 0;
            }
            *vectors = temp;
        }
         // Assign the global key
         current_vector.key_hex = my_strdup(global_key_hex);
         if (!current_vector.key_hex) {
              printf("Chyba alokacie pamate pre kluc posledneho vektora\n");
              // Cleanup
              free(current_vector.nonce_hex);
              free(current_vector.a_hex);
              free(current_vector.p_hex);
              free(current_vector.c_hex);
              freeTestVectors(*vectors, count);
              *vectors = NULL;
              free(global_key_hex);
              fclose(fp);
              return 0;
         }
        (*vectors)[count] = current_vector;
        count++;
    } else {
        // Free the last partially filled vector if it wasn't complete
        free(current_vector.nonce_hex);
        free(current_vector.a_hex);
        free(current_vector.p_hex);
        free(current_vector.c_hex);
    }

    *vector_count = count;
    free(global_key_hex); // Free the global key string
    fclose(fp);

    if (count == 0 && global_key_hex == NULL) {
        printf("Varovanie: Nepodarilo sa najst globalny kluc 'K :' v subore.\n");
        return 0; // Indicate failure if no key or vectors were found
    }
     if (count == 0) {
        printf("Varovanie: Nepodarilo sa nacitat ziadne platne testovacie vektory (N:, A:, P:, C:).\n");
        // Return 1 because the key might have been loaded, but no vectors
    }

    return 1; // Success
}

// Uvolnenie pamate alokovanej pre testovacie vektory
void freeTestVectors(OCB_Test_Vector *vectors, int count) {
    if (!vectors) return;
    for (int i = 0; i < count; i++) {
        free(vectors[i].key_hex);
        free(vectors[i].nonce_hex);
        free(vectors[i].a_hex);
        free(vectors[i].p_hex);
        free(vectors[i].c_hex);
    }
    free(vectors);
}

// --- Vykonanie OCB testu ---

int runOcbTest(const OCB_Test_Vector *vector, int key_size_bytes) {
    int overall_success = 1; // Celkovy uspech testu (sifrovanie aj desifrovanie)

    // Vypocet dlzok dat v bajtoch (delene 2 kvoli hex)
    size_t key_len = vector->key_hex ? strlen(vector->key_hex) / 2 : 0;
    size_t nonce_len = vector->nonce_hex ? strlen(vector->nonce_hex) / 2 : 0;
    size_t a_len = vector->a_hex ? strlen(vector->a_hex) / 2 : 0;
    size_t p_len = vector->p_hex ? strlen(vector->p_hex) / 2 : 0;
    size_t c_total_len = vector->c_hex ? strlen(vector->c_hex) / 2 : 0;

    // Kontrola platnosti vstupnych dat
    if (key_len != (size_t)key_size_bytes) {
        printf("Chyba: Nespravna dlzka kluca (%zu bajtov, ocakavano %d)\n", key_len, key_size_bytes);
        return 0;
    }
     if (nonce_len == 0 || nonce_len > 15) { // Nonce must be non-empty and at most 15 bytes for OCB
        printf("Chyba: Nespravna dlzka nonce (%zu bajtov, musi byt 1-15)\n", nonce_len);
        return 0;
    }
    if (c_total_len < OCB_TAG_LEN) {
        printf("Chyba: Dlzka C (%zu) je kratsia ako dlzka tagu (%d)\n", c_total_len, OCB_TAG_LEN);
        return 0;
    }
    if ((vector->a_hex && strlen(vector->a_hex) % 2 != 0) ||
        (vector->p_hex && strlen(vector->p_hex) % 2 != 0) ||
        (vector->c_hex && strlen(vector->c_hex) % 2 != 0) ||
        (vector->key_hex && strlen(vector->key_hex) % 2 != 0) ||
        (vector->nonce_hex && strlen(vector->nonce_hex) % 2 != 0)) {
        printf("Chyba: Neparny pocet znakov v hex retazci.\n");
        return 0;
    }


    size_t expected_c_len = c_total_len - OCB_TAG_LEN;
    size_t expected_tag_len = OCB_TAG_LEN;

    // Alokacia pamate pre binarne data
    uint8_t *key = malloc(key_len);
    uint8_t *nonce = malloc(nonce_len);
    uint8_t *a_data = a_len > 0 ? malloc(a_len) : NULL;
    uint8_t *p_data = p_len > 0 ? malloc(p_len) : NULL;
    uint8_t *expected_c = expected_c_len > 0 ? malloc(expected_c_len) : NULL;
    uint8_t *expected_tag = malloc(expected_tag_len);
    uint8_t *result_c = expected_c_len > 0 ? malloc(expected_c_len) : NULL; // Same size as expected ciphertext
    uint8_t *result_tag = malloc(expected_tag_len);
    uint8_t *result_p = p_len > 0 ? malloc(p_len) : NULL; // Same size as original plaintext

    // Kontrola uspesnosti alokacie
    if (!key || !nonce || !expected_tag || !result_tag ||
        (a_len > 0 && !a_data) || (p_len > 0 && !p_data) ||
        (expected_c_len > 0 && !expected_c) || (expected_c_len > 0 && !result_c) ||
        (p_len > 0 && !result_p)) {
        printf("Chyba: Alokacia pamate zlyhala\n");
        // Uvolnenie uz alokovanej pamate
        free(key); free(nonce); free(a_data); free(p_data); free(expected_c);
        free(expected_tag); free(result_c); free(result_tag); free(result_p);
        return 0;
    }

    // Konverzia hex retazcov na binarne data
    hex_to_bin(vector->key_hex, key, key_len);
    hex_to_bin(vector->nonce_hex, nonce, nonce_len);
    if (a_len > 0) hex_to_bin(vector->a_hex, a_data, a_len);
    if (p_len > 0) hex_to_bin(vector->p_hex, p_data, p_len);

    // Rozdelenie ocakavaneho C na ciphertext a tag
    uint8_t *c_total_bin = malloc(c_total_len);
    if (!c_total_bin) {
         printf("Chyba: Alokacia pamate pre C zlyhala\n");
         // Free other buffers
         free(key); free(nonce); free(a_data); free(p_data); free(expected_c);
         free(expected_tag); free(result_c); free(result_tag); free(result_p);
         return 0;
    }
    hex_to_bin(vector->c_hex, c_total_bin, c_total_len);
    if (expected_c_len > 0) memcpy(expected_c, c_total_bin, expected_c_len);
    memcpy(expected_tag, c_total_bin + expected_c_len, expected_tag_len);
    free(c_total_bin); // No longer needed


    printf("--- Test Sifrovania ---\n");
    printf("Kluc      : %s\n", vector->key_hex);
    printf("Nonce     : %s\n", vector->nonce_hex);
    printf("Assoc Data: %s\n", vector->a_hex ? vector->a_hex : "(prazdne)");
    printf("Plaintext : %s\n", vector->p_hex ? vector->p_hex : "(prazdne)");

    // Volanie AES_OCB_encrypt
    // Signature: AES_OCB_encrypt(key, nonce, pntxt, ptextLen, aData, aDataLen, crtxt, auTag)
    AES_OCB_encrypt(key, nonce, p_data, p_len, a_data, a_len, result_c, result_tag);

    int c_match = 1;
    if (expected_c_len > 0) {
        c_match = compareAndPrintHex("Ciphertext", expected_c, result_c, expected_c_len);
    } else {
        printf("Ciphertext:\n  (prazdny)\n"); // No ciphertext expected or generated
    }
    int tag_match = compareAndPrintHex("Tag", expected_tag, result_tag, expected_tag_len);

    if (!c_match || !tag_match) {
        overall_success = 0;
        printf("Vysledok sifrovania: NEUSPESNE\n");
    } else {
        printf("Vysledok sifrovania: USPESNE\n");
    }

    printf("\n--- Test Desifrovania ---\n");
    printf("Kluc      : %s\n", vector->key_hex);
    printf("Nonce     : %s\n", vector->nonce_hex);
    printf("Assoc Data: %s\n", vector->a_hex ? vector->a_hex : "(prazdne)");
    printf("Ciphertext: ");
    if(expected_c_len > 0) {
        char *expected_c_hex = malloc(expected_c_len * 2 + 1);
        if(expected_c_hex) {
            bytesToHex(expected_c, expected_c_len, expected_c_hex);
            printf("%s\n", expected_c_hex);
            free(expected_c_hex);
        } else { printf("(chyba alokacie)\n"); }
    } else { printf("(prazdne)\n"); }
    printf("Tag       : ");
    char *expected_tag_hex = malloc(expected_tag_len * 2 + 1);
    if(expected_tag_hex) {
        bytesToHex(expected_tag, expected_tag_len, expected_tag_hex);
        printf("%s\n", expected_tag_hex);
        free(expected_tag_hex);
    } else { printf("(chyba alokacie)\n"); }


    // Volanie AES_OCB_decrypt
    // Signature: AES_OCB_decrypt(key, nonce, crtxt, crtxtLen, aData, aDataLen, tagLen, pntxt)
    // Note: crtxt parameter expects ciphertext WITH the tag appended.

    // Create a buffer for ciphertext + tag for decryption input
    uint8_t *crtxt_with_tag = malloc(expected_c_len + expected_tag_len);
    if (!crtxt_with_tag) {
        printf("Chyba: Alokacia pamate pre ciphertext+tag zlyhala\n");
        // Free other buffers
        free(key); free(nonce); free(a_data); free(p_data); free(expected_c);
        free(expected_tag); free(result_c); free(result_tag); free(result_p);
        return 0;
    }
    if (expected_c_len > 0) memcpy(crtxt_with_tag, expected_c, expected_c_len);
    memcpy(crtxt_with_tag + expected_c_len, expected_tag, expected_tag_len);

    int decrypt_status = AES_OCB_decrypt(key, nonce, crtxt_with_tag, expected_c_len, a_data, a_len, (uint8_t)expected_tag_len, result_p);
    free(crtxt_with_tag); // Free the combined buffer

    if (decrypt_status == 0) { // 0 znamena uspech (tag sa zhoduje)
        printf("Autentifikacia: USPESNA (Tag sa zhoduje)\n");
        int p_match = 1;
        if (p_len > 0) {
            p_match = compareAndPrintHex("Plaintext", p_data, result_p, p_len);
        } else {
             printf("Plaintext:\n  (prazdny)\n"); // No plaintext expected or generated
        }
        if (!p_match) {
            overall_success = 0;
            printf("Vysledok desifrovania: NEUSPESNE (Plaintext sa nezhoduje)\n");
        } else {
             printf("Vysledok desifrovania: USPESNE\n");
        }
    } else { // Nenulova hodnota znamena zlyhanie autentifikacie
        overall_success = 0;
        printf("Autentifikacia: NEUSPESNA (Tag sa nezhoduje)\n");
        printf("Vysledok desifrovania: NEUSPESNE\n");
        // Vypiseme ocakavany plaintext aj ked desifrovanie zlyhalo
         printf("Ocakavany Plaintext:\n");
         if (p_len > 0) {
            char *p_data_hex = malloc(p_len * 2 + 1);
            if(p_data_hex) {
                bytesToHex(p_data, p_len, p_data_hex);
                printf("  %s (%zu bajtov)\n", p_data_hex, p_len);
                free(p_data_hex);
            } else { printf("  (chyba alokacie)\n"); }
         } else {
             printf("  (prazdny)\n");
         }
    }


    // Uvolnenie pamate pre tento test
    free(key);
    free(nonce);
    free(a_data);
    free(p_data);
    free(expected_c);
    free(expected_tag);
    free(result_c);
    free(result_tag);
    free(result_p);
    // free(crtxt_with_tag); // Already freed above

    printf("\nVysledok celkoveho testu vektora: %s\n", overall_success ? "USPESNY" : "NEUSPESNY");
    return overall_success;
}

// --- Hlavna funkcia ---

int main(int argc, char* argv[]) {
    // Zistenie velkosti kluca z kompilacnych definicii
    #if AES___ == 256
        const int aes_bits = 256;
        // const char* default_test_file = "test_vectors/ocb_256.txt"; // TODO: Add 256-bit vectors if needed
        printf("AES-OCB Demo (AES-256) - POZOR: Testovacie vektory su len pre AES-128!\n");
        // return 1; // Exit if compiled for 256 but only 128 vectors exist
    #elif AES___ == 192
        const int aes_bits = 192;
        // const char* default_test_file = "test_vectors/ocb_192.txt"; // TODO: Add 192-bit vectors if needed
        printf("AES-OCB Demo (AES-192) - POZOR: Testovacie vektory su len pre AES-128!\n");
        // return 1; // Exit if compiled for 192 but only 128 vectors exist
    #else // Predvolene AES-128
        const int aes_bits = 128;
        const char* default_test_file = "test_vectors/ocb_128.txt";
        printf("AES-OCB Demo (AES-128)\n");
    #endif

    // Allow overriding test file via command line argument
    const char* test_vectors_file = (argc > 1) ? argv[1] : default_test_file;
    int key_size_bytes = aes_bits / 8;

    // Check if the selected test file matches the compiled key size (basic check)
    if (strstr(test_vectors_file, "ocb_128") != NULL && aes_bits != 128) {
         printf("Varovanie: Kompilovane pre AES-%d, ale pouziva sa subor pre AES-128 (%s)\n", aes_bits, test_vectors_file);
    }
    // Add similar checks for 192/256 if those vector files exist

    printf("Pouziva sa subor s testovacimi vektormi: %s\n", test_vectors_file);

    OCB_Test_Vector *vectors = NULL;
    int vector_count = 0;
    int passed_count = 0;

    if (!loadTestVectors(test_vectors_file, &vectors, &vector_count)) {
        printf("Nepodarilo sa nacitat testovacie vektory.\n");
        return 1;
    }

    printf("Nacitanych %d testovacich vektorov.\n", vector_count);

    for (int i = 0; i < vector_count; i++) {
        printf("\n==================== Testovaci Vektor %d ====================\n", i + 1);
        if (runOcbTest(&vectors[i], key_size_bytes)) {
            passed_count++;
        }
        printf("===========================================================\n");
    }

    printf("\nTestovanie dokoncene: %d/%d testov uspesnych.\n", passed_count, vector_count);

    freeTestVectors(vectors, vector_count);

    return (passed_count == vector_count) ? 0 : 1; // Navratova hodnota 0 pri uspechu
}