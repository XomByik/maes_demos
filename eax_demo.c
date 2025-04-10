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

// Konvertuje bajty na hex retazec
void bytesToHex(const uint8_t *bytes, size_t len, char *hex) {
    if (!bytes || !hex) return;
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + i * 2, "%02x", bytes[i]);
    }
    hex[len * 2] = '\0'; // Ukoncovacia nula
}

// Vlastna implementacia strdup
char* my_strdup(const char* s) {
    if (!s) return NULL;
    size_t len = strlen(s) + 1;
    char* new_str = malloc(len);
    if (new_str) {
        memcpy(new_str, s, len);
    } else {
        fprintf(stderr, "Chyba alokacie pamate v my_strdup\n");
    }
    return new_str;
}

// Odstrani biele znaky na zaciatku a konci retazca
char* trim(char* str) {
    if (!str) return NULL;
    char* end;
    while(isspace((unsigned char)*str)) str++;
    if(*str == 0) return str;
    end = str + strlen(str) - 1;
    while(end > str && isspace((unsigned char)*end)) end--;
    *(end+1) = 0;
    return str;
}

// Porovna dve bajtove polia a vypise vysledok v hex formate
int compareAndPrintHex(const char *title, const uint8_t *expected, const uint8_t *actual, size_t len) {
    char expected_hex[2048] = {0}; // Dostacujuca velkost
    char actual_hex[2048] = {0};

    bytesToHex(expected, len, expected_hex);
    bytesToHex(actual, len, actual_hex);

    int match = (len == 0 || memcmp(expected, actual, len) == 0);

    printf("%s:\n", title);
    printf("  Ocakavane : %s (%zu bajtov)\n", expected_hex, len);
    printf("  Vypocitane: %s (%zu bajtov)\n", actual_hex, len);
    printf("  Zhoda     : %s\n", match ? "ANO" : "NIE");

    return match;
}


// --- Struktura pre testovacie vektory ---

typedef struct {
    char *key_hex;
    char *nonce_hex;
    char *header_hex;
    char *pt_hex; // Plaintext
    char *ct_hex; // Ciphertext
    char *tag_hex;
} EAX_Test_Vector;

// Deklaracia funkcie pre uvolnenie pamate
void freeTestVectors(EAX_Test_Vector *vectors, int count);

// --- Nacitanie testovacich vektorov ---

int loadTestVectors(const char *filename, EAX_Test_Vector **vectors, int *vector_count) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        printf("Chyba pri otvarani suboru s testovacimi vektormi: %s\n", filename);
        return 0;
    }

    char line[1024];
    int count = 0;
    int capacity = 10;
    *vectors = malloc(sizeof(EAX_Test_Vector) * capacity);
    if (!*vectors) {
        fclose(fp);
        printf("Chyba alokacie pamate pre vektory\n");
        return 0;
    }
    memset(*vectors, 0, sizeof(EAX_Test_Vector) * capacity); // Inicializacia na nulu

    EAX_Test_Vector current_vector = {0}; // Inicializacia aktualneho vektora
    int vector_complete = 0; // Priznak kompletnosti vektora

    while (fgets(line, sizeof(line), fp)) {
        char* trimmed_line = trim(line);
        if (strlen(trimmed_line) == 0) {
            // Prazdny riadok znamena koniec bloku vektora
            if (vector_complete) {
                 if (capacity <= count) {
                     capacity *= 2;
                     EAX_Test_Vector *temp = realloc(*vectors, sizeof(EAX_Test_Vector) * capacity);
                     if (!temp) {
                         printf("Chyba realokacie pamate pre vektory\n");
                         // Uvolnime ciastocne alokovane data
                         free(current_vector.key_hex);
                         free(current_vector.nonce_hex);
                         free(current_vector.header_hex);
                         free(current_vector.pt_hex);
                         free(current_vector.ct_hex);
                         free(current_vector.tag_hex);
                         free(*vectors); // Uvolnime hlavne pole
                         fclose(fp);
                         return 0;
                     }
                     *vectors = temp;
                 }
                 (*vectors)[count] = current_vector; // Ulozime kompletny vektor
                 count++;
                 memset(&current_vector, 0, sizeof(EAX_Test_Vector)); // Reset pre dalsi vektor
                 vector_complete = 0;
            }
            continue; // Preskocime na dalsi riadok
        }

        char *key = NULL, *value = NULL;
        key = strtok(trimmed_line, ":"); // Rozdelenie podla dvojbodky
        if (key) value = strtok(NULL, ""); // Zvysok riadku ako hodnota
        if (key && value) {
            char* trimmed_key = trim(key);
            char* trimmed_value = trim(value);

            // Bezpecnejsie priradenie pomocou my_strdup
            if (strcmp(trimmed_key, "MSG") == 0) { free(current_vector.pt_hex); current_vector.pt_hex = my_strdup(trimmed_value); }
            else if (strcmp(trimmed_key, "KEY") == 0) { free(current_vector.key_hex); current_vector.key_hex = my_strdup(trimmed_value); }
            else if (strcmp(trimmed_key, "NONCE") == 0) { free(current_vector.nonce_hex); current_vector.nonce_hex = my_strdup(trimmed_value); }
            else if (strcmp(trimmed_key, "HEADER") == 0) { free(current_vector.header_hex); current_vector.header_hex = my_strdup(trimmed_value); }
            else if (strcmp(trimmed_key, "CIPHER") == 0) {
                size_t cipher_len_hex = strlen(trimmed_value);
                size_t tag_len_hex = 16 * 2; // Standardny EAX tag je 16 bajtov (32 hex znakov)

                if (cipher_len_hex >= tag_len_hex) {
                    size_t ct_len_hex = cipher_len_hex - tag_len_hex;

                    // Uvolnenie predchadzajucich alokacii
                    free(current_vector.ct_hex);
                    free(current_vector.tag_hex);
                    current_vector.ct_hex = NULL;
                    current_vector.tag_hex = NULL;

                    // Alokacia a kopirovanie ciphertext casti
                    if (ct_len_hex > 0) {
                        current_vector.ct_hex = malloc(ct_len_hex + 1);
                        if (current_vector.ct_hex) {
                            strncpy(current_vector.ct_hex, trimmed_value, ct_len_hex);
                            current_vector.ct_hex[ct_len_hex] = '\0';
                        } else { printf("Chyba alokacie pamate pre ciphertext\n"); /* Mozna dalsia obsluha */ }
                    }

                    // Alokacia a kopirovanie tag casti
                    current_vector.tag_hex = malloc(tag_len_hex + 1);
                     if (current_vector.tag_hex) {
                        strncpy(current_vector.tag_hex, trimmed_value + ct_len_hex, tag_len_hex);
                        current_vector.tag_hex[tag_len_hex] = '\0';
                    } else { printf("Chyba alokacie pamate pre tag\n"); /* Mozna dalsia obsluha */ }

                    vector_complete = 1; // Oznacime vektor ako potencialne kompletny
                } else {
                    // Chyba: CIPHER riadok je prilis kratky
                    printf("Varovanie: CIPHER riadok prilis kratky vo vektore %d\n", count + 1);
                    free(current_vector.ct_hex);
                    free(current_vector.tag_hex);
                    current_vector.ct_hex = NULL;
                    current_vector.tag_hex = NULL;
                    vector_complete = 1; // Oznacime ako kompletny pre spracovanie (neplatneho) vektora
                }
            }
        }
    }

    // Ulozenie posledneho vektora, ak bol kompletny a subor nekoncil prazdnym riadkom
    if (vector_complete) {
         if (capacity <= count) {
             capacity++;
             EAX_Test_Vector *temp = realloc(*vectors, sizeof(EAX_Test_Vector) * capacity);
             if (!temp) {
                 printf("Chyba realokacie pamate pre posledny vektor\n");
                 // Uvolnime ciastocne alokovane data
                 free(current_vector.key_hex);
                 free(current_vector.nonce_hex);
                 free(current_vector.header_hex);
                 free(current_vector.pt_hex);
                 free(current_vector.ct_hex);
                 free(current_vector.tag_hex);
                 free(*vectors);
                 fclose(fp);
                 return 0;
             }
             *vectors = temp;
         }
        (*vectors)[count] = current_vector;
        count++;
    } else if (current_vector.key_hex || current_vector.nonce_hex || current_vector.pt_hex || current_vector.header_hex || current_vector.ct_hex || current_vector.tag_hex) {
         // Uvolnenie dat pre posledny nekompletny vektor
         free(current_vector.key_hex);
         free(current_vector.nonce_hex);
         free(current_vector.header_hex);
         free(current_vector.pt_hex);
         free(current_vector.ct_hex);
         free(current_vector.tag_hex);
    }

    *vector_count = count;
    fclose(fp);
    return 1;
}

// Uvolnenie pamate alokovanej pre testovacie vektory
void freeTestVectors(EAX_Test_Vector *vectors, int count) {
    if (!vectors) return;
    for (int i = 0; i < count; i++) {
        free(vectors[i].key_hex);
        free(vectors[i].nonce_hex);
        free(vectors[i].header_hex);
        free(vectors[i].pt_hex);
        free(vectors[i].ct_hex);
        free(vectors[i].tag_hex);
    }
    free(vectors);
}

// --- Vykonanie EAX testu ---

int runEaxTest(const EAX_Test_Vector *vector, int key_size_bytes) {
    int overall_success = 1; // Celkovy uspech testu (sifrovanie aj desifrovanie)

    // Vypocet dlzok dat v bajtoch
    size_t key_len = vector->key_hex ? strlen(vector->key_hex) / 2 : 0;
    size_t nonce_len = vector->nonce_hex ? strlen(vector->nonce_hex) / 2 : 0;
    size_t header_len = vector->header_hex ? strlen(vector->header_hex) / 2 : 0;
    size_t pt_len = vector->pt_hex ? strlen(vector->pt_hex) / 2 : 0;
    size_t ct_len = vector->ct_hex ? strlen(vector->ct_hex) / 2 : 0;
    size_t tag_len = vector->tag_hex ? strlen(vector->tag_hex) / 2 : 0;

    // Kontrola platnosti vstupnych dat
    if (key_len != (size_t)key_size_bytes) {
        printf("Chyba: Nespravna dlzka kluca (%zu != %d)\n", key_len, key_size_bytes);
        return 0;
    }
    if (tag_len == 0 || tag_len > 16) {
        printf("Chyba: Neplatna alebo chybajuca dlzka tagu (%zu)\n", tag_len);
        return 0; // EAX tag je typicky do 16 bajtov
    }
    if (pt_len != ct_len) {
        printf("Varovanie: Dlzka plaintextu (%zu) sa nezhoduje s dlzkou ciphertextu (%zu) v testovacom vektore.\n", pt_len, ct_len);
        // V EAX by mali byt rovnake, ale pokracujeme v teste
    }

    // Alokacia pamate pre binarne data
    // Pouzivame calloc pre inicializaciu na nulu, co je bezpecnejsie
    uint8_t *key = calloc(key_len, 1);
    uint8_t *nonce = calloc(nonce_len > 0 ? nonce_len : 1, 1); // Minimalne 1 bajt
    uint8_t *header = calloc(header_len > 0 ? header_len : 1, 1);
    uint8_t *pt = calloc(pt_len > 0 ? pt_len : 1, 1);
    uint8_t *expected_ct = calloc(ct_len > 0 ? ct_len : 1, 1);
    uint8_t *expected_tag = calloc(tag_len, 1);

    uint8_t *result_ct = calloc(pt_len > 0 ? pt_len : 1, 1); // CT dlzka == PT dlzka
    uint8_t *result_tag = calloc(tag_len, 1);
    uint8_t *result_pt = calloc(ct_len > 0 ? ct_len : 1, 1); // PT dlzka == CT dlzka
    uint8_t *combined_ct_tag = calloc((ct_len > 0 ? ct_len : 0) + tag_len, 1);

    // Kontrola uspesnosti alokacie
    if (!key || !nonce || !header || !pt || !expected_ct || !expected_tag || !result_ct || !result_tag || !result_pt || !combined_ct_tag) {
        printf("Chyba: Alokacia pamate zlyhala\n");
        // Uvolnenie uz alokovanej pamate
        free(key); free(nonce); free(header); free(pt); free(expected_ct);
        free(expected_tag); free(result_ct); free(result_tag); free(result_pt);
        free(combined_ct_tag);
        return 0;
    }

    // Konverzia hex retazcov na binarne data
    hex_to_bin(vector->key_hex, key, key_len);
    if (nonce_len > 0) hex_to_bin(vector->nonce_hex, nonce, nonce_len);
    if (header_len > 0) hex_to_bin(vector->header_hex, header, header_len);
    if (pt_len > 0) hex_to_bin(vector->pt_hex, pt, pt_len);
    if (ct_len > 0) hex_to_bin(vector->ct_hex, expected_ct, ct_len);
    hex_to_bin(vector->tag_hex, expected_tag, tag_len);

    // --- Test Sifrovania ---
    printf("--- Sifrovanie ---\n");
    char temp_hex[256]; // Buffer pre vypis hex hodnot

    bytesToHex(key, key_len, temp_hex);
    printf("Kluc      : %s (%zu bajtov)\n", temp_hex, key_len);
    bytesToHex(nonce, nonce_len, temp_hex);
    printf("Nonce     : %s (%zu bajtov)\n", temp_hex, nonce_len);
    bytesToHex(header, header_len, temp_hex);
    printf("Hlavicka  : %s (%zu bajtov)\n", temp_hex, header_len);
    bytesToHex(pt, pt_len, temp_hex);
    printf("Plaintext : %s (%zu bajtov)\n", temp_hex, pt_len);
    printf("\n");

    // Volanie EAX sifrovania
    AES_EAX_encrypt(key, nonce, pt, pt_len, header, header_len, result_ct, result_tag);

    int encrypt_ct_ok = compareAndPrintHex("Ciphertext", expected_ct, result_ct, ct_len);
    int encrypt_tag_ok = compareAndPrintHex("Tag", expected_tag, result_tag, tag_len);

    if (!encrypt_ct_ok || !encrypt_tag_ok) {
        overall_success = 0;
    }
    printf("Vysledok sifrovania: %s\n", (encrypt_ct_ok && encrypt_tag_ok) ? "USPESNE" : "NEUSPESNE");


    // --- Test Desifrovania ---
    printf("\n--- Desifrovanie ---\n");

    bytesToHex(key, key_len, temp_hex);
    printf("Kluc        : %s (%zu bajtov)\n", temp_hex, key_len);
    bytesToHex(nonce, nonce_len, temp_hex);
    printf("Nonce       : %s (%zu bajtov)\n", temp_hex, nonce_len);
    bytesToHex(header, header_len, temp_hex);
    printf("Hlavicka    : %s (%zu bajtov)\n", temp_hex, header_len);
    bytesToHex(expected_ct, ct_len, temp_hex);
    printf("Ciphertext  : %s (%zu bajtov)\n", temp_hex, ct_len);
    bytesToHex(expected_tag, tag_len, temp_hex);
    printf("Tag         : %s (%zu bajtov)\n", temp_hex, tag_len);
    printf("\n");

    // Spojenie ocakavaneho CT a Tagu pre vstup desifrovania
    if (ct_len > 0) memcpy(combined_ct_tag, expected_ct, ct_len);
    memcpy(combined_ct_tag + ct_len, expected_tag, tag_len);

    // Volanie EAX desifrovania
    int decrypt_status = AES_EAX_decrypt(key, nonce, combined_ct_tag, ct_len, header, header_len, tag_len, result_pt);

    printf("Status desifrovania: %s\n", decrypt_status == 0 ? "USPECH (Tag platny)" : "ZLYHANIE (Tag neplatny)");

    if (decrypt_status == 0) { // Uspesne desifrovanie
        int decrypt_pt_ok = compareAndPrintHex("Plaintext", pt, result_pt, pt_len);
        if (!decrypt_pt_ok) {
            overall_success = 0;
        }
        printf("Vysledok desifrovania: %s\n", decrypt_pt_ok ? "USPESNE" : "NEUSPESNE");
    } else {
        // Ak desifrovanie zlyhalo (neplatny tag), test je neuspesny
        printf("Vysledok desifrovania: NEUSPESNE (chyba autentifikacie)\n");
        overall_success = 0;
    }

    // Uvolnenie pamate
    free(key);
    free(nonce);
    free(header);
    free(pt);
    free(expected_ct);
    free(expected_tag);
    free(result_ct);
    free(result_tag);
    free(result_pt);
    free(combined_ct_tag);

    printf("\nVysledok testu: %s\n", overall_success ? "USPESNY" : "NEUSPESNY");
    return overall_success;
}

// --- Hlavna funkcia ---

int main(int argc, char* argv[]) {
    // Zistenie velkosti kluca z kompilacnych definicii
    #if AES___ == 256
        const int aes_bits = 256;
        const char* default_test_file = "test_vectors/eax_256.txt";
        printf("AES-EAX Demo (AES-256)\n");
    #elif AES___ == 192
        const int aes_bits = 192;
        const char* default_test_file = "test_vectors/eax_192.txt";
        printf("AES-EAX Demo (AES-192)\n");
    #else // Predvolene AES-128
        const int aes_bits = 128;
        const char* default_test_file = "test_vectors/eax_128.txt";
        printf("AES-EAX Demo (AES-128)\n");
    #endif

    const char* test_vectors_file = (argc > 1) ? argv[1] : default_test_file;
    int key_size_bytes = aes_bits / 8;

    printf("Pouziva sa subor s testovacimi vektormi: %s\n", test_vectors_file);

    EAX_Test_Vector *vectors = NULL;
    int vector_count = 0;
    int passed_count = 0;

    if (!loadTestVectors(test_vectors_file, &vectors, &vector_count)) {
        printf("Nepodarilo sa nacitat testovacie vektory.\n");
        return 1;
    }

    printf("Nacitanych %d testovacich vektorov.\n", vector_count);

    for (int i = 0; i < vector_count; i++) {
        printf("\n==================== Testovaci Vektor %d ====================\n", i + 1);
        if (runEaxTest(&vectors[i], key_size_bytes)) {
            passed_count++;
        }
        printf("===========================================================\n");
    }

    printf("\nTestovanie dokoncene: %d/%d testov uspesnych.\n", passed_count, vector_count);

    freeTestVectors(vectors, vector_count);

    return (passed_count == vector_count) ? 0 : 1; // Navratova hodnota 0 pri uspechu
}