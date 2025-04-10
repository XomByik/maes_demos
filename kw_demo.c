#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <stdbool.h>
#include "libs/micro_aes.h"

#ifndef KW
#warning "KW nie je definovane, kompilujem bez podpory KW."
#define KW 0
#endif

int hex_to_bin(const char *hex, uint8_t *bin, size_t bin_len) {
    if (hex == NULL || bin == NULL) {
         fprintf(stderr, "Error: NULL pointer passed to hex_to_bin.\n");
         return -1;
    }
    size_t hex_len = strlen(hex);
    if (hex_len != bin_len * 2) {
        if (!(bin_len == 0 && hex_len == 0)) {
             fprintf(stderr, "Error: Hex string length (%zu) must be (%zu), double the expected binary length (%zu).\n", hex_len, bin_len*2, bin_len);
             return -1;
        }
    }
    if (bin_len == 0) {
        return 0;
    }

    for (size_t i = 0; i < bin_len; ++i) {
        if (!isxdigit((unsigned char)hex[i * 2]) || !isxdigit((unsigned char)hex[i * 2 + 1])) {
             fprintf(stderr, "Error: Invalid non-hex character encountered in string '%s' at index %zu.\n", hex, i*2);
             return -1;
        }
        unsigned int byte_val;
        if (sscanf(hex + i * 2, "%2x", &byte_val) != 1) {
             fprintf(stderr, "Error: sscanf failed to parse hex byte from '%s' at index %zu.\n", hex, i*2);
             return -1;
        }
        bin[i] = (uint8_t)byte_val;
    }
    return 0;
}

void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s (%zu bajtov): ", label, len);
    if (data == NULL && len > 0) {
        printf("<NULL DATA>");
    } else if (len == 0) {
        printf("<PRAZDNE>");
    } else {
        for (size_t i = 0; i < len; i++) {
            printf("%02x", data[i]);
        }
    }
    printf("\n");
}

char* my_strdup(const char* s) {
    if (s == NULL) return NULL;
    size_t len = strlen(s) + 1;
    char* new_str = malloc(len);
    if (new_str) {
        memcpy(new_str, s, len);
    } else {
        perror("Chyba alokacie pamate v my_strdup");
    }
    return new_str;
}

char* trim(char* str) {
    if (!str) return NULL;
    char* end;

    while(isspace((unsigned char)*str)) str++;

    if(*str == 0)
        return str;

    end = str + strlen(str) - 1;
    while(end > str && isspace((unsigned char)*end)) end--;

    *(end+1) = 0;

    return str;
}

bool run_wrap_tests(const char* filename, int key_size_bytes) {
    printf("\n--- Testovanie Wrap (AE) zo suboru: %s ---\n", filename);
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("Nepodarilo sa otvorit subor");
        return false;
    }

    char line[1024];
    int test_count = 0;
    int passed_count = 0;
    int current_count = -1;
    char *hex_k = NULL;
    char *hex_p = NULL;
    char *hex_c_expected = NULL;
    size_t p_len = 0;

    while (fgets(line, sizeof(line), fp)) {
        char* trimmed_line = trim(line);
        if (strlen(trimmed_line) == 0 || trimmed_line[0] == '#') continue;

        if (strncmp(trimmed_line, "[PLAINTEXT LENGTH = ", 19) == 0) {
             sscanf(trimmed_line + 19, "%zu", &p_len);
             p_len /= 8;
             printf("Info: Dlzka plaintextu nastavena na %zu bajtov\n", p_len);
             continue;
        }

        if (strncmp(trimmed_line, "COUNT = ", 8) == 0) {
            if (current_count != -1 && hex_k && hex_p && hex_c_expected) {
                test_count++;
                printf("\nTest #%d\n", current_count);

                uint8_t key[key_size_bytes];
                uint8_t plaintext[p_len];
                size_t expected_c_len = p_len + 8;
                uint8_t ciphertext_expected[expected_c_len];
                uint8_t ciphertext_result[expected_c_len];
                bool conv_ok = true;

                conv_ok &= hex_to_bin(hex_k, key, key_size_bytes) == 0;
                conv_ok &= hex_to_bin(hex_p, plaintext, p_len) == 0;
                conv_ok &= hex_to_bin(hex_c_expected, ciphertext_expected, expected_c_len) == 0;

                if (!conv_ok) {
                    fprintf(stderr, "Chyba konverzie hex dat pre Test #%d\n", current_count);
                } else {
                    print_hex("Kluc", key, key_size_bytes);
                    print_hex("Plaintext", plaintext, p_len);
                    print_hex("Ocakavany Ciphertext", ciphertext_expected, expected_c_len);

                    int wrap_status = AES_KEY_wrap(key, plaintext, p_len, ciphertext_result);

                    if (wrap_status == 0) {
                        print_hex("Vypocitany Ciphertext", ciphertext_result, expected_c_len);
                        if (memcmp(ciphertext_result, ciphertext_expected, expected_c_len) == 0) {
                            printf("Vysledok: USPESNY\n");
                            passed_count++;
                        } else {
                            printf("Vysledok: NEUSPESNY (neshoda ciphertextu)\n");
                        }
                    } else {
                        printf("Vysledok: NEUSPESNY (chyba pri wrap: %d)\n", wrap_status);
                    }
                }
            }
            sscanf(trimmed_line + 8, "%d", &current_count);
            free(hex_k); hex_k = NULL;
            free(hex_p); hex_p = NULL;
            free(hex_c_expected); hex_c_expected = NULL;
            continue;
        }

        if (strncmp(trimmed_line, "K = ", 4) == 0) {
            free(hex_k);
            hex_k = my_strdup(trimmed_line + 4);
        } else if (strncmp(trimmed_line, "P = ", 4) == 0) {
            free(hex_p);
            hex_p = my_strdup(trimmed_line + 4);
        } else if (strncmp(trimmed_line, "C = ", 4) == 0) {
            free(hex_c_expected);
            hex_c_expected = my_strdup(trimmed_line + 4);
        }
    }

    if (current_count != -1 && hex_k && hex_p && hex_c_expected) {
         test_count++;
         printf("\nTest #%d\n", current_count);

         uint8_t key[key_size_bytes];
         uint8_t plaintext[p_len];
         size_t expected_c_len = p_len + 8;
         uint8_t ciphertext_expected[expected_c_len];
         uint8_t ciphertext_result[expected_c_len];
         bool conv_ok = true;

         conv_ok &= hex_to_bin(hex_k, key, key_size_bytes) == 0;
         conv_ok &= hex_to_bin(hex_p, plaintext, p_len) == 0;
         conv_ok &= hex_to_bin(hex_c_expected, ciphertext_expected, expected_c_len) == 0;

         if (!conv_ok) {
             fprintf(stderr, "Chyba konverzie hex dat pre Test #%d\n", current_count);
         } else {
             print_hex("Kluc", key, key_size_bytes);
             print_hex("Plaintext", plaintext, p_len);
             print_hex("Ocakavany Ciphertext", ciphertext_expected, expected_c_len);

             int wrap_status = AES_KEY_wrap(key, plaintext, p_len, ciphertext_result);

             if (wrap_status == 0) {
                 print_hex("Vypocitany Ciphertext", ciphertext_result, expected_c_len);
                 if (memcmp(ciphertext_result, ciphertext_expected, expected_c_len) == 0) {
                     printf("Vysledok: USPESNY\n");
                     passed_count++;
                 } else {
                     printf("Vysledok: NEUSPESNY (neshoda ciphertextu)\n");
                 }
             } else {
                 printf("Vysledok: NEUSPESNY (chyba pri wrap: %d)\n", wrap_status);
             }
         }
    }

    fclose(fp);
    free(hex_k);
    free(hex_p);
    free(hex_c_expected);
    printf("\nWrap testy dokoncene: %d/%d uspesnych\n", passed_count, test_count);
    return passed_count == test_count;
}

bool run_unwrap_tests(const char* filename, int key_size_bytes) {
    printf("\n--- Testovanie Unwrap (AD) zo suboru: %s ---\n", filename);
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("Nepodarilo sa otvorit subor");
        return false;
    }

    char line[1024];
    int test_count = 0;
    int passed_count = 0;
    int current_count = -1;
    char *hex_k = NULL;
    char *hex_c = NULL;
    char *hex_p_expected = NULL;
    bool expect_fail = false;
    size_t p_len = 0;

    while (fgets(line, sizeof(line), fp)) {
        char* trimmed_line = trim(line);
        if (strlen(trimmed_line) == 0 || trimmed_line[0] == '#') continue;

         if (strncmp(trimmed_line, "[PLAINTEXT LENGTH = ", 19) == 0) {
             sscanf(trimmed_line + 19, "%zu", &p_len);
             p_len /= 8;
             printf("Info: Dlzka plaintextu nastavena na %zu bajtov\n", p_len);
             continue;
        }

        if (strncmp(trimmed_line, "COUNT = ", 8) == 0) {
            if (current_count != -1 && hex_k && hex_c && (hex_p_expected || expect_fail)) {
                test_count++;
                printf("\nTest #%d\n", current_count);

                uint8_t key[key_size_bytes];
                size_t c_len = strlen(hex_c) / 2;
                uint8_t ciphertext[c_len];
                uint8_t plaintext_expected[p_len > 0 ? p_len : 1];
                uint8_t plaintext_result[p_len > 0 ? p_len : 1];
                bool conv_ok = true;

                conv_ok &= hex_to_bin(hex_k, key, key_size_bytes) == 0;
                conv_ok &= hex_to_bin(hex_c, ciphertext, c_len) == 0;
                if (!expect_fail) {
                    conv_ok &= hex_to_bin(hex_p_expected, plaintext_expected, p_len) == 0;
                }

                if (!conv_ok) {
                     fprintf(stderr, "Chyba konverzie hex dat pre Test #%d\n", current_count);
                } else {
                    print_hex("Kluc", key, key_size_bytes);
                    print_hex("Ciphertext", ciphertext, c_len);
                    if (!expect_fail) {
                        print_hex("Ocakavany Plaintext", plaintext_expected, p_len);
                    } else {
                        printf("Ocakavany Vysledok: ZLYHANIE (FAIL)\n");
                    }

                    int unwrap_status = AES_KEY_unwrap(key, ciphertext, c_len, plaintext_result);

                    if (unwrap_status == 0) {
                        printf("Status Unwrap: USPECH\n");
                        if (expect_fail) {
                            printf("Vysledok: NEUSPESNY (ocakavalo sa zlyhanie, ale prebehlo uspesne)\n");
                            print_hex("Vypocitany Plaintext", plaintext_result, p_len);
                        } else {
                            print_hex("Vypocitany Plaintext", plaintext_result, p_len);
                            if (memcmp(plaintext_result, plaintext_expected, p_len) == 0) {
                                printf("Vysledok: USPESNY\n");
                                passed_count++;
                            } else {
                                printf("Vysledok: NEUSPESNY (neshoda plaintextu)\n");
                            }
                        }
                    } else {
                        printf("Status Unwrap: ZLYHANIE (kod %d)\n", unwrap_status);
                         if (expect_fail) {
                            printf("Vysledok: USPESNY (ocakavane zlyhanie)\n");
                            passed_count++;
                        } else {
                            printf("Vysledok: NEUSPESNY (neocakavane zlyhanie)\n");
                        }
                    }
                }
            }
            sscanf(trimmed_line + 8, "%d", &current_count);
            free(hex_k); hex_k = NULL;
            free(hex_c); hex_c = NULL;
            free(hex_p_expected); hex_p_expected = NULL;
            expect_fail = false;
            continue;
        }

        if (strncmp(trimmed_line, "K = ", 4) == 0) {
            free(hex_k);
            hex_k = my_strdup(trimmed_line + 4);
        } else if (strncmp(trimmed_line, "C = ", 4) == 0) {
            free(hex_c);
            hex_c = my_strdup(trimmed_line + 4);
        } else if (strncmp(trimmed_line, "P = ", 4) == 0) {
            free(hex_p_expected);
            hex_p_expected = my_strdup(trimmed_line + 4);
        } else if (strcmp(trimmed_line, "FAIL") == 0) {
            expect_fail = true;
        }
    }

     if (current_count != -1 && hex_k && hex_c && (hex_p_expected || expect_fail)) {
         test_count++;
         printf("\nTest #%d\n", current_count);

         uint8_t key[key_size_bytes];
         size_t c_len = strlen(hex_c) / 2;
         uint8_t ciphertext[c_len];
         uint8_t plaintext_expected[p_len > 0 ? p_len : 1];
         uint8_t plaintext_result[p_len > 0 ? p_len : 1];
         bool conv_ok = true;

         conv_ok &= hex_to_bin(hex_k, key, key_size_bytes) == 0;
         conv_ok &= hex_to_bin(hex_c, ciphertext, c_len) == 0;
         if (!expect_fail) {
             conv_ok &= hex_to_bin(hex_p_expected, plaintext_expected, p_len) == 0;
         }

         if (!conv_ok) {
              fprintf(stderr, "Chyba konverzie hex dat pre Test #%d\n", current_count);
         } else {
             print_hex("Kluc", key, key_size_bytes);
             print_hex("Ciphertext", ciphertext, c_len);
             if (!expect_fail) {
                 print_hex("Ocakavany Plaintext", plaintext_expected, p_len);
             } else {
                 printf("Ocakavany Vysledok: ZLYHANIE (FAIL)\n");
             }

             int unwrap_status = AES_KEY_unwrap(key, ciphertext, c_len, plaintext_result);

             if (unwrap_status == 0) {
                 printf("Status Unwrap: USPECH\n");
                 if (expect_fail) {
                     printf("Vysledok: NEUSPESNY (ocakavalo sa zlyhanie, ale prebehlo uspesne)\n");
                     print_hex("Vypocitany Plaintext", plaintext_result, p_len);
                 } else {
                     print_hex("Vypocitany Plaintext", plaintext_result, p_len);
                     if (memcmp(plaintext_result, plaintext_expected, p_len) == 0) {
                         printf("Vysledok: USPESNY\n");
                         passed_count++;
                     } else {
                         printf("Vysledok: NEUSPESNY (neshoda plaintextu)\n");
                     }
                 }
             } else {
                 printf("Status Unwrap: ZLYHANIE (kod %d)\n", unwrap_status);
                  if (expect_fail) {
                     printf("Vysledok: USPESNY (ocakavane zlyhanie)\n");
                     passed_count++;
                 } else {
                     printf("Vysledok: NEUSPESNY (neocakavane zlyhanie)\n");
                 }
             }
         }
     }

    fclose(fp);
    free(hex_k);
    free(hex_c);
    free(hex_p_expected);
    printf("\nUnwrap testy dokoncene: %d/%d uspesnych\n", passed_count, test_count);
    return passed_count == test_count;
}

int main() {
    #if KW == 0
        printf("KW rezim nie je povoleny pri kompilacii.\n");
        return 1;
    #endif

    #if AES___ == 256
        const int aes_bits = 256;
        const char* wrap_file = "test_vectors/kw_ae_256.txt";
        const char* unwrap_file = "test_vectors/kw_ad_256.txt";
    #elif AES___ == 192
        const int aes_bits = 192;
        const char* wrap_file = "test_vectors/kw_ae_192.txt";
        const char* unwrap_file = "test_vectors/kw_ad_192.txt";
    #else
        const int aes_bits = 128;
        const char* wrap_file = "test_vectors/kw_ae_128.txt";
        const char* unwrap_file = "test_vectors/kw_ad_128.txt";
    #endif

    printf("Program skompilovany pre AES-%d KW rezim\n", aes_bits);

    bool wrap_ok = run_wrap_tests(wrap_file, aes_bits / 8);
    bool unwrap_ok = run_unwrap_tests(unwrap_file, aes_bits / 8);

    printf("\nCelkovy vysledok:\n");
    printf("  Wrap testy: %s\n", wrap_ok ? "USPESNE" : "ZLYHALI");
    printf("  Unwrap testy: %s\n", unwrap_ok ? "USPESNE" : "ZLYHALI");

    return (wrap_ok && unwrap_ok) ? 0 : 1;
}
