#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "libs/micro_aes.h"

/**
 * Pomocne funkcie na konverziu medzi hexadecimalnymi retazcami a bajtami
 */
void hexToBytes(const char *hex, uint8_t *bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        sscanf(hex + i * 2, "%2hhx", &bytes[i]);
    }
}

void bytesToHex(const uint8_t *bytes, size_t len, char *hex) {
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + i * 2, "%02x", bytes[i]);
    }
    hex[len * 2] = '\0';
}

/**
 * Porovnanie dvoch bajtovych poli s vypisy vysledkov
 * @return 0 ak sa polia zhoduju, ine hodnoty pri nezhode
 */
int32_t compareAndPrint(const char *title, const uint8_t *expected, const uint8_t *actual, size_t length) {
    char expected_hex[2048] = {0};
    char actual_hex[2048] = {0};
    
    bytesToHex(expected, length, expected_hex);
    bytesToHex(actual, length, actual_hex);
    
    int32_t result = memcmp(expected, actual, length);
    
    printf("%s:\n", title);
    printf("  Ocakavane: %s\n", expected_hex);
    printf("  Vypocitane: %s\n", actual_hex);
    printf("  Zhoda: %s\n\n", result == 0 ? "✓ ANO" : "✗ NIE");
    
    return result;
}

/**
 * Struktura pre testovacie vektory
 */
typedef struct {
    char *key_hex;      // Kluc v HEX formate
    char *iv_hex;       // IV/Nonce v HEX formate
    char *aad_hex;      // Dodatocne autentifikacne data v HEX formate
    char *plaintext_hex; // Plaintext v HEX formate
    char *ciphertext_hex; // Ciphertext v HEX formate
    char *tag_hex;      // Autentifikacny tag v HEX formate
    int8_t type;         // 0=sifrovanie, 1=desifrovanie, 2=len autentifikacia
    int8_t expected_status; // 0=uspech, 1=zlyhanie (FAIL)
} GCM_Test_Vector;

/**
 * Zisti dlzku nonce v bitoch
 */
int32_t getNonceBits(void) {
    #ifdef GCM_NONCE_LEN
        return GCM_NONCE_LEN * 8;
    #else
        return 96; // Standardna dlzka 96 bitov
    #endif
}

/**
 * Vypis informacie o aktualnej konfiguracji
 */
void printBuildInfo(void) {
    printf("=== AES-GCM Konfiguracia ===\n");
    printf("Velkost AES kluca: %d bitov\n", AES_KEY_SIZE * 8);
    
    int32_t nonce_bits = getNonceBits();
    printf("Dlzka GCM nonce: %d bitov", nonce_bits);
    
    if (nonce_bits == 1024) {
        printf(" (dlha verzia)\n");
    } else {
        printf(" (standardna verzia)\n");
    }
    printf("\n");
}

/**
 * Funkcia na nacitanie testovacich vektorov zo suboru
 * Automaticky urci, ci sa jedna o sifrovanie alebo desifrovanie
 * podla poradia PT a CT vo vektore alebo pritomnosti znacky FAIL
 */
int32_t loadTestVectors(const char *filename, GCM_Test_Vector **vectors, int32_t *vector_count) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        printf("Chyba: Nemozem otvorit subor %s\n", filename);
        return 0;
    }

    // Inicializacia
    *vector_count = 0;
    *vectors = NULL;
    
    // Docasne buffery
    char line[1024];
    int8_t pt_first = 0;   // Urcuje, ci PT alebo CT je prve v subore
    int8_t ct_first = 0;   // Urcuje, ci PT alebo CT je prve v subore

    // Prva iteracia - zisti pocet vektorov a typ testu
    int32_t counter = 0;
    int8_t firstVector = 1;
    
    while (fgets(line, sizeof(line), fp)) {
        // Odstranenie koncovych znakov noveho riadka
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';
            
        // Preskocenie prazdnych riadkov
        if (len == 0) continue;
        
        // Parsovanie Count = X zaznamov
        if (strncmp(line, "Count = ", 8) == 0) {
            counter++;
        }
        // Zisti, ci PT alebo CT je prve v subore (pre prvy vektor)
        else if (firstVector) {
            if (strncmp(line, "PT = ", 5) == 0) {
                pt_first = 1;
                firstVector = 0;
            }
            else if (strncmp(line, "CT = ", 5) == 0) {
                ct_first = 1;
                firstVector = 0;
            }
        }
    }
    
    // Druha iteracia - naplnenie vektorov
    rewind(fp);
    
    *vector_count = counter;
    *vectors = (GCM_Test_Vector*)malloc(sizeof(GCM_Test_Vector) * counter);
    if (!*vectors) {
        printf("Chyba: Nedostatok pamate pre vektory\n");
        fclose(fp);
        return 0;
    }
    
    // Inicializacia vsetkych poli
    for (int32_t i = 0; i < counter; i++) {
        (*vectors)[i].key_hex = NULL;
        (*vectors)[i].iv_hex = NULL;
        (*vectors)[i].aad_hex = NULL;
        (*vectors)[i].plaintext_hex = NULL;
        (*vectors)[i].ciphertext_hex = NULL;
        (*vectors)[i].tag_hex = NULL;
        (*vectors)[i].expected_status = 0; // Predvolene: ocakava sa uspech
        
        // Nastav predpokladany typ testu
        if (pt_first) {
            (*vectors)[i].type = 0;  // Sifrovanie (PT je prve)
        } else if (ct_first) {
            (*vectors)[i].type = 1;  // Desifrovanie (CT je prve)
        } else {
            (*vectors)[i].type = 0;  // Predvolene: sifrovanie
        }
    }

    int32_t current_vector = -1;
    
    while (fgets(line, sizeof(line), fp)) {
        // Odstranenie koncovych znakov noveho riadka
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';
            
        // Preskocenie prazdnych riadkov
        if (len == 0) continue;
        
        // Kontrola zaznamu FAIL, ktory znaci desifrovanie so zlhanim
        if (strncmp(line, "FAIL", 4) == 0) {
            if (current_vector >= 0 && current_vector < *vector_count) {
                (*vectors)[current_vector].type = 1;  // Oznac ako desifrovanie
                (*vectors)[current_vector].expected_status = 1; // Ocakava sa zlyhanie
            }
            continue;
        }
        
        // Parsovanie jednotlivych poli
        if (strncmp(line, "Count = ", 8) == 0) {
            current_vector++;
            if (current_vector >= counter) break; // Prevencia pretecenia
            continue;
        }
        
        if (current_vector < 0) continue; // Preskoc riadky pred prvym vektorom
        
        // Parsovanie hodnot
        if (strncmp(line, "Key = ", 6) == 0) {
            (*vectors)[current_vector].key_hex = strdup(line + 6);
        }
        else if (strncmp(line, "IV = ", 5) == 0) {
            (*vectors)[current_vector].iv_hex = strdup(line + 5);
        }
        else if (strncmp(line, "AAD = ", 6) == 0) {
            (*vectors)[current_vector].aad_hex = strdup(line + 6);
        }
        else if (strncmp(line, "PT = ", 5) == 0) {
            (*vectors)[current_vector].plaintext_hex = strdup(line + 5);
            // Ak CT uz bolo nacitane pred PT, je to desifrovanie
            if ((*vectors)[current_vector].ciphertext_hex != NULL) {
                (*vectors)[current_vector].type = 1; // Desifrovanie
            }
        }
        else if (strncmp(line, "CT = ", 5) == 0) {
            (*vectors)[current_vector].ciphertext_hex = strdup(line + 5);
            // Ak PT este nebolo nacitane a CT uz ano, je to pravdepodobne desifrovanie
            if ((*vectors)[current_vector].plaintext_hex == NULL) {
                (*vectors)[current_vector].type = 1; // Desifrovanie
            }
        }
        else if (strncmp(line, "Tag = ", 6) == 0) {
            (*vectors)[current_vector].tag_hex = strdup(line + 6);
        }
    }
    
    fclose(fp);
    return 1;
}

/**
 * Funkcia na uvolnenie pamate alokovanych testovacich vektorov
 */
void freeTestVectors(GCM_Test_Vector *vectors, int32_t count) {
    for (int32_t i = 0; i < count; i++) {
        if (vectors[i].key_hex) free(vectors[i].key_hex);
        if (vectors[i].iv_hex) free(vectors[i].iv_hex);
        if (vectors[i].aad_hex) free(vectors[i].aad_hex);
        if (vectors[i].plaintext_hex) free(vectors[i].plaintext_hex);
        if (vectors[i].ciphertext_hex) free(vectors[i].ciphertext_hex);
        if (vectors[i].tag_hex) free(vectors[i].tag_hex);
    }
    free(vectors);
}

/**
 * Najdenie vhodneho nazvu suboru pre testovacie vektory
 */
char* getTestVectorFilename(const char* explicit_file) {
    if (explicit_file != NULL) {
        return strdup(explicit_file);
    }
    
    char test_file_path[256];
    int32_t nonce_bits = getNonceBits();
    
    // Najprv skus presne zodpovedajuce testovacie vektory
    if (nonce_bits == 96) {
        // Standardne vektory (96-bit nonce)
        const char *std_patterns[] = {
            "test_vectors/gcm_test_vectors_%d.txt",
            "gcm_test_vectors_%d.txt"
        };
        
        for (uint32_t i = 0; i < (uint32_t)(sizeof(std_patterns)/sizeof(char*)); i++) {
            sprintf(test_file_path, std_patterns[i], AES_KEY_SIZE * 8);
            
            FILE *fp = fopen(test_file_path, "r");
            if (fp != NULL) {
                fclose(fp);
                return strdup(test_file_path);
            }
        }
    } else if (nonce_bits == 1024) {
        // 1024-bit nonce vektory
        const char *long_patterns[] = {
            "test_vectors/gcm1024_test_vectors_%d.txt",
            "gcm1024_test_vectors_%d.txt"
        };
        
        for (uint32_t i = 0; i < (uint32_t)(sizeof(long_patterns)/sizeof(char*)); i++) {
            sprintf(test_file_path, long_patterns[i], AES_KEY_SIZE * 8);
            
            FILE *fp = fopen(test_file_path, "r");
            if (fp != NULL) {
                fclose(fp);
                return strdup(test_file_path);
            }
        }
    } 
    
    // Predvoleny nazov suboru
    sprintf(test_file_path, "test_vectors/gcm%s_test_vectors_%d.txt", 
            nonce_bits != 96 ? "_custom" : "", AES_KEY_SIZE * 8);
    
    return strdup(test_file_path);
}

/**
 * Spracovanie a vykonanie testovania GCM pre dany vektor
 */
void runGcmTest(const GCM_Test_Vector *vector) {
    // Konverzia hexadecimalnych retazcov na bajty - ale kontrolujeme ci dlzky su platne (parne)
    size_t key_hex_len = vector->key_hex ? strlen(vector->key_hex) : 0;
    size_t iv_hex_len = vector->iv_hex ? strlen(vector->iv_hex) : 0;
    size_t aad_hex_len = vector->aad_hex ? strlen(vector->aad_hex) : 0;
    size_t pt_hex_len = vector->plaintext_hex ? strlen(vector->plaintext_hex) : 0;
    size_t ct_hex_len = vector->ciphertext_hex ? strlen(vector->ciphertext_hex) : 0;
    size_t tag_hex_len = vector->tag_hex ? strlen(vector->tag_hex) : 0;
    
    // Kontrola ci su dlzky hex stringov parne (platne hex pary)
    int8_t has_invalid_length = 0;
    if (pt_hex_len % 2 != 0) {
        printf("VAROVANIE: Plaintext ma neplatnu dlzku (neparny pocet hex znakov): %zu\n", pt_hex_len);
        has_invalid_length = 1;
    }
    if (ct_hex_len % 2 != 0) {
        printf("VAROVANIE: Ciphertext ma neplatnu dlzku (neparny pocet hex znakov): %zu\n", ct_hex_len);
        has_invalid_length = 1;
    }
    
    // Ak je neplatna dlzka, test automaticky zlyhava
    if (has_invalid_length) {
        printf("\nVysledok testu: ✗ NEUSPESNE - Neplatna dlzka hex stringu (musi byt parny pocet znakov)\n\n");
        return;
    }
    
    // Vypocet velkosti v bajtoch
    size_t key_len = key_hex_len / 2;
    size_t iv_len = iv_hex_len / 2;
    size_t aad_len = aad_hex_len / 2;
    size_t pt_len = pt_hex_len / 2;
    size_t ct_len = ct_hex_len / 2;
    size_t tag_len = tag_hex_len / 2;
    
    // Overenie spravnej velkosti kluca
    if (key_len != AES_KEY_SIZE) {
        printf("Chyba: Velkost kluca by mala byt %d bajtov\n", AES_KEY_SIZE);
        return;
    }

    // Alokovanie pamate
    uint8_t *key = (uint8_t*)malloc(key_len);
    uint8_t *iv = (uint8_t*)malloc(iv_len);
    uint8_t *aad = (uint8_t*)malloc(aad_len > 0 ? aad_len : 1);
    uint8_t *plaintext = (uint8_t*)malloc(pt_len > 0 ? pt_len : 1);
    uint8_t *ciphertext = (uint8_t*)malloc(ct_len > 0 ? ct_len : 1);
    uint8_t *tag = (uint8_t*)malloc(tag_len > 0 ? tag_len : 16);  // Minimalne 16 pre GCM tag
    
    // Konverzia hexadecimalnych hodnot na bajty
    hexToBytes(vector->key_hex, key, key_len);
    hexToBytes(vector->iv_hex, iv, iv_len);
    
    if (aad_len > 0) {
        hexToBytes(vector->aad_hex, aad, aad_len);
    }
    
    if (pt_len > 0) {
        hexToBytes(vector->plaintext_hex, plaintext, pt_len);
    }
    
    if (ct_len > 0) {
        hexToBytes(vector->ciphertext_hex, ciphertext, ct_len);
    }
    
    if (tag_len > 0) {
        hexToBytes(vector->tag_hex, tag, tag_len);
    }
    
    // Vypis zakladnych informacii o teste
    printf("=== GCM Test ===\n");
    printf("Dlzka kluca: %zu bajtov\n", key_len);
    printf("Dlzka IV: %zu bajtov\n", iv_len);
    printf("Dlzka AAD: %zu bajtov\n", aad_len);
    printf("Dlzka tagu: %zu bajtov\n", tag_len);
    
    // Vykonanie testu podla typu
    if (vector->type == 0) {  // Sifrovanie
        printf("Dlzka plaintextu: %zu bajtov\n", pt_len);
        printf("Typ testu: Sifrovanie\n\n");
        
        // Alokovanie pamate pre vysledky
        uint8_t *result_ciphertext = (uint8_t*)malloc(pt_len > 0 ? pt_len : 1);
        uint8_t *result_tag = (uint8_t*)malloc(16);  // Tag je vzdy 16 bajtov
        
        // Volanie AES-GCM sifrovania
        AES_GCM_encrypt(key, iv, plaintext, pt_len, aad, aad_len, 
                       result_ciphertext, result_tag);
        
        // Vypis celeho vypocitaneho ciphertextu
        char result_ct_hex[2048] = {0};
        bytesToHex(result_ciphertext, pt_len, result_ct_hex);
        printf("Vygenerovany ciphertext (%zu bajtov): %s\n", pt_len, result_ct_hex);
        
        // Vzdy vypiseme ocakavany ciphertext zo suboru (moze byt aj prazdny)
        char expected_hex[2048] = {0};
        bytesToHex(ciphertext, ct_len, expected_hex);
        printf("Ocakavany ciphertext (%zu bajtov): %s\n", ct_len, expected_hex);
        
        // Porovnanie vysledkov a vyhodnotenie testu
        int8_t success = 1;
        
        // Test je neuspesny, ak sa dlzky nezhoduju
        if (pt_len != ct_len) {
            printf("Chyba: Dlzka vypocitaneho ciphertextu (%zu) sa nezhoduje s dlzkou ocakavaneho ciphertextu (%zu)\n", 
                  pt_len, ct_len);
            success = 0;
        } else if (ct_len > 0) {
            // Porovnanie obsahu - musia sa zhodovat uplne
            int32_t ct_match = memcmp(ciphertext, result_ciphertext, ct_len);
            if (ct_match != 0) {
                printf("Ciphertext sa NEZHODUJE s ocakavanym\n");
                success = 0;
            } else {
                printf("Ciphertext sa ZHODUJE s ocakavanym\n");
            }
        } else {
            // Ak su oba prazdne, tak sa zhoduju
            printf("Ciphertext sa ZHODUJE s ocakavanym (oba su prazdne)\n");
        }
        
        // Porovnanie tagu - tag musi byt vzdy zhodny v celej dlzke
        int32_t tag_match = memcmp(tag, result_tag, tag_len);
        if (tag_match != 0) {
            // Vypiseme hodnoty pre porovnanie
            char expected_tag_hex[2048] = {0};
            char result_tag_hex[2048] = {0};
            bytesToHex(tag, tag_len, expected_tag_hex);
            bytesToHex(result_tag, tag_len, result_tag_hex);
            printf("Ocakavany tag (%zu bajtov): %s\n", tag_len, expected_tag_hex);
            printf("Vypocitany tag (%zu bajtov): %s\n", tag_len, result_tag_hex);
            printf("Tag sa NEZHODUJE s ocakavanym\n");
            success = 0;
        } else {
            printf("Tag sa ZHODUJE s ocakavanym\n");
        }
        
        printf("Vysledok sifovania: %s\n\n", success ? "✓ USPESNE" : "✗ NEUSPESNE");
        
        // Uvolnenie pamate
        free(result_ciphertext);
        free(result_tag);
    } 
    else if (vector->type == 1) {  // Desifrovanie
        printf("Dlzka ciphertextu: %zu bajtov\n", ct_len);
        printf("Typ testu: Desifrovanie\n");
        printf("Ocakavany status: %s\n\n", vector->expected_status ? "ZLYHANIE" : "USPECH");
        
        // Samostatne vypisanie ciphertextu a tagu
        char ct_hex[2048] = {0};
        char tag_hex[2048] = {0};
        
        bytesToHex(ciphertext, ct_len, ct_hex);
        bytesToHex(tag, tag_len, tag_hex);
        
        printf("Ciphertext: %s\n", ct_hex);
        printf("Tag: %s\n\n", tag_hex);
        
        // Vytvorenie spojeneho bufferu pre ciphertext + tag
        uint8_t *combined_buffer = (uint8_t*)malloc(ct_len + tag_len);
        uint8_t *result_plaintext = (uint8_t*)malloc(ct_len > 0 ? ct_len : 1);
        
        // Spojenie ciphertextu a tagu pre desifrovanie
        memcpy(combined_buffer, ciphertext, ct_len);
        memcpy(combined_buffer + ct_len, tag, tag_len);
        
        // Volanie AES-GCM desifrovania
        uint8_t decryption_status = AES_GCM_decrypt(
            key,                // kluc
            iv,                 // nonce/IV
            combined_buffer,    // ciphertext s pripojenym tagom
            ct_len,             // dlzka samotneho ciphertextu (bez tagu)
            aad,                // dodatocne autentifikacne data
            aad_len,            // dlzka AAD
            tag_len,            // velkost tagu v bajtoch
            result_plaintext    // vystupny buffer pre plaintext
        );
        
        // Kontrola, ci vysledok je v sulade s ocakavanim
        int8_t test_success = (decryption_status == NO_ERROR_RETURNED) != vector->expected_status;
        
        printf("Status desifrovania: %s\n", decryption_status == NO_ERROR_RETURNED ? 
               "✓ Uspesne" : "✗ Neuspesne (chyba autentifikacie)");
        
        printf("Kontrola statusu: %s (ocakavany status: %s, skutocny: %s)\n", 
               test_success ? "✓ OK" : "✗ CHYBA", 
               vector->expected_status ? "ZLYHANIE" : "USPECH", 
               decryption_status == NO_ERROR_RETURNED ? "USPECH" : "ZLYHANIE");
        
        // Zobrazenie vysledneho plaintextu ak desifrovanie bolo uspesne
        if (decryption_status == NO_ERROR_RETURNED) {
            // Vzdy vypiseme cely vypocitany plaintext v plnej dlzke
            char result_pt_hex[2048] = {0};
            bytesToHex(result_plaintext, ct_len, result_pt_hex);
            printf("Desifrovany plaintext (%zu bajtov): %s\n", ct_len, result_pt_hex);
            
            // Vzdy vypiseme ocakavany plaintext zo suboru (moze byt aj prazdny)
            char expected_hex[2048] = {0};
            bytesToHex(plaintext, pt_len, expected_hex);
            printf("Ocakavany plaintext (%zu bajtov): %s\n", pt_len, expected_hex);
            
            // Test je neuspesny, ak sa dlzky nezhoduju
            if (pt_len != ct_len) {
                printf("Chyba: Dlzka vypocitaneho plaintextu (%zu) sa nezhoduje s dlzkou ocakavaneho plaintextu (%zu)\n", 
                      ct_len, pt_len);
                test_success = 0;
            } else if (pt_len > 0) {
                // Test je neuspesny, ak sa obsah nezhoduje
                int32_t pt_match = memcmp(plaintext, result_plaintext, pt_len);
                if (pt_match != 0) {
                    printf("Plaintext sa NEZHODUJE s ocakavanym\n");
                    test_success = 0;
                } else {
                    printf("Plaintext sa ZHODUJE s ocakavanym\n");
                }
            } else {
                // Ak su oba prazdne, tak sa zhoduju
                printf("Plaintext sa ZHODUJE s ocakavanym (oba su prazdne)\n");
            }
            
            printf("Vysledok desifrovania: %s\n\n", test_success ? "✓ USPESNE" : "✗ NEUSPESNE");
        } else {
            printf("Nepodarilo sa desifrovat spravu. Zlyhala autentifikacia.\n");
        }
        
        // Uvolnenie pamate
        free(combined_buffer);
        free(result_plaintext);
    } 
    
    // Uvolnenie pamate
    free(key);
    free(iv);
    free(aad);
    free(plaintext);
    free(ciphertext);
    free(tag);
}

/**
 * Hlavna funkcia programu
 */
int32_t main(int32_t argc, char *argv[]) {
    printf("AES-GCM Demo s vyuzitim micro_aes kniznice\n");
    printBuildInfo();
    
    // Ziskanie nazvu suboru s testovacimi vektormi
    const char *user_file = (argc >= 2) ? argv[1] : NULL;
    char *test_file = getTestVectorFilename(user_file);
    
    printf("Pouziva sa subor s testovacimi vektormi: %s\n\n", test_file);
    
    // Nacitanie a spustenie testovacich vektorov
    GCM_Test_Vector *vectors;
    int32_t vector_count;
    
    if (loadTestVectors(test_file, &vectors, &vector_count)) {
        printf("Nacitanych %d testovacich vektorov\n\n", vector_count);
        
        for (int32_t i = 0; i < vector_count; i++) {
            printf("\n==========================================\n");
            printf("Spustam testovaci vektor %d z %d\n", i+1, vector_count);
            printf("==========================================\n\n");
            runGcmTest(&vectors[i]);
        }
        
        freeTestVectors(vectors, vector_count);
    } else {
        printf("Nepodarilo sa nacitat testovacie vektory zo suboru %s\n", test_file);
        free(test_file);
        return 1;
    }
    
    free(test_file);
    return 0;
}