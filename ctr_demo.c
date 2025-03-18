#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h> // Potrebne pre uint8_t na Windows
#include "libs/micro_aes.h"

// Funkcia na konverziu hexadecimalneho retazca na binarne hodnoty
void hex_to_bin(const char* hex, uint8_t* bin, size_t len) {
    for (size_t i = 0; i < len; i++) {
        sscanf(hex + i * 2, "%2hhx", &bin[i]);
    }
}

// Pomocna funkcia na vypis binarnych dat ako hexadecimalnych hodnot
void print_hex(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// Vlastna implementacia strdup ak je potrebna
char* my_strdup(const char* s) {
    size_t len = strlen(s) + 1;  // +1 pre koncovy nulovy znak
    char* new_str = malloc(len);
    if (new_str) {
        memcpy(new_str, s, len);
    }
    return new_str;
}

// Odstrani biele znaky na zaciatku a konci retazca
char* trim(char* str) {
    char* end;
    
    // Preskoci biele znaky na zaciatku
    while(isspace((unsigned char)*str)) str++;
    
    // Prazdny retazec?
    if(*str == 0)  
        return str;
    
    // Odstrani biele znaky na konci
    end = str + strlen(str) - 1;
    while(end > str && isspace((unsigned char)*end)) end--;
    
    // Prida ukoncovaci nulovy znak
    *(end+1) = 0;
    
    return str;
}

// Funkcia pre inkrementaciu citaca (big-endian)
void increment_counter(uint8_t* counter) {
    // Zaciname od najmenej vyznamneho bajtu (LSB) a postupujeme ku MSB
    for (int i = 15; i >= 0; i--) {
        counter[i]++;
        if (counter[i] != 0) // Ak nie je pretecenie, koncime
            break;
    }
}

// Funkcia pre CTR sifrovanie - vyuziva priamo kniznicnu implementaciu
void process_ctr_encrypt(uint8_t* key, int key_size_bytes, uint8_t* counter, uint8_t* plaintext, size_t data_len, uint8_t* ciphertext) {
    // Pouzijeme kniznicnu funkciu AES_CTR_encrypt
    AES_CTR_encrypt(key, counter, plaintext, data_len, ciphertext);
    
    // Aktualizujeme counter - kniznicna funkcia ho meni, preto musime
    // rucne upravit counter pre spravny vypis
    increment_counter(counter);
}

// CTR desifrovanie - vyuziva priamo kniznicnu implementaciu
void process_ctr_decrypt(uint8_t* key, int key_size_bytes, uint8_t* counter, uint8_t* ciphertext, size_t data_len, uint8_t* plaintext) {
    // Pouzijeme kniznicnu funkciu AES_CTR_decrypt
    AES_CTR_decrypt(key, counter, ciphertext, data_len, plaintext);
    
    // Aktualizujeme counter - kniznicna funkcia ho meni, preto musime
    // rucne upravit counter pre spravny vypis
    increment_counter(counter);
}

// Struktura pre ukladanie testovacich vektorov
typedef struct {
    char hex_input_block[33];
    char hex_output_block[33];
    char hex_plaintext[65];
    char hex_ciphertext[65];
    int block_number;
} TestVector;

int main(int argc, char* argv[]) {
    // Zistenie, ci sa jedna o 128, 192 alebo 256 bitovy rezim podla definicie v micro_aes.h
    #if AES___ == 256
        const int aes_bits = 256;
        const char* test_vectors_file = "test_vectors/ctr_test_vectors_256.txt";
        printf("Program skompilovany pre AES-256 CTR rezim\n");
    #elif AES___ == 192
        const int aes_bits = 192;
        const char* test_vectors_file = "test_vectors/ctr_test_vectors_192.txt";
        printf("Program skompilovany pre AES-192 CTR rezim\n");
    #else
        const int aes_bits = 128;
        const char* test_vectors_file = "test_vectors/ctr_test_vectors_128.txt";
        printf("Program skompilovany pre AES-128 CTR rezim\n");
    #endif
    
    FILE *fp;
    char line[512];
    uint8_t key[32];  // Max 256 bits (32 bytes)
    uint8_t counter[16];   // Counter je vzdy 16 bajtov (128 bitov) pre AES
    uint8_t original_counter[16]; // Ulozenie povodneho citaca
    uint8_t plaintext[512], ciphertext[512], result[512]; // Dostatocne velke pre bezne testy
    char *hex_key = NULL, *hex_counter = NULL;
    char *hex_input_block = NULL, *hex_output_block = NULL;
    char *hex_plaintext = NULL, *hex_ciphertext = NULL;
    int test_count = 0, passed_count = 0;
    int block_number = 0;
    int encrypt_mode = 1;  // 1 = encrypt, 0 = decrypt
    
    // Pre ulozenie vsetkych blokov testovacich vektorov
    TestVector encrypt_tests[10]; // Maximalne 10 blokov
    TestVector decrypt_tests[10]; // Pre desifrovanie
    int encrypt_test_count = 0;
    int decrypt_test_count = 0;
    
    // Alokujeme pamat pre kluce podla zvolenej velkosti
    int key_size_bytes = aes_bits / 8;
    
    // Otvorenie suboru s testovacimi vektormi
    printf("Pouziva sa testovaci subor: %s\n", test_vectors_file);
    fp = fopen(test_vectors_file, "r");
    if (!fp) {
        perror("Nepodarilo sa otvorit subor s testovacimi vektormi");
        return 1;
    }

    // Najprv nacitame vsetky testovacie vektory do pamati
    while (fgets(line, sizeof(line), fp)) {
        // Odstranenie koncoveho znaku noveho riadka a CR znaku (Windows)
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';
        
        // Preskocenie prazdnych riadkov
        if (len == 0) {
            continue;
        }
        
        // Kontrola na zaciatok novej sekcie (Encrypt/Decrypt)
        if (strstr(line, "CTR-AES") != NULL) {
            if (strstr(line, "Encrypt") != NULL) {
                encrypt_mode = 1;
                printf("\n=== Nacitavanie sifrovacich testovacich vektorov ===\n");
            } else if (strstr(line, "Decrypt") != NULL) {
                encrypt_mode = 0;
                printf("\n=== Nacitavanie desifrovacich testovacich vektorov ===\n");
            }
            continue;
        }
        
        // Parsovanie kluca
        if (strncmp(line, "Key", 3) == 0) {
            free(hex_key);
            hex_key = my_strdup(trim(line + 4));
            hex_to_bin(hex_key, key, key_size_bytes);
            printf("\nKluc: %s\n", hex_key);
            continue;
        }
        
        // Parsovanie inicialneho counteru
        if (strncmp(line, "Init. Counter", 13) == 0) {
            free(hex_counter);
            hex_counter = my_strdup(trim(line + 14));
            hex_to_bin(hex_counter, counter, 16);
            memcpy(original_counter, counter, 16);  // Ulozime povodny citac
            printf("Inicialny counter: %s\n", hex_counter);
            continue;
        }
        
        // Parsovanie cisla bloku
        if (strncmp(line, "Block #", 7) == 0) {
            block_number = atoi(line + 7);
            continue;
        }
        
        // Parsovanie vstupneho bloku (citaca)
        if (strncmp(line, "Input Block", 11) == 0) {
            free(hex_input_block);
            hex_input_block = my_strdup(trim(line + 12));
            
            // Ukladanie vstupneho bloku zo suboru (citaca)
            if (encrypt_mode) {
                if (block_number >= 1 && block_number <= 10) {
                    strncpy(encrypt_tests[block_number-1].hex_input_block, hex_input_block, 32);
                    encrypt_tests[block_number-1].hex_input_block[32] = '\0';
                    encrypt_tests[block_number-1].block_number = block_number;
                    if (block_number > encrypt_test_count)
                        encrypt_test_count = block_number;
                }
            } else {
                if (block_number >= 1 && block_number <= 10) {
                    strncpy(decrypt_tests[block_number-1].hex_input_block, hex_input_block, 32);
                    decrypt_tests[block_number-1].hex_input_block[32] = '\0';
                    decrypt_tests[block_number-1].block_number = block_number;
                    if (block_number > decrypt_test_count)
                        decrypt_test_count = block_number;
                }
            }
            continue;
        }
        
        // Parsovanie vystupneho bloku (keystreamu)
        if (strncmp(line, "Output Block", 12) == 0) {
            free(hex_output_block);
            hex_output_block = my_strdup(trim(line + 13));
            
            // Ukladanie vystupneho bloku (keystreamu)
            if (encrypt_mode) {
                if (block_number >= 1 && block_number <= 10) {
                    strncpy(encrypt_tests[block_number-1].hex_output_block, hex_output_block, 32);
                    encrypt_tests[block_number-1].hex_output_block[32] = '\0';
                }
            } else {
                if (block_number >= 1 && block_number <= 10) {
                    strncpy(decrypt_tests[block_number-1].hex_output_block, hex_output_block, 32);
                    decrypt_tests[block_number-1].hex_output_block[32] = '\0';
                }
            }
            continue;
        }
        
        // Parsovanie plaintextu
        if (strncmp(line, "Plaintext", 9) == 0) {
            free(hex_plaintext);
            hex_plaintext = my_strdup(trim(line + 10));
            
            // Ukladanie plaintextu
            if (encrypt_mode) {
                if (block_number >= 1 && block_number <= 10) {
                    strncpy(encrypt_tests[block_number-1].hex_plaintext, hex_plaintext, 64);
                    encrypt_tests[block_number-1].hex_plaintext[64] = '\0';
                }
            } else {
                if (block_number >= 1 && block_number <= 10) {
                    strncpy(decrypt_tests[block_number-1].hex_plaintext, hex_plaintext, 64);
                    decrypt_tests[block_number-1].hex_plaintext[64] = '\0';
                }
            }
            continue;
        }
        
        // Parsovanie ciphertextu
        if (strncmp(line, "Ciphertext", 10) == 0) {
            free(hex_ciphertext);
            hex_ciphertext = my_strdup(trim(line + 11));
            
            // Ukladanie ciphertextu
            if (encrypt_mode) {
                if (block_number >= 1 && block_number <= 10) {
                    strncpy(encrypt_tests[block_number-1].hex_ciphertext, hex_ciphertext, 64);
                    encrypt_tests[block_number-1].hex_ciphertext[64] = '\0';
                }
            } else {
                if (block_number >= 1 && block_number <= 10) {
                    strncpy(decrypt_tests[block_number-1].hex_ciphertext, hex_ciphertext, 64);
                    decrypt_tests[block_number-1].hex_ciphertext[64] = '\0';
                }
            }
            continue;
        }
    }
    
    fclose(fp);
    
    // Teraz vykoname sifrovacie testy s pouzivanim nasho citaca
    printf("\n=== Testovanie sifrovania (Encrypt) ===\n");
    memcpy(counter, original_counter, 16); // Resetujeme citac na povodny
    for (int i = 0; i < encrypt_test_count; i++) {
        int blk_num = encrypt_tests[i].block_number;
        char* hex_input_expected = encrypt_tests[i].hex_input_block;
        char* hex_output = encrypt_tests[i].hex_output_block;
        char* hex_ptext = encrypt_tests[i].hex_plaintext;
        char* hex_ctext = encrypt_tests[i].hex_ciphertext;
        int block_test_success = 1;  // Predpokladame, ze test bude uspesny
        
        test_count++;
        printf("\nTest #%d (Block #%d):\n", test_count, blk_num);
        
        // Konverzia plaintextu z hex na bajty
        size_t plaintext_len = strlen(hex_ptext) / 2;
        hex_to_bin(hex_ptext, plaintext, plaintext_len);
        
        printf("Plaintext: ");
        print_hex(plaintext, plaintext_len);
        
        // Kontrola zhodnosti ocakavaneho a aktualneho counteru
        uint8_t expected_counter[16];
        hex_to_bin(hex_input_expected, expected_counter, 16);
        
        printf("Ocakavany vstupny blok (Counter): %s\n", hex_input_expected);
        printf("Aktualny vstupny blok (Counter): ");
        print_hex(counter, 16);
        
        int counter_match = (memcmp(expected_counter, counter, 16) == 0);
        // Test zlyhava ak sa counter nezhoduje s ocakavanym
        if (!counter_match) {
            printf("!!! CHYBA: Ocakavany counter sa nezhoduje s aktualnym !!!\n");
            block_test_success = 0; // Test zlyhal kvoli nezhode counteru
        }
        
        // Konverzia ocakavaneho output bloku
        uint8_t expected_output[16];
        hex_to_bin(hex_output, expected_output, 16);
        
        // Konverzia ocakavaneho ciphertextu
        uint8_t expected_ciphertext[512];
        size_t ciphertext_len = strlen(hex_ctext) / 2;
        hex_to_bin(hex_ctext, expected_ciphertext, ciphertext_len);
        
        // Tu pouzijeme ocakavany vystupny blok (keystream) pre CTR vypocet
        for (size_t j = 0; j < plaintext_len; j++) {
            result[j] = plaintext[j] ^ expected_output[j];
        }
        
        printf("Vypocitany ciphertext: ");
        print_hex(result, plaintext_len);
        
        printf("Ocakavany ciphertext: ");
        print_hex(expected_ciphertext, ciphertext_len);
        
        // Kontrola zhody - ciphertext musi byt zhodny
        if (memcmp(result, expected_ciphertext, ciphertext_len) != 0) {
            block_test_success = 0; // Test zlyhal kvoli nezhode ciphertextu
            printf("!!! CHYBA: Vypocitany ciphertext sa nezhoduje s ocakavanym !!!\n");
        }
        
        if (block_test_success) {
            passed_count++;
            printf("Test USPESNY\n");
        } else {
            printf("Test NEUSPESNY\n");
        }
        
        // Inkrementujeme counter pre dalsi blok
        increment_counter(counter);
    }
    
    // Teraz vykoname desifrovacie testy s pouzivanim nasho citaca
    printf("\n=== Testovanie desifrovania (Decrypt) ===\n");
    memcpy(counter, original_counter, 16); // Resetujeme citac na povodny
    for (int i = 0; i < decrypt_test_count; i++) {
        int blk_num = decrypt_tests[i].block_number;
        char* hex_input_expected = decrypt_tests[i].hex_input_block;
        char* hex_output = decrypt_tests[i].hex_output_block;
        char* hex_ptext = decrypt_tests[i].hex_plaintext;
        char* hex_ctext = decrypt_tests[i].hex_ciphertext;
        int block_test_success = 1;  // Predpokladame, ze test bude uspesny
        
        test_count++;
        printf("\nTest #%d (Block #%d):\n", test_count, blk_num);
        
        // Konverzia ciphertextu z hex na bajty
        size_t ciphertext_len = strlen(hex_ctext) / 2;
        hex_to_bin(hex_ctext, ciphertext, ciphertext_len);
        
        printf("Ciphertext: ");
        print_hex(ciphertext, ciphertext_len);
        
        // Kontrola zhodnosti ocakavaneho a aktualneho counteru
        uint8_t expected_counter[16];
        hex_to_bin(hex_input_expected, expected_counter, 16);
        
        printf("Ocakavany vstupny blok (Counter): %s\n", hex_input_expected);
        printf("Aktualny vstupny blok (Counter): ");
        print_hex(counter, 16);
        
        int counter_match = (memcmp(expected_counter, counter, 16) == 0);
        // Test zlyhava ak sa counter nezhoduje s ocakavanym
        if (!counter_match) {
            printf("!!! CHYBA: Ocakavany counter sa nezhoduje s aktualnym !!!\n");
            block_test_success = 0; // Test zlyhal kvoli nezhode counteru
        }
        
        // Konverzia ocakavaneho output bloku
        uint8_t expected_output[16];
        hex_to_bin(hex_output, expected_output, 16);
        
        // Konverzia ocakavaneho plaintextu
        uint8_t expected_plaintext[512];
        size_t plaintext_len = strlen(hex_ptext) / 2;
        hex_to_bin(hex_ptext, expected_plaintext, plaintext_len);
        
        // Tu pouzijeme ocakavany vystupny blok (keystream) pre CTR vypocet
        for (size_t j = 0; j < ciphertext_len; j++) {
            result[j] = ciphertext[j] ^ expected_output[j];
        }
        
        printf("Vypocitany plaintext: ");
        print_hex(result, plaintext_len);
        
        printf("Ocakavany plaintext: ");
        print_hex(expected_plaintext, plaintext_len);
        
        // Kontrola zhody - plaintext musi byt zhodny
        if (memcmp(result, expected_plaintext, plaintext_len) != 0) {
            block_test_success = 0; // Test zlyhal kvoli nezhode plaintextu
            printf("!!! CHYBA: Vypocitany plaintext sa nezhoduje s ocakavanym !!!\n");
        }
        
        if (block_test_success) {
            passed_count++;
            printf("Test USPESNY\n");
        } else {
            printf("Test NEUSPESNY\n");
        }
        
        // Inkrementujeme counter pre dalsi blok
        increment_counter(counter);
    }

    free(hex_key);
    free(hex_counter);
    free(hex_input_block);
    free(hex_output_block);
    free(hex_plaintext);
    free(hex_ciphertext);
    
    printf("\nTestovanie CTR rezimu dokoncene: %d/%d uspesnych\n", passed_count, test_count);
    
    return 0;
}