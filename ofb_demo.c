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

// Funkcia pre OFB sifrovanie s explicitnym generovanim keystream-u
void process_ofb_encrypt(uint8_t* key, uint8_t* iv, uint8_t* plaintext, size_t plaintext_len, 
                        uint8_t* ciphertext, uint8_t* keystream) {
    // 1. Najprv generujeme keystream sifrovanim bloku nul
    uint8_t zero_block[16] = {0};
    uint8_t temp_iv[16];
    memcpy(temp_iv, iv, 16);
    
    // sifrujeme blok nul pre ziskanie cisteho vystupu sifry (keystream-u)
    AES_OFB_encrypt(key, temp_iv, zero_block, 16, keystream);
    
    // 2. Teraz pouzijeme keystream pre sifrovanie skutocnych dat
    // Keďze AES_OFB_encrypt by nam modifikovalo iv a keystream,
    // budeme vykonavat XOR manualne
    for (size_t i = 0; i < plaintext_len; i++) {
        ciphertext[i] = plaintext[i] ^ keystream[i];
    }
}

// Funkcia pre OFB desifrovanie s explicitnym generovanim keystream-u
void process_ofb_decrypt(uint8_t* key, uint8_t* iv, uint8_t* ciphertext, size_t ciphertext_len, 
                        uint8_t* plaintext, uint8_t* keystream) {
    // 1. Najprv generujeme keystream sifrovanim bloku nul
    uint8_t zero_block[16] = {0};
    uint8_t temp_iv[16];
    memcpy(temp_iv, iv, 16);
    
    // sifrujeme blok nul pre ziskanie cisteho vystupu sifry (keystream-u)
    AES_OFB_encrypt(key, temp_iv, zero_block, 16, keystream);
    
    // 2. Teraz pouzijeme keystream pre desifrovanie dat
    // Keďze OFB sifrovanie a desifrovanie je identicke, vykonavame XOR manualne
    for (size_t i = 0; i < ciphertext_len; i++) {
        plaintext[i] = ciphertext[i] ^ keystream[i];
    }
}

int main(int argc, char* argv[]) {
    // Zistenie, ci sa jedna o 128, 192 alebo 256 bitovy rezim podla definicie v micro_aes.h
    #if AES___ == 256
        const int aes_bits = 256;
        const char* test_vectors_file = "test_vectors/ofb_test_vectors_256.txt";
        printf("Program skompilovany pre AES-256 OFB rezim\n");
    #elif AES___ == 192
        const int aes_bits = 192;
        const char* test_vectors_file = "test_vectors/ofb_test_vectors_192.txt";
        printf("Program skompilovany pre AES-192 OFB rezim\n");
    #else
        const int aes_bits = 128;
        const char* test_vectors_file = "test_vectors/ofb_test_vectors_128.txt";
        printf("Program skompilovany pre AES-128 OFB rezim\n");
    #endif
    
    FILE *fp;
    char line[512];
    uint8_t key[32];  // Max 256 bits (32 bytes)
    uint8_t iv[16];   // IV je vzdy 16 bajtov
    uint8_t plaintext[512], ciphertext[512], result[512]; // Dostatocne velke pre bezne testy
    uint8_t keystream[16];  // Pre ulozenie keystream-u (vystupu sifry)
    char *hex_key = NULL, *hex_iv = NULL, *hex_input_block = NULL, *hex_output_block = NULL;
    char *hex_plaintext = NULL, *hex_ciphertext = NULL;
    int test_count = 0, passed_count = 0;
    int block_number = 0;
    int current_mode = 0;  // 0 = nespecifikovany, 1 = encrypt, 2 = decrypt
    
    // Pre ulozenie vsetkych blokov testovacich vektorov
    typedef struct {
        char hex_input_block[33];
        char hex_output_block[33];
        char hex_plaintext[65];
        char hex_ciphertext[65];
        int block_number;
    } TestVector;
    TestVector decrypt_tests[10]; // Maximalne 10 blokov
    TestVector encrypt_tests[10]; // Pre ulozenie vsetkych blokov pri sifrovani
    int decrypt_test_count = 0;
    int encrypt_test_count = 0;
    
    // Alokujeme pamat pre kluce podla zvolenej velkosti
    int key_size_bytes = aes_bits / 8;
    
    // Otvorenie suboru s testovacimi vektormi
    printf("Pouziva sa testovaci subor: %s\n", test_vectors_file);
    fp = fopen(test_vectors_file, "r");
    if (!fp) {
        perror("Nepodarilo sa otvorit subor s testovacimi vektormi");
        return 1;
    }

    // Nacitame vsetky testovacie vektory do pamate
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
        if (strstr(line, "OFB") != NULL) {
            if (strstr(line, "Encrypt") != NULL) {
                current_mode = 1; // encrypt
                printf("\n--- Testovanie sifrovania (Encrypt) ---\n");
            } else if (strstr(line, "Decrypt") != NULL) {
                current_mode = 2; // decrypt
                printf("\n--- Testovanie desifrovania (Decrypt) ---\n");
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
        
        // Parsovanie IV (inicializacneho vektora)
        if (strncmp(line, "IV", 2) == 0) {
            free(hex_iv);
            hex_iv = my_strdup(trim(line + 3));
            printf("IV: %s\n", hex_iv);
            continue;
        }
        
        // Parsovanie cisla bloku
        if (strncmp(line, "Block #", 7) == 0) {
            block_number = atoi(line + 7);
            continue;
        }
        
        // Parsovanie vstupneho bloku
        if (strncmp(line, "Input Block", 11) == 0) {
            free(hex_input_block);
            hex_input_block = my_strdup(trim(line + 12));
            
            // Ukladame vstupny blok podla aktualneho rezimu
            if (current_mode == 1) { // encrypt
                if (block_number > 0 && block_number <= 10) {
                    strcpy(encrypt_tests[block_number-1].hex_input_block, hex_input_block);
                    encrypt_tests[block_number-1].block_number = block_number;
                    if (block_number > encrypt_test_count)
                        encrypt_test_count = block_number;
                }
            } else if (current_mode == 2) { // decrypt
                if (block_number > 0 && block_number <= 10) {
                    strcpy(decrypt_tests[block_number-1].hex_input_block, hex_input_block);
                    decrypt_tests[block_number-1].block_number = block_number;
                    if (block_number > decrypt_test_count) 
                        decrypt_test_count = block_number;
                }
            }
            continue;
        }
        
        // Parsovanie vystupneho bloku
        if (strncmp(line, "Output Block", 12) == 0) {
            free(hex_output_block);
            hex_output_block = my_strdup(trim(line + 13));
            
            // Ukladame vystupny blok podla aktualneho rezimu
            if (current_mode == 1) { // encrypt
                if (block_number > 0 && block_number <= 10) {
                    strcpy(encrypt_tests[block_number-1].hex_output_block, hex_output_block);
                }
            } else if (current_mode == 2) { // decrypt
                if (block_number > 0 && block_number <= 10) {
                    strcpy(decrypt_tests[block_number-1].hex_output_block, hex_output_block);
                }
            }
            continue;
        }
        
        // Parsovanie plaintextu
        if (strncmp(line, "Plaintext", 9) == 0) {
            free(hex_plaintext);
            hex_plaintext = my_strdup(trim(line + 10));
            
            // Ukladame plaintext podla aktualneho rezimu
            if (current_mode == 1) { // encrypt
                if (block_number > 0 && block_number <= 10) {
                    strcpy(encrypt_tests[block_number-1].hex_plaintext, hex_plaintext);
                }
            } else if (current_mode == 2) { // decrypt
                if (block_number > 0 && block_number <= 10) {
                    strcpy(decrypt_tests[block_number-1].hex_plaintext, hex_plaintext);
                }
            }
            continue;
        }
        
        // Parsovanie ciphertextu
        if (strncmp(line, "Ciphertext", 10) == 0) {
            free(hex_ciphertext);
            hex_ciphertext = my_strdup(trim(line + 11));
            
            // Ukladame ciphertext podla aktualneho rezimu
            if (current_mode == 1) { // encrypt
                if (block_number > 0 && block_number <= 10) {
                    strcpy(encrypt_tests[block_number-1].hex_ciphertext, hex_ciphertext);
                }
            } else if (current_mode == 2) { // decrypt
                if (block_number > 0 && block_number <= 10) {
                    strcpy(decrypt_tests[block_number-1].hex_ciphertext, hex_ciphertext);
                }
            }
            continue;
        }
    }
    
    fclose(fp);
    
    // Spracovanie sifrovacich testov
    if (encrypt_test_count > 0) {
        printf("\n--- Vykonavanie sifrovacich testov ---\n");
        for (int i = 0; i < encrypt_test_count; i++) {
            int blk_num = encrypt_tests[i].block_number;
            char* hex_input = encrypt_tests[i].hex_input_block;
            char* hex_output = encrypt_tests[i].hex_output_block;
            char* hex_ptext = encrypt_tests[i].hex_plaintext;
            char* hex_ctext = encrypt_tests[i].hex_ciphertext;
            
            // Nastavime IV podla Input Block zo suboru
            hex_to_bin(hex_input, iv, 16);
            
            test_count++;
            printf("\nTest #%d (Block #%d):\n", test_count, blk_num);
            
            // Vypiseme Vstupny a Vystupny blok
            printf("Vstupny blok (IV): %s\n", hex_input);
            
            // 1. Generujeme keystream sifrovanim nuloveho bloku
            process_ofb_encrypt(key, iv, plaintext, 0, result, keystream);
            
            printf("Generovany keystream: ");
            print_hex(keystream, 16);
            
            // Kontrola zhodnosti keystream-u s ocakavanym output blokom
            uint8_t expected_output[16];
            hex_to_bin(hex_output, expected_output, 16);
            
            int keystream_match = (memcmp(keystream, expected_output, 16) == 0);
            if (!keystream_match) {
                printf("!!! CHYBA: Keystream sa nezhoduje s ocakavanym vystupnym blokom !!!\n");
                printf("Ocakavany vystupny blok: %s\n", hex_output);
            }
            
            // Kontrola, ci je nasledujuci input blok rovnaky ako aktualny output blok
            if (i < encrypt_test_count - 1) {
                uint8_t next_input[16];
                hex_to_bin(encrypt_tests[i+1].hex_input_block, next_input, 16);
                
                int next_block_match = (memcmp(keystream, next_input, 16) == 0);
                if (!next_block_match) {
                    printf("!!! CHYBA: Keystream sa nezhoduje s input blokom nasledujuceho bloku !!!\n");
                    printf("Nasledujuci input blok: %s\n", encrypt_tests[i+1].hex_input_block);
                }
            }
            
            // 2. sifrovanie plaintextu pouzitim vygenerovaneho keystream-u
            size_t plaintext_len = strlen(hex_ptext) / 2;
            hex_to_bin(hex_ptext, plaintext, plaintext_len);
            printf("Plaintext: ");
            print_hex(plaintext, plaintext_len);
            
            // XOR plaintext s keystream pre ziskanie ciphertext
            for (size_t j = 0; j < plaintext_len; j++) {
                result[j] = plaintext[j] ^ keystream[j];
            }
            
            // Konverzia ocakavaneho ciphertextu
            uint8_t expected_ciphertext[512];
            size_t ciphertext_len = strlen(hex_ctext) / 2;
            hex_to_bin(hex_ctext, expected_ciphertext, ciphertext_len);
            
            printf("Vypocitany ciphertext: ");
            print_hex(result, plaintext_len);
            
            printf("Ocakavany ciphertext: ");
            print_hex(expected_ciphertext, ciphertext_len);
            
            // Kontrola zhody ciphertextu
            if (memcmp(result, expected_ciphertext, ciphertext_len) == 0) {
                passed_count++;
                printf("Test USPESNY\n");
            } else {
                printf("Test NEUSPESNY\n");
            }
        }
    }

    // Spracovanie desifrovacich testov
    if (decrypt_test_count > 0) {
        printf("\n--- Vykonavanie desifrovacich testov ---\n");
        for (int i = 0; i < decrypt_test_count; i++) {
            int blk_num = decrypt_tests[i].block_number;
            char* hex_input = decrypt_tests[i].hex_input_block;
            char* hex_output = decrypt_tests[i].hex_output_block;
            char* hex_ctext = decrypt_tests[i].hex_ciphertext;
            char* hex_ptext = decrypt_tests[i].hex_plaintext;
            
            // Nastavime IV podla Input Block zo suboru
            hex_to_bin(hex_input, iv, 16);
            
            test_count++;
            printf("\nTest #%d (Block #%d):\n", test_count, blk_num);
            
            // Vypiseme Vstupny a Vystupny blok
            printf("Vstupny blok (IV): %s\n", hex_input);
            
            // 1. Generujeme keystream sifrovanim nuloveho bloku
            process_ofb_decrypt(key, iv, ciphertext, 0, result, keystream);
            
            printf("Generovany keystream: ");
            print_hex(keystream, 16);
            
            // Kontrola zhodnosti keystream-u s ocakavanym output blokom
            uint8_t expected_output[16];
            hex_to_bin(hex_output, expected_output, 16);
            
            int keystream_match = (memcmp(keystream, expected_output, 16) == 0);
            if (!keystream_match) {
                printf("!!! CHYBA: Keystream sa nezhoduje s ocakavanym vystupnym blokom !!!\n");
                printf("Ocakavany vystupny blok: %s\n", hex_output);
            }
            
            // Kontrola, ci je nasledujuci input blok rovnaky ako aktualny output blok
            if (i < decrypt_test_count - 1) {
                uint8_t next_input[16];
                hex_to_bin(decrypt_tests[i+1].hex_input_block, next_input, 16);
                
                int next_block_match = (memcmp(keystream, next_input, 16) == 0);
                if (!next_block_match) {
                    printf("!!! CHYBA: Keystream sa nezhoduje s input blokom nasledujuceho bloku !!!\n");
                    printf("Nasledujuci input blok: %s\n", decrypt_tests[i+1].hex_input_block);
                }
            }
            
            // 2. Desifrovanie ciphertextu pouzitim vygenerovaneho keystream-u
            size_t ciphertext_len = strlen(hex_ctext) / 2;
            hex_to_bin(hex_ctext, ciphertext, ciphertext_len);
            printf("Ciphertext: ");
            print_hex(ciphertext, ciphertext_len);
            
            // XOR ciphertext s keystream pre ziskanie plaintext
            for (size_t j = 0; j < ciphertext_len; j++) {
                result[j] = ciphertext[j] ^ keystream[j];
            }
            
            // Konverzia ocakavaneho plaintextu
            uint8_t expected_plaintext[512];
            size_t plaintext_len = strlen(hex_ptext) / 2;
            hex_to_bin(hex_ptext, expected_plaintext, plaintext_len);
            
            printf("Vypocitany plaintext: ");
            print_hex(result, ciphertext_len);
            
            printf("Ocakavany plaintext: ");
            print_hex(expected_plaintext, plaintext_len);
            
            // Kontrola zhody plaintextu
            if (memcmp(result, expected_plaintext, plaintext_len) == 0) {
                passed_count++;
                printf("Test USPESNY\n");
            } else {
                printf("Test NEUSPESNY\n");
            }
        }
    }

    free(hex_key);
    free(hex_iv);
    free(hex_input_block);
    free(hex_output_block);
    free(hex_plaintext);
    free(hex_ciphertext);
    
    printf("\nTestovanie OFB dokoncene: %d/%d uspesnych\n", passed_count, test_count);
    
    return 0;
}