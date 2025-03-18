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

int main(int argc, char* argv[]) {
    // Zistenie, ci sa jedna o 128, 192 alebo 256 bitovy rezim podla definicie v micro_aes.h
    #if AES___ == 256
        const int aes_bits = 256;
        const char* test_vectors_file = "test_vectors/cbc_test_vectors_256.txt";
        printf("Program skompilovany pre AES-256 CBC rezim\n");
    #elif AES___ == 192
        const int aes_bits = 192;
        const char* test_vectors_file = "test_vectors/cbc_test_vectors_192.txt";
        printf("Program skompilovany pre AES-192 CBC rezim\n");
    #else
        const int aes_bits = 128;
        const char* test_vectors_file = "test_vectors/cbc_test_vectors_128.txt";
        printf("Program skompilovany pre AES-128 CBC rezim\n");
    #endif
    
    FILE *fp;
    char line[512];
    uint8_t key[32];  // Max 256 bits (32 bytes)
    uint8_t iv[16];   // IV je vzdy 16 bajtov
    uint8_t current_iv[16]; // Aktualny IV pre retazenie blokov
    uint8_t plaintext[16], ciphertext[16], result[16];
    char *hex_key = NULL, *hex_iv = NULL, *hex_plaintext = NULL, *hex_ciphertext = NULL;
    int test_count = 0, passed_count = 0;
    int block_number = 0;
    int encrypt_mode = 1;  // 1 = encrypt, 0 = decrypt
    
    // Premenne pre retazenie blokov
    uint8_t prev_ciphertext[16] = {0}; // Pre ulozenie predchadzajuceho ciphertextu
    int is_first_block = 1;            // ci sa jedna o prvy blok v sekcii
    
    // Alokujeme pamat pre kluce podla zvolenej velkosti
    int key_size_bytes = aes_bits / 8;
    
    // Otvorenie suboru s testovacimi vektormi
    printf("Pouziva sa testovaci subor: %s\n", test_vectors_file);
    fp = fopen(test_vectors_file, "r");
    if (!fp) {
        perror("Nepodarilo sa otvorit subor s testovacimi vektormi");
        return 1;
    }

    // Spracovanie vsetkych testovacich vektorov
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
        if (strstr(line, "CBC-AES") != NULL) {
            if (strstr(line, "Encrypt") != NULL) {
                encrypt_mode = 1;
                is_first_block = 1; // Reset pre novu sekciu
                printf("\n=== Testovanie sifrovania (Encrypt) ===\n");
            } else if (strstr(line, "Decrypt") != NULL) {
                encrypt_mode = 0;
                is_first_block = 1; // Reset pre novu sekciu
                printf("\n=== Testovanie desifrovania (Decrypt) ===\n");
            }
            continue;
        }
        
        // Parsovanie kluca
        if (strncmp(line, "Key", 3) == 0) {
            free(hex_key);
            hex_key = my_strdup(trim(line + 4));
            continue;
        }
        
        // Parsovanie IV (inicializacneho vektora)
        if (strncmp(line, "IV", 2) == 0) {
            free(hex_iv);
            hex_iv = my_strdup(trim(line + 3));
            hex_to_bin(hex_iv, iv, 16); // Ulozime si IV
            is_first_block = 1; // Reset pocitadla blokov pretoze je novy IV
            continue;
        }
        
        // Parsovanie cisla bloku
        if (strncmp(line, "Block #", 7) == 0) {
            block_number = atoi(line + 7);
            // Ak je novy blok #1, resetujeme stav retazenia
            if (block_number == 1) {
                is_first_block = 1;
            }
            continue;
        }
        
        // Parsovanie plaintextu
        if (strncmp(line, "Plaintext", 9) == 0) {
            char* value = trim(line + 10);
            if (encrypt_mode) {
                // V sifrovani je plaintext vstupom
                free(hex_plaintext);
                hex_plaintext = my_strdup(value);
            } else {
                // V desifrovani je plaintext ocakavanym vystupom
                if (hex_key && hex_iv && hex_ciphertext) {
                    // Mame vsetko potrebne pre test desifrovania
                    test_count++;
                    printf("Test #%d (Block #%d, Decrypt):\n", test_count, block_number);
                    
                    // Konverzia hex na binarne hodnoty
                    hex_to_bin(hex_key, key, key_size_bytes);
                    
                    // Pripravime spravny IV - buď povodny alebo z predchadzajuceho bloku
                    if (is_first_block) {
                        memcpy(current_iv, iv, 16);
                        is_first_block = 0;
                    } else {
                        memcpy(current_iv, prev_ciphertext, 16);
                    }
                    
                    hex_to_bin(hex_ciphertext, ciphertext, 16);
                    // Ulozime si tento ciphertext pre ďalsie bloky
                    memcpy(prev_ciphertext, ciphertext, 16);
                    
                    printf("Kluc: ");
                    print_hex(key, key_size_bytes);
                    printf("IV/Predchadzajuci ciphertext: ");
                    print_hex(current_iv, 16);
                    printf("Ciphertext: ");
                    print_hex(ciphertext, 16);
                    
                    // Desifrovanie
                    char status = AES_CBC_decrypt(key, current_iv, ciphertext, 16, result);
                    if (status != 0) {
                        printf("Desifrovanie zlyhalo so statusom %d\n", status);
                    } else {
                        printf("Vypocitany plaintext: ");
                        print_hex(result, 16);
                        
                        // Konverzia ocakavaneho plaintextu
                        uint8_t expected_plaintext[16];
                        hex_to_bin(value, expected_plaintext, 16);
                        
                        printf("Ocakavany plaintext: ");
                        print_hex(expected_plaintext, 16);
                        
                        // Kontrola zhody
                        if (memcmp(result, expected_plaintext, 16) == 0) {
                            passed_count++;
                            printf("Test USPESNY\n");
                        } else {
                            printf("Test NEUSPESNY\n");
                        }
                    }
                    printf("\n");
                }
            }
            continue;
        }
        
        // Parsovanie ciphertextu
        if (strncmp(line, "Ciphertext", 10) == 0) {
            char* value = trim(line + 11);
            if (!encrypt_mode) {
                // V desifrovani je ciphertext vstupom
                free(hex_ciphertext);
                hex_ciphertext = my_strdup(value);
            } else {
                // V sifrovani je ciphertext ocakavanym vystupom
                if (hex_key && hex_iv && hex_plaintext) {
                    // Mame vsetko potrebne pre test sifrovania
                    test_count++;
                    printf("Test #%d (Block #%d, Encrypt):\n", test_count, block_number);
                    
                    // Konverzia hex na binarne hodnoty
                    hex_to_bin(hex_key, key, key_size_bytes);
                    
                    // Pripravime spravny IV - buď povodny alebo ciphertext z predchadzajuceho bloku
                    if (is_first_block) {
                        memcpy(current_iv, iv, 16);
                        is_first_block = 0;
                    } else {
                        memcpy(current_iv, prev_ciphertext, 16);
                    }
                    
                    hex_to_bin(hex_plaintext, plaintext, 16);
                    
                    printf("Kluc: ");
                    print_hex(key, key_size_bytes);
                    printf("IV/Predchadzajuci ciphertext: ");
                    print_hex(current_iv, 16);
                    printf("Plaintext: ");
                    print_hex(plaintext, 16);
                    
                    // sifrovanie
                    AES_CBC_encrypt(key, current_iv, plaintext, 16, result);
                    // Ulozime aktualny ciphertext pre ďalsi blok
                    memcpy(prev_ciphertext, result, 16);
                    
                    printf("Vypocitany ciphertext: ");
                    print_hex(result, 16);
                    
                    // Konverzia ocakavaneho ciphertextu
                    uint8_t expected_ciphertext[16];
                    hex_to_bin(value, expected_ciphertext, 16);
                    
                    printf("Ocakavany ciphertext: ");
                    print_hex(expected_ciphertext, 16);
                    
                    // Kontrola zhody
                    if (memcmp(result, expected_ciphertext, 16) == 0) {
                        passed_count++;
                        printf("Test USPESNY\n");
                    } else {
                        printf("Test NEUSPESNY\n");
                    }
                    printf("\n");
                }
            }
            continue;
        }
    }

    fclose(fp);
    free(hex_key);
    free(hex_iv);
    free(hex_plaintext);
    free(hex_ciphertext);
    
    printf("\nTestovanie dokoncene: %d/%d uspesnych\n", passed_count, test_count);
    
    return 0;
}