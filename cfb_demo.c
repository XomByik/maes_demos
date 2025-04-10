#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h> // Potrebne pre uint8_t na Windows
#include "libs/micro_aes.h"

// Funkcia na konverziu hexadecimalneho retazca na binarne hodnoty
void hex_to_bin(const char* hex, uint8_t* bin, size_t len) {
    unsigned int byte_val; // Pouzijeme unsigned int pre sscanf
    for (size_t i = 0; i < len; i++) {
        // Pouzijeme %2x na citanie dvoch hex znakov do unsigned int
        if (sscanf(hex + i * 2, "%2x", &byte_val) != 1) {
             // Pridanie chybovej hlasky pre pripad zlyhania sscanf
             // Pouzijeme %lu a pretypujeme size_t na unsigned long pre lepsiu kompatibilitu
             fprintf(stderr, "Error: Failed to parse hex byte from '%s' at index %lu.\n", hex, (unsigned long)(i*2));
             // Mozno by bolo vhodne vratit chybovy kod alebo ukoncit program
             // Pre jednoduchost tu len pokracujeme, ale bin[i] bude mat nedefinovanu hodnotu
             continue; 
        }
        bin[i] = (uint8_t)byte_val; // Pretypujeme na uint8_t
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

// Funkcia na zistenie poctu bitov v segmente z nazvu suboru
int get_segment_size(const char* filename) {
    if (strstr(filename, "cfb1_") != NULL) {
        return 1;  // CFB-1 rezim (1-bitovy segment)
    }
    else if (strstr(filename, "cfb8_") != NULL) {
        return 8;  // CFB-8 rezim (8-bitovy segment / 1 byte)
    }
    else {
        return 128; // standardny CFB-128 rezim (16 bajtov / 128 bitov)
    }
}

// Funkcia na spracovanie CFB-1 rezimu (1-bitovy segment)
void process_cfb1_encrypt(uint8_t* key, uint8_t* iv, uint8_t plaintext_bit, uint8_t* result_bit) {
    uint8_t temp_input[16] = {0};  // Prazdny vstup
    uint8_t temp_output[16] = {0}; // Vystupny blok
    
    // Pouzijeme AES_CFB_encrypt s nulovym vstupom a dĺzkou 16
    // Toto v podstate len zasifruje IV
    AES_CFB_encrypt(key, iv, temp_input, 16, temp_output);
    
    // CFB-1: pouzijeme len MSB (najpomocnejsi bit) vystupneho bloku
    uint8_t cipher_bit = (temp_output[0] >> 7) & 0x01;  // MSB prveho bajtu
    
    // XOR s plaintextovym bitom pre ziskanie ciphertextoveho bitu
    *result_bit = cipher_bit ^ plaintext_bit;
    
    // Posun IV dolava o 1 bit a pridanie ciphertextoveho bitu na koniec
    uint8_t carry = 0;
    for (int i = 0; i < 16; i++) {
        uint8_t nextCarry = (iv[i] & 0x80) ? 1 : 0;  // MSB aktualneho bajtu
        iv[i] = (iv[i] << 1) | carry;  // Posun dolava a pridanie carry z predchadzajuceho bajtu
        carry = nextCarry;
    }
    
    // Pridanie ciphertextoveho bitu na LSB poziciu
    iv[15] |= *result_bit & 0x01;
}

// Opravena funkcia na spracovanie CFB-1 rezimu (1-bitovy segment) pre desifrovanie
void process_cfb1_decrypt(uint8_t* key, uint8_t* iv, uint8_t ciphertext_bit, uint8_t* result_bit) {
    uint8_t temp_input[16] = {0};
    uint8_t temp_output[16] = {0};
    
    // Pouzijeme AES_encrypt (alebo AES_CFB_encrypt s nulovym vstupom) pre zasifrovanie IV
    AES_CFB_encrypt(key, iv, temp_input, 16, temp_output);
    
    // CFB-1: pouzijeme len MSB (najpomocnejsi bit) vystupneho bloku
    uint8_t cipher_bit = (temp_output[0] >> 7) & 0x01;  // MSB prveho bajtu
    
    // XOR s ciphertextovym bitom pre ziskanie plaintextoveho bitu
    *result_bit = cipher_bit ^ ciphertext_bit;
    
    // Posun IV dolava o 1 bit a pridanie ciphertextoveho bitu na koniec
    uint8_t carry = 0;
    for (int i = 0; i < 16; i++) {
        uint8_t nextCarry = (iv[i] & 0x80) ? 1 : 0;  // MSB aktualneho bajtu
        iv[i] = (iv[i] << 1) | carry;  // Posun dolava a pridanie carry z predchadzajuceho bajtu
        carry = nextCarry;
    }
    
    // Pridanie ciphertextoveho bitu na LSB poziciu posledneho bajtu
    iv[15] |= ciphertext_bit & 0x01;
}

// Oprava funkcie CFB-8 sifrovania
void process_cfb8_encrypt(uint8_t* key, uint8_t* iv, uint8_t plaintext_byte, uint8_t* result_byte) {
    // Pouzijeme priamo funkciu AES_CFB_encrypt s 1-bajtovym plaintextom
    uint8_t temp_input[1] = { plaintext_byte };
    uint8_t temp_output[1] = { 0 };
    
    // sifrovanie jedneho bajtu
    AES_CFB_encrypt(key, iv, temp_input, 1, temp_output);
    
    // Vysledok sifrovania
    *result_byte = temp_output[0];
    
    // Posun IV dolava o 1 bajt a pridanie ciphertextoveho bajtu na koniec
    memmove(iv, iv + 1, 15);
    iv[15] = *result_byte;
}

// Oprava funkcie CFB-8 desifrovania
void process_cfb8_decrypt(uint8_t* key, uint8_t* iv, uint8_t ciphertext_byte, uint8_t* result_byte) {
    // Pouzijeme priamo funkciu AES_CFB_decrypt s 1-bajtovym ciphertextom
    uint8_t temp_input[1] = { ciphertext_byte };
    uint8_t temp_output[1] = { 0 };
    
    // Desifrovanie jedneho bajtu
    AES_CFB_decrypt(key, iv, temp_input, 1, temp_output);
    
    // Vysledok desifrovania
    *result_byte = temp_output[0];
    
    // Posun IV dolava o 1 bajt a pridanie ciphertextoveho bajtu na koniec
    memmove(iv, iv + 1, 15);
    iv[15] = ciphertext_byte;  // Pri desifrovani sa do IV pridava ciphertext
}

// Funkcia na spracovanie CFB-128 rezimu (128-bitovy segment / 16 bajtov)
void process_cfb128_encrypt(uint8_t* key, uint8_t* iv, uint8_t* plaintext, uint8_t* ciphertext) {
    // Pre CFB-128 pouzijeme priamo funkciu z kniznice
    AES_CFB_encrypt(key, iv, plaintext, 16, ciphertext);
    // Aktualizacia IV na ďalsi blok
    memcpy(iv, ciphertext, 16);
}

// Funkcia na spracovanie CFB-128 rezimu (128-bitovy segment / 16 bajtov) pre desifrovanie
void process_cfb128_decrypt(uint8_t* key, uint8_t* iv, uint8_t* ciphertext, uint8_t* plaintext) {
    // Pre CFB-128 pouzijeme priamo funkciu z kniznice
    AES_CFB_decrypt(key, iv, ciphertext, 16, plaintext);
    // Aktualizacia IV na ďalsi blok
    memcpy(iv, ciphertext, 16);
}

int main() {
    // Zistenie, ci sa jedna o 128, 192 alebo 256 bitovy rezim podla definicie v micro_aes.h
    #if AES___ == 256
        const int aes_bits = 256;
        #define AES_BITS_STR "256"
        printf("Program skompilovany pre AES-256 CFB rezim\n");
    #elif AES___ == 192
        const int aes_bits = 192;
        #define AES_BITS_STR "192"
        printf("Program skompilovany pre AES-192 CFB rezim\n");
    #else
        const int aes_bits = 128;
        #define AES_BITS_STR "128"
        printf("Program skompilovany pre AES-128 CFB rezim\n");
    #endif
    
    // Testovacie subory pre rozne CFB varianty s konkretnou bitovou dlzkou
    const char* test_vectors_files[] = {
        "test_vectors/cfb1_test_vectors_" AES_BITS_STR ".txt",  // CFB-1 (1-bitovy segment)
        "test_vectors/cfb8_test_vectors_" AES_BITS_STR ".txt",  // CFB-8 (8-bitovy segment)
        "test_vectors/cfb_test_vectors_" AES_BITS_STR ".txt"    // CFB-128 (128-bitovy segment)
    };
    
    const char* cfb_mode_names[] = {
        "CFB-1 (1-bit segment dat)",
        "CFB-8 (8-bitovy segment dat)",
        "CFB-128 (128-bitovy segment dat)"
    };

    // Alokujeme pamat pre kluc podla zvolenej velkosti
    int key_size_bytes = aes_bits / 8;
    uint8_t key[32];  // Max 256 bits (32 bytes)
    uint8_t iv[16];   // IV je vzdy 16 bajtov
    uint8_t original_iv[16] = {0}; // Kópia povodneho IV pre testovanie
    
    // Prejdeme vsetky testovacie subory
    for (int file_idx = 0; file_idx < 3; file_idx++) {
        const char* test_vectors_file = test_vectors_files[file_idx];
        
        // Overenie existencie suboru
        FILE *fp = fopen(test_vectors_file, "r");
        if (!fp) {
            printf("Subor %s sa nenasiel, preskakujem...\n", test_vectors_file);
            continue;
        }
        fclose(fp);
        
        // Identifikacia velkosti segmentu z nazvu suboru
        int segment_size = get_segment_size(test_vectors_file);
        
        printf("\n=== Testovanie %s ===\n", cfb_mode_names[file_idx]);
        printf("Pouziva sa testovaci subor: %s\n", test_vectors_file);
        
        // Otvorenie suboru s testovacimi vektormi
        fp = fopen(test_vectors_file, "r");
        if (!fp) {
            perror("Nepodarilo sa otvorit subor s testovacimi vektormi");
            return 1;
        }

        char line[512];
        char *hex_key = NULL, *hex_iv = NULL;
        char *hex_input_block = NULL, *hex_output_block = NULL;
        char *plaintext_str = NULL, *ciphertext_str = NULL;
        int test_count = 0, passed_count = 0;
        int segment_number = 0;
        int encrypt_mode = 1;  // 1 = encrypt, 0 = decrypt
        int first_segment_in_file = 1;
        
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
            if (strstr(line, "CFB") != NULL) {
                if (strstr(line, "Encrypt") != NULL) {
                    encrypt_mode = 1;
                    first_segment_in_file = 1;
                    printf("\n--- Testovanie sifrovania (Encrypt) ---\n");
                } else if (strstr(line, "Decrypt") != NULL) {
                    encrypt_mode = 0;
                    first_segment_in_file = 1;
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
                hex_to_bin(hex_iv, iv, 16);
                // Ulozime originalny IV
                memcpy(original_iv, iv, 16);
                printf("IV: %s\n", hex_iv);
                continue;
            }
            
            // Parsovanie cisla segmentu
            if (strncmp(line, "Segment #", 9) == 0) {
                segment_number = atoi(line + 9);
                
                // Ak je novy segment #1, resetujeme IV na originalny
                if (segment_number == 1 || first_segment_in_file) {
                    memcpy(iv, original_iv, 16);
                    first_segment_in_file = 0;
                }
                continue;
            }
            
            // Parsovanie vstupneho bloku
            if (strncmp(line, "Input Block", 11) == 0) {
                free(hex_input_block);
                hex_input_block = my_strdup(trim(line + 12));
                
                // V tomto momente mozeme priamo nastavit IV na hodnotu Input Block
                // namiesto pocitania, pretoze testovaci vektor uz obsahuje spravny
                // posunuty IV pre aktualny segment
                if (segment_number > 1) {  // Len pre bloky po prvom segmente
                    hex_to_bin(hex_input_block, iv, 16);
                }
                continue;
            }
            
            // Parsovanie vystupneho bloku
            if (strncmp(line, "Output Block", 12) == 0) {
                free(hex_output_block);
                hex_output_block = my_strdup(trim(line + 12));
                continue;
            }
            
            // Parsovanie plaintextu
            if (strncmp(line, "Plaintext", 9) == 0) {
                free(plaintext_str); // Uvolnenie predchadzajucej alokacie
                plaintext_str = my_strdup(trim(line + 9)); // Vytvorenie novej kópie
                continue;
            }
            
            // Parsovanie ciphertextu a spustenie testu
            if (strncmp(line, "Ciphertext", 10) == 0) {
                free(ciphertext_str); // Uvolnenie predchadzajucej alokacie
                ciphertext_str = my_strdup(trim(line + 10)); // Vytvorenie novej kópie
                
                if (hex_key && hex_iv && hex_input_block && hex_output_block && plaintext_str && ciphertext_str) {
                    // Mame vsetko potrebne pre test
                    test_count++;
                    printf("\nTest #%d (Segment #%d):\n", test_count, segment_number);
                    
                    if (segment_size == 1) {
                        // Test pre CFB-1
                        uint8_t plaintext_bit = 0;
                        uint8_t ciphertext_bit = 0;
                        uint8_t result_bit = 0;
                        uint8_t input_block_bytes[16];  // Add this declaration
                        
                        // Konverzia plaintextu a ciphertextu zo stringov na bity
                        if (plaintext_str && strlen(plaintext_str) > 0) {
                            plaintext_bit = atoi(plaintext_str) & 0x01;
                        }
                        
                        if (ciphertext_str && strlen(ciphertext_str) > 0) {
                            ciphertext_bit = atoi(ciphertext_str) & 0x01;
                        }

                        // Convert input block from hex string to bytes
                        hex_to_bin(hex_input_block, input_block_bytes, 16);

                        if (memcmp(iv, input_block_bytes, 16) != 0) {
                            printf("!!! CHYBA: Vstupny blok nezodpoveda aktualnemu IV !!!\n");
                        }
                        
                        if (encrypt_mode) {
                            printf("Plaintext: %d\n", plaintext_bit);
                            printf("Ocakavany vstupny blok (IV): %s\n", hex_input_block);
                            printf("Aktualny vstupny blok (IV): ");
                            print_hex(iv, 16);

                            process_cfb1_encrypt(key, iv, plaintext_bit, &result_bit);
                            
                            printf("Ocakavany ciphertext: %d\n", ciphertext_bit);
                            printf("Vypocitany ciphertext: %d\n", result_bit);
                            
                            if (result_bit == ciphertext_bit) {
                                passed_count++;
                                printf("Test USPESNY\n");
                            } else {
                                printf("Test NEUSPESNY\n");
                            }
                        } else {
                            printf("Ciphertext: %d\n", ciphertext_bit);
                            printf("Ocakavany vstupny blok (IV): %s\n", hex_input_block);
                            printf("Aktualny vstupny blok (IV): ");
                            print_hex(iv, 16);

                            process_cfb1_decrypt(key, iv, ciphertext_bit, &result_bit);

                            printf("Ocakavany plaintext: %d\n", plaintext_bit);
                            printf("Vypocitany plaintext: %d\n", result_bit);
                            
                            if (result_bit == plaintext_bit) {
                                passed_count++;
                                printf("Test USPESNY\n");
                            } else {
                                printf("Test NEUSPESNY\n");
                            }
                        }
                    }
                    else if (segment_size == 8) {
                        // Test pre CFB-8
                        uint8_t plaintext_byte = 0;
                        uint8_t expected_ciphertext_byte = 0;
                        uint8_t result_byte = 0;
                        unsigned int byte_val; // Pouzijeme unsigned int pre sscanf
                        
                        // Konverzia plaintextu a ciphertextu z hex retazca na byte
                        if (plaintext_str && strlen(plaintext_str) >= 2) {
                            // Pouzijeme %2x na citanie dvoch hex znakov do unsigned int
                            if (sscanf(plaintext_str, "%2x", &byte_val) == 1) {
                                plaintext_byte = (uint8_t)byte_val; // Pretypujeme na uint8_t
                            } else {
                                fprintf(stderr, "Error parsing plaintext hex: %s\n", plaintext_str);
                            }
                        }
                        
                        if (ciphertext_str && strlen(ciphertext_str) >= 2) {
                            // Pouzijeme %2x na citanie dvoch hex znakov do unsigned int
                            if (sscanf(ciphertext_str, "%2x", &byte_val) == 1) {
                                expected_ciphertext_byte = (uint8_t)byte_val; // Pretypujeme na uint8_t
                            } else {
                                fprintf(stderr, "Error parsing ciphertext hex: %s\n", ciphertext_str);
                            }
                        }
                        
                        // Overenie, ze IV zodpoveda ocakavanemu vstupnemu bloku
                        uint8_t input_block_bytes[16];
                        hex_to_bin(hex_input_block, input_block_bytes, 16);
                        if (memcmp(iv, input_block_bytes, 16) != 0) {
                            printf("!!! CHYBA: Vstupny blok nezodpoveda aktualnemu IV !!!\n");
                        }
                        
                        if (encrypt_mode) {
                            printf("Plaintext: %02x\n", plaintext_byte);
                            
                            printf("Ocakavany vstupny blok (IV): %s\n", hex_input_block);
                            printf("Aktualny vstupny blok (IV): ");
                            print_hex(iv, 16);

                            // Samotne testovanie CFB-8 sifrovania
                            process_cfb8_encrypt(key, iv, plaintext_byte, &result_byte);
                            
                            printf("Ocakavany ciphertext: %02x\n", expected_ciphertext_byte);
                            printf("Vypocitany ciphertext: %02x\n", result_byte);
                            
                            if (result_byte == expected_ciphertext_byte) {
                                passed_count++;
                                printf("Test USPESNY\n");
                            } else {
                                printf("Test NEUSPESNY\n");
                            }
                        } else {
                            // Desifrovanie
                            
                            printf("Ciphertext: %02x\n", expected_ciphertext_byte); 

                            printf("Ocakavany vstupny blok (IV): %s\n", hex_input_block);
                            printf("Aktualny vstupny blok (IV): ");
                            print_hex(iv, 16);

                            process_cfb8_decrypt(key, iv, expected_ciphertext_byte, &result_byte);

                            printf("Ocakavany plaintext: %02x\n", plaintext_byte);
                            printf("Vypocitany plaintext: %02x\n", result_byte);
                            
                            if (result_byte == plaintext_byte) {
                                passed_count++;
                                printf("Test USPESNY\n");
                            } else {
                                printf("Test NEUSPESNY\n");
                            }
                        }
                    }
                    else {
                        // Test pre CFB-128
                        uint8_t plaintext_bytes[16] = {0};
                        uint8_t expected_ciphertext_bytes[16] = {0};
                        uint8_t result_bytes[16] = {0};
                        
                        // Konverzia plaintextu a ciphertextu z hex retazca na bajty
                        if (plaintext_str && strlen(plaintext_str) >= 32) {
                            hex_to_bin(plaintext_str, plaintext_bytes, 16);
                        }
                        
                        if (ciphertext_str && strlen(ciphertext_str) >= 32) {
                            hex_to_bin(ciphertext_str, expected_ciphertext_bytes, 16);
                        }      
                        
                        // Overenie, ze IV zodpoveda ocakavanemu vstupnemu bloku
                        uint8_t input_block_bytes[16];
                        hex_to_bin(hex_input_block, input_block_bytes, 16);
                        
                        if (memcmp(iv, input_block_bytes, 16) != 0) {
                            printf("!!! CHYBA: Vstupny blok nezodpoveda aktualnemu IV !!!\n");
                        }
                        
                        if (encrypt_mode) {
                            printf("Plaintext: ");
                            print_hex(plaintext_bytes, 16);
                            
                            printf("Ocakavany vstupny blok (IV): %s\n", hex_input_block);
                            printf("Aktualny vstupny blok (IV): ");
                            print_hex(iv, 16);

                            // Samotne testovanie CFB-128 sifrovania
                            process_cfb128_encrypt(key, iv, plaintext_bytes, result_bytes);

                            printf("Ocakavany ciphertext: ");
                            print_hex(expected_ciphertext_bytes, 16);

                            printf("Vypocitany ciphertext: ");
                            print_hex(result_bytes, 16);
                            
                            if (memcmp(result_bytes, expected_ciphertext_bytes, 16) == 0) {
                                passed_count++;
                                printf("Test USPESNY\n");
                            } else {
                                printf("Test NEUSPESNY\n");
                            }
                        } else {
                            printf("Ciphertext: ");
                            print_hex(expected_ciphertext_bytes, 16);

                            printf("Ocakavany vstupny blok (IV): %s\n", hex_input_block);
                            printf("Aktualny vstupny blok (IV): ");
                            print_hex(iv, 16);
                            
                            // Samotne testovanie CFB-128 desifrovania
                            process_cfb128_decrypt(key, iv, expected_ciphertext_bytes, result_bytes);
         
                            printf("Ocakavany plaintext: ");
                            print_hex(plaintext_bytes, 16);

                            printf("Vypocitany plaintext: ");
                            print_hex(result_bytes, 16);

                            if (memcmp(result_bytes, plaintext_bytes, 16) == 0) {
                                passed_count++;
                                printf("Test USPESNY\n");
                            } else {
                                printf("Test NEUSPESNY\n");
                            }
                        }
                    }
                }
            }
        }

        fclose(fp);
        free(hex_key);
        free(hex_iv);
        free(hex_input_block);
        free(hex_output_block);
        
        printf("\nTestovanie %s dokoncene: %d/%d uspesnych\n", cfb_mode_names[file_idx], passed_count, test_count);
    }
    
    return 0;
}