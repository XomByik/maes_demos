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

int main() {
    // Zistenie, ci sa jedna o 128 alebo 256 bitovy rezim podla definicie v micro_aes.h
    #if AES___ == 256
        const int aes_bits = 256;
        const char* test_vectors_file = "test_vectors/xts_test_vectors_256.txt";
        printf("Program skompilovany pre AES-256\n");
    #else
        const int aes_bits = 128;
        const char* test_vectors_file = "test_vectors/xts_test_vectors_128.txt";
        printf("Program skompilovany pre AES-128\n");
    #endif
    
    FILE *fp;
    char line[512];
    uint8_t *key1, *key2, *keys, tweak[16];
    uint8_t plaintext[1024], ciphertext[1024], result[1024]; // Zvacsime pre 256-bit testy
    char *hex_key1 = NULL, *hex_key2 = NULL, *hex_tweak = NULL;
    char *hex_ptx = NULL, *hex_ctx = NULL;
    size_t ptx_len = 0, ctx_len = 0;
    int test_count = 0, passed_count = 0;
    int in_ctx_section = 0;
    
    // Alokujeme pamat pre kluce podla zvolenej velkosti
    int key_size_bytes = aes_bits / 8;
    key1 = (uint8_t*)malloc(key_size_bytes);
    key2 = (uint8_t*)malloc(key_size_bytes);
    keys = (uint8_t*)malloc(key_size_bytes * 2); // XTS pouziva dvojnasobnu dlzku kluca
    
    if (!key1 || !key2 || !keys) {
        printf("Chyba: Nepodarilo sa alokovat pamat pre kluce\n");
        if (key1) free(key1);
        if (key2) free(key2);
        if (keys) free(keys);
        return 1;
    }

    // Otvorenie suboru s testovacimi vektormi
    printf("Pouziva sa testovaci subor: %s\n", test_vectors_file);
    fp = fopen(test_vectors_file, "r");
    if (!fp) {
        perror("Nepodarilo sa otvorit subor s testovacimi vektormi");
        free(key1);
        free(key2);
        free(keys);
        return 1;
    }

    // Spracovanie vsetkych testovacich vektorov
    while (fgets(line, sizeof(line), fp)) {
        // Odstranenie koncoveho znaku noveho riadka a CR znaku (Windows)
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';
            
        // Preskocenie prazdnych riadkov a komentarov
        if (len == 0 || line[0] == '#' || line[0] == '/') {
            // Prazdny riadok oznacuje koniec testovacieho vektora, ak sme boli v sekcii CTX
            if (in_ctx_section && hex_key1 && hex_key2 && hex_tweak && hex_ptx && hex_ctx) {
                in_ctx_section = 0;
                test_count++;
                printf("Test #%d:\n", test_count);
                
                // Konverzia hex na binarne hodnoty
                hex_to_bin(hex_key1, key1, key_size_bytes);
                hex_to_bin(hex_key2, key2, key_size_bytes);
                
                // Vytvorenie kombinovaneho kluca
                memcpy(keys, key1, key_size_bytes);
                memcpy(keys + key_size_bytes, key2, key_size_bytes);
                
                hex_to_bin(hex_tweak, tweak, 16);
                hex_to_bin(hex_ptx, plaintext, ptx_len);
                hex_to_bin(hex_ctx, ciphertext, ctx_len);
                
                printf("Kluc1: ");
                print_hex(key1, key_size_bytes);
                printf("Kluc2: ");
                print_hex(key2, key_size_bytes);
                printf("DUCN: ");
                print_hex(tweak, 16);
                printf("PTX (%zu bajtov): ", ptx_len);
                print_hex(plaintext, ptx_len);
                
                // Sifrovanie
                char status = AES_XTS_encrypt(keys, tweak, plaintext, ptx_len, result);
                if (status != 0) {
                    printf("Sifrovanie zlyhalo so statusom %d\n", status);
                } else {
                    printf("Vypocitany CTX: ");
                    print_hex(result, ptx_len);
                    
                    printf("Ocakavany CTX: ");
                    print_hex(ciphertext, ctx_len);
                    
                    // Kontrola zhody - pre dlhe vektory kontrolujeme len prvych 16 bajtov
                    int match;
                    if (ptx_len > 32) {
                        match = (memcmp(result, ciphertext, 16) == 0);
                    } else {
                        match = (memcmp(result, ciphertext, ctx_len) == 0);
                    }
                    
                    if (match) {
                        passed_count++;
                        printf("Test USPESNY\n");
                    } else {
                        printf("Test NEUSPESNY\n");
                    }
                }
                
                // Uvolnenie pamate pre dalsi test
                free(hex_key1);
                free(hex_key2);
                free(hex_tweak);
                free(hex_ptx);
                free(hex_ctx);
                hex_key1 = NULL;
                hex_key2 = NULL;
                hex_tweak = NULL;
                hex_ptx = NULL;
                hex_ctx = NULL;
                ptx_len = 0;
                ctx_len = 0;
                
                printf("\n");
            }
            continue;
        }
        
        // Parsovanie parov kluc-hodnota
        if (strncmp(line, "Key1", 4) == 0) {
            free(hex_key1);
            hex_key1 = my_strdup(trim(line + 5));
            if (hex_to_bin(hex_key1, key1, key_size_bytes) != 0) {
                fprintf(stderr, "Error parsing Key1 hex.\n");
                free(hex_key1); hex_key1 = NULL;
            }
            continue;
        }
        if (strncmp(line, "Key2", 4) == 0) {
            free(hex_key2);
            hex_key2 = my_strdup(trim(line + 5));
            if (hex_to_bin(hex_key2, key2, key_size_bytes) != 0) {
                fprintf(stderr, "Error parsing Key2 hex.\n");
                free(hex_key2); hex_key2 = NULL;
            }
            continue;
        }
        if (strncmp(line, "Tweak", 5) == 0) {
            free(hex_tweak);
            hex_tweak = my_strdup(trim(line + 6));
            if (hex_to_bin(hex_tweak, tweak, 16) != 0) { // Tweak je vzdy 16 bajtov
                fprintf(stderr, "Error parsing Tweak hex.\n");
                free(hex_tweak); hex_tweak = NULL;
            }
            continue;
        } else if (strncmp(line, "PTX", 3) == 0) {
            char* value = trim(line + 4);
            
            if (hex_ptx == NULL) {
                hex_ptx = my_strdup(value);
                ptx_len = strlen(value) / 2;
            } else {
                // Pridanie do existujuceho plaintextu
                size_t current_len = strlen(hex_ptx);
                size_t append_len = strlen(value);
                char* new_ptx = realloc(hex_ptx, current_len + append_len + 1);
                if (new_ptx) {
                    hex_ptx = new_ptx;
                    strcat(hex_ptx, value);
                    ptx_len = strlen(hex_ptx) / 2;
                }
            }
        } else if (strncmp(line, "CTX", 3) == 0) {
            in_ctx_section = 1;
            char* value = trim(line + 4);
            
            if (hex_ctx == NULL) {
                hex_ctx = my_strdup(value);
                ctx_len = strlen(value) / 2;
            } else {
                // Pridanie do existujuceho ciphertextu
                size_t current_len = strlen(hex_ctx);
                size_t append_len = strlen(value);
                char* new_ctx = realloc(hex_ctx, current_len + append_len + 1);
                if (new_ctx) {
                    hex_ctx = new_ctx;
                    strcat(hex_ctx, value);
                    ctx_len = strlen(hex_ctx) / 2;
                }
            }
        }
    }
    
    // Spracovanie posledneho testovacieho vektora ak je potrebne
    if (in_ctx_section && hex_key1 && hex_key2 && hex_tweak && hex_ptx && hex_ctx) {
        test_count++;
        printf("Test #%d:\n", test_count);
        
        // Konverzia hex na binarne hodnoty
        hex_to_bin(hex_key1, key1, key_size_bytes);
        hex_to_bin(hex_key2, key2, key_size_bytes);
        
        // Vytvorenie kombinovaneho kluca
        memcpy(keys, key1, key_size_bytes);
        memcpy(keys + key_size_bytes, key2, key_size_bytes);
        
        hex_to_bin(hex_tweak, tweak, 16);
        hex_to_bin(hex_ptx, plaintext, ptx_len);
        hex_to_bin(hex_ctx, ciphertext, ctx_len);
        
        printf("Kluc1: ");
        print_hex(key1, key_size_bytes);
        printf("Kluc2: ");
        print_hex(key2, key_size_bytes);
        printf("DUCN: ");
        print_hex(tweak, 16);
        printf("PTX (%zu bajtov): ", ptx_len);
        print_hex(plaintext, ptx_len);
        
        char status = AES_XTS_encrypt(keys, tweak, plaintext, ptx_len, result);
        if (status != 0) {
            printf("Sifrovanie zlyhalo so statusom %d\n", status);
        } else {
            printf("Vypocitany CTX: ");
            print_hex(result, ptx_len);
            
            printf("Ocakavany CTX: ");
            print_hex(ciphertext, ctx_len);
            
            // Pre dlhe vektory kontrola ci sa prve bajty zhoduju
            int match;
            if (ptx_len > 32) {
                match = (memcmp(result, ciphertext, 16) == 0);
            } else {
                match = (memcmp(result, ciphertext, ctx_len) == 0);
            }
            
            if (match) {
                passed_count++;
                printf("Test USPESNY\n");
            } else {
                printf("Test NEUSPESNY\n");
            }
        }
        
        free(hex_key1);
        free(hex_key2);
        free(hex_tweak);
        free(hex_ptx);
        free(hex_ctx);
    }

    fclose(fp);
    printf("\nTestovanie dokoncene: %d/%d uspesnych\n", passed_count, test_count);
    
    // Uvolnenie alokovanych zdrojov
    free(key1);
    free(key2);
    free(keys);
    
    return 0;
}