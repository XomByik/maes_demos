#include "fpe_config.h"

typedef enum {
    COUNT, METHOD, ALPHABET, KEY, TWEAK, PT, CT, UNKNOWN
} LineType;

static LineType get_line_type(const char* line) {
    if (strstr(line, "Count = ")) return COUNT;
    if (strstr(line, "Method = ")) return METHOD;
    if (strstr(line, "Alphabet = ")) return ALPHABET;
    if (strstr(line, "Key = ")) return KEY;
    if (strstr(line, "Tweak = ")) return TWEAK;
    if (strstr(line, "PT = ")) return PT;
    if (strstr(line, "CT = ")) return CT;
    return UNKNOWN;
}

static char* get_line_value(const char* line, const char* prefix) {
    size_t prefix_len = strlen(prefix);
    if (strncmp(line, prefix, prefix_len) == 0) {
        char* temp = my_strdup(line + prefix_len);
        if (!temp) return NULL;
        char* trimmed = trim(temp);
        if (trimmed != temp) {
            memmove(temp, trimmed, strlen(trimmed) + 1);
        }
        return temp;
    }
    return NULL;
}

void free_test_case_data(TestCaseData *data) {
    if (!data) return;
    free(data->count_str);
    free(data->method_str);
    free(data->alphabet_str);
    free(data->hex_key);
    free(data->hex_tweak);
    free(data->pt_str);
    free(data->expected_ct_str);
    memset(data, 0, sizeof(TestCaseData));
}

bool parse_next_test_case(FILE *fp, TestCaseData *data) {
    char line[FPE_LINE_BUFFER_SIZE];
    char *value;
    bool in_test_case = false;
    long start_pos = ftell(fp);
    
    free_test_case_data(data);
    
    while (fgets(line, sizeof(line), fp)) {
        char *trimmed = trim(line);
        if (!trimmed || strlen(trimmed) == 0 || trimmed[0] == '#') {
            if (in_test_case) start_pos = ftell(fp);
            continue;
        }

        LineType type = get_line_type(trimmed);
        value = NULL;

        switch(type) {
            case COUNT:
                value = get_line_value(trimmed, "Count = ");
                if (in_test_case && data->hex_key && data->hex_tweak && 
                    data->pt_str && data->expected_ct_str &&
                    data->method_str && data->alphabet_str) {
                    fseek(fp, start_pos, SEEK_SET);
                    free(value);
                    return true;
                }
                if (value) {
                    data->count_str = value;
                    data->count = atoi(value);
                    in_test_case = true;
                    // Inicializácia tweak na prázdny reťazec (ak nie je určený)
                    if (!data->hex_tweak) {
                        data->hex_tweak = my_strdup("");
                    }
                }
                break;

            case METHOD:
                value = get_line_value(trimmed, "Method = ");
                if (value) {
                    data->method_str = value;
                }
                break;

            case ALPHABET:
                value = get_line_value(trimmed, "Alphabet = ");
                if (value) {
                    data->alphabet_str = value;
                }
                break;

            case KEY:
                value = get_line_value(trimmed, "Key = ");
                if (value) {
                    data->hex_key = value;
                }
                break;

            case TWEAK:
                value = get_line_value(trimmed, "Tweak = ");
                if (value) {
                    free(data->hex_tweak); // Uvoľní prípadný prázdny reťazec
                    data->hex_tweak = value;
                }
                break;

            case PT:
                value = get_line_value(trimmed, "PT = ");
                if (value) {
                    data->pt_str = value;
                }
                break;

            case CT:
                value = get_line_value(trimmed, "CT = ");
                if (value) {
                    data->expected_ct_str = value;
                }
                break;

            case UNKNOWN:
                // Ignorovať neznáme riadky
                break;
        }
        
        start_pos = ftell(fp);
        
        // Po každom spracovaní riadku skontrolujeme, či nemáme kompletný test
        if (in_test_case && data->hex_key && data->hex_tweak && 
            data->pt_str && data->expected_ct_str &&
            data->method_str && data->alphabet_str) {
            return true;
        }
    }

    // Koniec súboru - vrátime posledný kompletný test, ak existuje
    return (in_test_case && data->hex_key && data->hex_tweak && 
            data->pt_str && data->expected_ct_str && 
            data->method_str && data->alphabet_str);
}

bool process_test_case(const TestCaseData *data, int *passed_encrypt, int *passed_decrypt) {
    if (!data || !data->hex_key || !data->pt_str || !data->expected_ct_str ||
        !data->method_str || !data->alphabet_str) {
        fprintf(stderr, "Chyba: Neplatny ukazovatel v strukture testovacieho vektora.\n");
        return false;
    }
    
    #if FF_X == 1
        const char* compiled_method = "FF1";
    #elif FF_X == 3
        const char* compiled_method = "FF3";
    #endif
    
    // Kontrola metódy
    if (strcmp(data->method_str, compiled_method) != 0) {
        printf("Test #%d - Nezhoda metody (%s vs %s), preskakujem\n", 
               data->count, data->method_str, compiled_method);
        return false;
    }
    
    // Kontrola abecedy
    const char* default_alphabet = "0123456789";
    if (strcmp(data->alphabet_str, default_alphabet) != 0) {
        printf("Test #%d - Nepodporovana abeceda '%s', preskakujem\n", 
               data->count, data->alphabet_str);
        return false;
    }

    // Dĺžky vstupov
    size_t key_len = strlen(data->hex_key) / 2;
    size_t tweak_len = strlen(data->hex_tweak) / 2;
    size_t pt_len = strlen(data->pt_str);
    size_t ct_len = strlen(data->expected_ct_str);
    
    // Validácia vstupov
    if (pt_len != ct_len) {
        printf("Test #%d - Nerovnaka dlzka PT (%zu) a CT (%zu)\n", data->count, pt_len, ct_len);
        return false;
    }
    
    if (key_len != 16 && key_len != 24 && key_len != 32) {
        printf("Test #%d - Neplatna dlzka kluca (%zu bajtov)\n", data->count, key_len);
        return false;
    }
    
    #if FF_X == 3
        if (tweak_len != FF3_TWEAK_LEN && tweak_len > 0) {
            printf("Test #%d - Neplatna dlzka tweak-u (%zu bajtov)\n", data->count, tweak_len);
            return false;
        }
    #endif
    
    // Alokácia bufferov
    uint8_t *key = calloc(key_len, 1);
    uint8_t *tweak = calloc(tweak_len > 0 ? tweak_len : 1, 1);
    char *calculated_ct = calloc(pt_len + 1, 1);
    char *decrypted_pt = calloc(pt_len + 1, 1);
    
    if (!key || !tweak || !calculated_ct || !decrypted_pt) {
        fprintf(stderr, "Test #%d - Chyba alokacie pamate\n", data->count);
        free(key); free(tweak); free(calculated_ct); free(decrypted_pt);
        return false;
    }
    
    // Konverzia hex na bin
    if (hex_to_bin(data->hex_key, key, key_len) != 0 ||
        (tweak_len > 0 && hex_to_bin(data->hex_tweak, tweak, tweak_len) != 0)) {
        fprintf(stderr, "Test #%d - Chyba pri konverzii hex hodnot\n", data->count);
        free(key); free(tweak); free(calculated_ct); free(decrypted_pt);
        return false;
    }
    
    // Výpis informácií o teste
    printf("=== Test #%d ===\n", data->count);
    printf("Vstupne data:\n");
    printf("  Metoda  : %s\n", data->method_str);
    printf("  Abeceda : %s\n", data->alphabet_str);
    printf("  Kluc    : %s\n", data->hex_key);
    printf("  Tweak   : %s\n", data->hex_tweak);
    printf("  PT      : %s\n", data->pt_str);
    printf("  Ocakavane CT: %s\n", data->expected_ct_str);
    
    // Test šifrovania
    printf("\nTest sifrovania:\n");
    char enc_status;
    
    #if FF_X == 3
        enc_status = AES_FPE_encrypt(key, tweak, data->pt_str, pt_len, calculated_ct);
    #else // FF1
        enc_status = AES_FPE_encrypt(key, tweak, tweak_len, data->pt_str, pt_len, calculated_ct);
    #endif
    
    bool enc_success = false;
    if (enc_status == NO_ERROR_RETURNED) {
        printf("  Vypocitany ciphertext: %s\n", calculated_ct);
        printf("  Ocakavany ciphertext: %s\n", data->expected_ct_str);
        
        enc_success = (strcmp(calculated_ct, data->expected_ct_str) == 0);
        if (enc_success) (*passed_encrypt)++;
        printf("  Vysledok sifrovania: %s\n", enc_success ? "USPESNY" : "NEUSPESNY");
    } else {
        printf("  Sifrovanie zlyhalo s chybou %d\n", enc_status);
    }
    
    // Test dešifrovania
    printf("\nTest desifrovania:\n");
    bool dec_success = false;
    
    if (enc_status == NO_ERROR_RETURNED) {
        char dec_status;
        
        #if FF_X == 3
            dec_status = AES_FPE_decrypt(key, tweak, calculated_ct, pt_len, decrypted_pt);
        #else // FF1
            dec_status = AES_FPE_decrypt(key, tweak, tweak_len, calculated_ct, pt_len, decrypted_pt);
        #endif
        
        if (dec_status == NO_ERROR_RETURNED) {
            printf("  Vypocitany plaintext: %s\n", decrypted_pt);
            printf("  Povodny plaintext: %s\n", data->pt_str);
            
            dec_success = (strcmp(decrypted_pt, data->pt_str) == 0);
            if (dec_success) (*passed_decrypt)++;
            printf("  Vysledok desifrovania: %s\n", dec_success ? "USPESNY" : "NEUSPESNY");
        } else {
            printf("  Desifrovanie zlyhalo s chybou %d\n", dec_status);
        }
    } else {
        printf("  Desifrovanie preskocene (sifrovanie zlyhalo)\n");
    }
    
    // Uvoľnenie pamäte
    free(key);
    free(tweak);
    free(calculated_ct);
    free(decrypted_pt);
    
    return (enc_success && dec_success);
}

int main() {
    const char* test_vectors_file;
    
    #if FF_X == 1
        const char* mode_name = "FF1";
    #elif FF_X == 3
        const char* mode_name = "FF3-1";
    #endif
    
    #if AES___ == 256
        #if FF_X == 3
            test_vectors_file = "test_vectors/ff3_256.txt";
        #else
            test_vectors_file = "test_vectors/ff1_256.txt";
        #endif
        printf("AES-256 %s Test\n", mode_name);
    #elif AES___ == 192
        #if FF_X == 3
            test_vectors_file = "test_vectors/ff3_192.txt";
        #else
            test_vectors_file = "test_vectors/ff1_192.txt";
        #endif
        printf("AES-192 %s Test\n", mode_name);
    #else
        #if FF_X == 3
            test_vectors_file = "test_vectors/ff3_128.txt";
        #else
            test_vectors_file = "test_vectors/ff1_128.txt";
        #endif
        printf("AES-128 %s Test\n", mode_name);
    #endif

    printf("Pouziva sa testovaci subor: %s\n", test_vectors_file);

    FILE *fp = fopen(test_vectors_file, "r");
    if (!fp) {
        perror("Nepodarilo sa otvorit subor s testovacimi vektormi");
        return 1;
    }

    int tests_passed_encrypt = 0;
    int tests_passed_decrypt = 0;
    TestCaseData current_test = {0};
    int processed_tests = 0;
    int skipped_tests = 0;

    while (parse_next_test_case(fp, &current_test)) {
        #if FF_X == 1
            const bool method_ok = (strcmp(current_test.method_str, "FF1") == 0);
        #else
            const bool method_ok = (strcmp(current_test.method_str, "FF3") == 0);
        #endif
        
        const bool alphabet_ok = (strcmp(current_test.alphabet_str, "0123456789") == 0);
        
        if (!method_ok || !alphabet_ok) {
            skipped_tests++;
            free_test_case_data(&current_test);
            continue;
        }
        
        processed_tests++;
        process_test_case(&current_test, &tests_passed_encrypt, &tests_passed_decrypt);
        free_test_case_data(&current_test);
    }

    fclose(fp);

    int total_passed = tests_passed_encrypt + tests_passed_decrypt;
    int expected_passes = processed_tests * 2; // každý test má encrypt aj decrypt
    bool success = (processed_tests > 0 && total_passed == expected_passes);

    printf("\nCelkove vysledky:\n");
    printf("Nacitanych testovych vektorov: %d\n", processed_tests + skipped_tests);
    printf("Preskocenych testov (nespravna metoda/abeceda): %d\n", skipped_tests);
    printf("Spracovanych testov: %d\n", processed_tests);
    printf("Uspesnych testov sifrovania: %d / %d\n", tests_passed_encrypt, processed_tests);
    printf("Uspesnych testov desifrovania: %d / %d\n", tests_passed_decrypt, processed_tests);
    printf("Celkovy vysledok: %s\n", success ? "USPESNY" : "NEUSPESNY");

    return success ? 0 : 1;
}