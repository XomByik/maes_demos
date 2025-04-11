#include "kw_config.h"

typedef enum {
    KEY, PLAINTEXT, CIPHERTEXT, COUNT, FAIL, PLAINTEXT_LEN
} LineType;

static LineType get_line_type(const char* line) {
    if (strstr(line, "K = ")) return KEY;
    if (strstr(line, "P = ")) return PLAINTEXT;
    if (strstr(line, "C = ")) return CIPHERTEXT;
    if (strstr(line, "COUNT = ")) return COUNT;
    if (strstr(line, "FAIL")) return FAIL;
    if (strstr(line, "[PLAINTEXT LENGTH = ")) return PLAINTEXT_LEN;
    return -1;
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
    free(data->hex_key);
    free(data->hex_plaintext);
    free(data->hex_ciphertext);
    memset(data, 0, sizeof(TestCaseData));
}

bool parse_next_test_case(FILE *fp, TestCaseData *data, size_t *p_length, bool is_unwrap_file) {
    char line[KW_LINE_BUFFER_SIZE];
    char *value;
    bool in_test_case = false;
    long start_pos = ftell(fp);
    bool fail_tag_seen = false;

    free_test_case_data(data);
    // Explicitne nastavenie podľa typu súboru
    data->is_unwrap = is_unwrap_file;

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
                value = get_line_value(trimmed, "COUNT = ");
                if (in_test_case) {
                    fseek(fp, start_pos, SEEK_SET);
                    free(value);
                    data->should_fail = fail_tag_seen;
                    return true;
                }
                data->count = atoi(value);
                in_test_case = true;
                fail_tag_seen = false;
                data->should_fail = false;
                free(value);
                break;

            case KEY:
                value = get_line_value(trimmed, "K = ");
                if (!data->hex_key) data->hex_key = value; else free(value);
                break;

            case PLAINTEXT:
                value = get_line_value(trimmed, "P = ");
                if (!data->hex_plaintext) data->hex_plaintext = value; else free(value);
                break;

            case CIPHERTEXT:
                value = get_line_value(trimmed, "C = ");
                if (!data->hex_ciphertext) data->hex_ciphertext = value; else free(value);
                break;

            case PLAINTEXT_LEN:
                if (sscanf(trimmed + 19, "%zu", p_length) == 1) {
                    *p_length /= 8; // Convert from bits to bytes
                }
                break;

            case FAIL:
                fail_tag_seen = true;
                break;
        }
        start_pos = ftell(fp);
    }

    if (in_test_case) {
        data->should_fail = fail_tag_seen;
        return true;
    }
    return false;
}

bool process_test_case(const TestCaseData *data, int *passed_count) {
    
    size_t key_len = strlen(data->hex_key) / 2;
    size_t pt_len = 0;
    size_t ct_len = 0;
    
    if (data->hex_plaintext) {
        pt_len = strlen(data->hex_plaintext) / 2;
    }
    
    if (data->hex_ciphertext) {
        ct_len = strlen(data->hex_ciphertext) / 2;
    }
    
    // For Wrap, output length is always input length + 8
    // For Unwrap, output length is always input length - 8
    size_t expected_len = data->is_unwrap ? (ct_len - 8) : (pt_len + 8);
    
    uint8_t *key = calloc(key_len + 1, 1);
    uint8_t *plaintext = calloc(pt_len + 1, 1);
    uint8_t *ciphertext_expected = calloc(ct_len + 1, 1);
    uint8_t *result_buffer = calloc(expected_len + 1, 1);

    if (!key || (!plaintext && pt_len > 0) || 
        (!ciphertext_expected && ct_len > 0) || !result_buffer) {
        free(key);
        free(plaintext);
        free(ciphertext_expected);
        free(result_buffer);
        return false;
    }

    // Convert hex to binary
    hex_to_bin(data->hex_key, key, key_len);
    
    if (data->hex_plaintext) {
        hex_to_bin(data->hex_plaintext, plaintext, pt_len);
    }
    
    if (data->hex_ciphertext) {
        hex_to_bin(data->hex_ciphertext, ciphertext_expected, ct_len);
    }

    printf("=== Test #%d ===\n", data->count);
    printf("Vstupne data:\n");
    printf("  Kluc: %s\n", data->hex_key);

    int operation_status;
    bool success = false;

    if (data->is_unwrap) {
        // Unwrap operation
        printf("  Ciphertext: %s\n", data->hex_ciphertext);
        if (data->hex_plaintext) {
            printf("  Ocakavany plaintext: %s\n", data->hex_plaintext);
        } else if (data->should_fail) {
            printf("  Ocakavany vysledok: ZLYHANIE\n");
        }

        printf("\nTest Unwrap (AD):\n");
        operation_status = AES_KEY_unwrap(key, ciphertext_expected, ct_len, result_buffer);

        if (operation_status == 0) {
            printf("  Status Unwrap: USPECH\n");
            if (data->should_fail) {
                printf("  Vysledok: NEUSPESNY (ocakavalo sa zlyhanie, ale prebehlo uspesne)\n");
                printf("  Vypocitany plaintext: ");
                print_hex(result_buffer, expected_len);
            } else {
                printf("  Vypocitany plaintext: ");
                print_hex(result_buffer, expected_len);
                
                if (data->hex_plaintext) {
                    printf("  Ocakavany plaintext: ");
                    print_hex(plaintext, pt_len);
                    success = (memcmp(result_buffer, plaintext, pt_len) == 0);
                    printf("  Vysledok: %s\n\n", success ? "USPESNY" : "NEUSPESNY (neshoda plaintextu)");
                } else {
                    success = true;
                    printf("  Vysledok: USPESNY\n\n");
                }
            }
        } else {
            printf("  Status Unwrap: ZLYHANIE (kod %d)\n", operation_status);
            if (data->should_fail) {
                success = true;
                printf("  Vysledok: USPESNY (ocakavane zlyhanie)\n\n");
            } else {
                printf("  Vysledok: NEUSPESNY (neocakavane zlyhanie)\n\n");
            }
        }

        if (success) (*passed_count)++; // len inkrementujeme passed_count
    } else {
        // Wrap operation
        printf("  Plaintext: %s\n", data->hex_plaintext);
        if (data->hex_ciphertext) {
            printf("  Ocakavany ciphertext: %s\n", data->hex_ciphertext);
        }

        printf("\nTest Wrap (AE):\n");
        operation_status = AES_KEY_wrap(key, plaintext, pt_len, result_buffer);

        if (operation_status == 0) {
            printf("  Vypocitany ciphertext: ");
            print_hex(result_buffer, expected_len);
            
            if (data->hex_ciphertext) {
                printf("  Ocakavany ciphertext: ");
                print_hex(ciphertext_expected, ct_len);
                success = (memcmp(result_buffer, ciphertext_expected, expected_len) == 0);
                printf("  Vysledok: %s\n\n", success ? "USPESNY" : "NEUSPESNY (neshoda ciphertextu)");
            } else {
                success = true;
                printf("  Vysledok: USPESNY\n\n");
            }
        } else {
            printf("  Status Wrap: ZLYHANIE (kod %d)\n", operation_status);
            printf("  Vysledok: NEUSPESNY\n\n");
        }

        if (success) (*passed_count)++; // len inkrementujeme passed_count
    }

    free(key);
    free(plaintext);
    free(ciphertext_expected);
    free(result_buffer);
    
    return true;
}

int main() {
    #if KW == 0
        printf("KW rezim nie je povoleny pri kompilacii.\n");
        return 1;
    #endif

    // Zisti AES verziu a vyber spravne testovacie subory
    const int aes_bits = 
        #if AES___ == 256
            256
        #elif AES___ == 192
            192
        #else
            128
        #endif
    ;

    const char *wrap_file = 
        #if AES___ == 256
            "test_vectors/kw_ae_256.txt"
        #elif AES___ == 192
            "test_vectors/kw_ae_192.txt"
        #else
            "test_vectors/kw_ae_128.txt"
        #endif
    ;

    const char *unwrap_file = 
        #if AES___ == 256
            "test_vectors/kw_ad_256.txt"
        #elif AES___ == 192
            "test_vectors/kw_ad_192.txt"
        #else
            "test_vectors/kw_ad_128.txt"
        #endif
    ;

    printf("AES-%d Key Wrap Test\n", aes_bits);
    printf("Wrap testovaci subor: %s\n", wrap_file);
    printf("Unwrap testovaci subor: %s\n", unwrap_file);

    // Inicializacia statistiky
    int wrap_passed = 0, unwrap_passed = 0;
    int wrap_total = 0, unwrap_total = 0;
    TestCaseData test = {0};
    size_t pt_length = 0;

    // Testovanie Wrap operacie
    FILE *fp = fopen(wrap_file, "r");
    if (!fp) {
        perror("Nepodarilo sa otvorit subor pre Wrap testy");
        return 1;
    }

    printf("\n--- Testovanie Wrap (AE) ---\n");
    while (parse_next_test_case(fp, &test, &pt_length, false)) { // false = nie je unwrap súbor
        wrap_total++;
        process_test_case(&test, &wrap_passed); 
    }
    fclose(fp);

    // Pre unwrap testy
    fp = fopen(unwrap_file, "r");
    if (!fp) {
        perror("Nepodarilo sa otvorit subor pre Unwrap testy");
        return 1;
    }

    printf("\n--- Testovanie Unwrap (AD) ---\n");
    while (parse_next_test_case(fp, &test, &pt_length, true)) { // true = je unwrap súbor
        unwrap_total++;
        process_test_case(&test, &unwrap_passed);
    }
    fclose(fp);

    // Sumarizacia vysledkov
    bool all_passed = (wrap_passed == wrap_total) && (unwrap_passed == unwrap_total);
    
    printf("\nCelkove vysledky:\n");
    printf("Wrap testy: %d/%d uspesnych\n", wrap_passed, wrap_total);
    printf("Unwrap testy: %d/%d uspesnych\n", unwrap_passed, unwrap_total);
    printf("Celkovy vysledok: %s\n", all_passed ? "USPESNY" : "NEUSPESNY");

    free_test_case_data(&test);
    return all_passed ? 0 : 1;
}