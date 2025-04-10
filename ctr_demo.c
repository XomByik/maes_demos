#include "ctr_config.h"

static LineType get_line_type(const char* line) {
    if (strncmp(line, "Key", 3) == 0) return KEY;
    if (strncmp(line, "Init. Counter", 13) == 0) return COUNTER;
    if (strncmp(line, "Block #", 7) == 0) return BLOCK;
    if (strncmp(line, "Input Block", 11) == 0) return INPUT_BLOCK;
    if (strncmp(line, "Output Block", 12) == 0) return OUTPUT_BLOCK;
    if (strncmp(line, "Plaintext", 9) == 0) return PLAINTEXT;
    if (strncmp(line, "Ciphertext", 10) == 0) return CIPHERTEXT;
    if (strstr(line, "CTR-AES") != NULL) return MODE_CHANGE;
    return UNKNOWN;
}

static void init_test_case_data(TestCaseData *data) {
    memset(data, 0, sizeof(TestCaseData));
    data->is_encrypt_mode = true;
}

void free_test_case_data(TestCaseData *data) {
    free(data->hex_key);
    free(data->hex_counter);
    memset(data, 0, sizeof(TestCaseData));
}

static bool process_test_vector(const TestVector *test, const uint8_t *key, 
                              bool is_encrypt, int *test_count, 
                              int *passed_count) {
    uint8_t plaintext[MAX_BUFFER_SIZE], ciphertext[MAX_BUFFER_SIZE];
    uint8_t result[MAX_BUFFER_SIZE];
    uint8_t counter[16];
    size_t data_len;
    bool success = true;

    (*test_count)++;
    printf("\nTest #%d (Block #%d):\n", *test_count, test->block_number);

    // Convert input counter from hex string - use exact input block
    hex_to_bin(test->hex_input_block, counter, 16);
    
    if (is_encrypt) {
        data_len = strlen(test->hex_plaintext) / 2;
        hex_to_bin(test->hex_plaintext, plaintext, data_len);
        hex_to_bin(test->hex_ciphertext, ciphertext, data_len);
        
        printf("Plaintext: ");
        print_hex(plaintext, data_len);
        
        // Use exact counter from test vector
        AES_CTR_encrypt(key, counter, plaintext, data_len, result);

        printf("Vypocitany ciphertext: ");
        print_hex(result, data_len);
        printf("Ocakavany ciphertext: ");
        print_hex(ciphertext, data_len);
    } else {
        data_len = strlen(test->hex_ciphertext) / 2;
        hex_to_bin(test->hex_ciphertext, ciphertext, data_len);
        hex_to_bin(test->hex_plaintext, plaintext, data_len);
        
        printf("Ciphertext: ");
        print_hex(ciphertext, data_len);
        
        // Use same exact counter for decryption
        AES_CTR_decrypt(key, counter, ciphertext, data_len, result);

        printf("Vypocitany plaintext: ");
        print_hex(result, data_len);
        printf("Ocakavany plaintext: ");
        print_hex(plaintext, data_len);
    }

    printf("Vstupny blok (Counter): ");
    print_hex(counter, 16);

    // Compare results
    uint8_t *expected = is_encrypt ? ciphertext : plaintext;
    if (memcmp(result, expected, data_len) != 0) {
        printf("!!! CHYBA: Vypocitany %s sa nezhoduje s ocakavanym !!!\n",
               is_encrypt ? "ciphertext" : "plaintext");
        success = false;
    }

    if (success) {
        (*passed_count)++;
        printf("Test USPESNY\n");
    } else {
        printf("Test NEUSPESNY\n");
    }

    return success;
}

static void process_line(char *line, TestCaseData *data, int *block_number, 
                        uint8_t *key, size_t key_size) {
    size_t len = strlen(line);
    while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r')) {
        line[--len] = '\0';
    }
    if (len == 0) return;

    LineType type = get_line_type(line);
    char *value;

    switch (type) {
        case MODE_CHANGE:
            data->is_encrypt_mode = (strstr(line, "Encrypt") != NULL);
            printf("\n=== %s ===\n", data->is_encrypt_mode ? 
                   "Nacitavanie sifrovacich testovacich vektorov" : 
                   "Nacitavanie desifrovacich testovacich vektorov");
            break;

        case KEY:
            free(data->hex_key);
            data->hex_key = my_strdup(trim(line + 4));
            hex_to_bin(data->hex_key, key, key_size);
            printf("\nKluc: %s\n", data->hex_key);
            break;

        case COUNTER:
            free(data->hex_counter);
            data->hex_counter = my_strdup(trim(line + 14));
            printf("Inicialny counter: %s\n", data->hex_counter);
            break;

        case BLOCK:
            *block_number = atoi(line + 7);
            break;

        case INPUT_BLOCK:
            value = my_strdup(trim(line + 12));
            if (*block_number >= 1 && *block_number <= MAX_TEST_VECTORS) {
                TestVector *target = data->is_encrypt_mode ? 
                    &data->encrypt_tests[*block_number-1] : 
                    &data->decrypt_tests[*block_number-1];
                strncpy(target->hex_input_block, value, 32);
                target->hex_input_block[32] = '\0';
                target->block_number = *block_number;
                if (data->is_encrypt_mode) {
                    if (*block_number > data->encrypt_test_count)
                        data->encrypt_test_count = *block_number;
                } else {
                    if (*block_number > data->decrypt_test_count)
                        data->decrypt_test_count = *block_number;
                }
            }
            free(value);
            break;

        case OUTPUT_BLOCK:
            value = my_strdup(trim(line + 13));
            if (*block_number >= 1 && *block_number <= MAX_TEST_VECTORS) {
                TestVector *target = data->is_encrypt_mode ? 
                    &data->encrypt_tests[*block_number-1] : 
                    &data->decrypt_tests[*block_number-1];
                strncpy(target->hex_output_block, value, 32);
                target->hex_output_block[32] = '\0';
            }
            free(value);
            break;

        case PLAINTEXT:
            value = my_strdup(trim(line + 10));
            if (*block_number >= 1 && *block_number <= MAX_TEST_VECTORS) {
                TestVector *target = data->is_encrypt_mode ? 
                    &data->encrypt_tests[*block_number-1] : 
                    &data->decrypt_tests[*block_number-1];
                strncpy(target->hex_plaintext, value, 64);
                target->hex_plaintext[64] = '\0';
            }
            free(value);
            break;

        case CIPHERTEXT:
            value = my_strdup(trim(line + 11));
            if (*block_number >= 1 && *block_number <= MAX_TEST_VECTORS) {
                TestVector *target = data->is_encrypt_mode ? 
                    &data->encrypt_tests[*block_number-1] : 
                    &data->decrypt_tests[*block_number-1];
                strncpy(target->hex_ciphertext, value, 64);
                target->hex_ciphertext[64] = '\0';
            }
            free(value);
            break;

        default:
            break;
    }
}

int main() {
    const char* test_vectors_file;
    const int aes_bits = 
        #if AES___ == 256
            256
        #elif AES___ == 192
            192
        #else
            128
        #endif
    ;

    test_vectors_file = 
        #if AES___ == 256
            "test_vectors/ctr_256.txt"
        #elif AES___ == 192
            "test_vectors/ctr_192.txt"
        #else
            "test_vectors/ctr_128.txt"
        #endif
    ;

    printf("Program skompilovany pre AES-%d CTR rezim\n", aes_bits);
    printf("Pouziva sa testovaci subor: %s\n", test_vectors_file);

    FILE *fp = fopen(test_vectors_file, "r");
    if (!fp) {
        perror("Nepodarilo sa otvorit subor s testovacimi vektormi");
        return 1;
    }

    TestCaseData data;
    init_test_case_data(&data);
    
    int block_number = 0;
    int test_count = 0, passed_count = 0;
    char line[MAX_LINE_LENGTH];
    uint8_t key[32];
    size_t key_size = aes_bits / 8;

    while (fgets(line, sizeof(line), fp)) {
        process_line(line, &data, &block_number, key, key_size);
    }
    fclose(fp);

    // Execute encryption tests
    printf("\n=== Testovanie sifrovania (Encrypt) ===\n");
    for (int i = 0; i < data.encrypt_test_count; i++) {
        process_test_vector(&data.encrypt_tests[i], key, true, &test_count, &passed_count);
    }

    // Execute decryption tests
    printf("\n=== Testovanie desifrovania (Decrypt) ===\n");
    for (int i = 0; i < data.decrypt_test_count; i++) {
        process_test_vector(&data.decrypt_tests[i], key, false, &test_count, &passed_count);
    }

    free_test_case_data(&data);
    printf("\nTestovanie CTR rezimu dokoncene: %d/%d uspesnych\n", 
           passed_count, test_count);

    return (passed_count == test_count) ? 0 : 1;
}