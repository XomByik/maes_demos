#ifndef CBC_CONFIG_H
#define CBC_CONFIG_H

#include <stdint.h>
#include <stdbool.h>

#define CBC_LINE_BUFFER_SIZE 512

typedef struct {
    int count;
    int block_number;
    char *hex_key;
    char *hex_iv;
    char *hex_plaintext;
    char *hex_ciphertext;
    bool is_encrypt;
} TestCaseData;

typedef enum {
    KEY, IV, BLOCK, PLAINTEXT, CIPHERTEXT, MODE_CHANGE, UNKNOWN
} LineType;

void free_test_case_data(TestCaseData *data);
bool process_test_case(const TestCaseData *data, uint8_t* key, uint8_t* iv, uint8_t* prev_ciphertext, 
    int* passed_count, bool* is_first_block);
bool parse_test_data(FILE *fp, TestCaseData *data, uint8_t *key, uint8_t *iv, uint8_t *prev_ciphertext,
    int *test_count, int *passed_count, bool *is_first_block);

#endif // CBC_CONFIG_H