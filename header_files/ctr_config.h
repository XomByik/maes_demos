#ifndef CTR_CONFIG_H
#define CTR_CONFIG_H

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include "libs/micro_aes.h"
#include "common.h"

#define MAX_LINE_LENGTH 512
#define MAX_TEST_VECTORS 10
#define MAX_BUFFER_SIZE 512
#define CTR_LINE_BUFFER_SIZE 2048

typedef enum {
    KEY,
    COUNTER,
    BLOCK,
    INPUT_BLOCK, 
    OUTPUT_BLOCK,
    PLAINTEXT,
    CIPHERTEXT,
    MODE_CHANGE,
    UNKNOWN
} LineType;

typedef struct {
    char hex_input_block[33];
    char hex_output_block[33];
    char hex_plaintext[65];
    char hex_ciphertext[65];
    int block_number;
} TestVector;

typedef struct {
    char *hex_key;
    char *hex_counter;
    TestVector encrypt_tests[MAX_TEST_VECTORS];
    TestVector decrypt_tests[MAX_TEST_VECTORS];
    int encrypt_test_count;
    int decrypt_test_count;
    bool is_encrypt_mode;
} TestCaseData;

void free_test_case_data(TestCaseData *data);
bool parse_next_test_case(FILE *fp, TestCaseData *data);
bool process_test_case(const TestCaseData *data, int *passed_encrypt, int *passed_decrypt);
void print_limited(const char* data, size_t limit);

#endif