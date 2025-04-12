#ifndef ECB_CONFIG_H
#define ECB_CONFIG_H

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "libs/micro_aes.h"
#include "common.h"

#define ECB_LINE_BUFFER_SIZE 2048
#define MAX_LINE_LENGTH 75

typedef struct {
    int count;
    int block_number;
    char *hex_key;
    char *hex_plaintext;
    char *hex_ciphertext;
    bool is_encrypt;
    bool should_fail;
} TestCaseData;

void free_test_case_data(TestCaseData *data);
bool parse_next_test_case(FILE *fp, TestCaseData *data);
bool process_test_case(const TestCaseData *data, int *passed_encrypt, int *passed_decrypt);

#endif