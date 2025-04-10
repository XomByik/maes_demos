#ifndef GCM_CONFIG_H
#define GCM_CONFIG_H

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libs/micro_aes.h"
#include "common.h"

#define GCM_LINE_BUFFER_SIZE 2048

typedef struct {
    int count;
    char *hex_key;
    char *hex_iv;
    char *hex_aad;
    char *hex_plaintext;
    char *hex_ciphertext;
    char *hex_tag;
    bool is_decrypt;    // true if CT comes first, false if PT comes first
    bool should_fail;   // true if FAIL flag present for decrypt tests
} TestCaseData;

void free_test_case_data(TestCaseData *data);
bool parse_next_test_case(FILE *fp, TestCaseData *data);
bool process_test_case(const TestCaseData *data, int *passed_encrypt, int *passed_decrypt);

#endif