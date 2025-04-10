#ifndef GCM_SIV_CONFIG_H
#define GCM_SIV_CONFIG_H

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libs/micro_aes.h"
#include "common.h" // Assuming common functions like hex_to_bin, print_hex, trim, my_strdup are here

#define GCM_SIV_LINE_BUFFER_SIZE 2048
#define GCM_SIV_TAG_LEN 16
#define GCM_SIV_NONCE_LEN 12

typedef struct {
    int count;
    char *hex_key;
    char *hex_nonce; // GCM-SIV uses Nonce
    char *hex_aad;
    char *hex_plaintext;
    char *hex_ciphertext; // Derived from combined CT field
    char *hex_tag;        // Derived from combined CT field
} TestCaseData;

// Function prototypes
void free_test_case_data(TestCaseData *data);
bool parse_next_test_case(FILE *fp, TestCaseData *data);
bool process_test_case(const TestCaseData *data, int *passed_encrypt, int *passed_decrypt);
void print_limited(const char* data, size_t limit);

#endif // GCM_SIV_CONFIG_H