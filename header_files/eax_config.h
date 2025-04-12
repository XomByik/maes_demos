#ifndef EAX_CONFIG_H
#define EAX_CONFIG_H

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "libs/micro_aes.h"
#include "common.h"

#define EAX_LINE_BUFFER_SIZE 2048
#define MAX_LINE_LENGTH 75
typedef struct {
    int count;
    char *key_hex;
    char *nonce_hex;
    char *header_hex;
    char *pt_hex;
    char *ct_hex;
    char *tag_hex;
    bool should_fail;
} TestCaseData;

// Function prototypes
void free_test_case_data(TestCaseData *data);
bool parse_next_test_case(FILE *fp, TestCaseData *data);
bool process_test_case(const TestCaseData *data, int *passed_encrypt, int *passed_decrypt);

// Helper function pre konverziu hex na binárne dáta
int hex_to_bin(const char *hex, uint8_t *bin, size_t bin_len);

// Pomocná funkcia pre duplikáciu reťazcov
char* my_strdup(const char* s);

// Pomocná funkcia pre odstránenie bielych znakov
char* trim(char* str);

#endif