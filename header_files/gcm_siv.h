#ifndef GCM_SIV_CONFIG_H
#define GCM_SIV_CONFIG_H

#include "../libs/micro_aes.h"
#include "common.h"

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
bool process_test_case(const TestCaseData *data, int *passed_encrypt,
                       int *passed_decrypt);
void print_limited(const char *data, size_t limit);

#endif // GCM_SIV_CONFIG_H