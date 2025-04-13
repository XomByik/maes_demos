#ifndef OCB_CONFIG_H
#define OCB_CONFIG_H

#include "../libs/micro_aes.h"
#include "common.h"

#define OCB_LINE_BUFFER_SIZE 2048
#define OCB_TAG_LEN 16 // Standard OCB tag length is 128 bits (16 bytes)

typedef struct {
  int count;
  char *hex_key;
  char *hex_nonce;
  char *hex_aad;
  char *hex_plaintext;
  char *hex_ciphertext;
  char *hex_tag;
  bool should_fail;
} TestCaseData;

// Function prototypes
void free_test_case_data(TestCaseData *data);
bool parse_next_test_case(FILE *fp, TestCaseData *data);
bool process_test_case(const TestCaseData *data, int *passed_encrypt,
                       int *passed_decrypt);

#endif // OCB_CONFIG_H