#ifndef XTS_CONFIG_H
#define XTS_CONFIG_H

#include "../libs/micro_aes.h"
#include "common.h"

#define XTS_LINE_BUFFER_SIZE 2048

typedef struct {
  int count;
  char *hex_key1;
  char *hex_key2;
  char *hex_tweak;
  char *hex_plaintext;
  char *hex_ciphertext;
  bool should_fail;
} TestCaseData;

// Function prototypes
void free_test_case_data(TestCaseData *data);
bool parse_next_test_case(FILE *fp, TestCaseData *data);
bool process_test_case(const TestCaseData *data, int *passed_count);

#endif