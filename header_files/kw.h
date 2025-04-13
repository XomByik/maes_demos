#ifndef KW_CONFIG_H
#define KW_CONFIG_H

#include "../libs/micro_aes.h"
#include "common.h"

#ifndef KW
#define KW 0
#endif

#define KW_LINE_BUFFER_SIZE 2048

typedef struct {
  int count;
  char *hex_key;
  char *hex_plaintext;
  char *hex_ciphertext;
  bool is_unwrap;
  bool should_fail;
} TestCaseData;

void free_test_case_data(TestCaseData *data);
bool parse_next_test_case(FILE *fp, TestCaseData *data, size_t *p_length,
                          bool is_unwrap_file);
bool process_test_case(const TestCaseData *data, int *passed_count);

#endif // KW_CONFIG_H