#ifndef FPE_CONFIG_H
#define FPE_CONFIG_H

#include "../libs/micro_aes.h"
#include "common.h"

#define FPE_LINE_BUFFER_SIZE 1024

// Kontrola FF_X (musí byť definované pri kompilácii)
#ifndef FF_X
#error                                                                    \
    "FF_X macro (1 for FF1, 3 for FF3-1) must be defined during compilation."
#endif

#if FF_X != 1 && FF_X != 3
#error "Invalid value for FF_X. Must be 1 or 3."
#endif

// Štruktúra pre FPE testovací prípad
typedef struct {
  int count;
  char *count_str;
  char *method_str;
  char *alphabet_str;
  char *hex_key;
  char *hex_tweak;
  char *pt_str;
  char *expected_ct_str;
} TestCaseData;

void free_test_case_data(TestCaseData *data);
bool parse_next_test_case(FILE *fp, TestCaseData *data);
bool process_test_case(const TestCaseData *data, int *passed_encrypt,
                       int *passed_decrypt);

#endif // FPE_CONFIG_H