#ifndef CCM_CONFIG_H
#define CCM_CONFIG_H

#include "../libs/micro_aes.h"
#include "common.h"
#include <stddef.h>

// --- Test Case Data Structure ---
typedef struct {
  int count;
  char *hex_nonce;
  char *hex_adata;
  char *hex_payload;
  char *hex_ct_tag; // Combined Ciphertext + Tag
} TestCaseData;

// --- File Format Constants ---
#define CCM_LINE_BUFFER_SIZE 1024

// Prefixes for parsing test vector file
#define CCM_PREFIX_ALEN "Alen = "
#define CCM_PREFIX_PLEN "Plen = "
#define CCM_PREFIX_NLEN "Nlen = "
#define CCM_PREFIX_TLEN "Tlen = "
#define CCM_PREFIX_KEY "Key = "
#define CCM_PREFIX_COUNT "Count = "
#define CCM_PREFIX_NONCE "Nonce = "
#define CCM_PREFIX_ADATA "Adata = "
#define CCM_PREFIX_PAYLOAD "Payload = "
#define CCM_PREFIX_CT "CT = "

// Runtime validation of compile-time parameters
#ifndef CCM_NONCE_LEN
#define CCM_NONCE_LEN 7
#endif

#ifndef CCM_TAG_LEN
#define CCM_TAG_LEN 16
#endif

#define CCM_DEMO_NONCE_LEN ((size_t)CCM_NONCE_LEN)
#define CCM_DEMO_TAG_LEN ((size_t)CCM_TAG_LEN)

// --- Function Declarations ---
void free_test_case_data(TestCaseData *data);
bool parse_header(FILE *fp, size_t *Alen, size_t *Plen);
bool parse_initial_key(FILE *fp, uint8_t *key, int key_size_bytes);
bool parse_next_test_case(FILE *fp, TestCaseData *data, uint8_t *key,
                          int key_size_bytes);
bool process_test_case(int test_num, const uint8_t *key,
                       const TestCaseData *data, size_t Alen, size_t Plen,
                       int *passed_encrypt, int *passed_decrypt);
void print_limited(const char *data, size_t limit);

#endif // CCM_CONFIG_H