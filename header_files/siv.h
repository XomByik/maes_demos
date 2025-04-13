#ifndef SIV_CONFIG_H
#define SIV_CONFIG_H

#include "../libs/micro_aes.h"
#include "common.h"

#define SIV_TAG_LEN 16
#define SIV_LINE_BUFFER_SIZE 1024

typedef struct {
  int count;
  char *hex_key;
  char *hex_ad; // Associated Data pre SIV
  char *hex_plaintext;
  char *hex_expected_iv; // Očakávaný IV (tag) pre SIV
  char *hex_expected_ct; // Očakávaný ciphertext
  bool is_decrypt;
  bool should_fail;
} TestCaseData;

// Funkcie pre AES-SIV
// Upravené deklarácie podľa micro_aes.h
extern char AES_SIV_decrypt(const uint8_t *key, const uint8_t iv[16],
                            const uint8_t *ctext, size_t ctextLen,
                            const uint8_t *aData, size_t aDataLen,
                            uint8_t *ptext);

extern void AES_SIV_encrypt(const uint8_t *key, const uint8_t *ptext,
                            size_t ptextLen, const uint8_t *aData,
                            size_t aDataLen, uint8_t iv[16],
                            uint8_t *ctext);

// Funkcie pre spracovanie testov
void free_test_case_data(TestCaseData *data);
bool parse_test_vector(TestCaseData *data);
bool process_test_case(const TestCaseData *data, int *passed_encrypt,
                       int *passed_decrypt);
void remove_spaces(char *str);

#endif // SIV_CONFIG_H