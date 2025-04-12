#ifndef OFB_CONFIG_H
#define OFB_CONFIG_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "libs/micro_aes.h"
#include "common.h"

// Konfiguračné konštanty
#define OFB_LINE_BUFFER_SIZE 512
#define OFB_MAX_BLOCKS 10
#define OFB_HEX_BUFFER_SIZE 65
#define OFB_MAX_DATA_SIZE 512

// Štruktúra pre testovací vektor
typedef struct {
    char hex_input_block[OFB_HEX_BUFFER_SIZE];
    char hex_output_block[OFB_HEX_BUFFER_SIZE];
    char hex_plaintext[OFB_HEX_BUFFER_SIZE];
    char hex_ciphertext[OFB_HEX_BUFFER_SIZE];
    int block_number;
} TestVector;

// Deklarácie funkcií
void free_test_case_data(TestVector *test);
void generate_keystream(uint8_t* key, uint8_t* iv, uint8_t* keystream);
bool parse_test_vectors(FILE *fp, TestVector encrypt_tests[], TestVector decrypt_tests[], 
                    int *encrypt_test_count, int *decrypt_test_count, uint8_t *key);
bool process_ofb_test_case(uint8_t *key, TestVector *test, int *passed_count, int test_count, bool is_encrypt);
void AES_OFB_encrypt(const uint8_t* key, const uint8_t iVec[16], 
                    const void* pntxt, const size_t ptextLen, void* crtxt);

#endif // OFB_CONFIG_H