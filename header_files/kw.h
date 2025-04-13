/************************************************************************
 * Nazov projektu: Demonštracia funkcnosti rezimov AES-u z kniznice micro-AES
 * -----------------------------------------------------------------------
 * Subor: kw.h
 * Verzia: 1.1
 * Datum: 13.4.2025
 *
 * Autor: Kamil Berecky
 *
 * Popis: Hlavickovy subor pre KW demo program. Definuje konstanty, 
 * datove struktury a prototypy funkcii pre testovanie rezimu AES-KW 
 * (Key Wrap) pomocou oficialnych testovacich vektorov.
 * 
 * Vyuzite zdroje:
 * - micro-AES kniznica: 
 *   https://github.com/polfosol/micro-AES
 * - Cryptographic Algorithm Validation Program (CAVP):
 *   https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/cavp-testing-block-cipher-modes#KW
 * 
 * Pre viac info pozri README.md
 ***********************************************************************/

#ifndef KW_CONFIG_H
#define KW_CONFIG_H

#include "../libs/micro_aes.h"
#include "common.h"

// Konstanty pre buffer a limity
#define KW_LINE_BUFFER_SIZE 2048      // Velkost buffra pre citanie riadkov
#define KW_MAX_LINE_LENGTH 75         // Maximalny pocet znakov pre vypis

// Nazvy testovacich suborov
#define KW_AE_TEST_VECTORS_128 "test_vectors/kw_ae_128.txt"  // Test vektory pre AES-128 Wrap
#define KW_AE_TEST_VECTORS_192 "test_vectors/kw_ae_192.txt"  // Test vektory pre AES-192 Wrap
#define KW_AE_TEST_VECTORS_256 "test_vectors/kw_ae_256.txt"  // Test vektory pre AES-256 Wrap
#define KW_AD_TEST_VECTORS_128 "test_vectors/kw_ad_128.txt"  // Test vektory pre AES-128 Unwrap
#define KW_AD_TEST_VECTORS_192 "test_vectors/kw_ad_192.txt"  // Test vektory pre AES-192 Unwrap
#define KW_AD_TEST_VECTORS_256 "test_vectors/kw_ad_256.txt"  // Test vektory pre AES-256 Unwrap

// Prefixy pre parsovanie testovacich vektorov
#define KW_PREFIX_COUNT "COUNT = "              // Prefix pre cislo testu
#define KW_PREFIX_KEY "K = "                    // Prefix pre kluc
#define KW_PREFIX_PLAINTEXT "P = "              // Prefix pre plaintext
#define KW_PREFIX_CIPHERTEXT "C = "             // Prefix pre ciphertext
#define KW_PREFIX_PLAINTEXT_LEN "[PLAINTEXT LENGTH = "  // Prefix pre dlzku plaintextu
#define KW_PREFIX_FAIL "FAIL"                   // Prefix pre oznacenie ocakavaneho zlyhania

// Struktura pre testovacie data
typedef struct {
  int count;                // Cislo testu
  char *hex_key;            // Kluc v hex formate
  char *hex_plaintext;      // Plaintext v hex formate
  char *hex_ciphertext;     // Ciphertext v hex formate
  bool is_unwrap;           // Priznak ci ide o unwrap test
  bool should_fail;         // Priznak ci sa ocakava zlyhanie
} TestCaseData;

// Prototypy funkcii
void free_test_case_data(TestCaseData *data);
bool parse_next_test_case(FILE *fp, TestCaseData *data, size_t *p_length, bool is_unwrap_file);
bool process_test_case(const TestCaseData *data, int *passed_count);

#endif // KW_CONFIG_H