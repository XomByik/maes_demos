/************************************************************************
 * Nazov projektu: Demonštracia funkcnosti rezimov AES-u z kniznice micro-AES
 * -----------------------------------------------------------------------
 * Subor: cbc.h
 * Verzia: 1.1
 * Datum: 13.4.2025
 *
 * Autor: Kamil Berecky
 *
 * Popis: Hlavickovy subor pre CBC demo program. Definuje konstanty, 
 * datove struktury a prototypy funkcii pre testovanie rezimu AES-CBC 
 * pomocou oficialnych testovacich vektorov.
 * Vyuzite zdroje:
 * - micro-AES kniznica:
 * https://github.com/polfosol/micro-AES
 * - NIST SP 800-38A (2001):
 * https://doi.org/10.6028/NIST.SP.800-38A
 * 
 * Pre viac info pozri README.md
 ***********************************************************************/

#ifndef CBC_CONFIG_H
#define CBC_CONFIG_H

#include "../libs/micro_aes.h"
#include "common.h"

// Velkost buffera pre citanie riadkov z testovacieho suboru
#define CBC_LINE_BUFFER_SIZE 512   
// Maximalna velkost kluca v bajtoch (256 bitov)
#define AES_MAX_KEY_SIZE 32        
// Velkost IV v bajtoch (128 bitov)
#define IV_SIZE 16
// Velkost bloku AES v bajtoch (128 bitov)
#define BLOCK_SIZE 16

// Struktura pre uchovanie dat testovacieho vektora
typedef struct {
  int count;
  int block_number;
  char *hex_key;
  char *hex_iv;
  char *hex_plaintext;
  char *hex_ciphertext;
  bool is_encrypt;
} TestCaseData; 

// Typy riadkov v testovacom subore
typedef enum {
  KEY,
  IV,
  BLOCK,
  PLAINTEXT,
  CIPHERTEXT,
  MODE_CHANGE,
  UNKNOWN
} LineType;

//Deklaracie funkcii
void free_test_case_data(TestCaseData *data);
bool process_test_case(const TestCaseData *data, uint8_t *key, uint8_t *iv,
                       uint8_t *prev_ciphertext, int *passed_count,
                       bool *is_first_block);
bool parse_test_data(FILE *fp, TestCaseData *data, uint8_t *key,
                     uint8_t *iv, uint8_t *prev_ciphertext,
                     int *test_count, int *passed_count,
                     bool *is_first_block);

#endif // CBC_CONFIG_H