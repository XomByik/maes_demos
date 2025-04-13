/************************************************************************
 * Nazov projektu: Demonštracia funkcnosti rezimov AES-u z kniznice micro-AES
 * -----------------------------------------------------------------------
 * Subor: ecb.h
 * Verzia: 1.1
 * Datum: 13.4.2025
 *
 * Autor: Kamil Berecky
 *
 * Popis: Hlavickovy subor pre ECB demo program. Definuje konstanty, 
 * datove struktury a prototypy funkcii pre testovanie rezimu AES-ECB 
 * pomocou oficialnych testovacich vektorov.
 * 
 * Vyuzite zdroje:
 * - micro-AES kniznica:
 *   https://github.com/polfosol/micro-AES
 * - NIST SP 800-38A (2001):
 *   https://doi.org/10.6028/NIST.SP.800-38A
 * 
 * Pre viac info pozri README.md
 ***********************************************************************/

#ifndef ECB_CONFIG_H
#define ECB_CONFIG_H

#include "../libs/micro_aes.h"
#include "common.h"

// Konstanty pre buffer a limity
#define ECB_LINE_BUFFER_SIZE 2048    // Velkost buffera pre citanie riadkov
#define ECB_MAX_LINE_LENGTH 75       // Maximalny pocet znakov pre vypis

// Konstanty pre velkosti blokov a klucov
#define ECB_BLOCK_SIZE 16            // Velkost bloku v bajtoch (128 bitov)
#define ECB_MAX_KEY_SIZE 32          // Maximalna velkost kluca v bajtoch (256 bitov)

// Nazvy testovacich suborov
#define ECB_TEST_VECTORS_128 "test_vectors/ecb_128.txt"    // Testovaci subor pre AES-128
#define ECB_TEST_VECTORS_192 "test_vectors/ecb_192.txt"    // Testovaci subor pre AES-192
#define ECB_TEST_VECTORS_256 "test_vectors/ecb_256.txt"    // Testovaci subor pre AES-256

// Prefixy pre parsovanie testovacich vektorov
#define ECB_PREFIX_KEY "Key"            // Prefix pre riadok s klucom
#define ECB_PREFIX_PLAINTEXT "Plaintext"   // Prefix pre riadok s plaintextom
#define ECB_PREFIX_CIPHERTEXT "Ciphertext" // Prefix pre riadok s ciphertextom
#define ECB_PREFIX_BLOCK "Block #"      // Prefix pre riadok s cislom bloku

// Dlzky prefixov pre parsovanie
#define ECB_PREFIX_LEN_KEY 3           // Dlzka prefixu "Key"
#define ECB_PREFIX_LEN_PLAINTEXT 9     // Dlzka prefixu "Plaintext"
#define ECB_PREFIX_LEN_CIPHERTEXT 10   // Dlzka prefixu "Ciphertext"
#define ECB_PREFIX_LEN_BLOCK 7         // Dlzka prefixu "Block #"

// Identifikatory pre zmenu modu
#define ECB_MODE_IDENTIFIER "ECB-AES"  // Retazec pre identifikaciu ECB modu
#define ECB_MODE_ENCRYPT "Encrypt"     // Retazec pre identifikaciu modu sifrovania

// Struktura pre testovacie data
typedef struct {
  int count;               // Cislo testu
  int block_number;        // Cislo bloku v testovacom vektore
  char *hex_key;           // Kluc v hex formate
  char *hex_plaintext;     // Plaintext v hex formate
  char *hex_ciphertext;    // Ciphertext v hex formate
  bool is_encrypt;         // Priznak ci ide o sifrovanie (true) alebo desifrovanie (false)
  bool should_fail;        // Priznak ci sa ocakava zlyhanie operacie
} TestCaseData;

// Prototypy funkcii
void free_test_case_data(TestCaseData *data);
bool parse_next_test_case(FILE *fp, TestCaseData *data);
bool process_test_case(const TestCaseData *data, int *passed_encrypt,
                       int *passed_decrypt);

#endif // ECB_CONFIG_H