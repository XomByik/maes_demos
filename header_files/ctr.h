/************************************************************************
 * Nazov projektu: Demonštracia funkcnosti rezimov AES-u z kniznice micro-AES
 * -----------------------------------------------------------------------
 * Subor: ctr.h
 * Verzia: 1.1
 * Datum: 13.4.2025
 *
 * Autor: Kamil Berecky
 *
 * Popis: Hlavickovy subor pre CTR demo program. Definuje konstanty, 
 * datove struktury a prototypy funkcii pre testovanie rezimu AES-CTR 
 * pomocou oficialnych testovacich vektorov.
 * 
 * Vyuzite zdroje:
 * - micro-AES kniznica:
 * https://github.com/polfosol/micro-AES
 * - NIST SP 800-38A (2001):
 * https://doi.org/10.6028/NIST.SP.800-38A
 * 
 * Pre viac info pozri README.md
 ***********************************************************************/

 #ifndef CTR_CONFIG_H
 #define CTR_CONFIG_H
 
 #include "../libs/micro_aes.h"
 #include "common.h"
 #include <stdio.h>
 #include <string.h>
 #include <stdbool.h>
 
 // Velkost buffera pre citanie riadkov z testovacieho suboru
 #define CTR_MAX_LINE_LENGTH 512
 
 // Velkost bloku AES v bajtoch (128 bitov)
 #define CTR_BLOCK_SIZE 16
 
 // Maximalna velkost kluca v bajtoch (256 bitov)
 #define CTR_MAX_KEY_SIZE 32
 
 // Maximalna velkost buffera pre data
 #define CTR_MAX_BUFFER_SIZE 128
 
 // Maximalny pocet testovacich vektorov
 #define CTR_MAX_TEST_VECTORS 100
 
 // Dlzky hexadecimalnych retazcov
 #define CTR_INPUT_BLOCK_HEX_LEN 32  // 16 bajtov = 32 hex znakov pre vstupny blok
 #define CTR_OUTPUT_BLOCK_HEX_LEN 32 // 16 bajtov = 32 hex znakov pre vystupny blok
 #define CTR_PLAINTEXT_HEX_LEN 64    // Maximalna dlzka plaintextu v hex formate
 #define CTR_CIPHERTEXT_HEX_LEN 64   // Maximalna dlzka ciphertextu v hex formate
 
 // Dlzky prefixov v testovacich suboroch
 #define CTR_PREFIX_LEN_KEY 4        // "Key "
 #define CTR_PREFIX_LEN_COUNTER 14   // "Init. Counter "
 #define CTR_PREFIX_LEN_BLOCK 7      // "Block # "
 #define CTR_PREFIX_LEN_INPUT 12     // "Input Block "
 #define CTR_PREFIX_LEN_OUTPUT 13    // "Output Block "
 #define CTR_PREFIX_LEN_PLAINTEXT 10 // "Plaintext "
 #define CTR_PREFIX_LEN_CIPHERTEXT 11 // "Ciphertext "
 
 // Typ riadku v testovacom subore
 typedef enum {
   KEY,           // Riadok s klucom
   COUNTER,       // Riadok s pociatocnou hodnotou counteru
   BLOCK,         // Riadok oznacujuci cislo bloku
   INPUT_BLOCK,   // Riadok so vstupnym blokom
   OUTPUT_BLOCK,  // Riadok s vystupnym blokom
   PLAINTEXT,     // Riadok s plaintextom
   CIPHERTEXT,    // Riadok s ciphertextom
   MODE_CHANGE,   // Riadok oznacujuci zmenu modu (encrypt/decrypt)
   UNKNOWN        // Neznamy typ riadku
 } LineType;
 
 // Struktura pre jeden testovaci vektor
 typedef struct {
   int block_number;                                  // Cislo bloku
   char hex_input_block[CTR_INPUT_BLOCK_HEX_LEN + 1]; // Vstupny blok (counter) v hex formate
   char hex_output_block[CTR_OUTPUT_BLOCK_HEX_LEN + 1]; // Vystupny blok v hex formate
   char hex_plaintext[CTR_PLAINTEXT_HEX_LEN + 1];     // Plaintext v hex formate
   char hex_ciphertext[CTR_CIPHERTEXT_HEX_LEN + 1];   // Ciphertext v hex formate
 } TestVector;
 
 // Struktura pre uchovanie vsetkych testovacich dat
 typedef struct {
   char *hex_key;                                          // Kluc v hex formate
   char *hex_counter;                                      // Pociatocny counter v hex formate
   TestVector encrypt_tests[CTR_MAX_TEST_VECTORS];         // Testovacie vektory pre sifrovanie
   TestVector decrypt_tests[CTR_MAX_TEST_VECTORS];         // Testovacie vektory pre desifrovanie
   int encrypt_test_count;                                // Pocet testov sifrovania
   int decrypt_test_count;                                // Pocet testov desifrovania
   bool is_encrypt_mode;                                  // Priznak ci ide o sifrovacie alebo desifovacie testy
 } TestCaseData;
 
 // Prototypy funkcii
 void free_test_case_data(TestCaseData *data);
 
 #endif // CTR_CONFIG_H