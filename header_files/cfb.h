/************************************************************************
 * Nazov projektu: Demonštracia funkcnosti rezimov AES-u z kniznice micro-AES
 * -----------------------------------------------------------------------
 * Subor: cfb.h
 * Verzia: 1.1
 * Datum: 13.4.2025
 *
 * Autor: Kamil Berecky
 *
 * Popis: Hlavickovy subor pre CFB demo program. Definuje konstanty, 
 * datove struktury a prototypy funkcii pre testovanie rezimu AES-CFB 
 * pomocou oficialnych testovacich vektorov. Podporuje tri varianty CFB:
 * 1-bit, 8-bit a 128-bit.
 * 
 * Vyuzite zdroje:
 * - micro-AES kniznica:
 * https://github.com/polfosol/micro-AES
 * - NIST SP 800-38A (2001):
 * https://doi.org/10.6028/NIST.SP.800-38A
 * 
 * Pre viac info pozri README.md
 ***********************************************************************/

 #ifndef CFB_CONFIG_H
 #define CFB_CONFIG_H
 
 #include "../libs/micro_aes.h"
 #include "common.h"
 #include <stdio.h>
 
 // Velkost buffera pre citanie riadkov z testovacieho suboru
 #define CFB_LINE_BUFFER_SIZE 512
 
 // Velkost bloku AES v bajtoch (128 bitov)
 #define CFB_BLOCK_SIZE 16
 
 // Maximalna velkost kluca v bajtoch (256 bitov)
 #define CFB_MAX_KEY_SIZE 32
 
 // Velkost segmentu v bitoch
 #define CFB_SEGMENT_SIZE_1BIT     1
 #define CFB_SEGMENT_SIZE_8BIT     8
 #define CFB_SEGMENT_SIZE_128BIT   128
 
 // Pocet variantov CFB modu
 #define CFB_MODE_VARIANTS_COUNT   3
 
 // Prefixove retazce pre identifikaciu testovacich suborov
 #define CFB_FILE_PREFIX_1BIT     "cfb1_"
 #define CFB_FILE_PREFIX_8BIT     "cfb8_"
 #define CFB_FILE_PREFIX_128BIT   "cfb"
 
 // Identifikatory typov riadkov v testovacom subore
 #define CFB_PREFIX_KEY          "Key"          // Dlzka: 3
 #define CFB_PREFIX_IV           "IV"           // Dlzka: 2
 #define CFB_PREFIX_SEGMENT      "Segment #"    // Dlzka: 9
 #define CFB_PREFIX_INPUT_BLOCK  "Input Block"  // Dlzka: 11
 #define CFB_PREFIX_OUTPUT_BLOCK "Output Block" // Dlzka: 12
 #define CFB_PREFIX_PLAINTEXT    "Plaintext"    // Dlzka: 9
 #define CFB_PREFIX_CIPHERTEXT   "Ciphertext"   // Dlzka: 10
 
 // Dlzky identifikatorov pre preskakanie prefixov
 #define CFB_PREFIX_LEN_KEY           4  // "Key " 
 #define CFB_PREFIX_LEN_IV            3  // "IV "
 #define CFB_PREFIX_LEN_SEGMENT       9  // "Segment #"
 #define CFB_PREFIX_LEN_INPUT_BLOCK  12  // "Input Block "
 #define CFB_PREFIX_LEN_OUTPUT_BLOCK 12  // "Output Block "
 #define CFB_PREFIX_LEN_PLAINTEXT     9  // "Plaintext "
 #define CFB_PREFIX_LEN_CIPHERTEXT   10  // "Ciphertext "
 
 // Struktura pre uchovanie dat testovacieho vektora
 typedef struct {
   int count;                // Cislo aktualneho testu
   char *hex_key;            // Kluc v hexadecimalnom formate
   char *hex_iv;             // Inicializacny vektor v hexadecimalnom formate
   char *hex_input_block;    // Vstupny blok v hexadecimalnom formate
   char *hex_output_block;   // Vystupny blok v hexadecimalnom formate
   char *plaintext_str;      // Plaintext v hexadecimalnom formate
   char *ciphertext_str;     // Ciphertext v hexadecimalnom formate
   int segment_size;         // Velkost segmentu (1, 8, 128 bitov)
   int segment_number;       // Cislo segmentu v aktualnom testovacom vektore
   bool is_encrypt;          // Priznak ci ide o sifrovanie (true) alebo desifrovanie (false)
 } TestCaseData;
 
 // Typy riadkov v testovacom subore
 typedef enum {
   KEY,            // Riadok s klucom
   IV,             // Riadok s inicializacnym vektorom
   SEGMENT,        // Riadok s cislom segmentu
   INPUT_BLOCK,    // Riadok so vstupnym blokom
   OUTPUT_BLOCK,   // Riadok s vystupnym blokom
   PLAINTEXT,      // Riadok s plaintextom
   CIPHERTEXT,     // Riadok s ciphertextom
   MODE_CHANGE,    // Riadok oznacujuci zmenu modu (encrypt/decrypt)
   UNKNOWN         // Neznamy typ riadku
 } LineType;
 
 // Deklaracie funkcii
 void free_test_case_data(TestCaseData *data);
 void process_cfb(uint8_t *key, uint8_t *iv, const void *input,
                  void *output, int segment_size, bool encrypt);
 bool process_test_case(const TestCaseData *data, uint8_t *key, uint8_t *iv,
                        int *passed_count);
 bool parse_test_data(FILE *fp, TestCaseData *data, uint8_t *key,
                      uint8_t *iv, uint8_t *original_iv, int *test_count,
                      int *passed_count, int segment_size,
                      bool *first_segment_in_file);
 
 #endif // CFB_CONFIG_H