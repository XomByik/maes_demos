/************************************************************************
 * Nazov projektu: Demonštracia funkcnosti rezimov AES-u z kniznice micro-AES
 * -----------------------------------------------------------------------
 * Subor: ofb.h
 * Verzia: 1.1
 * Datum: 13.4.2025
 *
 * Autor: Kamil Berecky
 *
 * Popis: Hlavickovy subor pre OFB demo program. Definuje konstanty, 
 * datove struktury a prototypy funkcii pre testovanie rezimu AES-OFB 
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

 #ifndef OFB_CONFIG_H
 #define OFB_CONFIG_H
 
 #include "../libs/micro_aes.h"
 #include "common.h"
 
 // Konstanty pre buffer a limity
 #define OFB_LINE_BUFFER_SIZE 2048     // Velkost buffera pre citanie riadkov
 #define OFB_MAX_LINE_LENGTH 75        // Maximalny pocet znakov pre vypis
 
 // Konstanty pre velkosti blokov a dat
 #define OFB_BLOCK_SIZE 16             // Velkost bloku v bajtoch (128 bitov)
 #define OFB_MAX_DATA_SIZE 128         // Maximalna velkost dat v bajtoch
 #define OFB_HEX_BUFFER_SIZE 256       // Velkost buffra pre hexadecimalne retazce
 #define OFB_MAX_BLOCKS 20             // Maximalny pocet testovanych blokov
 
 // Nazvy testovacich suborov
 #define OFB_TEST_VECTORS_128 "test_vectors/ofb_128.txt"  // Testovaci subor pre AES-128
 #define OFB_TEST_VECTORS_192 "test_vectors/ofb_192.txt"  // Testovaci subor pre AES-192
 #define OFB_TEST_VECTORS_256 "test_vectors/ofb_256.txt"  // Testovaci subor pre AES-256
 
 // Prefixy pre parsovanie testovacich vektorov
 #define OFB_PREFIX_KEY "Key"                  // Prefix pre riadok s klucom
 #define OFB_PREFIX_IV "IV"                    // Prefix pre riadok s IV
 #define OFB_PREFIX_BLOCK "Block #"            // Prefix pre riadok s cislom bloku
 #define OFB_PREFIX_INPUT_BLOCK "Input Block"  // Prefix pre vstupny blok
 #define OFB_PREFIX_OUTPUT_BLOCK "Output Block" // Prefix pre vystupny blok
 #define OFB_PREFIX_PLAINTEXT "Plaintext"      // Prefix pre plaintext
 #define OFB_PREFIX_CIPHERTEXT "Ciphertext"    // Prefix pre ciphertext
 
 // Dlzky prefixov pre parsovanie
 #define OFB_PREFIX_LEN_KEY 3           // Dlzka prefixu "Key"
 #define OFB_PREFIX_LEN_IV 2            // Dlzka prefixu "IV"
 #define OFB_PREFIX_LEN_BLOCK 7         // Dlzka prefixu "Block #"
 #define OFB_PREFIX_LEN_INPUT 11        // Dlzka prefixu "Input Block"
 #define OFB_PREFIX_LEN_OUTPUT 12       // Dlzka prefixu "Output Block"
 #define OFB_PREFIX_LEN_PLAINTEXT 9     // Dlzka prefixu "Plaintext"
 #define OFB_PREFIX_LEN_CIPHERTEXT 10   // Dlzka prefixu "Ciphertext"
 
 // Identifikatory pre zmenu modu
 #define OFB_MODE_IDENTIFIER "OFB"      // Retazec pre identifikaciu OFB modu
 #define OFB_MODE_ENCRYPT "Encrypt"     // Retazec pre identifikaciu modu sifrovania
 #define OFB_MODE_DECRYPT "Decrypt"     // Retazec pre identifikaciu modu desifrovania
 
 // Definicia hodnot pre mod spracovania
 #define OFB_MODE_UNDEFINED 0           // Nedefinovany mod
 #define OFB_MODE_ENCRYPTION 1          // Mod sifrovania
 #define OFB_MODE_DECRYPTION 2          // Mod desifrovania
 
 // Struktura pre testovaci vektor
 typedef struct {
   int block_number;                         // Cislo bloku v testovacom vektore
   char hex_input_block[OFB_HEX_BUFFER_SIZE];  // Vstupny blok v hex formate (IV)
   char hex_output_block[OFB_HEX_BUFFER_SIZE]; // Vystupny blok v hex formate
   char hex_plaintext[OFB_HEX_BUFFER_SIZE];    // Plaintext v hex formate
   char hex_ciphertext[OFB_HEX_BUFFER_SIZE];   // Ciphertext v hex formate
 } TestVector;
 
 // Prototypy funkcii
 void free_test_case_data(TestVector *test);
 void generate_keystream(uint8_t *key, uint8_t *iv, uint8_t *keystream);
 bool parse_test_vectors(FILE *fp, TestVector encrypt_tests[],
                         TestVector decrypt_tests[],
                         int *encrypt_test_count, int *decrypt_test_count,
                         uint8_t *key);
 bool process_ofb_test_case(uint8_t *key, TestVector *test,
                            int *passed_count, int test_count,
                            bool is_encrypt);
 
 #endif // OFB_CONFIG_H