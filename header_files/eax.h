/************************************************************************
 * Nazov projektu: Demonštracia funkcnosti rezimov AES-u z kniznice micro-AES
 * -----------------------------------------------------------------------
 * Subor: eax.h
 * Verzia: 1.1
 * Datum: 13.4.2025
 *
 * Autor: Kamil Berecky
 *
 * Popis: Hlavickovy subor pre EAX demo program. Definuje konstanty, 
 * datove struktury a prototypy funkcii pre testovanie rezimu AES-EAX 
 * pomocou oficialnych testovacich vektorov.
 * 
 * Vyuzite zdroje:
 * - micro-AES kniznica:
 *   https://github.com/polfosol/micro-AES
 * - EAX specifikacia:
 *   https://csrc.nist.gov/publications/detail/sp/800-38d/final
 * 
 * Pre viac info pozri README.md
 ***********************************************************************/

 #ifndef EAX_CONFIG_H
 #define EAX_CONFIG_H
 
 #include "../libs/micro_aes.h"
 #include "common.h"
 
 // Konstanty pre buffers a limity
 #define EAX_LINE_BUFFER_SIZE 2048    // Velkost buffra pre citanie riadkov
 #define EAX_MAX_LINE_LENGTH 75       // Maximalny pocet znakov pre vypis
 
 // Konstanty pre velkosti a formaty dat
 #define EAX_TAG_LENGTH_BYTES 16      // Velkost tagu v bajtoch
 #define EAX_TAG_LENGTH_HEX 32        // Velkost tagu v hex formate (2 znaky na bajt)
 #define EAX_MIN_TAG_LENGTH_HEX 32    // Minimalna dlzka CIPHER retazca pre obsahovanie tagu
 
 // Nazvy testovacich suborov
 #define EAX_TEST_VECTORS_FILE "test_vectors/eax_128.txt"
 
 // Prefixy pre identifikaciu typu riadku v testovacom subore
 #define EAX_PREFIX_KEY "KEY:"
 #define EAX_PREFIX_NONCE "NONCE:"
 #define EAX_PREFIX_HEADER "HEADER:"
 #define EAX_PREFIX_MSG "MSG:"
 #define EAX_PREFIX_CIPHER "CIPHER:"
 #define EAX_PREFIX_COUNT "Count = "
 #define EAX_PREFIX_FAIL "FAIL"
 
 // Struktura pre testovacie data
 typedef struct {
   int count;            // Cislo testu
   char *key_hex;        // Kluc v hex formate
   char *nonce_hex;      // Nonce v hex formate
   char *header_hex;     // Hlavicka (AAD) v hex formate
   char *pt_hex;         // Plaintext v hex formate
   char *ct_hex;         // Ciphertext v hex formate
   char *tag_hex;        // Tag v hex formate
   bool should_fail;     // Priznak ci sa ocakava zlyhanie (tag neplatny)
 } TestCaseData;
 
 // Deklaracie funkcii
 void free_test_case_data(TestCaseData *data);
 bool parse_next_test_case(FILE *fp, TestCaseData *data);
 bool process_test_case(const TestCaseData *data, int *passed_encrypt,
                        int *passed_decrypt);
 
 #endif // EAX_CONFIG_H