/************************************************************************
 * Nazov projektu: Demonštracia funkcnosti rezimov AES-u z kniznice micro-AES
 * -----------------------------------------------------------------------
 * Subor: gcm.h
 * Verzia: 1.1
 * Datum: 13.4.2025
 *
 * Autor: Kamil Berecky
 *
 * Popis: Hlavickovy subor pre GCM demo program. Definuje konstanty, 
 * datove struktury a prototypy funkcii pre testovanie rezimu AES-GCM 
 * pomocou oficialnych testovacich vektorov.
 * 
 * Vyuzite zdroje:
 * - micro-AES kniznica:
 *   https://github.com/polfosol/micro-AES
 * - NIST SP 800-38D (2011):
 *   https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
 * 
 * Pre viac info pozri README.md
 ***********************************************************************/

 #ifndef GCM_CONFIG_H
 #define GCM_CONFIG_H
 
 #include "../libs/micro_aes.h"
 #include "common.h"
 
 // Konstanty pre buffer a limity
 #define GCM_LINE_BUFFER_SIZE 2048    // Velkost buffera pre citanie riadkov
 #define GCM_MAX_LINE_LENGTH 75       // Maximalny pocet znakov pre vypis
 
 // Prefixy pre parsovanie testovacich vektorov
 #define GCM_PREFIX_KEY "Key = "            // Prefix pre riadok s klucom
 #define GCM_PREFIX_IV "IV = "              // Prefix pre riadok s inicializacnym vektorom
 #define GCM_PREFIX_AAD "AAD = "            // Prefix pre riadok s pridanymi autentifikacnymi datami
 #define GCM_PREFIX_PT "PT = "              // Prefix pre riadok s plaintextom
 #define GCM_PREFIX_CT "CT = "              // Prefix pre riadok s ciphertextom
 #define GCM_PREFIX_TAG "Tag = "            // Prefix pre riadok s tagom
 #define GCM_PREFIX_COUNT "Count = "        // Prefix pre riadok s cislom testu
 #define GCM_PREFIX_FAIL "FAIL"             // Prefix pre riadok indikujuci ocakavane zlyhanie
 
 // Nazvy testovacich suborov pre rozne velkosti klucov a nonce
 #define GCM_TEST_VECTORS_128 "test_vectors/gcm_128.txt"    // Testovaci subor pre AES-128 so standardnym nonce
 #define GCM_TEST_VECTORS_192 "test_vectors/gcm_192.txt"    // Testovaci subor pre AES-192 so standardnym nonce
 #define GCM_TEST_VECTORS_256 "test_vectors/gcm_256.txt"    // Testovaci subor pre AES-256 so standardnym nonce
 #define GCM_TEST_VECTORS_1024_128 "test_vectors/gcm1024_128.txt"   // Testovaci subor pre AES-128 s 1024-bitovym nonce
 #define GCM_TEST_VECTORS_1024_192 "test_vectors/gcm1024_192.txt"   // Testovaci subor pre AES-192 s 1024-bitovym nonce
 #define GCM_TEST_VECTORS_1024_256 "test_vectors/gcm1024_256.txt"   // Testovaci subor pre AES-256 s 1024-bitovym nonce
 
 // Struktura pre testovacie data
 typedef struct {
   int count;                 // Cislo testu
   char *hex_key;             // Kluc v hex formate
   char *hex_iv;              // Inicializacny vektor v hex formate
   char *hex_aad;             // Pridane autentifikacne data v hex formate
   char *hex_plaintext;       // Plaintext v hex formate
   char *hex_ciphertext;      // Ciphertext v hex formate
   char *hex_tag;             // Autentifikacny tag v hex formate
   bool is_decrypt;           // Priznak ci ide o desiforvaci test
   bool should_fail;          // Priznak ci sa ocakava zlyhanie autentifikacie
 } TestCaseData;
 
 // Prototypy funkcii
 void free_test_case_data(TestCaseData *data);
 bool parse_next_test_case(FILE *fp, TestCaseData *data);
 bool process_test_case(const TestCaseData *data, int *passed_encrypt,
                        int *passed_decrypt);
 
 #endif // GCM_CONFIG_H