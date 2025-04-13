/************************************************************************
 * Nazov projektu: Demonštracia funkcnosti rezimov AES-u z kniznice micro-AES
 * -----------------------------------------------------------------------
 * Subor: xts.h
 * Verzia: 1.1
 * Datum: 13.4.2025
 *
 * Autor: Kamil Berecky
 *
 * Popis: Hlavickovy subor pre XTS demo program. Definuje konstanty, 
 * datove struktury a prototypy funkcii pre testovanie rezimu AES-XTS 
 * pomocou oficialnych testovacich vektorov.
 * 
 * Vyuzite zdroje:
 * - micro-AES kniznica: 
 *   https://github.com/polfosol/micro-AES
 * - IEEE Std 1619-2007: 
 *   https://doi.org/10.1109/IEEESTD.2019.8637988
 * 
 * Pre viac info pozri README.md
 ***********************************************************************/

 #ifndef XTS_CONFIG_H
 #define XTS_CONFIG_H
 
 #include "../libs/micro_aes.h"
 #include "common.h"
 
 // Konstanty pre buffer a limity
 #define XTS_LINE_BUFFER_SIZE 2048     // Velkost buffera pre citanie riadkov
 #define XTS_MAX_LINE_LENGTH 75        // Maximalny pocet znakov pre vypis
 
 // Prefixy pre parsovanie testovacich vektorov
 #define XTS_PREFIX_COUNT "Count = "   // Prefix pre cislo testu
 #define XTS_PREFIX_KEY1 "Key1"        // Prefix pre prvy kluc
 #define XTS_PREFIX_KEY2 "Key2"        // Prefix pre druhy kluc
 #define XTS_PREFIX_TWEAK "Tweak"      // Prefix pre tweak
 #define XTS_PREFIX_DUCN "DUCN"        // Alternativny prefix pre tweak
 #define XTS_PREFIX_PTX "PTX"          // Prefix pre plaintext
 #define XTS_PREFIX_CTX "CTX"          // Prefix pre ciphertext
 #define XTS_PREFIX_FAIL "FAIL"        // Prefix pre oznacenie ocakavaneho zlyhania
 
 // Nazvy testovacich suborov
 #define XTS_TEST_VECTORS_128 "test_vectors/xts_128.txt"  // Testovaci subor pre AES-128-XTS
 #define XTS_TEST_VECTORS_256 "test_vectors/xts_256.txt"  // Testovaci subor pre AES-256-XTS
 
 // Informacne spravy
 #define XTS_MSG_SUCCESS "USPESNY"     // Sprava pre uspesny test
 #define XTS_MSG_FAILURE "NEUSPESNY"   // Sprava pre neuspesny test
 
 // Struktura pre testovacie data
 typedef struct {
   int count;               // Cislo testu
   char *hex_key1;          // Prvy kluc (data key) v hex formate
   char *hex_key2;          // Druhy kluc (tweak key) v hex formate
   char *hex_tweak;         // Tweak (data unit sequence number) v hex formate
   char *hex_plaintext;     // Plaintext v hex formate
   char *hex_ciphertext;    // Ciphertext v hex formate
   bool should_fail;        // Priznak ci sa ocakava zlyhanie operacie
 } TestCaseData;
 
 // Prototypy funkcii
 void free_test_case_data(TestCaseData *data);
 bool parse_next_test_case(FILE *fp, TestCaseData *data);
 bool process_test_case(const TestCaseData *data, int *passed_count);
 
 #endif // XTS_CONFIG_H