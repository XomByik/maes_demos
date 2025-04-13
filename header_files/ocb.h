/************************************************************************
 * Nazov projektu: Demonštracia funkcnosti rezimov AES-u z kniznice micro-AES
 * -----------------------------------------------------------------------
 * Subor: ocb.h
 * Verzia: 1.1
 * Datum: 13.4.2025
 *
 * Autor: Kamil Berecky
 *
 * Popis: Hlavickovy subor pre OCB demo program. Definuje konstanty, 
 * datove struktury a prototypy funkcii pre testovanie rezimu AES-OCB 
 * pomocou oficialnych testovacich vektorov.
 * 
 * Vyuzite zdroje:
 * - micro-AES kniznica: 
 *   https://github.com/polfosol/micro-AES
 * - RFC 7253:
 *   https://doi.org/10.17487/RFC7253
 * 
 * Pre viac info pozri README.md
 ***********************************************************************/

 #ifndef OCB_CONFIG_H
 #define OCB_CONFIG_H
 
 #include "../libs/micro_aes.h"
 #include "common.h"
 
 // Konstanty pre buffer a limity
 #define OCB_LINE_BUFFER_SIZE 2048     // Velkost buffera pre citanie riadkov
 #define OCB_MAX_LINE_LENGTH 75        // Maximalny pocet znakov pre vypis
 
 // Konstanty velkosti
 #define OCB_TAG_LEN 16                // Velkost OCB tagu v bajtoch (128 bitov)
 
 // Nazvy testovacich suborov
 #define OCB_TEST_VECTORS_128 "test_vectors/ocb_128.txt"  // Testovaci subor pre AES-128
 #define OCB_TEST_VECTORS_192 "test_vectors/ocb_192.txt"  // Testovaci subor pre AES-192
 #define OCB_TEST_VECTORS_256 "test_vectors/ocb_256.txt"  // Testovaci subor pre AES-256
 
 // Prefixy pre parsovanie testovacich vektorov
 #define OCB_PREFIX_COUNT "COUNT = "   // Prefix pre riadok s cislom testu
 #define OCB_PREFIX_KEY "K : "         // Prefix pre riadok s klucom
 #define OCB_PREFIX_NONCE_SHORT "N:"   // Kratky prefix pre nonce
 #define OCB_PREFIX_NONCE_LONG "N : "  // Dlhy prefix pre nonce
 #define OCB_PREFIX_AAD_SHORT "A:"     // Kratky prefix pre AAD
 #define OCB_PREFIX_AAD_LONG "A : "    // Dlhy prefix pre AAD
 #define OCB_PREFIX_PT_SHORT "P:"      // Kratky prefix pre plaintext
 #define OCB_PREFIX_PT_LONG "P : "     // Dlhy prefix pre plaintext
 #define OCB_PREFIX_CT_SHORT "C:"      // Kratky prefix pre ciphertext
 #define OCB_PREFIX_CT_LONG "C : "     // Dlhy prefix pre ciphertext
 #define OCB_PREFIX_FAIL "FAIL"        // Prefix oznacujuci ocakavane zlyhanie testu
 
 // Struktura pre testovacie data
 typedef struct {
   int count;                // Cislo testu
   char *hex_key;            // Kluc v hex formate
   char *hex_nonce;          // Nonce v hex formate
   char *hex_aad;            // Pridane autentifikacne data v hex formate
   char *hex_plaintext;      // Plaintext v hex formate
   char *hex_ciphertext;     // Ciphertext v hex formate
   char *hex_tag;            // Autentifikacny tag v hex formate
   bool should_fail;         // Priznak ci sa ocakava zlyhanie autentifikacie
 } TestCaseData;
 
 // Prototypy funkcii
 void free_test_case_data(TestCaseData *data);
 bool parse_next_test_case(FILE *fp, TestCaseData *data);
 bool process_test_case(const TestCaseData *data, int *passed_encrypt,
                        int *passed_decrypt);
 
 #endif // OCB_CONFIG_H