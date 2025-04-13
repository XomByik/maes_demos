/************************************************************************
 * Nazov projektu: Demonštracia funkcnosti rezimov AES-u z kniznice micro-AES
 * -----------------------------------------------------------------------
 * Subor: gcm_siv.h
 * Verzia: 1.1
 * Datum: 13.4.2025
 *
 * Autor: Kamil Berecky
 *
 * Popis: Hlavickovy subor pre GCM-SIV demo program. Definuje konstanty, 
 * datove struktury a prototypy funkcii pre testovanie rezimu AES-GCM-SIV 
 * pomocou oficialnych testovacich vektorov.
 * 
 * Vyuzite zdroje:
 * - micro-AES kniznica: 
 *   https://github.com/polfosol/micro-AES
 * - RFC 8452:
 *   https://tools.ietf.org/html/rfc8452
 *
 * Pre viac info pozri README.md
 **********************************************************************/

 #ifndef GCM_SIV_CONFIG_H
 #define GCM_SIV_CONFIG_H
 
 #include "../libs/micro_aes.h"
 #include "common.h"
 
 // Konstanty pre buffer a limity
 #define GCM_SIV_LINE_BUFFER_SIZE 2048  // Velkost buffera pre citanie riadkov
 #define GCM_SIV_MAX_LINE_LENGTH 75     // Maximalny pocet znakov pre vypis
 
 // Konstanty pre velkosti komponentov GCM-SIV
 #define GCM_SIV_NONCE_LEN 12           // Velkost nonce v bajtoch
 #define GCM_SIV_TAG_LEN 16             // Velkost tagu v bajtoch
 
 // Nazvy testovacich suborov
 #define GCM_SIV_TEST_VECTORS_128 "test_vectors/gcm_siv_128.txt"  // Testovaci subor pre AES-128
 #define GCM_SIV_TEST_VECTORS_256 "test_vectors/gcm_siv_256.txt"  // Testovaci subor pre AES-256
 
 // Prefixy pre parsovanie testovacich vektorov
 #define GCM_SIV_PREFIX_KEY "key = "      // Prefix pre riadok s klucom
 #define GCM_SIV_PREFIX_NONCE "iv = "     // Prefix pre riadok s nonce (IV)
 #define GCM_SIV_PREFIX_AAD "aad = "      // Prefix pre riadok s AAD
 #define GCM_SIV_PREFIX_PT "pt = "        // Prefix pre riadok s plaintextom
 #define GCM_SIV_PREFIX_CT "ct = "        // Prefix pre riadok s ciphertextom a tagom
 #define GCM_SIV_PREFIX_COUNT "Count = "  // Prefix pre riadok s cislom testu
 
 // Struktura pre testovacie data
 typedef struct {
   int count;                 // Cislo testovacieho vektora
   char *hex_key;             // Kluc v hex formate
   char *hex_nonce;           // Nonce (IV) v hex formate
   char *hex_aad;             // Pridane autentifikacne data v hex formate
   char *hex_plaintext;       // Plaintext v hex formate
   char *hex_ciphertext;      // Ciphertext v hex formate
   char *hex_tag;             // Autentifikacny tag v hex formate
 } TestCaseData;
 
 // Prototypy funkcii
 void free_test_case_data(TestCaseData *data);
 bool parse_next_test_case(FILE *fp, TestCaseData *data);
 bool process_test_case(const TestCaseData *data, int *passed_encrypt,
                        int *passed_decrypt);
 
 #endif // GCM_SIV_CONFIG_H