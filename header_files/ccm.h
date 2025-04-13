/************************************************************************
 * Nazov projektu: Demonštracia funkcnosti rezimov AES-u z kniznice micro-AES
 * -----------------------------------------------------------------------
 * Subor: ccm.h
 * Verzia: 1.1
 * Datum: 13.4.2025
 *
 * Autor: Kamil Berecky
 *
 * Popis: Hlavickovy subor pre CCM demo program. Definuje konstanty, 
 * datove struktury a prototypy funkcii pre testovanie rezimu AES-CCM 
 * pomocou oficialnych testovacich vektorov.
 * 
 * Vyuzite zdroje:
 * - micro-AES kniznica: 
 *   https://github.com/polfosol/micro-AES
 * - NIST SP 800-38C (2004):
 *   https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/cavp-testing-block-cipher-modes#CCM
 *
 * Pre viac info pozri README.md
 **********************************************************************/

 #ifndef CCM_CONFIG_H
 #define CCM_CONFIG_H
 
 #include "../libs/micro_aes.h"
 #include "common.h"
 #include <stddef.h>
 
 // Enum pre rozpoznavanie riadkov v testovacom subore
 typedef enum {
   CCM_COUNT,    // Riadok s cislom testu
   CCM_KEY,      // Riadok so sifrovacim klucom
   CCM_NONCE,    // Riadok s nonce
   CCM_ADATA,    // Riadok s asociovanymi datami
   CCM_PAYLOAD,  // Riadok s plaintext datami
   CCM_CT,       // Riadok s ciphertext a tagom
   CCM_ALEN,     // Riadok s dlzkou asociovanych dat
   CCM_PLEN,     // Riadok s dlzkou plaintextu
   CCM_NLEN,     // Riadok s dlzkou nonce
   CCM_TLEN,     // Riadok s dlzkou tagu
   CCM_UNKNOWN   // Neznamy typ riadku
 } LineType;
 
 // Struktura pre uchovanie testovacich dat
 typedef struct {
   int count;
   char *hex_nonce;
   char *hex_adata;
   char *hex_payload;
   char *hex_ct_tag; // Kombinovany Ciphertext + Tag
 } TestCaseData;
 
 // --- Konstanty pre citanie a spracovanie dat ---
 #define CCM_LINE_BUFFER_SIZE 1024  // Velkost buffra pre citanie riadkov
 
 // Prefixy pre rozpoznavanie riadkov v testovacom subore
 #define CCM_PREFIX_ALEN "Alen = "
 #define CCM_PREFIX_PLEN "Plen = "
 #define CCM_PREFIX_NLEN "Nlen = "
 #define CCM_PREFIX_TLEN "Tlen = "
 #define CCM_PREFIX_KEY "Key = "
 #define CCM_PREFIX_COUNT "Count = "
 #define CCM_PREFIX_NONCE "Nonce = "
 #define CCM_PREFIX_ADATA "Adata = "
 #define CCM_PREFIX_PAYLOAD "Payload = "
 #define CCM_PREFIX_CT "CT = "
 
 // Kontrola parametrov kompilacie
 #ifndef CCM_NONCE_LEN
 #define CCM_NONCE_LEN 7  // Predvolena dlzka nonce v bajtoch
 #endif
 
 #ifndef CCM_TAG_LEN
 #define CCM_TAG_LEN 16  // Predvolena dlzka tagu v bajtoch
 #endif
 
 // --- Deklaracie funkcii ---
 LineType get_line_type(const char *line);
 void free_test_case_data(TestCaseData *data);
 bool parse_header(FILE *fp, size_t *Alen, size_t *Plen);
 bool parse_initial_key(FILE *fp, uint8_t *key, int key_size_bytes);
 bool parse_next_test_case(FILE *fp, TestCaseData *data, uint8_t *key,
                           int key_size_bytes);
 bool process_test_case(int test_num, const uint8_t *key,
                        const TestCaseData *data, size_t Alen, size_t Plen,
                        int *passed_encrypt, int *passed_decrypt);
 void print_limited(const char *data, size_t limit);
 
 #endif // CCM_CONFIG_H