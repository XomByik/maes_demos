/************************************************************************
 * Nazov projektu: Demonštracia funkcnosti rezimov AES-u z kniznice micro-AES
 * -----------------------------------------------------------------------
 * Subor: siv.h
 * Verzia: 1.1
 * Datum: 13.4.2025
 *
 * Autor: Kamil Berecky
 *
 * Popis: Hlavickovy subor pre SIV demo program. Definuje konstanty, 
 * datove struktury a prototypy funkcii pre testovanie rezimu AES-SIV 
 * pomocou oficialnych testovacich vektorov.
 * 
 * Vyuzite zdroje:
 * - micro-AES kniznica: 
 *   https://github.com/polfosol/micro-AES
 * - RFC 5297 (Synthetic Initialization Vector):
 *   https://tools.ietf.org/html/rfc5297
 * 
 * Pre viac info pozri README.md
 ***********************************************************************/

 #ifndef SIV_CONFIG_H
 #define SIV_CONFIG_H
 
 #include "../libs/micro_aes.h"
 #include "common.h"
 
 // Konstanty pre buffer a limity
 #define SIV_LINE_BUFFER_SIZE 1024     // Velkost buffera pre citanie riadkov
 #define SIV_MAX_LINE_LENGTH 75        // Maximalny pocet znakov pre vypis
 
 // Konstanty pre velkosti
 #define SIV_TAG_LEN 16                // Velkost SIV tagu v bajtoch (128 bitov)
 #define SIV_MAX_DATA_SIZE 128         // Maximalna velkost dat v bajtoch

  /**
  * Enum pre rozlisenie typov riadkov v testovacom subore
  */
 typedef enum {
  KEY_T,       // Riadok obsahujuci kluc
  AD_T,        // Riadok obsahujuci asociovane data
  PT_T,        // Riadok obsahujuci plaintext
  CT_T,        // Riadok obsahujuci ciphertext
  CMAC_T,      // Riadok obsahujuci vysledok CMAC (IV)
  IV_C_T,      // Riadok obsahujuci kombinaciu IV a ciphertextu
  COUNT_T,     // Riadok obsahujuci cislo testu
  FAIL_T       // Riadok oznacujuci ocakavane zlyhanie
} LineType;

// Prefixy pre rozpoznavanie typov riadkov
#define SIV_PREFIX_KEY_1 "Key:"          // Prvy prefix pre riadok s klucom
#define SIV_PREFIX_KEY_2 "Key = "        // Druhy prefix pre riadok s klucom
#define SIV_PREFIX_AD_1 "AD:"            // Prvy prefix pre riadok s asociovanymi datami
#define SIV_PREFIX_AD_2 "AD = "          // Druhy prefix pre riadok s asociovanymi datami
#define SIV_PREFIX_PT_1 "Plaintext:"     // Prvy prefix pre riadok s plaintextom
#define SIV_PREFIX_PT_2 "Plaintext = "   // Druhy prefix pre riadok s plaintextom
#define SIV_PREFIX_CT_1 "Ciphertext:"    // Prvy prefix pre riadok s ciphertextom
#define SIV_PREFIX_CT_2 "Ciphertext = "  // Druhy prefix pre riadok s ciphertextom
#define SIV_PREFIX_CMAC "CMAC(final):"   // Prefix pre riadok s CMAC (IV)
#define SIV_PREFIX_IV_C "IV || C:"       // Prefix pre riadok s kombinaciou IV a ciphertextu
#define SIV_PREFIX_COUNT "Count = "      // Prefix pre riadok s cislom testu
#define SIV_PREFIX_FAIL "FAIL"           // Prefix pre riadok oznacujuci zlyhanie
#define SIV_PREFIX_INPUT "Input:"        // Prefix pre oznacenie sekcie vstupnych dat
#define SIV_PREFIX_OUTPUT "Output:"      // Prefix pre oznacenie sekcie vystupnych dat

// Konstanty pre vysledkove spravy
#define SIV_MSG_SUCCESS "USPESNY"        // Sprava pre uspesny test
#define SIV_MSG_FAILURE "NEUSPESNY"      // Sprava pre neuspesny test
#define SIV_MSG_AUTH_SUCCESS "USPESNA"   // Sprava pre uspesnu autentifikaciu
#define SIV_MSG_AUTH_FAILURE "NEUSPESNA" // Sprava pre neuspesnu autentifikaciu
 
 // Struktura pre testovacie data
 typedef struct {
   int count;               // Cislo testu
   char *hex_key;           // Kluc v hex formate
   char *hex_ad;            // Pridane autentifikacne data (Associated Data) v hex formate
   char *hex_plaintext;     // Plaintext v hex formate
   char *hex_expected_iv;   // Ocakavany inicializacny vektor (tag) v hex formate
   char *hex_expected_ct;   // Ocakavany ciphertext v hex formate
   bool is_decrypt;         // Priznak ci ide o desifrovanie
   bool should_fail;        // Priznak ci sa ocakava zlyhanie autentifikacie
 } TestCaseData;

 
 // Funkcie pre AES-SIV z kniznice micro_aes.h
 extern char AES_SIV_decrypt(const uint8_t *key, const uint8_t iv[16],
                             const uint8_t *ctext, size_t ctextLen,
                             const uint8_t *aData, size_t aDataLen,
                             uint8_t *ptext);
 
 extern void AES_SIV_encrypt(const uint8_t *key, const uint8_t *ptext,
                             size_t ptextLen, const uint8_t *aData,
                             size_t aDataLen, uint8_t iv[16],
                             uint8_t *ctext);
 
 // Prototypy funkcii
 void free_test_case_data(TestCaseData *data);
 bool parse_next_test_case(FILE *fp, TestCaseData *data);
 bool process_test_case(const TestCaseData *data, int *passed_encrypt,
                        int *passed_decrypt);
 void remove_spaces(char *str);
 
 #endif // SIV_CONFIG_H