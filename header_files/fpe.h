/************************************************************************
 * Nazov projektu: Demonštracia funkcnosti rezimov AES-u z kniznice micro-AES
 * -----------------------------------------------------------------------
 * Subor: fpe.h
 * Verzia: 1.1
 * Datum: 13.4.2025
 *
 * Autor: Kamil Berecky
 *
 * Popis: Hlavickovy subor pre FPE demo program. Definuje konstanty, 
 * datove struktury a prototypy funkcii pre testovanie rezimu AES-FPE 
 * pomocou oficialnych testovacich vektorov, s podporou FF1 a FF3-1 algoritmov.
 * 
 * Vyuzite zdroje:
 * - micro-AES kniznica:
 *   https://github.com/polfosol/micro-AES
 * - NIST SP 800-38G (2016):
 *   https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf
 * 
 * Pre viac info pozri README.md
 ***********************************************************************/

 #ifndef FPE_CONFIG_H
 #define FPE_CONFIG_H
 
 #include "../libs/micro_aes.h"
 #include "../libs/micro_fpe.h"
 #include "common.h"
 
 // Konstanty pre buffers a limity
 #define FPE_LINE_BUFFER_SIZE 1024    // Velkost buffera pre citanie riadkov
 
 // Nazvy testovacich suborov
 #define FPE_TEST_VECTORS_FF1_128 "test_vectors/ff1_128.txt"  // FF1 s AES-128
 #define FPE_TEST_VECTORS_FF1_192 "test_vectors/ff1_192.txt"  // FF1 s AES-192
 #define FPE_TEST_VECTORS_FF1_256 "test_vectors/ff1_256.txt"  // FF1 s AES-256
 #define FPE_TEST_VECTORS_FF3_128 "test_vectors/ff3_128.txt"  // FF3 s AES-128
 #define FPE_TEST_VECTORS_FF3_192 "test_vectors/ff3_192.txt"  // FF3 s AES-192
 #define FPE_TEST_VECTORS_FF3_256 "test_vectors/ff3_256.txt"  // FF3 s AES-256
 
 // Prefixy pre identifikaciu typov riadkov
 #define FPE_PREFIX_COUNT "Count = "        // Prefix pre cislo testu
 #define FPE_PREFIX_METHOD "Method = "      // Prefix pre metodu
 #define FPE_PREFIX_ALPHABET "Alphabet = "  // Prefix pre abecedu
 #define FPE_PREFIX_KEY "Key = "            // Prefix pre kluc
 #define FPE_PREFIX_TWEAK "Tweak = "        // Prefix pre tweak
 #define FPE_PREFIX_PT "PT = "              // Prefix pre plaintext
 #define FPE_PREFIX_CT "CT = "              // Prefix pre ciphertext
 
 // Konstanty pre FPE metody a parametre
 #define FPE_METHOD_FF1 "FF1"               // Nazov metody FF1
 #define FPE_METHOD_FF3 "FF3"               // Nazov metody FF3
 #define FPE_METHOD_FF3_1 "FF3-1"           // Nazov metody FF3-1
 #define FPE_DEFAULT_ALPHABET "0123456789"  // Predvolena ciselna abeceda
 
 // Konstanty pre velkosti AES klucov
 #define AES_128_KEY_SIZE 16                // Velkost 128-bitoveho kluca v bajtoch
 #define AES_192_KEY_SIZE 24                // Velkost 192-bitoveho kluca v bajtoch
 #define AES_256_KEY_SIZE 32                // Velkost 256-bitoveho kluca v bajtoch
 
 // Kontrola FF_X (musi byt definovane pri kompilacii)
 #ifndef FF_X
 #error "FF_X macro (1 pre FF1, 3 pre FF3-1) musi byt definovane pri kompilacii."
 #endif
 
 #if FF_X != 1 && FF_X != 3
 #error "Neplatna hodnota pre FF_X. Musi byt 1 alebo 3."
 #endif
 
 // Struktura pre FPE testovaci vektor
 typedef struct {
   int count;               // Cislo testu
   char *count_str;         // Cislo testu v retazcovej podobe
   char *method_str;        // Metoda (FF1 alebo FF3)
   char *alphabet_str;      // Pouzita abeceda
   char *hex_key;           // Kluc v hex formate
   char *hex_tweak;         // Tweak v hex formate
   char *pt_str;            // Plaintext
   char *expected_ct_str;   // Ocakavany ciphertext
 } TestCaseData;
 
 // Prototypy funkcii
 void free_test_case_data(TestCaseData *data);
 bool parse_next_test_case(FILE *fp, TestCaseData *data);
 bool process_test_case(const TestCaseData *data, int *passed_encrypt,
                        int *passed_decrypt);
 
 #endif // FPE_CONFIG_H