/************************************************************************
 * Nazov projektu: Demonštracia funkcnosti rezimov AES-u z kniznice micro-AES
 * -----------------------------------------------------------------------
 * Subor: ofb_demo.c
 * Verzia: 1.1
 * Datum: 13.4.2025
 *
 * Autor: Kamil Berecky
 *
 * Popis: Program demonstruje funkcnost rezimu AES-OFB pomocou oficialnych
 * testovacich vektorov. Implementuje operacie sifrovania a desifrovania v
 * OFB rezime, ktory umoznuje premenit blokovú sifru na prúdovú. Na rozdiel
 * od CFB, OFB nevyzaduje inverznu operaciu pre desifrovanie.
 * Program podporuje rozne velkosti klucov (128, 192, 256 bitov).
 * 
 * Vyuzite zdroje:
 * - micro-AES kniznica: 
 *   https://github.com/polfosol/micro-AES
 * - NIST SP 800-38A (2001):
 *   https://doi.org/10.6028/NIST.SP.800-38A
 * 
 * Pre viac info pozri README.md
 **********************************************************************/

 #include "../header_files/ofb.h"

 /**
  * Enum pre rozlisenie typov riadkov v testovacom subore
  */
 typedef enum {
   KEY,           // Riadok obsahujuci kluc
   IV,            // Riadok obsahujuci inicializacny vektor
   BLOCK,         // Riadok obsahujuci cislo bloku
   INPUT_BLOCK,   // Riadok obsahujuci vstupny blok
   OUTPUT_BLOCK,  // Riadok obsahujuci vystupny blok
   PLAINTEXT,     // Riadok obsahujuci plaintext
   CIPHERTEXT,    // Riadok obsahujuci ciphertext
   MODE_CHANGE,   // Riadok oznacujuci zmenu modu (sifrovanie/desifrovanie)
   UNKNOWN        // Neznamy typ riadku
 } LineType;
 
 /**
  * Urci typ riadku v testovacom subore
  *
  * Popis: Funkcia analyzuje vstupny riadok a urcuje jeho typ podla
  * klucovych slov na zaciatku riadku.
  *
  * Proces:
  * 1. Kontrola vyskytu roznych prefixov na zaciatku riadku
  * 2. Vratenie zodpovedajuceho enumeracneho typu
  *
  * Parametre:
  * @param line - Vstupny riadok na analyzu
  *
  * Navratova hodnota:
  * @return LineType - Enum hodnota reprezentujuca typ riadku
  */
 static LineType get_line_type(const char *line) {
   if (strncmp(line, OFB_PREFIX_KEY, OFB_PREFIX_LEN_KEY) == 0)
     return KEY;  // Riadok obsahuje kluc
   if (strncmp(line, OFB_PREFIX_IV, OFB_PREFIX_LEN_IV) == 0)
     return IV;  // Riadok obsahuje IV
   if (strncmp(line, OFB_PREFIX_BLOCK, OFB_PREFIX_LEN_BLOCK) == 0)
     return BLOCK;  // Riadok obsahuje cislo bloku
   if (strncmp(line, OFB_PREFIX_INPUT_BLOCK, OFB_PREFIX_LEN_INPUT) == 0)
     return INPUT_BLOCK;  // Riadok obsahuje vstupny blok
   if (strncmp(line, OFB_PREFIX_OUTPUT_BLOCK, OFB_PREFIX_LEN_OUTPUT) == 0)
     return OUTPUT_BLOCK;  // Riadok obsahuje vystupny blok
   if (strncmp(line, OFB_PREFIX_PLAINTEXT, OFB_PREFIX_LEN_PLAINTEXT) == 0)
     return PLAINTEXT;  // Riadok obsahuje plaintext
   if (strncmp(line, OFB_PREFIX_CIPHERTEXT, OFB_PREFIX_LEN_CIPHERTEXT) == 0)
     return CIPHERTEXT;  // Riadok obsahuje ciphertext
   if (strstr(line, OFB_MODE_IDENTIFIER) != NULL)
     return MODE_CHANGE;  // Riadok indikuje zmenu modu (Encrypt/Decrypt)
   return UNKNOWN;  // Neznamy typ riadku, bude ignorovany
 }
 
 /**
  * Uvolni pamat alokovanu pre testovacie data
  *
  * Popis: Funkcia vynuluje vsetky polia v strukture TestVector.
  * Keďže v tejto implementácií štruktúra nepouźíva dynamicky
  * alokovanú pamät, stačí ju vynulovať.
  *
  * Proces:
  * 1. Kontrola ci vstupny pointer nie je NULL
  * 2. Vynulovanie struktury pomocou memset
  *
  * Parametre:
  * @param test - Pointer na strukturu s testovacimi datami
  */
 void free_test_case_data(TestVector *test) {
   if (!test)
     return;  // Ochrana pred NULL pointerom
   memset(test, 0, sizeof(TestVector));  // Vynulovanie celej struktury
 }
 
 /**
  * Vygeneruje keystream pre OFB operaciu
  *
  * Popis: Funkcia generuje keystream pouzitim AES-OFB algoritmu
  * s nulovym blokom dat. Tento keystream je potom pouzity pre
  * sifrovanie alebo desifrovanie pomocou XOR operacie.
  *
  * Proces:
  * 1. Vytvorenie nuloveho bloku ako vstupu
  * 2. Pouzitie AES_OFB_encrypt pre generovanie keystreamu
  *
  * Parametre:
  * @param key - Sifrovaci kluc pouzity pre operaciu
  * @param iv - Inicializacny vektor
  * @param keystream - Vystupny buffer pre ulozenie keystreamu
  */
 void generate_keystream(uint8_t *key, uint8_t *iv, uint8_t *keystream) {
   uint8_t zero_block[OFB_BLOCK_SIZE] = {0};  // Vytvorenie nuloveho bloku
   // Pouzivame AES_OFB_encrypt s nulovym blokom pre generovanie keystreamu
   AES_OFB_encrypt(key, iv, zero_block, OFB_BLOCK_SIZE, keystream);
 }
 
 /**
  * Spracuje subor s testovacimi vektormi
  *
  * Popis: Funkcia cita subor s testovacimi vektormi riadok po riadku,
  * identifikuje typy riadkov a extrahuje informacie potrebne pre vykonanie
  * testov. Rozlisuje testovacie vektory pre sifrovanie a desifrovanie.
  *
  * Proces:
  * 1. Inicializacia premennych a pocitadiel
  * 2. Citanie suboru po riadkoch a identifikacia typov riadkov
  * 3. Spracovanie riadkov podla ich typu (kluc, IV, blok, plaintext, ciphertext)
  * 4. Ukladanie dat do poli testovacich vektorov
  *
  * Parametre:
  * @param fp - Pointer na otvoreny subor na citanie
  * @param encrypt_tests - Pole pre ulozenie sifrovacich testov
  * @param decrypt_tests - Pole pre ulozenie desifrovacich testov
  * @param encrypt_test_count - Pointer pre ulozenie poctu sifrovacich testov
  * @param decrypt_test_count - Pointer pre ulozenie poctu desifrovacich testov
  * @param key - Vystupny buffer pre ulozenie sifrovacieho kluca
  *
  * Navratova hodnota:
  * @return bool - true ak sa nacital aspon jeden testovaci vektor, false inak
  */
 bool parse_test_vectors(FILE *fp, TestVector encrypt_tests[],
                         TestVector decrypt_tests[],
                         int *encrypt_test_count, int *decrypt_test_count,
                         uint8_t *key) {
   char line[OFB_LINE_BUFFER_SIZE];  // Buffer pre citanie riadkov
   char *hex_key = NULL;  // Docasny buffer pre kluc v hex formate
   char *hex_iv = NULL;  // Docasny buffer pre IV v hex formate
   char *hex_input_block = NULL;  // Docasny buffer pre vstupny blok
   char *hex_output_block = NULL;  // Docasny buffer pre vystupny blok
   char *hex_plaintext = NULL;  // Docasny buffer pre plaintext
   char *hex_ciphertext = NULL;  // Docasny buffer pre ciphertext
   int block_number = 0;  // Aktualne cislo bloku
   int current_mode = OFB_MODE_UNDEFINED;  // Aktualny mod: 0=nedefinovany, 1=encrypt, 2=decrypt
 
   // Inicializacia pocitadiel testov
   *encrypt_test_count = 0;  // Pociatocna hodnota pre sifrovacie testy
   *decrypt_test_count = 0;  // Pociatocna hodnota pre desifovacie testy
 
   // Citanie suboru po riadkoch
   while (fgets(line, sizeof(line), fp)) {
     // Odstranenie koncoveho znaku noveho riadka a CR znaku (Windows)
     size_t len = strlen(line);  // Zistenie dlzky riadku
     while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
       line[--len] = '\0';  // Odstranenie koncovych znakov
 
     // Preskocenie prazdnych riadkov
     if (len == 0)
       continue;  // Preskocenie prazdneho riadku
 
     char *trimmed = trim(line);  // Odstranenie medzier zo zaciatku a konca
     LineType type = get_line_type(trimmed);  // Urcenie typu riadku
 
     // Spracovanie riadku podla jeho typu
     switch (type) {
     case MODE_CHANGE:  // Zmena modu (sifrovanie/desifrovanie)
       // Nastavenie modu podla obsahu riadku
       current_mode = (strstr(trimmed, OFB_MODE_ENCRYPT) != NULL)   ? OFB_MODE_ENCRYPTION  // Sifrovanie
                      : (strstr(trimmed, OFB_MODE_DECRYPT) != NULL) ? OFB_MODE_DECRYPTION  // Desifrovanie
                                                                    : OFB_MODE_UNDEFINED;  // Nedefinovany mod
 
       // Vypis informacie o detekovanom mode
       printf("\n--- Testovanie %s ---\n",
              (current_mode == OFB_MODE_ENCRYPTION)   ? "sifrovania (Encrypt)"  // Sifrovanie
              : (current_mode == OFB_MODE_DECRYPTION) ? "desifrovania (Decrypt)"  // Desifrovanie
                                                      : "neznameho rezimu");  // Nedefinovany mod
       break;
 
     case KEY:  // Riadok s klucom
       // Uvolnenie predchadzajuceho kluca a extrakcia noveho
       free(hex_key);  // Uvolnenie predchadzajuceho kluca
       hex_key = strdup(trim(trimmed + OFB_PREFIX_LEN_KEY));  // Kopirovanie novej hodnoty kluca
       
       // Konverzia hex kluca na binarne data
       if (hex_to_bin(hex_key, key, AES_KEY_SIZE) != 0) {
         fprintf(stderr, "Error parsing Key hex.\n");  // Chybova sprava
         free(hex_key);  // Uvolnenie neplatneho kluca
         hex_key = NULL;  // Nastavenie na NULL
       } else {
         printf("\nKluc: %s\n", hex_key);  // Vypis kluca pre kontrolu
       }
       break;
 
     case IV:  // Riadok s inicializacnym vektorom
       free(hex_iv);  // Uvolnenie predchadzajuceho IV
       hex_iv = strdup(trim(trimmed + OFB_PREFIX_LEN_IV));  // Extrakcia noveho IV
       break;
 
     case BLOCK:  // Riadok s cislom bloku
       block_number = atoi(trimmed + OFB_PREFIX_LEN_BLOCK);  // Konverzia cisla bloku na integer
       break;
 
     case INPUT_BLOCK:  // Riadok so vstupnym blokom
       free(hex_input_block);  // Uvolnenie predchadzajuceho vstupneho bloku
       hex_input_block = strdup(trim(trimmed + OFB_PREFIX_LEN_INPUT));  // Extrakcia noveho vstupneho bloku
 
       // Pridanie vstupneho bloku do prislusneho testovacieho vektora, ak je platny
       if (block_number > 0 && block_number <= OFB_MAX_BLOCKS) {
         // Vyber cieloveho testovacieho vektora podla aktualneho modu
         TestVector *target =
             (current_mode == OFB_MODE_ENCRYPTION)   ? &encrypt_tests[block_number - 1]  // Sifrovaci test
             : (current_mode == OFB_MODE_DECRYPTION) ? &decrypt_tests[block_number - 1]  // Desifrovaci test
                                                     : NULL;  // Neplatny mod
 
         if (target) {
           // Kopirovanie vstupneho bloku do cieloveho testovacieho vektora
           strncpy(target->hex_input_block, hex_input_block,
                   OFB_HEX_BUFFER_SIZE - 1);  // Kopirovanie s ochranou pred pretecenim
           target->block_number = block_number;  // Nastavenie cisla bloku
 
           // Aktualizacia pocitadiel testov podla modu
           if (current_mode == OFB_MODE_ENCRYPTION && block_number > *encrypt_test_count)
             *encrypt_test_count = block_number;  // Aktualizacia poctu sifrovacich testov
           else if (current_mode == OFB_MODE_DECRYPTION && block_number > *decrypt_test_count)
             *decrypt_test_count = block_number;  // Aktualizacia poctu desifrovacich testov
         }
       }
       break;
 
     case OUTPUT_BLOCK:  // Riadok s vystupnym blokom
       free(hex_output_block);  // Uvolnenie predchadzajuceho vystupneho bloku
       hex_output_block = strdup(trim(trimmed + OFB_PREFIX_LEN_OUTPUT));  // Extrakcia noveho vystupneho bloku
 
       // Pridanie vystupneho bloku do prislusneho testovacieho vektora, ak je platny
       if (block_number > 0 && block_number <= OFB_MAX_BLOCKS) {
         // Vyber cieloveho testovacieho vektora podla aktualneho modu
         TestVector *target =
             (current_mode == OFB_MODE_ENCRYPTION)   ? &encrypt_tests[block_number - 1]  // Sifrovaci test
             : (current_mode == OFB_MODE_DECRYPTION) ? &decrypt_tests[block_number - 1]  // Desifrovaci test
                                                     : NULL;  // Neplatny mod
 
         if (target) {
           // Kopirovanie vystupneho bloku do cieloveho testovacieho vektora
           strncpy(target->hex_output_block, hex_output_block,
                   OFB_HEX_BUFFER_SIZE - 1);  // Kopirovanie s ochranou pred pretecenim
         }
       }
       break;
 
     case PLAINTEXT:  // Riadok s plaintextom
       free(hex_plaintext);  // Uvolnenie predchadzajuceho plaintextu
       hex_plaintext = strdup(trim(trimmed + OFB_PREFIX_LEN_PLAINTEXT));  // Extrakcia noveho plaintextu
 
       // Pridanie plaintextu do prislusneho testovacieho vektora, ak je platny
       if (block_number > 0 && block_number <= OFB_MAX_BLOCKS) {
         // Vyber cieloveho testovacieho vektora podla aktualneho modu
         TestVector *target =
             (current_mode == OFB_MODE_ENCRYPTION)   ? &encrypt_tests[block_number - 1]  // Sifrovaci test
             : (current_mode == OFB_MODE_DECRYPTION) ? &decrypt_tests[block_number - 1]  // Desifrovaci test
                                                     : NULL;  // Neplatny mod
 
         if (target) {
           // Kopirovanie plaintextu do cieloveho testovacieho vektora
           strncpy(target->hex_plaintext, hex_plaintext,
                   OFB_HEX_BUFFER_SIZE - 1);  // Kopirovanie s ochranou pred pretecenim
         }
       }
       break;
 
     case CIPHERTEXT:  // Riadok s ciphertextom
       free(hex_ciphertext);  // Uvolnenie predchadzajuceho ciphertextu
       hex_ciphertext = strdup(trim(trimmed + OFB_PREFIX_LEN_CIPHERTEXT));  // Extrakcia noveho ciphertextu
 
       // Pridanie ciphertextu do prislusneho testovacieho vektora, ak je platny
       if (block_number > 0 && block_number <= OFB_MAX_BLOCKS) {
         // Vyber cieloveho testovacieho vektora podla aktualneho modu
         TestVector *target =
             (current_mode == OFB_MODE_ENCRYPTION)   ? &encrypt_tests[block_number - 1]  // Sifrovaci test
             : (current_mode == OFB_MODE_DECRYPTION) ? &decrypt_tests[block_number - 1]  // Desifrovaci test
                                                     : NULL;  // Neplatny mod
 
         if (target) {
           // Kopirovanie ciphertextu do cieloveho testovacieho vektora
           strncpy(target->hex_ciphertext, hex_ciphertext,
                   OFB_HEX_BUFFER_SIZE - 1);  // Kopirovanie s ochranou pred pretecenim
         }
       }
       break;
 
     case UNKNOWN:  // Neznámy typ riadka
       // Neznámy typ riadka, preskakujeme
       break;
     }
   }
 
   // Uvolnenie docasnych bufferov
   free(hex_key);  // Uvolnenie kluca
   free(hex_iv);  // Uvolnenie IV
   free(hex_input_block);  // Uvolnenie vstupneho bloku
   free(hex_output_block);  // Uvolnenie vystupneho bloku
   free(hex_plaintext);  // Uvolnenie plaintextu
   free(hex_ciphertext);  // Uvolnenie ciphertextu
 
   // Vratime true ak sa podarilo nacitat aspon jeden testovaci vektor
   return (*encrypt_test_count > 0 || *decrypt_test_count > 0);
 }
 
 /**
  * Spracuje a vyhodnoti jeden testovaci vektor
  *
  * Popis: Hlavna funkcia, ktora vykonava samotne testovanie jedneho OFB
  * testovacieho vektora. Obsahuje generovanie keystreamu, sifrovanie alebo
  * desifrovanie podla modu a porovnanie vysledkov s ocakavanymi hodnotami.
  *
  * Proces:
  * 1. Konverzia hex hodnot na binarne data
  * 2. Generovanie keystreamu z kluca a IV
  * 3. Vykonanie XOR operacie pre sifrovanie alebo desifrovanie
  * 4. Porovnanie vysledkov s ocakavanymi hodnotami
  * 5. Aktualizacia statistiky testov
  *
  * Parametre:
  * @param key - Sifrovaci kluc pouzity pre operaciu
  * @param test - Struktura s testovacim vektorom
  * @param passed_count - Pointer na pocitadlo uspesnych testov
  * @param test_count - Poradove cislo aktualneho testu
  * @param is_encrypt - Priznak ci ide o sifrovanie (true) alebo desifrovanie (false)
  *
  * Navratova hodnota:
  * @return bool - true ak test bol uspesny, false ak nebol
  */
 bool process_ofb_test_case(uint8_t *key, TestVector *test,
                            int *passed_count, int test_count,
                            bool is_encrypt) {
   uint8_t iv[OFB_BLOCK_SIZE], keystream[OFB_BLOCK_SIZE];  // Buffery pre IV a keystream
   uint8_t input[OFB_MAX_DATA_SIZE], expected[OFB_MAX_DATA_SIZE],
       result[OFB_MAX_DATA_SIZE];  // Buffery pre vstup, ocakavany vystup a vysledok
   uint8_t expected_output[OFB_BLOCK_SIZE];  // Buffer pre ocakavany vystupny blok
   size_t input_len, expected_len;  // Dlzky vstupnych a ocakavanych dat
 
   // Nastavime IV podla Input Block zo suboru
   hex_to_bin(test->hex_input_block, iv, OFB_BLOCK_SIZE);  // Konverzia IV z hex do bin
 
   // Vypis informacii o teste
   printf("\nTest #%d (Block #%d):\n", test_count, test->block_number);
   printf("Vstupny blok (IV): %s\n", test->hex_input_block);
 
   // Generovanie keystreamu
   uint8_t zero_block[OFB_BLOCK_SIZE] = {0};  // Vytvorenie nuloveho bloku
   AES_OFB_encrypt(key, iv, zero_block, OFB_BLOCK_SIZE, keystream);  // Generovanie keystreamu
 
   // Vypis keystreamu pre kontrolu
   printf("Generovany keystream: ");
   print_hex(keystream, OFB_BLOCK_SIZE);  // Vypis keystreamu v hex formate
 
   // Kontrola zhodnosti keystreamu s ocakavanym output blokom
   hex_to_bin(test->hex_output_block, expected_output, OFB_BLOCK_SIZE);  // Konverzia ocakavaneho vystupu
 
   // Porovnanie keystreamu s ocakavanym vystupom
   bool keystream_match = (memcmp(keystream, expected_output, OFB_BLOCK_SIZE) == 0);
   if (!keystream_match) {
     printf("!!! CHYBA: Keystream sa nezhoduje s ocakavanym vystupnym "
            "blokom !!!\n");
     printf("Ocakavany vystupny blok: %s\n", test->hex_output_block);
   }
 
   // Spracovanie podla modu - sifrovanie alebo desifrovanie
   if (is_encrypt) {  // Mod sifrovania
     // Ziskam plaintext a ocakavany ciphertext
     input_len = strlen(test->hex_plaintext) / 2;  // Dlzka plaintextu v bajtoch
     expected_len = strlen(test->hex_ciphertext) / 2;  // Dlzka ciphertextu v bajtoch
 
     // Konverzia hex hodnot na binarne data
     hex_to_bin(test->hex_plaintext, input, input_len);  // Konverzia plaintextu
     hex_to_bin(test->hex_ciphertext, expected, expected_len);  // Konverzia ocakavaneho ciphertextu
 
     // Vypis vstupnych dat
     printf("Plaintext: ");
     print_hex(input, input_len);  // Vypis plaintextu v hex formate
 
     // XOR plaintext s keystream pre ziskanie ciphertext
     for (size_t j = 0; j < input_len; j++) {
       result[j] = input[j] ^ keystream[j];  // Sifrovanie pomocou XOR
     }
 
     // Vypis vypocitaneho a ocakavaneho vystupu
     printf("Vypocitany ciphertext: ");
     print_hex(result, input_len);  // Vypis vypocitaneho ciphertextu
 
     printf("Ocakavany ciphertext: ");
     print_hex(expected, expected_len);  // Vypis ocakavaneho ciphertextu
   } else {  // Mod desifrovania
     // Ziskam ciphertext a ocakavany plaintext
     input_len = strlen(test->hex_ciphertext) / 2;  // Dlzka ciphertextu v bajtoch
     expected_len = strlen(test->hex_plaintext) / 2;  // Dlzka plaintextu v bajtoch
 
     // Konverzia hex hodnot na binarne data
     hex_to_bin(test->hex_ciphertext, input, input_len);  // Konverzia ciphertextu
     hex_to_bin(test->hex_plaintext, expected, expected_len);  // Konverzia ocakavaneho plaintextu
 
     // Vypis vstupnych dat
     printf("Ciphertext: ");
     print_hex(input, input_len);  // Vypis ciphertextu v hex formate
 
     // XOR ciphertext s keystream pre ziskanie plaintext
     for (size_t j = 0; j < input_len; j++) {
       result[j] = input[j] ^ keystream[j];  // Desifrovanie pomocou XOR
     }
 
     // Vypis vypocitaneho a ocakavaneho vystupu
     printf("Vypocitany plaintext: ");
     print_hex(result, input_len);  // Vypis vypocitaneho plaintextu
 
     printf("Ocakavany plaintext: ");
     print_hex(expected, expected_len);  // Vypis ocakavaneho plaintextu
   }
 
   // Kontrola zhody výsledku s ocakavanym vystupom
   bool success = (memcmp(result, expected, expected_len) == 0);  // Porovnanie vysledku
   if (success) {
     (*passed_count)++;  // Inkrementacia pocitadla uspesnych testov
     printf("Test USPESNY\n");  // Vypis informacie o uspesnosti
   } else {
     printf("Test NEUSPESNY\n");  // Vypis informacie o neuspesnosti
   }
 
   return success;  // Vratenie vysledku testu
 }
 
 /**
  * Hlavna funkcia programu
  *
  * Popis: Hlavna funkcia inicializuje program, otvara subor s testovacimi
  * vektormi, spusta spracovanie a testovanie jednotlivych vektorov,
  * a na zaver zobrazuje celkovu statistiku uspesnosti testov.
  * Program automaticky vyberie spravny subor s testovacimi vektormi
  * na zaklade kompilacnych nastaveni velkosti kluca.
  *
  * Proces:
  * 1. Detekcia velkosti kluca pomocou preprocesorovych definicii
  * 2. Otvorenie suboru s testovacimi vektormi
  * 3. Parsovanie a nacitanie testovacich vektorov
  * 4. Vykonavanie testov sifrovania a desifrovania
  * 5. Zobrazenie celkovych vysledkov testovania
  *
  * Navratova hodnota:
  * @return int - 0 pri uspesnom dokonceni vsetkych testov, 1 ak niektory test zlyhal
  */
 int main() {
 // Zistenie velkosti kluca z kompilacnych definicii
 #if AES___ == 256
   const int aes_bits = 256;  // 256-bitovy kluc
   const char *test_vectors_file = OFB_TEST_VECTORS_256;  // Subor pre AES-256
 #elif AES___ == 192
   const int aes_bits = 192;  // 192-bitovy kluc
   const char *test_vectors_file = OFB_TEST_VECTORS_192;  // Subor pre AES-192
 #else // Predvolene AES-128
   const int aes_bits = 128;  // 128-bitovy kluc (predvolene)
   const char *test_vectors_file = OFB_TEST_VECTORS_128;  // Subor pre AES-128
 #endif
 
   // Vypis zakladnych informacii o teste
   printf("AES-%d OFB Test\n", aes_bits);  // Vypis velkosti kluca
   printf("Pouziva sa subor s testovacimi vektormi: %s\n",
          test_vectors_file);  // Vypis pouzivaneho suboru
 
   // Alokujeme pamat pre kluc
   uint8_t key[AES_KEY_SIZE] = {0};  // Inicializacia kluca nulovymi hodnotami
 
   // Inicializacia testovacich vektorov
   TestVector encrypt_tests[OFB_MAX_BLOCKS] = {0};  // Pole pre sifrovacie testy
   TestVector decrypt_tests[OFB_MAX_BLOCKS] = {0};  // Pole pre desifovacie testy
   int encrypt_test_count = 0;  // Pocitadlo sifrovacich testov
   int decrypt_test_count = 0;  // Pocitadlo desifrovacich testov
 
   // Otvorenie suboru s testovacimi vektormi
   FILE *fp = fopen(test_vectors_file, "r");  // Otvorenie suboru na citanie
   if (!fp) {
     perror("Nepodarilo sa otvorit subor s testovacimi vektormi");  // Chybova sprava
     return 1;  // Navratova hodnota pre chybu
   }
 
   // Parsovanie suboru a nacitanie testov
   if (!parse_test_vectors(fp, encrypt_tests, decrypt_tests,
                           &encrypt_test_count, &decrypt_test_count, key)) {
     printf("Nepodarilo sa nacitat ziadne testovacie vektory.\n");  // Chybova sprava
     fclose(fp);  // Zatvorenie suboru
     return 1;  // Navratova hodnota pre chybu
   }
 
   fclose(fp);  // Zatvorenie suboru po dokonceni citania
 
   // Inicializacia pocitadiel pre vysledky testov
   int test_count = 0;  // Celkovy pocet vykonanych testov
   int passed_count = 0;  // Pocet uspesnych testov
 
   // Spracovanie sifrovacich testov
   if (encrypt_test_count > 0) {  // Ak mame nejake sifrovacie testy
     printf("\n--- Vykonavanie sifrovacich testov ---\n");
     for (int i = 0; i < encrypt_test_count; i++) {  // Iteracia cez vsetky sifrovacie testy
       test_count++;  // Inkrementacia celkoveho poctu testov
       process_ofb_test_case(key, &encrypt_tests[i], &passed_count,
                             test_count, true);  // Vykonavanie sifrovacieho testu
     }
   }
 
   // Spracovanie desifrovacich testov
   if (decrypt_test_count > 0) {  // Ak mame nejake desifovacie testy
     printf("\n--- Vykonavanie desifrovacich testov ---\n");
     for (int i = 0; i < decrypt_test_count; i++) {  // Iteracia cez vsetky desifovacie testy
       test_count++;  // Inkrementacia celkoveho poctu testov
       process_ofb_test_case(key, &decrypt_tests[i], &passed_count,
                             test_count, false);  // Vykonavanie desifrovacieho testu
     }
   }
 
   // Vyhodnotenie celkovej uspesnosti testov
   bool success = (test_count > 0 && passed_count == test_count);  // True ak vsetky testy presli
 
   // Vypis celkovych vysledkov testovania
   printf("\nCelkove vysledky:\n");
   printf("Spracovanych testovacich vektorov: %d\n", test_count);  // Celkovy pocet testov
   printf("Uspesnych testov: %d\n", passed_count);  // Pocet uspesnych testov
   printf("Celkovy vysledok: %s\n", success ? "USPESNY" : "NEUSPESNY");  // Celkovy vysledok
 
   return success ? 0 : 1;  // Navratovy kod: 0 pre uspech, 1 pre neuspech
 }