/************************************************************************
 * Nazov projektu: Demonstracia funkcnosti rezimov AES-u z kniznice micro-AES
 * -----------------------------------------------------------------------
 * Subor: cbc_demo.c
 * Verzia: 1.1
 * Datum: 13.4.2025
 *
 * Autor: Kamil Berecky
 *
 * Popis: Program demonstruje funkcnost rezimu AES-CBC pomocou oficialnych
 * testovacich vektorov. Implementuje sifrovanie a desifrovanie pomocou
 * micro-AES kniznice, a nasledne porovnava vysledky s ocakavanymi hodnotami
 * zo standardizovanych testovacich vektorov. Program podporuje rozne 
 * velkosti klucov (128, 192, 256 bitov).
 * 
 * Vyuzite zdroje:
 * - micro-AES kniznica: 
 *   https://github.com/polfosol/micro-AES
 * - NIST SP 800-38A (2001): 
 *   https://doi.org/10.6028/NIST.SP.800-38A
 *
 * Pre viac info pozri README.md
 **********************************************************************/

 #include "../header_files/cbc.h"

 /**
  * Urci typ riadku v testovacom subore
  *
  * Popis: Funkcia analyzuje vstupny riadok a urcuje jeho typ na zaklade
  * klucovych slov. To umoznuje spravne spracovanie roznych casti testovacich
  * vektorov, ako su kluc, inicializacny vektor, plaintext a ciphertext.
  *
  * Proces:
  * 1. Porovnava zaciatok riadku s ocakavanymi klucovymi slovami
  * 2. Vracia enum hodnotu reprezentujucu dany typ riadku
  * 3. Ak sa nenajde zhoda, vracia UNKNOWN
  *
  * Parametre:
  * @param line - Vstupny riadok na analyzu
  *
  * Navratova hodnota:
  * @return LineType - Enum hodnota reprezentujucu typ riadku
  */
 static LineType get_line_type(const char *line) {
   if (strncmp(line, "Key", 3) == 0)
     return KEY;  // Riadok obsahuje kluc
   if (strncmp(line, "IV", 2) == 0)
     return IV;   // Riadok obsahuje inicializacny vektor
   if (strncmp(line, "Block #", 7) == 0)
     return BLOCK;  // Riadok oznacuje cislo bloku
   if (strncmp(line, "Plaintext", 9) == 0)
     return PLAINTEXT;  // Riadok obsahuje nezasifrovany text
   if (strncmp(line, "Ciphertext", 10) == 0)
     return CIPHERTEXT;  // Riadok obsahuje zasifrovany text
   if (strstr(line, "CBC-AES") != NULL)
     return MODE_CHANGE;  // Riadok oznacuje zmenu rezimu (sifrovanie/desifrovanie)
   return UNKNOWN;  // Neznamy typ riadku, bude ignorovany
 }
 
 /**
  * Uvolni pamat alokovanu pre testovacie data
  *
  * Popis: Funkcia uvolnuje vsetku dynamicky alokovanu pamat, ktora
  * bola pouzita na ulozenie testovacich dat. Sluzi na cistenie
  * pamate a zabranenie memory leakom pred ukoncenim programu alebo
  * pri prechode na nove testovacie data.
  *
  * Proces:
  * 1. Kontrola ci vstupny pointer nie je NULL
  * 2. Uvolnenie alokovanych retazcov pre rozne casti testovacieho vektora
  * 3. Vynulovanie struktury pre zabranenie vyuzitia po uvolneni
  *
  * Parametre:
  * @param data - Pointer na strukturu s testovacimi datami na uvolnenie
  */
 void free_test_case_data(TestCaseData *data) {
   if (!data)
     return;  // Ochrana pred NULL pointerom
   free(data->hex_key);  // Uvolnenie kluca
   free(data->hex_iv);   // Uvolnenie inicializacneho vektora
   free(data->hex_plaintext);  // Uvolnenie plaintextu
   free(data->hex_ciphertext);  // Uvolnenie ciphertextu
   memset(data, 0, sizeof(TestCaseData));  // Vycistenie struktury nulami
 }
 
 /**
  * Spracovanie jedneho testovacieho vektora
  *
  * Popis: Funkcia vykonava testovanie bud sifrovania alebo desifovania
  * jedneho bloku dat v rezime AES-CBC. Spracuje vstupne data, vykona
  * prislusnu operaciu a porovna vysledky s ocakavanymi hodnotami.
  *
  * Proces:
  * 1. Priprava inicializacneho vektora (IV) - bud povodny (ked je prvy
  * blok) alebo predchadzajuci sifrovany blok
  * 2. Spracovanie vstupnych dat z hexadecimalneho formatu
  * 3. Volanie AES_CBC funkcie pre sifrovanie alebo desifrovanie
  * 4. Porovnanie vysledku s ocakavanymi hodnotami
  * 5. Zaznam vysledku testu a aktualizacia statistiky
  *
  * Parametre:
  * @param data - Struktura obsahujuca testovacie data
  * @param key - Sifrovaci/desifrovaci kluc
  * @param iv - Pociatocny inicializacny vektor
  * @param prev_ciphertext - Predchadzajuci sifrovany blok pre retazenie
  * @param passed_count - Pocitadlo uspesnych testov
  * @param is_first_block - Flag indikujuci ci ide o prvy blok v retazci
  *
  * Navratova hodnota:
  * @return bool - true ak test prebehol uspesne, inak false
  */
 bool process_test_case(const TestCaseData *data, uint8_t *key, uint8_t *iv,
                        uint8_t *prev_ciphertext, int *passed_count,
                        bool *is_first_block) {
   printf("\nTest #%d (Block #%d, %s):\n", data->count, data->block_number,
          data->is_encrypt ? "Encrypt" : "Decrypt");
 
   uint8_t current_iv[IV_SIZE];  // Aktualny inicializacny vektor
   uint8_t plaintext[BLOCK_SIZE] = {0};  // Nezasifrovane data
   uint8_t ciphertext[BLOCK_SIZE] = {0};  // Zasifrovane data
   uint8_t result[BLOCK_SIZE] = {0};  // Vysledny buffer
 
   // V CBC rezime kazdy blok pouziva ako IV predchadzajuci zasifrovany blok
   if (*is_first_block) {
     memcpy(current_iv, iv, IV_SIZE);  // Pre prvy blok pouzijeme povodny IV
     *is_first_block = false;
   } else {
     memcpy(current_iv, prev_ciphertext, IV_SIZE);  // Pre dalsie bloky pouzijeme predchadzajuci ciphertext
   }
 
   bool success = false;
 
   // Vetva pre sifrovanie
   if (data->is_encrypt) {
     // Prevod plaintextu z hexadecimalneho retazca na binarne data
     if (hex_to_bin(data->hex_plaintext, plaintext, BLOCK_SIZE) != 0) {
       fprintf(stderr, "Error parsing PLAINTEXT hex for test %d.\n",
               data->count);
       return false;
     }
 
     // Vypis vstupnych parametrov
     printf("Kluc: ");
     print_hex(key, strlen(data->hex_key) / 2);
     printf("IV/Predchadzajuci ciphertext: ");
     print_hex(current_iv, 16);
     printf("Plaintext: ");
     print_hex(plaintext, 16);
 
     // Volanie funkcie na sifrovanie v rezime CBC
     AES_CBC_encrypt(key, current_iv, plaintext, BLOCK_SIZE, result);
     memcpy(prev_ciphertext, result, BLOCK_SIZE);  // Ulozenie vysledku pre dalsie bloky
 
     // Vypis vysledku
     printf("Vypocitany ciphertext: ");
     print_hex(result, 16);
 
     // Kontrola spravnosti vysledku
     uint8_t expected_ciphertext[BLOCK_SIZE];
     if (hex_to_bin(data->hex_ciphertext, expected_ciphertext, BLOCK_SIZE) != 0) {
       return false;
     }
 
     printf("Ocakavany ciphertext: ");
     print_hex(expected_ciphertext, 16);
 
     success = (memcmp(result, expected_ciphertext, BLOCK_SIZE) == 0);
   } 
   // Vetva pre desifrovanie
   else {
     // Prevod ciphertextu z hexadecimalneho retazca na binarne data
     if (hex_to_bin(data->hex_ciphertext, ciphertext, 16) != 0) {
       return false;
     }
 
     memcpy(prev_ciphertext, ciphertext, 16);  // Ulozenie ciphertextu pre dalsie bloky
 
     // Vypis vstupnych parametrov
     printf("Kluc: ");
     print_hex(key, strlen(data->hex_key) / 2);
     printf("IV/Predchadzajuci ciphertext: ");
     print_hex(current_iv, 16);
     printf("Ciphertext: ");
     print_hex(ciphertext, 16);
 
     // Volanie funkcie na desifrovanie v rezime CBC
     char status = AES_CBC_decrypt(key, current_iv, ciphertext, BLOCK_SIZE, result);
     if (status != 0) {
       printf("Desifrovanie zlyhalo so statusom %d\n", status);
       return false;
     }
 
     // Vypis vysledku
     printf("Vypocitany plaintext: ");
     print_hex(result, BLOCK_SIZE);
 
     // Kontrola spravnosti vysledku
     uint8_t expected_plaintext[BLOCK_SIZE];
     if (hex_to_bin(data->hex_plaintext, expected_plaintext, BLOCK_SIZE) != 0) {
       return false;
     }
 
     printf("Ocakavany plaintext: ");
     print_hex(expected_plaintext, BLOCK_SIZE);
 
     success = (memcmp(result, expected_plaintext, BLOCK_SIZE) == 0);
   }
 
   // Vyhodnotenie testu
   if (success) {
     (*passed_count)++;
     printf("Test USPESNY\n");
   } else {
     printf("Test NEUSPESNY\n");
   }
 
   return success;
 }
 
 /**
  * Spracovanie testovacich dat zo suboru
  *
  * Popis: Funkcia nacitava testovacie vektory zo suboru, spracovava ich
  * po riadkoch a identifikuje jednotlive casti testovacich prikladov.
  * Ak su testovacie vektory kompletne vykonana otestuje ich.
  *
  * Proces:
  * 1. Nacitavanie a spracovanie vstupneho suboru riadok po riadku
  * 2. Klasifikacia riadkov pomocou funkcie get_line_type
  * 3. Spracovanie a ulozenie dat podla ich typu
  * 4. Spustenie testovania ked su vsetky potrebne data k dispozicii
  * 5. Prepinanie medzi rezimami sifrovania a desifovania podla 
  *    identifikatorov v testovacich vektoroch
  *
  * Parametre:
  * @param fp - Pointer na otvoreny subor s testovacimi vektormi
  * @param data - Struktura pre ulozenie testovacich dat
  * @param key - Pole pre ulozenie sifrovacieho kluca
  * @param iv - Pole pre ulozenie inicializacneho vektora
  * @param prev_ciphertext - Pole pre ulozenie predchadzajuceho sifrovaneho bloku
  * @param test_count - Pocitadlo vykonanych testov
  * @param passed_count - Pocitadlo uspesnych testov
  * @param is_first_block - Flag indikujuci ci ide o prvy blok
  *
  * Navratova hodnota:
  * @return bool - true ak spracovanie bolo uspesne, inak false
  */
 bool parse_test_data(FILE *fp, TestCaseData *data, uint8_t *key,
                      uint8_t *iv, uint8_t *prev_ciphertext,
                      int *test_count, int *passed_count,
                      bool *is_first_block) {
   char line[CBC_LINE_BUFFER_SIZE];
   static bool encrypt_mode = true;  // Predvoleny rezim je sifrovanie
 
   while (fgets(line, sizeof(line), fp)) {
     size_t len = strlen(line);
     // Odstranenie znakov noveho riadka a navratu vozika
     while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
       line[--len] = '\0';
 
     if (len == 0)
       continue;  // Preskocenie prazdnych riadkov
 
     char *trimmed = trim(line);  // Odstranenie medzier na zaciatku a konci
     LineType type = get_line_type(trimmed);  // Urcenie typu riadku
 
     switch (type) {
     case MODE_CHANGE:
       // Prepnutie medzi rezimom sifrovania a desifrovania
       if (strstr(trimmed, "Encrypt") != NULL) {
         encrypt_mode = true;
         *is_first_block = true;  // Novy rezim znamena novy prvy blok
         printf("\n=== Testovanie sifrovania (Encrypt) ===\n");
       } else if (strstr(trimmed, "Decrypt") != NULL) {
         encrypt_mode = false;
         *is_first_block = true;  // Novy rezim znamena novy prvy blok
         printf("\n=== Testovanie desifrovania (Decrypt) ===\n");
       }
       break;
 
     case KEY:
       // Nacitanie kluca (kluc + 4 preskoci "Key " na zaciatku riadku)
       free(data->hex_key);
       data->hex_key = strdup(trim(line + 4));  // Odstranenie "Key " a medzier
       hex_to_bin(data->hex_key, key, strlen(data->hex_key) / 2);  // Konverzia hex na bin
       break;
 
     case IV:
       // Nacitanie inicializacneho vektora (IV + 3 preskoci "IV " na zaciatku riadku)
       free(data->hex_iv);
       data->hex_iv = strdup(trim(line + 3));  // Odstranenie "IV " a medzier
       if (hex_to_bin(data->hex_iv, iv, IV_SIZE) != 0) {  // IV ma vzdy IV_SIZE bajtov (128 bitov)
         free(data->hex_iv);
         data->hex_iv = NULL;
       }
       *is_first_block = true;  // Novy IV znamena novy prvy blok
       break;
 
     case BLOCK:
       // Nacitanie cisla bloku
       data->block_number = atoi(line + 7);  // Konverzia string na int 
       if (data->block_number == 1) {
         *is_first_block = true;  // Blok #1 vzdy pouziva orig. IV
       }
       break;
 
     case PLAINTEXT:
       // Nacitanie plaintextu
       if (encrypt_mode) {
         // V rezime sifrovania potrebujeme plaintext ako vstup
         free(data->hex_plaintext);
         data->hex_plaintext = strdup(trim(line + 10));  // Odstranenie "Plaintext " a medzier
       } else {
         // V rezime desifrovania potrebujeme plaintext na overenie vysledku
         free(data->hex_plaintext);
         data->hex_plaintext = strdup(trim(line + 10));  // Odstranenie "Plaintext " a medzier
 
         // Ak mame vsetky potrebne udaje, mozeme spustit test desifrovania
         if (data->hex_key && data->hex_iv && data->hex_ciphertext &&
             data->hex_plaintext) {
           (*test_count)++;
           data->count = *test_count;
           data->is_encrypt = encrypt_mode;
 
           process_test_case(data, key, iv, prev_ciphertext, passed_count,
                             is_first_block);
         }
       }
       break;
 
     case CIPHERTEXT:
       // Nacitanie ciphertextu
       if (!encrypt_mode) {
         // V rezime desifrovania potrebujeme ciphertext ako vstup
         free(data->hex_ciphertext);
         data->hex_ciphertext = strdup(trim(line + 11));  // Odstranenie "Ciphertext " a medzier
       } else {
         // V rezime sifrovania potrebujeme ciphertext na overenie vysledku
         free(data->hex_ciphertext);
         data->hex_ciphertext = strdup(trim(line + 11));  // Odstranenie "Ciphertext " a medzier
 
         // Ak mame vsetky potrebne udaje, mozeme spustit test sifrovania
         if (data->hex_key && data->hex_iv && data->hex_plaintext &&
             data->hex_ciphertext) {
           (*test_count)++;
           data->count = *test_count;
           data->is_encrypt = encrypt_mode;
 
           process_test_case(data, key, iv, prev_ciphertext, passed_count,
                             is_first_block);
         }
       }
       break;
 
     case UNKNOWN:
       // Neznamy typ riadku - ignorujeme
       break;
     }
   }
 
   return false;  // Koniec suboru
 }
 
 /**
  * Hlavna funkcia programu
  *
  * Popis: Hlavna funkcia inicializuje program, otvara subor s testovacimi
  * vektormi, spusta spracovanie a testovanie, a na zaver zobrazuje
  * celkovu statistiku testov. Automaticky vyberie spravny testovaci
  * subor podla skompilovanej velkosti kluca.
  *
  * Proces:
  * 1. Urcenie spravneho suboru s testovacimi vektormi podla velkosti kluca
  * 2. Otvorenie suboru a kontrola chyb
  * 3. Inicializacia pomocnych premennych a struktur
  * 4. Spustenie spracovania a testovania
  * 5. Cistenie pamate a zobrazenie vysledkov
  *
  * Navratova hodnota:
  * @return int - 0 pri uspesnom dokonceni, 1 ked sa nepodarilo otvorit subor
  */
 int main() {
   // Vyber spravneho testovacieho suboru podla predkompilovanej velkosti kluca
 #if AES___ == 256
   const char *test_vectors_file = "test_vectors/cbc_256.txt";
   printf("Program skompilovany pre AES-256 CBC rezim\n");
 #elif AES___ == 192
   const char *test_vectors_file = "test_vectors/cbc_192.txt";
   printf("Program skompilovany pre AES-192 CBC rezim\n");
 #else
   const char *test_vectors_file = "test_vectors/cbc_128.txt";
   printf("Program skompilovany pre AES-128 CBC rezim\n");
 #endif
 
   printf("Pouziva sa testovaci subor: %s\n", test_vectors_file);
 
   // Otvorenie suboru s testovacimi vektormi
   FILE *fp = fopen(test_vectors_file, "r");
   if (!fp) {
     perror("Nepodarilo sa otvorit subor s testovacimi vektormi");
     return 1;
   }
 
   // Inicializacia pamate pre kluc, IV a predchadzajuci ciphertext
   uint8_t key[AES_MAX_KEY_SIZE] = {0}; // Max 256 bitov (32 bajtov)
   uint8_t iv[IV_SIZE] = {0};  // IV je vzdy 16 bajtov
   uint8_t prev_ciphertext[BLOCK_SIZE] = {
       0}; // Pre ulozenie predchadzajuceho ciphertextu
 
   // Priprava struktur a pocitadiel pre testovanie
   TestCaseData test_data = {0};
   int test_count = 0;
   int passed_count = 0;
   bool is_first_block = true;
 
   // Spracovanie dat a vykonanie testov
   parse_test_data(fp, &test_data, key, iv, prev_ciphertext, &test_count,
                   &passed_count, &is_first_block);
 
   // Vycistenie pamate a zatvorenie suboru
   fclose(fp);
   free_test_case_data(&test_data);
 
   // Zobrazenie celkoveho vysledku testovania
   printf("\nTestovanie dokoncene: %d/%d uspesnych\n", passed_count,
          test_count);
 
   return 0;
 }