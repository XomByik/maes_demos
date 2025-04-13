/************************************************************************
 * Nazov projektu: Demonstracia funkcnosti rezimov AES-u z kniznice micro-AES
 * -----------------------------------------------------------------------
 * Subor: ecb_demo.c
 * Verzia: 1.1
 * Datum: 13.4.2025
 *
 * Autor: Kamil Berecky
 *
 * Popis: Program demonstruje funkcnost rezimu AES-ECB pomocou oficialnych
 * testovacich vektorov. Implementuje sifrovanie a desifrovanie blokov dat
 * bez pouzitia inicializacneho vektora a porovnava vysledky s ocakavanymi
 * hodnotami zo standardizovanych testovacich vektorov. Program podporuje
 * rozne velkosti klucov (128, 192, 256 bitov).
 * 
 * Vyuzite zdroje:
 * - micro-AES kniznica: 
 *   https://github.com/polfosol/micro-AES
 * - NIST SP 800-38A (2001): 
 *   https://doi.org/10.6028/NIST.SP.800-38A
 *
 * Pre viac info pozri README.md
 **********************************************************************/

 #include "../header_files/ecb.h"

 /**
  * Enum pre rozlisenie typov riadkov v testovacom subore
  */
 typedef enum {
   KEY,          // Riadok obsahujuci kluc
   PLAINTEXT,    // Riadok obsahujuci nezasifrovane data
   CIPHERTEXT,   // Riadok obsahujuci zasifrovane data
   BLOCK,        // Riadok oznacujuci blok dat
   MODE_CHANGE,  // Riadok oznacujuci zmenu modu (encrypt/decrypt)
   UNKNOWN       // Neznamy typ riadku
 } LineType;
 
 /**
  * Urci typ riadku v testovacom subore
  *
  * Popis: Funkcia analyzuje vstupny riadok a urcuje jeho typ podla
  * obsahu klucovych slov na zaciatku riadku.
  *
  * Proces:
  * 1. Porovnanie zaciatku riadku s ocakavanymi prefixami
  * 2. Kontrola obsahu retazca na specialne klucove slova
  * 3. Vratenie zodpovedajuceho typu riadku
  *
  * Parametre:
  * @param line - Vstupny riadok na analyzu
  *
  * Navratova hodnota:
  * @return LineType - Enum hodnota reprezentujuca typ riadku
  */
 static LineType get_line_type(const char *line) {
   if (strncmp(line, ECB_PREFIX_KEY, ECB_PREFIX_LEN_KEY) == 0)
     return KEY;  // Riadok obsahuje kluc
   if (strncmp(line, ECB_PREFIX_PLAINTEXT, ECB_PREFIX_LEN_PLAINTEXT) == 0)
     return PLAINTEXT;  // Riadok obsahuje plaintext (nezasifrovane data)
   if (strncmp(line, ECB_PREFIX_CIPHERTEXT, ECB_PREFIX_LEN_CIPHERTEXT) == 0)
     return CIPHERTEXT;  // Riadok obsahuje ciphertext (zasifrovane data)
   if (strncmp(line, ECB_PREFIX_BLOCK, ECB_PREFIX_LEN_BLOCK) == 0)
     return BLOCK;  // Riadok oznacuje cislo bloku
   if (strstr(line, ECB_MODE_IDENTIFIER) != NULL)
     return MODE_CHANGE;  // Riadok indikuje zmenu modu (encrypt/decrypt)
   return UNKNOWN;  // Neznamy typ riadku, bude ignorovany
 }
 
 /**
  * Extrahuje hodnotu za danym prefixom v riadku
  *
  * Popis: Funkcia hlada zadany prefix v riadku a vracia kopiu hodnoty,
  * ktora nasleduje za nim, s odstranenym odsadenim.
  *
  * Proces:
  * 1. Najdenie pozicie prefixu v riadku
  * 2. Preskocenie prefixu a vektornych medzier za nim
  * 3. Kopirovanie a ocistenie vysledneho retazca
  *
  * Parametre:
  * @param line - Vstupny riadok na spracovanie
  * @param prefix - Hladany prefix
  *
  * Navratova hodnota:
  * @return char* - Novo-alokovany retazec s hodnotou, NULL ak prefix nebol najdeny
  */
 static char *get_line_value(const char *line, const char *prefix) {
   const char *start = strstr(line, prefix);  // Najdenie pozicie prefixu
   if (!start)
     return NULL;  // Prefix nebol najdeny
     
   start += strlen(prefix);  // Preskocenie prefixu
   while (isspace(*start))
     start++;  // Preskocenie medzier za prefixom
 
   char *temp = strdup(start);  // Vytvorenie kopie retazca
   if (temp) {
     char *trimmed = trim(temp);  // Odstranenie medzier na zaciatku a konci
     if (trimmed != temp) {
       memmove(temp, trimmed, strlen(trimmed) + 1);  // Posun ocisteneho retazca na zaciatok
     }
   }
   return temp;  // Vratenie vysledneho retazca
 }
 
 /**
  * Uvolni pamat alokovanu pre testovacie data
  *
  * Popis: Funkcia uvolnuje vsetky dynamicky alokovane retazce
  * zo struktury TestCaseData a vynuluje celu strukturu.
  *
  * Proces:
  * 1. Kontrola ci vstupny pointer nie je NULL
  * 2. Uvolnenie alokovanych retazcov
  * 3. Vynulovanie struktury pre bezpecnost
  *
  * Parametre:
  * @param data - Pointer na strukturu s testovacimi datami
  */
 void free_test_case_data(TestCaseData *data) {
   if (!data)
     return;  // Ochrana pred NULL pointerom
     
   free(data->hex_key);  // Uvolnenie kluca
   free(data->hex_plaintext);  // Uvolnenie plaintextu
   free(data->hex_ciphertext);  // Uvolnenie ciphertextu
   memset(data, 0, sizeof(TestCaseData));  // Vynulovanie celej struktury pre bezpecnost
 }
 
 /**
  * Nacita nasledujuci testovaci vektor zo suboru
  *
  * Popis: Funkcia cita data zo suboru a nacitava hodnoty pre nasledujuci
  * testovaci vektor. Udrzuje informacie o aktualnom stave spracovania a
  * podporuje postupne nacitanie klucov, plaintextov a ciphertextov.
  *
  * Proces:
  * 1. Inicializacia premennych a uvolnenie predchadzajucich dat
  * 2. Citanie riadkov zo suboru a ich spracovanie podla typu
  * 3. Detekcia kompletneho testovacieho vektora
  * 4. Automaticke cislovanie testovacich vektorov
  *
  * Parametre:
  * @param fp - Pointer na otvoreny subor na citanie
  * @param data - Struktura pre ulozenie dat testovacieho vektora
  *
  * Navratova hodnota:
  * @return bool - true ak sa podarilo nacitat kompletny testovaci vektor, false inak
  */
 bool parse_next_test_case(FILE *fp, TestCaseData *data) {
   char line[ECB_LINE_BUFFER_SIZE];  // Buffer pre citanie riadku
   static int current_count = 0;  // Staticke pocitadlo testov
   static bool is_encrypt = false;  // Aktualny mod (sifrovanie/desifrovanie)
   static char *current_key = NULL;  // Globalne uchovany kluc
   char *value = NULL;  // Pomocna premenna pre docasne hodnoty
   bool in_test_case = false;  // Priznak ci sme vo vnutri testovacieho vektora
   long start_pos;  // Pozicia v subore pre vratenie kurzora
 
   // Uchovaj si predchadzajuci kluc 
   char *prev_key = data->hex_key ? strdup(data->hex_key) : NULL;  // Kopirovanie aktualneho kluca
   free_test_case_data(data);  // Uvolnenie vsetkych dat z predchadzajuceho testu
 
   // Nastav kluc z predchadzajuceho behu alebo globalneho kluca
   data->hex_key =
       prev_key ? prev_key : (current_key ? strdup(current_key) : NULL);
   data->is_encrypt = is_encrypt;  // Nastav aktualny mod
 
   // Citanie suboru po riadkoch
   while (fgets(line, sizeof(line), fp)) {
     char *trimmed = trim(line);  // Odstranenie medzier zo zaciatku a konca
     if (!trimmed || !*trimmed)
       continue;  // Preskocenie prazdnych riadkov
 
     start_pos = ftell(fp);  // Zapamataj si aktualnu poziciu v subore
     LineType type = get_line_type(trimmed);  // Urcenie typu riadku
 
     switch (type) {
     case MODE_CHANGE:  // Riadok oznacujuci prepnutie modu (encrypt/decrypt)
       is_encrypt = (strstr(trimmed, ECB_MODE_ENCRYPT) != NULL);  // Detekcia modu encrypt
       data->is_encrypt = is_encrypt;  // Aktualizacia modu v strukture
       data->block_number = 0;  // Reset cisla bloku pre novy mod
       in_test_case = true;  // Indikacia ze sme vo vnutri testovacieho vektora
       free(current_key);  // Uvolnenie globalneho kluca pri zmene modu
       current_key = NULL;  // Reset pointera
       break;
 
     case BLOCK:  // Riadok oznacujuci cislo bloku
       // Ak mame kompletny test, vrat ho pred spracovanim noveho bloku
       if (in_test_case && data->hex_key && data->hex_plaintext &&
           data->hex_ciphertext) {
         fseek(fp, start_pos, SEEK_SET);  // Vrat kurzor na zaciatok tohto riadku
         if (!data->count)
           data->count = ++current_count;  // Automaticke cislovanie
         return true;  // Vratime kompletny testovaci vektor
       }
       data->block_number = atoi(trimmed + ECB_PREFIX_LEN_BLOCK);  // Extrakcia cisla bloku
       break;
 
     case KEY:  // Riadok obsahujuci kluc
       value = get_line_value(trimmed, ECB_PREFIX_KEY);  // Ziskanie hodnoty kluca
       if (value) {
         free(current_key);  // Uvolnenie aktualneho globalneho kluca
         current_key = strdup(value);  // Ulozenie noveho globalneho kluca
         free(data->hex_key);  // Uvolnenie stareho kluca v strukture
         data->hex_key = value;  // Nastavenie noveho kluca
         value = NULL;  // Zabranenie uvolneniu hodnoty kluca nizsie
       }
       break;
 
     case PLAINTEXT:  // Riadok obsahujuci plaintext
       value = get_line_value(trimmed, ECB_PREFIX_PLAINTEXT);  // Ziskanie hodnoty plaintextu
       if (value) {
         free(data->hex_plaintext);  // Uvolnenie stareho plaintextu
         data->hex_plaintext = value;  // Nastavenie noveho plaintextu
         value = NULL;  // Zabranenie uvolneniu hodnoty plaintextu nizsie
       }
       break;
 
     case CIPHERTEXT:  // Riadok obsahujuci ciphertext
       value = get_line_value(trimmed, ECB_PREFIX_CIPHERTEXT);  // Ziskanie hodnoty ciphertextu
       if (value) {
         free(data->hex_ciphertext);  // Uvolnenie stareho ciphertextu
         data->hex_ciphertext = value;  // Nastavenie noveho ciphertextu
         value = NULL;  // Zabranenie uvolneniu hodnoty ciphertextu nizsie
       }
       break;
       
     case UNKNOWN:  // Neznamy typ riadku
       // Ignorujeme neznamy riadok
       break;
     }
 
     free(value);  // Uvolnenie pomocnej premennej, ak nebola nastavena na NULL
 
     // Kontrola ci mame kompletny test
     if (data->hex_key && data->block_number > 0 && data->hex_plaintext &&
         data->hex_ciphertext) {
       if (!data->count)
         data->count = ++current_count;  // Automaticke cislovanie
       return true;  // Vratime kompletny testovaci vektor
     }
   }
 
   // Koniec suboru, skontrolujeme ci mame kompletny test
   if (data->hex_key && data->block_number > 0 && data->hex_plaintext &&
       data->hex_ciphertext) {
     if (!data->count)
       data->count = ++current_count;  // Automaticke cislovanie
     return true;  // Vratime kompletny testovaci vektor
   }
 
   free(prev_key);  // Uvolnenie docasneho kluca
   return false;  // Nepodarilo sa nacitat kompletny testovaci vektor
 }
 
 /**
  * Spracuje a vyhodnoti jeden testovaci vektor
  *
  * Popis: Hlavna funkcia, ktora vykonava samotne testovanie jedneho ECB
  * testovacieho vektora. Obsahuje sifrovanie, desifrovanie a porovnanie 
  * vysledkov s ocakavanymi hodnotami.
  *
  * Proces:
  * 1. Kontrola velkosti vstupnych dat
  * 2. Konverzia hexadecimalnych retazcov na binarne data
  * 3. Vykonanie sifrovania alebo desifrovania podla modu
  * 4. Porovnanie vysledkov s ocakavanymi hodnotami
  * 5. Aktualizacia statistiky testov
  *
  * Parametre:
  * @param data - Struktura obsahujuca testovacie data
  * @param passed_encrypt - Pointer na pocitadlo uspesnych encrypt testov
  * @param passed_decrypt - Pointer na pocitadlo uspesnych decrypt testov
  *
  * Navratova hodnota:
  * @return bool - true ak sa test uspesne spracoval (nezavisle od vysledku), false pri chybe
  */
 bool process_test_case(const TestCaseData *data, int *passed_encrypt,
                        int *passed_decrypt) {
   size_t key_len = strlen(data->hex_key) / 2;  // Dlzka kluca v bajtoch
   size_t pt_len =
       data->hex_plaintext ? strlen(data->hex_plaintext) / 2 : 0;  // Dlzka plaintextu v bajtoch
   size_t ct_len =
       data->hex_ciphertext ? strlen(data->hex_ciphertext) / 2 : 0;  // Dlzka ciphertextu v bajtoch
 
   // Kontrola velkosti blokov
   if (pt_len != ECB_BLOCK_SIZE || ct_len != ECB_BLOCK_SIZE) {
     printf("Neplatna velkost bloku - musi byt %d bajtov\n", ECB_BLOCK_SIZE);
     return false;  // Neplatna velkost bloku
   }
 
   // Inicializacia bufferov
   uint8_t key[ECB_MAX_KEY_SIZE] = {0};  // Buffer pre kluc
   uint8_t plaintext[ECB_BLOCK_SIZE] = {0};  // Buffer pre plaintext
   uint8_t ciphertext[ECB_BLOCK_SIZE] = {0};  // Buffer pre ciphertext
   uint8_t result[ECB_BLOCK_SIZE] = {0};  // Buffer pre vysledok operacie
   bool success = false;  // Predvolena hodnota uspesnosti testu
 
   // Konverzia hex na binarne hodnoty
   if (hex_to_bin(data->hex_key, key, key_len) != 0 ||
       hex_to_bin(data->hex_plaintext, plaintext, pt_len) != 0 ||
       hex_to_bin(data->hex_ciphertext, ciphertext, ct_len) != 0) {
     return false;  // Chyba pri konverzii hex -> bin
   }
 
   // Vypis informacii o teste
   printf("=== Test #%d (Block #%d) ===\n", data->count,
          data->block_number);
   printf("Vstupne data:\n");
   printf("  Kluc: ");
   print_limited(data->hex_key, ECB_MAX_LINE_LENGTH);  // Vypis kluca s obmedzenim dlzky
 
   // Vetva pre sifrovanie
   if (data->is_encrypt) {
     printf("\nTest sifrovania:\n");
     printf("  Plaintext: ");
     print_limited(data->hex_plaintext, ECB_MAX_LINE_LENGTH);  // Vypis plaintextu
 
     // Volanie funkcie na sifrovanie v rezime ECB
     AES_ECB_encrypt(key, plaintext, ECB_BLOCK_SIZE, result);
 
     // Vypis vysledkov sifrovania
     printf("  Vypocitany ciphertext: ");
     print_hex(result, ECB_BLOCK_SIZE);
     printf("  Ocakavany ciphertext: ");
     print_hex(ciphertext, ECB_BLOCK_SIZE);
 
     // Kontrola vysledku
     success = (memcmp(result, ciphertext, ECB_BLOCK_SIZE) == 0);
     if (success)
       (*passed_encrypt)++;  // Inkrementacia uspesnych testov sifrovania
 
   } else {  // Vetva pre desifrovanie
     printf("\nTest desifrovania:\n");
     printf("  Ciphertext: ");
     print_limited(data->hex_ciphertext, ECB_MAX_LINE_LENGTH);  // Vypis ciphertextu
 
     // Volanie funkcie na desifrovanie v rezime ECB
     char status = AES_ECB_decrypt(key, ciphertext, ECB_BLOCK_SIZE, result);
 
     // Kontrola navratovej hodnoty
     if (status != 0) {
       printf("  Desifrovanie zlyhalo so statusom %d\n", status);
       return true;  // Vraciame true aj ked desifrovanie zlyhalo, kedze test prebehol
     }
 
     // Vypis vysledkov desifrovania
     printf("  Vypocitany plaintext: ");
     print_hex(result, ECB_BLOCK_SIZE);
     printf("  Ocakavany plaintext: ");
     print_hex(plaintext, ECB_BLOCK_SIZE);
 
     // Kontrola vysledku
     success = (memcmp(result, plaintext, ECB_BLOCK_SIZE) == 0);
     if (success)
       (*passed_decrypt)++;  // Inkrementacia uspesnych testov desifrovania
   }
 
   // Vypis vysledku testu
   printf("  Vysledok: %s\n\n", success ? "USPESNY" : "NEUSPESNY");
   return true;  // Test bol uspesne spracovany (nezavisle od vysledku)
 }
 
 /**
  * Hlavna funkcia programu
  *
  * Popis: Hlavna funkcia inicializuje program, otvara subor s testovacimi
  * vektormi, spusta spracovanie a testovanie jednotlivych vektorov,
  * a na zaver zobrazuje celkovu statistiku uspesnosti testov.
  *
  * Proces:
  * 1. Vyberie spravny testovaci subor podla velkosti kluca
  * 2. Otvori testovaci subor a kontroluje chyby
  * 3. Spracuje testovacie vektory v cykle
  * 4. Zobrazi celkovu statistiku testov
  * 5. Vrati navratovy kod podla uspesnosti testov
  *
  * Navratova hodnota:
  * @return int - 0 ak vsetky testy uspesne, 1 ak nie
  */
 int main() {
   const char *test_vectors_file;  // Nazov suboru s testovacimi vektormi
 
   // Zistenie velkosti kluca z kompilacnych nastaveni
 #if AES___ == 256
   test_vectors_file = ECB_TEST_VECTORS_256;  // Pre 256-bitovy kluc
   printf("AES-256 ECB Test\n");
 #elif AES___ == 192
   test_vectors_file = ECB_TEST_VECTORS_192;  // Pre 192-bitovy kluc
   printf("AES-192 ECB Test\n");
 #else
   test_vectors_file = ECB_TEST_VECTORS_128;  // Pre 128-bitovy kluc (predvolene)
   printf("AES-128 ECB Test\n");
 #endif
 
   printf("Pouziva sa testovaci subor: %s\n", test_vectors_file);
 
   // Otvorenie testovacieho suboru
   FILE *fp = fopen(test_vectors_file, "r");
   if (!fp) {
     perror("Nepodarilo sa otvorit subor s testovacimi vektormi");
     return 1;  // Chybovy navratovy kod
   }
 
   // Inicializacia premennych pre testovanie
   int tests_passed_encrypt = 0;  // Pocitadlo uspesnych testov sifrovania
   int tests_passed_decrypt = 0;  // Pocitadlo uspesnych testov desifrovania
   TestCaseData current_test = {0};  // Struktura pre aktualny test
   int processed_tests = 0;  // Pocitadlo spracovanych testov
 
   // Spracovanie testovacich vektorov v cykle
   while (parse_next_test_case(fp, &current_test)) {
     processed_tests++;  // Inkrementacia pocitadla spracovanych testov
     process_test_case(&current_test, &tests_passed_encrypt,
                       &tests_passed_decrypt);  // Spracovanie aktualneho testu
     free_test_case_data(&current_test);  // Uvolnenie pamate
   }
 
   fclose(fp);  // Zatvorenie suboru
 
   // Vyhodnotenie celkovej uspesnosti testov
   int total_passed = tests_passed_encrypt + tests_passed_decrypt;  // Celkovy pocet uspesnych testov
   bool success = (processed_tests > 0 && total_passed == processed_tests);  // Celkova uspesnost
 
   // Zobrazenie celkovej statistiky
   printf("\nCelkove vysledky:\n");
   printf("Spracovanych testov: %d\n", processed_tests);
   printf("Uspesnych testov sifrovania: %d\n", tests_passed_encrypt);
   printf("Uspesnych testov desifrovania: %d\n", tests_passed_decrypt);
   printf("Celkovy vysledok: %s\n", success ? "USPESNY" : "NEUSPESNY");
 
   return success ? 0 : 1;  // Vratenie navratoveho kodu podla celkovej uspesnosti
 }