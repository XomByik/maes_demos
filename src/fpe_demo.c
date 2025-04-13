/************************************************************************
 * Nazov projektu: Demonstracia funkcnosti rezimov AES-u z kniznice micro-AES
 * -----------------------------------------------------------------------
 * Subor: fpe_demo.c
 * Verzia: 1.1
 * Datum: 13.4.2025
 *
 * Autor: Kamil Berecky
 *
 * Popis: Program demonstruje funkcnost rezimu AES-FPE pomocou oficialnych
 * testovacich vektorov. Implementuje sifrovanie a desifrovanie s formatom
 * zachovavajucim sifrovanim podla algoritmov FF1 a FF3-1. Program podporuje
 * rozne velkosti klucov (128, 192, 256 bitov) a tento priklad pracuje s 
 * ciselnou abecedou.
 * 
 * Vyuzite zdroje:
 * - micro-AES kniznica: 
 *   https://github.com/polfosol/micro-AES
 * - NIST SP 800-38G (2016): 
 *   https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf
 *
 * Pre viac info pozri README.md
 **********************************************************************/

 #include "../header_files/fpe.h"

 /**
  * Enum pre rozlisenie typov riadkov v testovacom subore
  */
 typedef enum {
   LINE_COUNT,     // Riadok obsahujuci cislo testu
   LINE_METHOD,    // Riadok obsahujuci metodu (FF1 alebo FF3)
   LINE_ALPHABET,  // Riadok obsahujuci abecedu
   LINE_KEY,       // Riadok obsahujuci sifrovaci kluc
   LINE_TWEAK,     // Riadok obsahujuci tweak hodnotu
   LINE_PT,        // Riadok obsahujuci plaintext
   LINE_CT,        // Riadok obsahujuci ciphertext
   LINE_UNKNOWN    // Neznamy typ riadku
 } LineType;
 
 /**
  * Urci typ riadku v testovacom subore
  *
  * Popis: Funkcia analyzuje vstupny riadok a urcuje jeho typ podla
  * pritomnosti klucovych slov na zaciatku riadku.
  *
  * Proces:
  * 1. Kontrola vyskytu roznych prefixov v riadku
  * 2. Vratenie zodpovedajuceho enumeracneho typu
  *
  * Parametre:
  * @param line - Vstupny riadok na analyzu
  *
  * Navratova hodnota:
  * @return LineType - Enum hodnota reprezentujuca typ riadku
  */
 static LineType get_line_type(const char *line) {
   if (strstr(line, FPE_PREFIX_COUNT))
     return LINE_COUNT;  // Riadok s cislom testu
   if (strstr(line, FPE_PREFIX_METHOD))
     return LINE_METHOD;  // Riadok s metodou
   if (strstr(line, FPE_PREFIX_ALPHABET))
     return LINE_ALPHABET;  // Riadok s abecedou
   if (strstr(line, FPE_PREFIX_KEY))
     return LINE_KEY;  // Riadok s klucom
   if (strstr(line, FPE_PREFIX_TWEAK))
     return LINE_TWEAK;  // Riadok s tweak hodnotou
   if (strstr(line, FPE_PREFIX_PT))
     return LINE_PT;  // Riadok s plaintextom
   if (strstr(line, FPE_PREFIX_CT))
     return LINE_CT;  // Riadok s ciphertextom
   return LINE_UNKNOWN;  // Neznamy typ riadku
 }
 
 /**
  * Extrahuje hodnotu za danym prefixom v riadku
  *
  * Popis: Funkcia hlada zadany prefix v riadku a vracia kopiu retazca,
  * ktora nasleduje za nim, s odstranenym odsadenim.
  *
  * Proces:
  * 1. Kontrola ci riadok zacina s danym prefixom
  * 2. Kopirovanie a ocistenie retazca nasledujuceho za prefixom
  * 3. Spracovanie pripadnych medzier v retazci
  *
  * Parametre:
  * @param line - Vstupny riadok na spracovanie
  * @param prefix - Hladany prefix
  *
  * Navratova hodnota:
  * @return char* - Novo-alokovany retazec s hodnotou, NULL ak prefix nebol najdeny
  */
 static char *get_line_value(const char *line, const char *prefix) {
   size_t prefix_len = strlen(prefix);  // Dlzka prefixu
   if (strncmp(line, prefix, prefix_len) == 0) {  // Ak riadok zacina s prefixom
     char *temp = strdup(line + prefix_len);  // Kopirovanie retazca za prefixom
     if (!temp)
       return NULL;  // Zlyhanie alokacie
     char *trimmed = trim(temp);  // Odstranenie nadbytocnych medzier
     if (trimmed != temp) {
       memmove(temp, trimmed, strlen(trimmed) + 1);  // Presun ocisteneho retazca na zaciatok
     }
     return temp;  // Vratenie vysledneho retazca
   }
   return NULL;  // Prefix nebol najdeny
 }
 
 /**
  * Uvolni pamat alokovanu pre testovacie data
  *
  * Popis: Funkcia uvolnuje vsetky dynamicky alokovane retazce
  * zo struktury TestCaseData a vynuluje celu strukturu.
  *
  * Proces:
  * 1. Kontrola ci vstupny pointer nie je NULL
  * 2. Uvolnenie vsetkych alokovanych retazcov
  * 3. Vynulovanie celej struktury pre bezpecnost
  *
  * Parametre:
  * @param data - Pointer na strukturu s testovacimi datami
  */
 void free_test_case_data(TestCaseData *data) {
   if (!data)
     return;  // Ochrana pred NULL pointerom
     
   free(data->count_str);  // Uvolnenie retazca s cislom testu
   free(data->method_str);  // Uvolnenie retazca s metodou
   free(data->alphabet_str);  // Uvolnenie retazca s abecedou
   free(data->hex_key);  // Uvolnenie kluca
   free(data->hex_tweak);  // Uvolnenie tweak hodnoty
   free(data->pt_str);  // Uvolnenie plaintextu
   free(data->expected_ct_str);  // Uvolnenie ocakavaneho ciphertextu
   memset(data, 0, sizeof(TestCaseData));  // Vynulovanie celej struktury pre bezpecnost
 }
 
 /**
  * Nacita nasledujuci testovaci vektor zo suboru
  *
  * Popis: Funkcia cita riadky zo suboru a nacitava hodnoty pre nasledujuci
  * testovaci vektor. Pri dosiahnutii kompletneho vektora ho vrati.
  *
  * Proces:
  * 1. Inicializacia premennych a uvolnenie predchadzajucich dat
  * 2. Citanie riadkov zo suboru a ich spracovanie podla typu
  * 3. Kontinualna kontrola, ci uz mame vsetky potrebne data pre test
  * 4. Vratenie kompletneho testovacieho vektora
  *
  * Parametre:
  * @param fp - Pointer na otvoreny subor na citanie
  * @param data - Struktura pre ulozenie dat testovacieho vektora
  *
  * Navratova hodnota:
  * @return bool - true ak sa podarilo nacitat kompletny testovaci vektor, false inak
  */
 bool parse_next_test_case(FILE *fp, TestCaseData *data) {
   char line[FPE_LINE_BUFFER_SIZE];  // Buffer pre citanie riadkov
   char *value;  // Pomocna premenna pre extrahovane hodnoty
   bool in_test_case = false;  // Priznak, ci sme vo vnutri testovacieho vektora
   long start_pos = ftell(fp);  // Zapamatanie aktualnej pozicie v subore
 
   free_test_case_data(data);  // Uvolnenie predchadzajucich dat
 
   // Citanie suboru riadok po riadku
   while (fgets(line, sizeof(line), fp)) {
     char *trimmed = trim(line);  // Odstranenie medzier zo zaciatku a konca
     if (!trimmed || strlen(trimmed) == 0 || trimmed[0] == '#') {
       if (in_test_case)
         start_pos = ftell(fp);  // Aktualizacia pozicie pre prazdne riadky vo vnutri testu
       continue;  // Preskocenie prazdnych riadkov a komentarov
     }
 
     LineType type = get_line_type(trimmed);  // Urcenie typu riadku
     value = NULL;  // Reset pomocnej premennej
 
     // Spracovanie riadku podla jeho typu
     switch (type) {
     case LINE_COUNT:
       value = get_line_value(trimmed, FPE_PREFIX_COUNT);
       // Ak uz mame kompletny predchadzajuci test, vratime sa naspat v subore
       if (in_test_case && data->hex_key && data->hex_tweak &&
           data->pt_str && data->expected_ct_str && data->method_str &&
           data->alphabet_str) {
         fseek(fp, start_pos, SEEK_SET);  // Vratenie pozicie na zaciatok aktualneho riadku
         free(value);  // Uvolnenie nepouzitej hodnoty
         return true;  // Vratime kompletny test
       }
       if (value) {
         data->count_str = value;  // Ulozenie retazca s cislom testu
         data->count = atoi(value);  // Konverzia na cislo
         in_test_case = true;  // Oznacenie zaciatku noveho testu
         // Inicializacia tweak na prazdny retazec (ak nie je urceny)
         if (!data->hex_tweak) {
           data->hex_tweak = strdup("");  // Vytvorenie prazdneho retazca pre tweak
         }
       }
       break;
 
     case LINE_METHOD:
       value = get_line_value(trimmed, FPE_PREFIX_METHOD);
       if (value) {
         data->method_str = value;  // Ulozenie pouzitej metody (FF1 alebo FF3)
       }
       break;
 
     case LINE_ALPHABET:
       value = get_line_value(trimmed, FPE_PREFIX_ALPHABET);
       if (value) {
         data->alphabet_str = value;  // Ulozenie pouzitej abecedy
       }
       break;
 
     case LINE_KEY:
       value = get_line_value(trimmed, FPE_PREFIX_KEY);
       if (value) {
         data->hex_key = value;  // Ulozenie kluca v hex formate
       }
       break;
 
     case LINE_TWEAK:
       value = get_line_value(trimmed, FPE_PREFIX_TWEAK);
       if (value) {
         free(data->hex_tweak);  // Uvolnenie pripadneho prazdneho retazca
         data->hex_tweak = value;  // Ulozenie tweak hodnoty
       }
       break;
 
     case LINE_PT:
       value = get_line_value(trimmed, FPE_PREFIX_PT);
       if (value) {
         data->pt_str = value;  // Ulozenie plaintextu
       }
       break;
 
     case LINE_CT:
       value = get_line_value(trimmed, FPE_PREFIX_CT);
       if (value) {
         data->expected_ct_str = value;  // Ulozenie ocakavaneho ciphertextu
       }
       break;
 
     case LINE_UNKNOWN:
       // Ignorovanie neznamych typov riadkov
       break;
     }
 
     start_pos = ftell(fp);  // Aktualizacia pozicie pre dalsi riadok
 
     // Po kazdom spracovani riadku skontrolujeme, ci nemame kompletny test
     if (in_test_case && data->hex_key && data->hex_tweak && data->pt_str &&
         data->expected_ct_str && data->method_str && data->alphabet_str) {
       return true;  // Vratime kompletny test
     }
   }
 
   // Koniec suboru - vratime posledny kompletny test, ak existuje
   return (in_test_case && data->hex_key && data->hex_tweak &&
           data->pt_str && data->expected_ct_str && data->method_str &&
           data->alphabet_str);
 }
 
 /**
  * Spracuje a vyhodnoti jeden testovaci vektor
  *
  * Popis: Hlavna funkcia, ktora vykonava samotne testovanie jedneho FPE
  * testovacieho vektora. Obsahuje sifrovanie, desifrovanie a porovnanie
  * vysledkov s ocakavanymi hodnotami.
  *
  * Proces:
  * 1. Validacia vstupnych dat a parametrov
  * 2. Konverzia hex hodnot na binarne data
  * 3. Vykonanie sifrovania a porovnanie s ocakavanymi hodnotami
  * 4. Vykonanie desifrovania a overenie spravnosti
  * 5. Aktualizacia statistiky testov
  *
  * Parametre:
  * @param data - Struktura obsahujuca testovacie data
  * @param passed_encrypt - Pointer na pocitadlo uspesnych encrypt testov
  * @param passed_decrypt - Pointer na pocitadlo uspesnych decrypt testov
  *
  * Navratova hodnota:
  * @return bool - true ak sa test uspesne vykonal, false pri chybe alebo preskoceni testu
  */
 bool process_test_case(const TestCaseData *data, int *passed_encrypt,
                        int *passed_decrypt) {
   // Kontrola vstupnych parametrov
   if (!data || !data->hex_key || !data->pt_str || !data->expected_ct_str ||
       !data->method_str || !data->alphabet_str) {
     fprintf(
         stderr,
         "Chyba: Neplatny ukazovatel v strukture testovacieho vektora.\n");
     return false;  // Chybajuce povinne data
   }
 
   // Zistenie pouzitej metody podla kompilacnych nastaveni
 #if FF_X == 1
   const char *compiled_method = FPE_METHOD_FF1;  // Metoda FF1
 #elif FF_X == 3
   const char *compiled_method = FPE_METHOD_FF3;  // Metoda FF3
 #endif
 
   // Kontrola kompatibility metody
   if (strcmp(data->method_str, compiled_method) != 0) {
     printf("Test #%d - Nezhoda metody (%s vs %s), preskakujem\n",
            data->count, data->method_str, compiled_method);
     return false;  // Nekompatibilna metoda
   }
 
   // Kontrola podporovanej abecedy
   const char *default_alphabet = FPE_DEFAULT_ALPHABET;
   if (strcmp(data->alphabet_str, default_alphabet) != 0) {
     printf("Test #%d - Nepodporovana abeceda '%s', preskakujem\n",
            data->count, data->alphabet_str);
     return false;  // Nepodporovana abeceda
   }
 
   // Dlzky vstupnych dat
   size_t key_len = strlen(data->hex_key) / 2;  // Dlzka kluca v bajtoch (hex->bin)
   size_t tweak_len = strlen(data->hex_tweak) / 2;  // Dlzka tweak hodnoty v bajtoch
   size_t pt_len = strlen(data->pt_str);  // Dlzka plaintextu
   size_t ct_len = strlen(data->expected_ct_str);  // Dlzka ocakavaneho ciphertextu
 
   // Validacia vstupov a kontrola dlzok
   if (pt_len != ct_len) {
     printf("Test #%d - Nerovnaka dlzka PT (%zu) a CT (%zu)\n", data->count,
            pt_len, ct_len);
     return false;  // Nezhoda v dlzke plaintextu a ciphertextu
   }
 
   // Kontrola dlzky kluca (podporovane su 128, 192 a 256 bitov)
   if (key_len != AES_128_KEY_SIZE && key_len != AES_192_KEY_SIZE && key_len != AES_256_KEY_SIZE) {
     printf("Test #%d - Neplatna dlzka kluca (%zu bajtov)\n", data->count,
            key_len);
     return false;  // Neplatna velkost kluca
   }
 
   // Pre FF3 mod kontrolujeme fixnu dlzku tweaku
 #if FF_X == 3
   if (tweak_len != FF3_TWEAK_LEN && tweak_len > 0) {
     printf("Test #%d - Neplatna dlzka tweak-u (%zu bajtov)\n", data->count,
            tweak_len);
     return false;  // Neplatna velkost tweaku pre FF3
   }
 #endif
 
   // Alokacia pamate pre potrebne buffery
   uint8_t *key = calloc(key_len, 1);  // Buffer pre kluc
   uint8_t *tweak = calloc(tweak_len > 0 ? tweak_len : 1, 1);  // Buffer pre tweak
   char *calculated_ct = calloc(pt_len + 1, 1);  // Buffer pre vypocitany ciphertext
   char *decrypted_pt = calloc(pt_len + 1, 1);  // Buffer pre desifrovany plaintext
 
   // Kontrola uspesnosti alokacie
   if (!key || !tweak || !calculated_ct || !decrypted_pt) {
     fprintf(stderr, "Test #%d - Chyba alokacie pamate\n", data->count);
     free(key);
     free(tweak);
     free(calculated_ct);
     free(decrypted_pt);
     return false;  // Zlyhanie alokacie pamate
   }
 
   // Konverzia hex hodnot na binarne data
   if (hex_to_bin(data->hex_key, key, key_len) != 0 ||
       (tweak_len > 0 &&
        hex_to_bin(data->hex_tweak, tweak, tweak_len) != 0)) {
     fprintf(stderr, "Test #%d - Chyba pri konverzii hex hodnot\n",
             data->count);
     free(key);
     free(tweak);
     free(calculated_ct);
     free(decrypted_pt);
     return false;  // Chyba pri konverzii hex->bin
   }
 
   // Vypis informacii o teste
   printf("=== Test #%d ===\n", data->count);
   printf("Vstupne data:\n");
   printf("  Metoda  : %s\n", data->method_str);
   printf("  Abeceda : %s\n", data->alphabet_str);
   printf("  Kluc    : %s\n", data->hex_key);
   printf("  Tweak   : %s\n", data->hex_tweak);
   printf("  PT      : %s\n", data->pt_str);
   printf("  Ocakavane CT: %s\n", data->expected_ct_str);
 
   // Test sifrovania
   printf("\nTest sifrovania:\n");
   char enc_status;  // Navratovy kod sifrovania
 
   // Vykonanie sifrovania podla zvolenej metody
 #if FF_X == 3
   // FF3 ma iny prototyp funkcie bez dlzky tweaku
   enc_status =
       AES_FPE_encrypt(key, tweak, data->pt_str, pt_len, calculated_ct);
 #else // FF1
   enc_status = AES_FPE_encrypt(key, tweak, tweak_len, data->pt_str, pt_len,
                                calculated_ct);
 #endif
 
   // Vyhodnotenie vysledku sifrovania
   bool enc_success = false;
   if (enc_status == NO_ERROR_RETURNED) {  // Uspesne sifrovanie
     printf("  Vypocitany ciphertext: %s\n", calculated_ct);
     printf("  Ocakavany ciphertext: %s\n", data->expected_ct_str);
 
     enc_success = (strcmp(calculated_ct, data->expected_ct_str) == 0);  // Porovnanie s ocakavanym vysledkom
     if (enc_success)
       (*passed_encrypt)++;  // Inkrementacia uspesnych encrypt testov
     printf("  Vysledok sifrovania: %s\n",
            enc_success ? "USPESNY" : "NEUSPESNY");
   } else {
     printf("  Sifrovanie zlyhalo s chybou %d\n", enc_status);  // Vypis chyboveho kodu
   }
 
   // Test desifrovania
   printf("\nTest desifrovania:\n");
   bool dec_success = false;  // Predvolena hodnota uspesnosti
 
   // Desifrovanie vykoname len ak sifrovanie uspesne prebehlo
   if (enc_status == NO_ERROR_RETURNED) {
     char dec_status;  // Navratovy kod desifrovania
 
     // Vykonanie desifrovania podla zvolenej metody
 #if FF_X == 3
     // FF3 ma iny prototyp funkcie bez dlzky tweaku
     dec_status =
         AES_FPE_decrypt(key, tweak, calculated_ct, pt_len, decrypted_pt);
 #else // FF1
     dec_status = AES_FPE_decrypt(key, tweak, tweak_len, calculated_ct,
                                  pt_len, decrypted_pt);
 #endif
 
     // Vyhodnotenie vysledku desifrovania
     if (dec_status == NO_ERROR_RETURNED) {  // Uspesne desifrovanie
       printf("  Vypocitany plaintext: %s\n", decrypted_pt);
       printf("  Povodny plaintext: %s\n", data->pt_str);
 
       dec_success = (strcmp(decrypted_pt, data->pt_str) == 0);  // Porovnanie s povodnym plaintextom
       if (dec_success)
         (*passed_decrypt)++;  // Inkrementacia uspesnych decrypt testov
       printf("  Vysledok desifrovania: %s\n",
              dec_success ? "USPESNY" : "NEUSPESNY");
     } else {
       printf("  Desifrovanie zlyhalo s chybou %d\n", dec_status);  // Vypis chyboveho kodu
     }
   } else {
     printf("  Desifrovanie preskocene (sifrovanie zlyhalo)\n");
   }
 
   // Uvolnenie pamate
   free(key);
   free(tweak);
   free(calculated_ct);
   free(decrypted_pt);
 
   return (enc_success && dec_success);  // Vratime true len ak boli obe operacie uspesne
 }
 
 /**
  * Hlavna funkcia programu
  *
  * Popis: Hlavna funkcia inicializuje program, otvara subor s testovacimi
  * vektormi, spracuje testovacie vektory a spusti testy pre sifrovanie
  * a desifrovanie v FPE rezime.
  *
  * Proces:
  * 1. Vyberie spravny testovaci subor podla pouzitej metody a velkosti kluca
  * 2. Otvori testovaci subor a kontroluje chyby
  * 3. Spracuje testovacie vektory v cykle
  * 4. Zobrazi celkovu statistiku
  *
  * Navratova hodnota:
  * @return int - 0 ak vsetky spracovane testy uspesne, 1 inak
  */
 int main() {
   const char *test_vectors_file;  // Nazov suboru s testovacimi vektormi
   const char *mode_name;  // Nazov pouzitej metody
 
   // Urcenie nazvu metody podla kompilacnych nastaveni
 #if FF_X == 1
   mode_name = FPE_METHOD_FF1;  // FF1 metoda
 #elif FF_X == 3
   mode_name = FPE_METHOD_FF3_1;  // FF3-1 metoda
 #endif
 
   // Vyberie spravny testovaci subor podla velkosti kluca a metody
 #if AES___ == 256
 #if FF_X == 3
   test_vectors_file = FPE_TEST_VECTORS_FF3_256;  // AES-256 FF3
 #else
   test_vectors_file = FPE_TEST_VECTORS_FF1_256;  // AES-256 FF1
 #endif
   printf("AES-256 %s Test\n", mode_name);
 #elif AES___ == 192
 #if FF_X == 3
   test_vectors_file = FPE_TEST_VECTORS_FF3_192;  // AES-192 FF3
 #else
   test_vectors_file = FPE_TEST_VECTORS_FF1_192;  // AES-192 FF1
 #endif
   printf("AES-192 %s Test\n", mode_name);
 #else
 #if FF_X == 3
   test_vectors_file = FPE_TEST_VECTORS_FF3_128;  // AES-128 FF3
 #else
   test_vectors_file = FPE_TEST_VECTORS_FF1_128;  // AES-128 FF1
 #endif
   printf("AES-128 %s Test\n", mode_name);
 #endif
 
   printf("Pouziva sa testovaci subor: %s\n", test_vectors_file);
 
   // Otvorenie testovacieho suboru
   FILE *fp = fopen(test_vectors_file, "r");
   if (!fp) {
     perror("Nepodarilo sa otvorit subor s testovacimi vektormi");
     return 1;  // Chybovy navratovy kod
   }
 
   // Inicializacia premennych pre testovanie
   int tests_passed_encrypt = 0;  // Pocitadlo uspesnych encrypt testov
   int tests_passed_decrypt = 0;  // Pocitadlo uspesnych decrypt testov
   TestCaseData current_test = {0};  // Struktura pre aktualny test
   int processed_tests = 0;  // Pocitadlo spracovanych testov
   int skipped_tests = 0;  // Pocitadlo preskocenych testov
 
   // Spracovanie testovacich vektorov v cykle
   while (parse_next_test_case(fp, &current_test)) {
     // Kontrola spravnej metody (FF1 alebo FF3)
 #if FF_X == 1
     const bool method_ok = (strcmp(current_test.method_str, FPE_METHOD_FF1) == 0);
 #else
     const bool method_ok = (strcmp(current_test.method_str, FPE_METHOD_FF3) == 0);
 #endif
 
     // Kontrola podporovanej abecedy
     const bool alphabet_ok =
         (strcmp(current_test.alphabet_str, FPE_DEFAULT_ALPHABET) == 0);
 
     // Ak metoda alebo abeceda nie je podporovana, test preskocime
     if (!method_ok || !alphabet_ok) {
       skipped_tests++;  // Inkrementacia pocitadla preskocenych testov
       free_test_case_data(&current_test);  // Uvolnenie pamate testovacej struktury
       continue;  // Preskocenie na dalsi test
     }
 
     // Spracovanie a vyhodnotenie testu
     processed_tests++;  // Inkrementacia pocitadla spracovanych testov
     process_test_case(&current_test, &tests_passed_encrypt,
                       &tests_passed_decrypt);  // Vykonanie testu
     free_test_case_data(&current_test);  // Uvolnenie pamate po dokonceni testu
   }
 
   fclose(fp);  // Zatvorenie suboru
 
   // Vypocet celkovej uspesnosti
   int total_passed = tests_passed_encrypt + tests_passed_decrypt;
   int expected_passes =
       processed_tests * 2;  // Kazdy test ma encrypt aj decrypt
   bool success = (processed_tests > 0 && total_passed == expected_passes);
 
   // Vypis celkovej statistiky testov
   printf("\nCelkove vysledky:\n");
   printf("Nacitanych testovych vektorov: %d\n",
          processed_tests + skipped_tests);
   printf("Preskocenych testov (nespravna metoda/abeceda): %d\n",
          skipped_tests);
   printf("Spracovanych testov: %d\n", processed_tests);
   printf("Uspesnych testov sifrovania: %d / %d\n", tests_passed_encrypt,
          processed_tests);
   printf("Uspesnych testov desifrovania: %d / %d\n", tests_passed_decrypt,
          processed_tests);
   printf("Celkovy vysledok: %s\n", success ? "USPESNY" : "NEUSPESNY");
 
   return success ? 0 : 1;  // Navratova hodnota podla uspesnosti testov
 }