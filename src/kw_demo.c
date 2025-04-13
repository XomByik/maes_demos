/************************************************************************
 * Nazov projektu: Demonstracia funkcnosti rezimov AES-u z kniznice micro-AES
 * -----------------------------------------------------------------------
 * Subor: kw_demo.c
 * Verzia: 1.1
 * Datum: 13.4.2025
 *
 * Autor: Kamil Berecky
 *
 * Popis: Program demonstruje funkcnost rezimu AES-KW (Key Wrap) pomocou
 * oficialnych testovacich vektorov. Implementuje operacie zabalenia (wrap)
 * a odbalenia (unwrap) klucov, ktore sluzia na bezpecnu vymenu klucov.
 * Program podporuje rozne velkosti klucov (128, 192, 256 bitov).
 * 
 * Vyuzite zdroje:
 * - micro-AES kniznica: 
 *   https://github.com/polfosol/micro-AES
 * - Cryptographic Algorithm Validation Program (CAVP):
 *   https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/cavp-testing-block-cipher-modes#KW
 *
 * Pre viac info pozri README.md
 **********************************************************************/

 #include "../header_files/kw.h"

 /**
  * Enum pre rozlisenie typov riadkov v testovacom subore
  */
 typedef enum {
   KEY,            // Riadok obsahujuci kluc
   PLAINTEXT,      // Riadok obsahujuci plaintext
   CIPHERTEXT,     // Riadok obsahujuci ciphertext
   COUNT,          // Riadok obsahujuci cislo testu
   FAIL,           // Riadok oznacujuci ocakavane zlyhanie
   PLAINTEXT_LEN   // Riadok obsahujuci dlzku plaintextu
 } LineType;
 
 /**
  * Urci typ riadku v testovacom subore
  *
  * Popis: Funkcia analyzuje vstupny riadok a urcuje jeho typ podla
  * pritomnosti klucovych slov.
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
   if (strstr(line, KW_PREFIX_KEY))
     return KEY;  // Riadok obsahuje kluc
   if (strstr(line, KW_PREFIX_PLAINTEXT))
     return PLAINTEXT;  // Riadok obsahuje plaintext
   if (strstr(line, KW_PREFIX_CIPHERTEXT))
     return CIPHERTEXT;  // Riadok obsahuje ciphertext
   if (strstr(line, KW_PREFIX_COUNT))
     return COUNT;  // Riadok obsahuje cislo testu
   if (strstr(line, KW_PREFIX_FAIL))
     return FAIL;  // Riadok oznacuje ocakavane zlyhanie
   if (strstr(line, KW_PREFIX_PLAINTEXT_LEN))
     return PLAINTEXT_LEN;  // Riadok obsahuje dlzku plaintextu
   return -1;  // Neznamy typ riadku
 }
 
 /**
  * Extrahuje hodnotu za danym prefixom v riadku
  *
  * Popis: Funkcia hlada zadany prefix v riadku a vracia kopiu retazca,
  * ktora nasleduje za nim, s odstranenym odsadenim.
  *
  * Proces:
  * 1. Kontrola ci riadok zacina s danym prefixom
  * 2. Kopirovanie a ocistenie retazca za prefixom
  * 3. Uprava retazca odstranenim nadbytocnych medzier
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
     
   free(data->hex_key);  // Uvolnenie kluca
   free(data->hex_plaintext);  // Uvolnenie plaintextu
   free(data->hex_ciphertext);  // Uvolnenie ciphertextu
   memset(data, 0, sizeof(TestCaseData));  // Vynulovanie celej struktury pre bezpecnost
 }
 
 /**
  * Nacita nasledujuci testovaci vektor zo suboru
  *
  * Popis: Funkcia cita testovacie data zo suboru riadok po riadku,
  * spracovava rozne typy riadkov a zostavuje kompletny testovaci vektor.
  *
  * Proces:
  * 1. Inicializacia premennych a uvolnenie predchadzajucich dat
  * 2. Nastavenie priznaku is_unwrap podla typu suboru
  * 3. Citanie riadkov zo suboru a ich spracovanie podla typu
  * 4. Detekcia kompletneho testovacieho vektora
  * 5. Spracovanie informacie o dlzke plaintextu pre Key Wrap
  *
  * Parametre:
  * @param fp - Pointer na otvoreny subor na citanie
  * @param data - Struktura pre ulozenie dat testovacieho vektora
  * @param p_length - Pointer na premennu pre ulozenie dlzky plaintextu
  * @param is_unwrap_file - Priznak ci citame unwrap alebo wrap vektory
  *
  * Navratova hodnota:
  * @return bool - true ak sa podarilo nacitat kompletny testovaci vektor, false inak
  */
 bool parse_next_test_case(FILE *fp, TestCaseData *data, size_t *p_length,
                           bool is_unwrap_file) {
   char line[KW_LINE_BUFFER_SIZE];  // Buffer pre citanie riadku
   char *value;  // Pomocna premenna pre extrahovane hodnoty
   bool in_test_case = false;  // Priznak, ci sme vo vnutri testovacieho vektora
   long start_pos = ftell(fp);  // Zapamatanie aktualnej pozicie v subore
   bool fail_tag_seen = false;  // Priznak, ci sme narazili na FAIL flag
 
   free_test_case_data(data);  // Uvolnenie predchadzajucich dat
   // Explicitne nastavenie podľa typu súboru
   data->is_unwrap = is_unwrap_file;  // Nastavenie priznaku ci ide o unwrap operaciu
 
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
 
     // Spracovanie riadku podla typu
     switch (type) {
     case COUNT:  // Riadok s cislom testovacieho vektora
       value = get_line_value(trimmed, KW_PREFIX_COUNT);
       if (in_test_case) {
         // Ak uz spracovavame test a narazime na novy Count,
         // vratime sa spat a ukoncime spracovanie aktualneho testu
         fseek(fp, start_pos, SEEK_SET);  // Vratenie kurzora na zaciatok riadku
         free(value);  // Uvolnenie docasnej hodnoty
         data->should_fail = fail_tag_seen;  // Nastavenie priznaku ocakavaneho zlyhania
         return true;  // Vratime kompletny testovaci vektor
       }
       data->count = atoi(value);  // Konverzia stringu na cislo
       in_test_case = true;  // Oznacenie zaciatku noveho testu
       fail_tag_seen = false;  // Reset priznaku zlyhania
       data->should_fail = false;  // Predvolena hodnota - neocakava sa zlyhanie
       free(value);  // Uvolnenie docasnej hodnoty
       break;
 
     case KEY:  // Riadok s klucom
       value = get_line_value(trimmed, KW_PREFIX_KEY);
       if (!data->hex_key)
         data->hex_key = value;  // Ulozenie kluca
       else
         free(value);  // Uz mame kluc, uvolnime duplikat
       break;
 
     case PLAINTEXT:  // Riadok s plaintextom
       value = get_line_value(trimmed, KW_PREFIX_PLAINTEXT);
       if (!data->hex_plaintext)
         data->hex_plaintext = value;  // Ulozenie plaintextu
       else
         free(value);  // Uz mame plaintext, uvolnime duplikat
       break;
 
     case CIPHERTEXT:  // Riadok s ciphertextom
       value = get_line_value(trimmed, KW_PREFIX_CIPHERTEXT);
       if (!data->hex_ciphertext)
         data->hex_ciphertext = value;  // Ulozenie ciphertextu
       else
         free(value);  // Uz mame ciphertext, uvolnime duplikat
       break;
 
     case PLAINTEXT_LEN:  // Riadok s dlzkou plaintextu
       // Extrakcia dlzky plaintextu a konverzia z bitov na bajty
       if (sscanf(trimmed + strlen(KW_PREFIX_PLAINTEXT_LEN), "%zu", p_length) == 1) {
         *p_length /= 8;  // Konverzia z bitov na bajty
       }
       break;
 
     case FAIL:  // Riadok oznacujuci ocakavane zlyhanie
       fail_tag_seen = true;  // Zaznamenanie FAIL flagu
       break;
     }
     start_pos = ftell(fp);  // Aktualizacia pozicie pre dalsi riadok
   }
 
   // Koniec suboru - nastavenie priznakov a vratenie kompletneho testu, ak existuje
   if (in_test_case) {
     data->should_fail = fail_tag_seen;  // Nastavenie priznaku zlyhania
     return true;  // Vratime kompletny testovaci vektor
   }
   return false;  // Nenasli sme ziadny dalsi platny test
 }
 
 /**
  * Spracuje a vyhodnoti jeden testovaci vektor
  *
  * Popis: Hlavna funkcia, ktora vykonava samotne testovanie jedneho KW
  * testovacieho vektora. Obsahuje wrap alebo unwrap operacie a porovnanie
  * vysledkov s ocakavanymi hodnotami.
  *
  * Proces:
  * 1. Vypocet velkosti vstupnych dat
  * 2. Alokacia pamate pre vstupne a vystupne buffery
  * 3. Konverzia hex retazcov na binarne data
  * 4. Vykonanie wrap alebo unwrap operacie
  * 5. Porovnanie vysledkov s ocakavanymi hodnotami
  * 6. Aktualizacia statistiky testov
  *
  * Parametre:
  * @param data - Struktura obsahujuca testovacie data
  * @param passed_count - Pointer na pocitadlo uspesnych testov
  *
  * Navratova hodnota:
  * @return bool - true ak sa test uspesne vykonal, false pri chybe
  */
 bool process_test_case(const TestCaseData *data, int *passed_count) {
   // Vypocet velkosti jednotlivych komponentov v bajtoch
   size_t key_len = strlen(data->hex_key) / 2;  // Dlzka kluca v bajtoch (hex->bin)
   size_t pt_len = 0;  // Dlzka plaintextu
   size_t ct_len = 0;  // Dlzka ciphertextu
   
   // Zistenie dlzky plaintextu, ak je dostupny
   if (data->hex_plaintext) {
     pt_len = strlen(data->hex_plaintext) / 2;  // Konverzia hex na bajty
   }
 
   // Zistenie dlzky ciphertextu, ak je dostupny
   if (data->hex_ciphertext) {
     ct_len = strlen(data->hex_ciphertext) / 2;  // Konverzia hex na bajty
   }
 
   // Pre Wrap, vystupna dlzka je vzdy vstupna dlzka + 8 (pridanie hlavicky)
   // Pre Unwrap, vystupna dlzka je vzdy vstupna dlzka - 8 (odstranenie hlavicky)
   size_t expected_len = data->is_unwrap ? (ct_len - 8) : (pt_len + 8);  // Ocakavana velkost vysledku
 
   // Alokacia pamate pre potrebne buffery
   uint8_t *key = calloc(key_len + 1, 1);  // Buffer pre kluc
   uint8_t *plaintext = calloc(pt_len + 1, 1);  // Buffer pre plaintext
   uint8_t *ciphertext_expected = calloc(ct_len + 1, 1);  // Buffer pre ocakavany ciphertext
   uint8_t *result_buffer = calloc(expected_len + 1, 1);  // Buffer pre vysledok operacie
 
   // Kontrola uspesnosti alokacie
   if (!key || (!plaintext && pt_len > 0) ||
       (!ciphertext_expected && ct_len > 0) || !result_buffer) {
     free(key);
     free(plaintext);
     free(ciphertext_expected);
     free(result_buffer);
     return false;  // Zlyhanie alokacie pamate
   }
 
   // Konverzia hex hodnot na binarne data
   hex_to_bin(data->hex_key, key, key_len);  // Konverzia kluca
 
   if (data->hex_plaintext) {
     hex_to_bin(data->hex_plaintext, plaintext, pt_len);  // Konverzia plaintextu
   }
 
   if (data->hex_ciphertext) {
     hex_to_bin(data->hex_ciphertext, ciphertext_expected, ct_len);  // Konverzia ciphertextu
   }
 
   // Vypis informacii o teste
   printf("=== Test #%d ===\n", data->count);
   printf("Vstupne data:\n");
   printf("  Kluc: %s\n", data->hex_key);
 
   int operation_status;  // Status navratovy kod operacie
   bool success = false;  // Priznak uspesnosti testu
 
   // Vetva pre Unwrap operaciu
   if (data->is_unwrap) {
     // Zobrazenie vstupnych dat pre unwrap
     printf("  Ciphertext: %s\n", data->hex_ciphertext);
     if (data->hex_plaintext) {
       printf("  Ocakavany plaintext: %s\n", data->hex_plaintext);
     } else if (data->should_fail) {
       printf("  Ocakavany vysledok: ZLYHANIE\n");  // Ocakavame zlyhanie operacie
     }
 
     printf("\nTest Unwrap (AD):\n");
     // Vykonanie Unwrap operacie
     operation_status =
         AES_KEY_unwrap(key, ciphertext_expected, ct_len, result_buffer);
 
     // Vyhodnotenie vysledku Unwrap operacie
     if (operation_status == 0) {  // Uspesna operacia
       printf("  Status Unwrap: USPECH\n");
       if (data->should_fail) {  // Ocakavane zlyhanie, ale operacia uspesna
         printf("  Vysledok: NEUSPESNY (ocakavalo sa zlyhanie, ale "
                "prebehlo uspesne)\n");
         printf("  Vypocitany plaintext: ");
         print_hex(result_buffer, expected_len);
       } else {  // Ocakavany uspech a operacia uspesna
         printf("  Vypocitany plaintext: ");
         print_hex(result_buffer, expected_len);
 
         if (data->hex_plaintext) {  // Ak mame ocakavany plaintext, porovname ho
           printf("  Ocakavany plaintext: ");
           print_hex(plaintext, pt_len);
           success = (memcmp(result_buffer, plaintext, pt_len) == 0);  // Porovnanie vysledku
           printf("  Vysledok: %s\n\n",
                  success ? "USPESNY" : "NEUSPESNY (neshoda plaintextu)");
         } else {  // Nemame ocakavany plaintext, povazujeme za uspech
           success = true;
           printf("  Vysledok: USPESNY\n\n");
         }
       }
     } else {  // Operacia zlyhala
       printf("  Status Unwrap: ZLYHANIE (kod %d)\n", operation_status);
       if (data->should_fail) {  // Ocakavane zlyhanie, operacia zlyhala
         success = true;
         printf("  Vysledok: USPESNY (ocakavane zlyhanie)\n\n");
       } else {  // Neocakavane zlyhanie
         printf("  Vysledok: NEUSPESNY (neocakavane zlyhanie)\n\n");
       }
     }
 
     if (success)
       (*passed_count)++;  // Inkrementacia pocitadla uspesnych testov
   } 
   // Vetva pre Wrap operaciu
   else {
     // Zobrazenie vstupnych dat pre wrap
     printf("  Plaintext: %s\n", data->hex_plaintext);
     if (data->hex_ciphertext) {
       printf("  Ocakavany ciphertext: %s\n", data->hex_ciphertext);
     }
 
     printf("\nTest Wrap (AE):\n");
     // Vykonanie Wrap operacie
     operation_status = AES_KEY_wrap(key, plaintext, pt_len, result_buffer);
 
     // Vyhodnotenie vysledku Wrap operacie
     if (operation_status == 0) {  // Uspesna operacia
       printf("  Vypocitany ciphertext: ");
       print_hex(result_buffer, expected_len);
 
       if (data->hex_ciphertext) {  // Ak mame ocakavany ciphertext, porovname ho
         printf("  Ocakavany ciphertext: ");
         print_hex(ciphertext_expected, ct_len);
         success = (memcmp(result_buffer, ciphertext_expected,
                           expected_len) == 0);  // Porovnanie vysledku
         printf("  Vysledok: %s\n\n",
                success ? "USPESNY" : "NEUSPESNY (neshoda ciphertextu)");
       } else {  // Nemame ocakavany ciphertext, povazujeme za uspech
         success = true;
         printf("  Vysledok: USPESNY\n\n");
       }
     } else {  // Operacia zlyhala
       printf("  Status Wrap: ZLYHANIE (kod %d)\n", operation_status);
       printf("  Vysledok: NEUSPESNY\n\n");
     }
 
     if (success)
       (*passed_count)++;  // Inkrementacia pocitadla uspesnych testov
   }
 
   // Uvolnenie alokovanych bufferov
   free(key);
   free(plaintext);
   free(ciphertext_expected);
   free(result_buffer);
 
   return true;  // Vratime true, pretoze test bol spracovany
 }
 
 /**
  * Hlavna funkcia programu
  *
  * Popis: Hlavna funkcia inicializuje program, otvara subory s testovacimi
  * vektormi, spusta spracovanie a testovanie jednotlivych vektorov,
  * a na zaver zobrazuje celkovu statistiku uspesnosti testov.
  *
  * Proces:
  * 1. Kontrola dostupnosti KW rezimu
  * 2. Vyberie spravne testovacie subory podla velkosti kluca
  * 3. Postupne testuje Wrap a Unwrap operacie
  * 4. Zobrazi celkovu statistiku testov
  * 5. Vrati navratovy kod podla uspesnosti testov
  *
  * Navratova hodnota:
  * @return int - 0 ak vsetky testy uspesne, 1 ak nie
  */
 int main() {
 #if KW == 0
   printf("KW rezim nie je povoleny pri kompilacii.\n");
   return 1;  // Ukoncenie programu, ak nie je povoleny KW rezim
 #endif
 
   // Zisti AES verziu a vyber spravne testovacie subory
   const int aes_bits =
 #if AES___ == 256
       256  // AES-256
 #elif AES___ == 192
       192  // AES-192
 #else
       128  // Predvolene AES-128
 #endif
       ;
 
   // Vyber spravneho suboru pre Wrap testy podla velkosti kluca
   const char *wrap_file =
 #if AES___ == 256
       KW_AE_TEST_VECTORS_256  // AES-256 Wrap
 #elif AES___ == 192
       KW_AE_TEST_VECTORS_192  // AES-192 Wrap
 #else
       KW_AE_TEST_VECTORS_128  // AES-128 Wrap
 #endif
       ;
 
   // Vyber spravneho suboru pre Unwrap testy podla velkosti kluca
   const char *unwrap_file =
 #if AES___ == 256
       KW_AD_TEST_VECTORS_256  // AES-256 Unwrap
 #elif AES___ == 192
       KW_AD_TEST_VECTORS_192  // AES-192 Unwrap
 #else
       KW_AD_TEST_VECTORS_128  // AES-128 Unwrap
 #endif
       ;
 
   printf("AES-%d Key Wrap Test\n", aes_bits);  // Vypis velkosti kluca
   printf("Wrap testovaci subor: %s\n", wrap_file);  // Vypis pouzivaneho wrap suboru
   printf("Unwrap testovaci subor: %s\n", unwrap_file);  // Vypis pouzivaneho unwrap suboru
 
   // Inicializacia statistiky
   int wrap_passed = 0, unwrap_passed = 0;  // Pocitadla uspesnych testov
   int wrap_total = 0, unwrap_total = 0;  // Pocitadla celkovych testov
   TestCaseData test = {0};  // Struktura pre testovaci vektor
   size_t pt_length = 0;  // Dlzka plaintextu
 
   // Testovanie Wrap operacie
   FILE *fp = fopen(wrap_file, "rb");  // Otvorenie suboru s wrap testami
   if (!fp) {
     perror("Nepodarilo sa otvorit subor pre Wrap testy");
     return 1;  // Chybovy navratovy kod
   }
 
   printf("\n--- Testovanie Wrap (AE) ---\n");
   // Spracovanie wrap testovacich vektorov
   while (parse_next_test_case(fp, &test, &pt_length,
                               false)) {  // false = nie je unwrap súbor
     wrap_total++;  // Inkrementacia pocitadla testov
     process_test_case(&test, &wrap_passed);  // Spracovanie testu
   }
   fclose(fp);  // Zatvorenie wrap suboru
 
   // Testovanie Unwrap operacie
   fp = fopen(unwrap_file, "rb");  // Otvorenie suboru s unwrap testami
   if (!fp) {
     perror("Nepodarilo sa otvorit subor pre Unwrap testy");
     return 1;  // Chybovy navratovy kod
   }
 
   printf("\n--- Testovanie Unwrap (AD) ---\n");
   // Spracovanie unwrap testovacich vektorov
   while (parse_next_test_case(fp, &test, &pt_length,
                               true)) {  // true = je unwrap súbor
     unwrap_total++;  // Inkrementacia pocitadla testov
     process_test_case(&test, &unwrap_passed);  // Spracovanie testu
   }
   fclose(fp);  // Zatvorenie unwrap suboru
 
   // Vyhodnotenie celkovej uspesnosti testov
   bool all_passed =
       (wrap_passed == wrap_total) && (unwrap_passed == unwrap_total);  // Vsetky testy uspesne?
 
   // Vypis celkovej statistiky testov
   printf("\nCelkove vysledky:\n");
   printf("Wrap testy: %d/%d uspesnych\n", wrap_passed, wrap_total);
   printf("Unwrap testy: %d/%d uspesnych\n", unwrap_passed, unwrap_total);
   printf("Celkovy vysledok: %s\n", all_passed ? "USPESNY" : "NEUSPESNY");
 
   free_test_case_data(&test);  // Uvolnenie pamate
   return all_passed ? 0 : 1;  // Navratovy kod podla celkovej uspesnosti
 }