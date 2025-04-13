/************************************************************************
 * Nazov projektu: Demonštracia funkcnosti rezimov AES-u z kniznice micro-AES
 * -----------------------------------------------------------------------
 * Subor: xts_demo.c
 * Verzia: 1.1
 * Datum: 13.4.2025
 *
 * Autor: Kamil Berecky
 *
 * Popis: Program demonstruje funkcnost rezimu AES-XTS pomocou oficialnych
 * testovacich vektorov. XTS (XEX-based Tweaked CodeBook mode with CipherText
 * Stealing) je specialny rezim sifrovania pre sektor-orientovane ulozne media,
 * kde kazdy sektor ma jedinecny tweak (index sektora) pre zabezpecenie
 * kryptografickej nezavislosti sektorov.
 * 
 * Vyuzite zdroje:
 * - micro-AES kniznica: 
 *   https://github.com/polfosol/micro-AES
 * - IEEE Std 1619-2007: 
 *   https://doi.org/10.1109/IEEESTD.2019.8637988
 * 
 * Pre viac info pozri README.md
 **********************************************************************/

 #include "../header_files/xts.h"

 /**
  * Enum pre rozlisenie typov riadkov v testovacom subore
  */
 typedef enum {
   KEY1_T,     // Riadok obsahujuci prvy kluc (data key)
   KEY2_T,     // Riadok obsahujuci druhy kluc (tweak key)
   TWEAK_T,    // Riadok obsahujuci tweak (DUCN - Data Unit Count Number)
   PTX_T,      // Riadok obsahujuci plaintext
   CTX_T,      // Riadok obsahujuci ciphertext
   COUNT_T,    // Riadok obsahujuci cislo testu
   FAIL_T      // Riadok oznacujuci ocakavane zlyhanie
 } LineType;
 
 /**
  * Urci typ riadku v testovacom subore
  *
  * Popis: Funkcia analyzuje vstupny riadok a identifikuje jeho typ
  * na zaklade klucovych slov nachadajucich sa v riadku.
  *
  * Parametre:
  * @param line - Vstupny riadok na analyzu
  *
  * Navratova hodnota:
  * @return LineType - Enum hodnota reprezentujuca typ riadku, -1 ak neznamy
  */
 static LineType get_line_type(const char *line) {
   if (strstr(line, XTS_PREFIX_KEY1))
     return KEY1_T;  // Riadok obsahuje prvy kluc
   if (strstr(line, XTS_PREFIX_KEY2))
     return KEY2_T;  // Riadok obsahuje druhy kluc
   if (strstr(line, XTS_PREFIX_DUCN) || strstr(line, XTS_PREFIX_TWEAK))
     return TWEAK_T;  // Riadok obsahuje tweak (DUCN alebo Tweak)
   if (strstr(line, XTS_PREFIX_PTX))
     return PTX_T;    // Riadok obsahuje plaintext
   if (strstr(line, XTS_PREFIX_CTX))
     return CTX_T;    // Riadok obsahuje ciphertext
   if (strstr(line, XTS_PREFIX_COUNT))
     return COUNT_T;  // Riadok obsahuje cislo testu
   if (strstr(line, XTS_PREFIX_FAIL))
     return FAIL_T;   // Riadok oznacujuci ocakavane zlyhanie
   return -1;         // Neznamy typ riadku
 }
 
 /**
  * Extrahuje hodnotu za danym prefixom v riadku
  *
  * Popis: Funkcia hlada zadany prefix v riadku a vracia kopiu retazca,
  * ktora nasleduje za nim, s odstranenym odsadenim. Podporuje alternativne
  * prefixy pre tweak (DUCN/Tweak).
  *
  * Parametre:
  * @param line - Vstupny riadok na spracovanie
  * @param prefix - Hladany prefix
  *
  * Navratova hodnota:
  * @return char* - Novo-alokovany retazec s hodnotou, NULL ak prefix nebol najdeny
  */
 static char *get_line_value(const char *line, const char *prefix) {
   const char *start = strstr(line, prefix);  // Hladanie prefixu v riadku
   
   if (!start) {
     // Ak nenajde prefix, skusime alternativy (napr. DUCN vs Tweak)
     if (!strcmp(prefix, XTS_PREFIX_TWEAK) && strstr(line, XTS_PREFIX_DUCN)) {
       start = strstr(line, XTS_PREFIX_DUCN);  // Skusime alternativny prefix DUCN
     } else if (!strcmp(prefix, XTS_PREFIX_DUCN) && strstr(line, XTS_PREFIX_TWEAK)) {
       start = strstr(line, XTS_PREFIX_TWEAK);  // Skusime alternativny prefix Tweak
     } else {
       return NULL;  // Ziadny z prefixov nebol najdeny
     }
   }
 
   // Presun za prefix na medzeru a potom za medzery
   start += strlen(start) - strlen(strchr(start, ' '));  // Presun na medzeru
   while (isspace(*start))
     start++;  // Preskocenie medzier
 
   // Vytvorenie kopie retazca a odstranenie medzier
   char *temp = strdup(start);  // Kopirovanie retazca za prefixom
   if (!temp)
     return NULL;  // Zlyhanie alokacie pamate
 
   // Odstranenie medzier zo zaciatku a konca
   char *trimmed = trim(temp);  // Funkcia trim je definovana v common.h
   if (trimmed != temp) {
     memmove(temp, trimmed, strlen(trimmed) + 1);  // Presun ocisteneho retazca na zaciatok
   }
 
   return temp;  // Vratenie vysledneho retazca
 }
 
 /**
  * Uvolni pamat alokovanu pre testovacie data
  *
  * Popis: Funkcia uvolnuje vsetky dynamicky alokovane retazce
  * zo struktury TestCaseData a vynuluje celu strukturu.
  *
  * Parametre:
  * @param data - Pointer na strukturu s testovacimi datami
  */
 void free_test_case_data(TestCaseData *data) {
   if (!data)
     return;  // Ochrana pred NULL pointerom
     
   free(data->hex_key1);        // Uvolnenie prveho kluca
   free(data->hex_key2);        // Uvolnenie druheho kluca
   free(data->hex_tweak);       // Uvolnenie tweak hodnoty
   free(data->hex_plaintext);   // Uvolnenie plaintextu
   free(data->hex_ciphertext);  // Uvolnenie ciphertextu
   
   memset(data, 0, sizeof(TestCaseData));  // Vynulovanie celej struktury pre bezpecnost
 }
 
 /**
  * Nacita nasledujuci testovaci vektor zo suboru
  *
  * Popis: Funkcia cita testovacie data zo suboru riadok po riadku,
  * spracovava rozne typy riadkov a zostavuje kompletny testovaci vektor.
  * Podporuje nacitanie po castiach rozdeleneho plaintextu a ciphertextu.
  *
  * Proces:
  * 1. Inicializacia premennych a uvolnenie predchadzajucich dat
  * 2. Citanie riadkov zo suboru a ich spracovanie podla typu
  * 3. Zlucovanie rozdeleneho plaintextu a ciphertextu
  * 4. Detekcia kompletneho testovacieho vektora
  *
  * Parametre:
  * @param fp - Pointer na otvoreny subor na citanie
  * @param data - Struktura pre ulozenie dat testovacieho vektora
  *
  * Navratova hodnota:
  * @return bool - true ak sa podarilo nacitat kompletny testovaci vektor, false inak
  */
 bool parse_next_test_case(FILE *fp, TestCaseData *data) {
   char line[XTS_LINE_BUFFER_SIZE];     // Buffer pre citanie riadku
   char *value;                         // Pomocna premenna pre extrahovane hodnoty
   bool in_test_case = false;           // Priznak ci sme vo vnutri testovacieho vektora
   bool in_ctx_section = false;         // Priznak ci sme v sekcii ciphertextu
   long start_pos = ftell(fp);          // Zapamatanie aktualnej pozicie v subore
   bool fail_tag_seen = false;          // Priznak ci sme narazili na FAIL flag
   static int current_count = 0;        // Staticke pocitadlo pre automaticke cislovanie
 
   free_test_case_data(data);  // Uvolnenie predchadzajucich dat
   data->count = 0;            // Inicializacia pocitadla testov
 
   // Citanie suboru riadok po riadku
   while (fgets(line, sizeof(line), fp)) {
     char *trimmed = trim(line);  // Odstranenie medzier zo zaciatku a konca
     
     // Preskocenie prazdnych riadkov a komentarov
     if (!trimmed || strlen(trimmed) == 0 || trimmed[0] == '#' || trimmed[0] == '/') {
       // Ak sme na prazdnom riadku a mame vsetky potrebne data, mozeme vratit test
       if (in_test_case && in_ctx_section && data->hex_key1 && data->hex_key2 && 
           data->hex_tweak && data->hex_plaintext && data->hex_ciphertext) {
         data->should_fail = fail_tag_seen;  // Nastavenie priznaku zlyhania
         if (data->count == 0)
           data->count = ++current_count;  // Automaticke cislovanie ak chyba
         return true;  // Vratime kompletny testovaci vektor
       }
       
       // Alternativna detekcia konca testu - vsetky data su pritomne
       if (in_test_case && data->hex_key1 && data->hex_key2 &&
           data->hex_tweak && data->hex_plaintext && data->hex_ciphertext) {
         data->should_fail = fail_tag_seen;  // Nastavenie priznaku zlyhania
         if (data->count == 0)
           data->count = ++current_count;  // Automaticke cislovanie ak chyba
         return true;  // Vratime kompletny testovaci vektor
       }
       continue;  // Preskocenie prazdneho riadku/komentara
     }
 
     LineType type = get_line_type(trimmed);  // Urcenie typu riadku
     value = NULL;  // Reset pomocnej premennej
 
     // Spracovanie riadku podla typu
     switch (type) {
     case COUNT_T:  // Riadok obsahujuci cislo testu
       value = get_line_value(trimmed, XTS_PREFIX_COUNT);  // Ziskanie hodnoty
       if (value) {
         if (in_test_case) {
           // Ak uz spracovavame testovaci vektor, vratime sa na toto miesto neskor
           fseek(fp, start_pos, SEEK_SET);  // Vratenie kurzora na zaciatok riadku
           free(value);  // Uvolnenie docasnej hodnoty
           
           data->should_fail = fail_tag_seen;  // Nastavenie priznaku zlyhania
           if (data->count == 0)
             data->count = ++current_count;  // Automaticke cislovanie ak chyba
             
           return true;  // Vratime kompletny testovaci vektor
         }
         
         data->count = atoi(value);  // Konverzia retazca na cislo
         current_count = data->count;  // Aktualizovat aj globalne pocitadlo
         in_test_case = true;  // Oznacenie zaciatku noveho testu
         fail_tag_seen = false;  // Reset priznaku zlyhania
         free(value);  // Uvolnenie docasnej hodnoty
       }
       break;
 
     case KEY1_T:  // Riadok obsahujuci prvy kluc
       value = get_line_value(trimmed, XTS_PREFIX_KEY1);  // Ziskanie hodnoty
       if (!data->hex_key1) {
         data->hex_key1 = value;  // Ulozenie prveho kluca
         in_test_case = true;  // Zaciatok noveho testu moze zacinat aj klucom
       } else
         free(value);  // Uz mame kluc, uvolnime duplikat
       break;
 
     case KEY2_T:  // Riadok obsahujuci druhy kluc
       value = get_line_value(trimmed, XTS_PREFIX_KEY2);  // Ziskanie hodnoty
       if (!data->hex_key2)
         data->hex_key2 = value;  // Ulozenie druheho kluca
       else
         free(value);  // Uz mame kluc, uvolnime duplikat
       break;
 
     case TWEAK_T:  // Riadok obsahujuci tweak
       // Najskor skusime DUCN ako prefix
       value = get_line_value(trimmed, XTS_PREFIX_DUCN);  // Skusime najprv DUCN
       
       // Ak sa to nepodari, skusime Tweak
       if (!value)
         value = get_line_value(trimmed, XTS_PREFIX_TWEAK);  // Ak neuspesne, skusime Tweak
         
       if (!data->hex_tweak)
         data->hex_tweak = value;  // Ulozenie tweak hodnoty
       else
         free(value);  // Uz mame tweak, uvolnime duplikat
       break;
 
     case PTX_T:  // Riadok obsahujuci plaintext
       value = get_line_value(trimmed, XTS_PREFIX_PTX);  // Ziskanie hodnoty
       if (!data->hex_plaintext) {
         data->hex_plaintext = value;  // Vytvorenie noveho plaintextu
       } else {
         // Pridanie k existujucemu plaintextu - pokial je plaintext rozdeleny na viac riadkov
         size_t current_len = strlen(data->hex_plaintext);  // Dlzka aktualneho plaintextu
         size_t append_len = strlen(value);  // Dlzka novej casti na pridanie
         
         // Realokacia pamate pre zluceny plaintext
         char *new_ptx = realloc(data->hex_plaintext, current_len + append_len + 1);  // +1 pre '\0'
         
         if (new_ptx) {
           data->hex_plaintext = new_ptx;  // Aktualizacia pointera
           strcat(data->hex_plaintext, value);  // Pridanie novej casti
         }
         free(value);  // Uvolnenie docasnej hodnoty, ktora uz bola skopirovana
       }
       break;
 
     case CTX_T:  // Riadok obsahujuci ciphertext
       in_ctx_section = true;  // Oznacenie ze sme v sekcii ciphertextu
       value = get_line_value(trimmed, XTS_PREFIX_CTX);  // Ziskanie hodnoty
       
       if (!data->hex_ciphertext) {
         data->hex_ciphertext = value;  // Vytvorenie noveho ciphertextu
       } else {
         // Pridanie k existujucemu ciphertextu - pokial je ciphertext rozdeleny na viac riadkov
         size_t current_len = strlen(data->hex_ciphertext);  // Dlzka aktualneho ciphertextu
         size_t append_len = strlen(value);  // Dlzka novej casti na pridanie
         
         // Realokacia pamate pre zluceny ciphertext
         char *new_ctx = realloc(data->hex_ciphertext, current_len + append_len + 1);  // +1 pre '\0'
         
         if (new_ctx) {
           data->hex_ciphertext = new_ctx;  // Aktualizacia pointera
           strcat(data->hex_ciphertext, value);  // Pridanie novej casti
         }
         free(value);  // Uvolnenie docasnej hodnoty, ktora uz bola skopirovana
       }
       break;
 
     case FAIL_T:  // Riadok oznacujuci ocakavane zlyhanie
       fail_tag_seen = true;  // Zaznamenanie FAIL flagu
       break;
 
     default:  // Nerozpoznany typ riadku
       // Specialne spracovanie - ak ide o novy Key1 pocas existujuceho testu
       if (strstr(trimmed, XTS_PREFIX_KEY1) && in_test_case) {
         // Zahajuje sa novy test, takze vratime doterajsie data
         fseek(fp, start_pos, SEEK_SET);  // Vratenie kurzora na zaciatok riadku
         data->should_fail = fail_tag_seen;  // Nastavenie priznaku zlyhania
         
         if (data->count == 0)
           data->count = ++current_count;  // Automaticke cislovanie ak chyba
           
         return true;  // Vratime kompletny testovaci vektor
       }
       break;
     }
     start_pos = ftell(fp);  // Aktualizacia pozicie pre dalsi riadok
   }
 
   // Ak sme na konci suboru a este mame neukonceny testovaci vektor
   if (in_test_case && data->hex_key1 && data->hex_key2 &&
       data->hex_tweak && data->hex_plaintext && data->hex_ciphertext) {
     data->should_fail = fail_tag_seen;  // Nastavenie priznaku zlyhania
     
     if (data->count == 0)
       data->count = ++current_count;  // Automaticke cislovanie ak chyba
       
     return true;  // Vratime kompletny testovaci vektor
   }
 
   return false;  // Nenasli sme ziadny dalsi platny testovaci vektor
 }
 
 /**
  * Spracuje a vyhodnoti jeden testovaci vektor
  *
  * Popis: Hlavna funkcia, ktora vykonava samotne testovanie jedneho XTS
  * testovacieho vektora. Obsahuje sifrovanie a porovnanie vysledkov s
  * ocakavanymi hodnotami.
  *
  * Proces:
  * 1. Kontrola uplnosti testovacich dat
  * 2. Alokacia bufferov pre data a vytvorenie kombinovaneho kluca
  * 3. Konverzia hex retazcov na binarne data
  * 4. Vykonanie XTS sifrovania
  * 5. Porovnanie vysledkov s ocakavanymi hodnotami
  * 6. Aktualizacia statistiky testov
  *
  * Parametre:
  * @param data - Struktura s testovacimi datami
  * @param passed_count - Pointer na pocitadlo uspesnych testov
  *
  * Navratova hodnota:
  * @return bool - true ak test bol uspesne vykonany (nezavisle od vysledku), false pri chybe
  */
 bool process_test_case(const TestCaseData *data, int *passed_count) {
   // Kontrola ci mame vsetky potrebne data
   if (!data->hex_key1 || !data->hex_key2 || !data->hex_tweak ||
       !data->hex_plaintext || !data->hex_ciphertext) {
     printf("Nekompletne testovacie data\n");
     return false;  // Nekompletne testovacie data
   }
 
   // Vypocet velkosti jednotlivych komponentov
   size_t lens[] = {
     strlen(data->hex_key1) / 2,      // Velkost prveho kluca v bajtoch
     strlen(data->hex_key2) / 2,      // Velkost druheho kluca v bajtoch
     strlen(data->hex_tweak) / 2,     // Velkost tweak hodnoty v bajtoch
     strlen(data->hex_plaintext) / 2, // Velkost plaintextu v bajtoch
     strlen(data->hex_ciphertext) / 2 // Velkost ciphertextu v bajtoch
   };
 
   // Alokacia pamate pre buffery
   uint8_t *bufs[] = {
       calloc(lens[0] + 1, 1),          // key1 - prvy kluc
       calloc(lens[1] + 1, 1),          // key2 - druhy kluc
       calloc(lens[2] + 1, 1),          // tweak - hodnota tweak
       calloc(lens[3] + 1, 1),          // plaintext - vstupny text
       calloc(lens[4] + 1, 1),          // ciphertext - ocakavany zasifrovany text
       calloc(lens[0] + lens[1] + 1, 1) // combined key - kombinovany kluc
   };
 
   // Vytvorenie bufferu pre vysledok sifrovania
   uint8_t *result = calloc(lens[3] + 1, 1);  // Buffer pre vysledok sifrovania
   if (!result)
     goto cleanup;  // Pri chybe alokacie preskocime na cistenie
 
   // Kontrola uspesnosti alokacie vsetkych bufferov
   for (int i = 0; i < 6; i++) {
     if (!bufs[i])
       goto cleanup;  // Pri chybe alokacie preskocime na cistenie
   }
 
   // Konverzia hex retazcov na binarne data
   const char *hexs[] = {
     data->hex_key1,       // Prvy kluc (data key)
     data->hex_key2,       // Druhy kluc (tweak key)
     data->hex_tweak,      // Tweak hodnota (DUCN)
     data->hex_plaintext,  // Plaintext
     data->hex_ciphertext, // Ocakavany ciphertext
     NULL                  // Nevyuzity
   };
 
   // Konverzia vsetkych hex retazcov na binarne data
   for (int i = 0; i < 5; i++) {
     if (hex_to_bin(hexs[i], bufs[i], lens[i]) != 0)
       goto cleanup;  // Pri chybe konverzie preskocime na cistenie
   }
 
   // Vytvorenie kombinovaneho kluca - XTS pouziva dva kluce spojene do jedneho
   memcpy(bufs[5], bufs[0], lens[0]);  // Kopirovanie prveho kluca
   memcpy(bufs[5] + lens[0], bufs[1], lens[1]);  // Kopirovanie druheho kluca za prvy
 
   // Vypis informacii o teste
   printf("=== Test #%d ===\n", data->count);
   printf("Vstupne data:\n");
   printf("  Kluc1 (%zu bajtov): ", lens[0]);
   print_limited(data->hex_key1, XTS_MAX_LINE_LENGTH);  // Obmedzeny vypis prveho kluca
   printf("  Kluc2 (%zu bajtov): ", lens[1]);
   print_limited(data->hex_key2, XTS_MAX_LINE_LENGTH);  // Obmedzeny vypis druheho kluca
   printf("  DUCN: ");
   print_limited(data->hex_tweak, XTS_MAX_LINE_LENGTH);  // Obmedzeny vypis tweak hodnoty
   printf("  PTX (%zu bajtov): ", lens[3]);
   print_limited(data->hex_plaintext, XTS_MAX_LINE_LENGTH);  // Obmedzeny vypis plaintextu
   // Nebudeme vypisovat ocakavany CTX medzi vstupnymi datami
 
   // Spustenie sifrovania
   printf("\nTest sifrovania:\n");
   char status = AES_XTS_encrypt(bufs[5], bufs[2], bufs[3], lens[3], result);  // Volanie XTS sifrovania
 
   // Kontrola navratoveho kodu sifrovania
   if (status != 0) {
     printf("  Sifrovanie zlyhalo so statusom %d\n", status);
     goto cleanup;  // Pri chybe sifrovania preskocime na cistenie
   }
 
   // Porovnanie vysledku s ocakavanym ciphertextom
   bool match = (memcmp(result, bufs[4], lens[4]) == 0);  // True ak sa vysledky zhoduju
 
   // Konverzia vysledku do hex retazca pre vypis
   char *result_hex = calloc(lens[3] * 2 + 1, 1);  // Buffer pre hex retazec
   if (!result_hex)
     goto cleanup;  // Pri chybe alokacie preskocime na cistenie
 
   // Konvertovanie vysledku na hex retazec
   for (size_t i = 0; i < lens[3]; i++) {
     sprintf(result_hex + (i * 2), "%02x", result[i]);  // Konverzia kazdeho bajtu na 2 hex znaky
   }
 
   // Vypis vysledkov
   printf("  Vypocitany CTX: ");
   print_limited(result_hex, XTS_MAX_LINE_LENGTH);  // Obmedzeny vypis vypocitaneho ciphertextu
   printf("  Ocakavany CTX: ");
   print_limited(data->hex_ciphertext, XTS_MAX_LINE_LENGTH);  // Obmedzeny vypis ocakavaneho ciphertextu
 
   // Vyhodnotenie vysledku testu
   if (match) {
     (*passed_count)++;  // Inkrementacia pocitadla uspesnych testov
     printf("  Vysledok: %s\n\n", XTS_MSG_SUCCESS);  // Vypis informacie o uspesnosti
   } else {
     printf("  Vysledok: %s\n\n", XTS_MSG_FAILURE);  // Vypis informacie o neuspesnosti
   }
 
   free(result_hex);  // Uvolnenie hex retazca
 
 cleanup:
   // Uvolnenie vsetkych alokovanych bufferov
   for (int i = 0; i < 6; i++) {
     free(bufs[i]);  // Uvolnenie jednotlivych bufferov
   }
   free(result);  // Uvolnenie bufferu pre vysledok
   return true;  // Vratime true, pretoze test bol spracovany
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
 
   // Vyber spravneho testovacieho suboru podla velkosti kluca
 #if AES___ == 256
   test_vectors_file = XTS_TEST_VECTORS_256;  // Pre AES-256
   printf("AES-256 XTS Test\n");
 #else
   test_vectors_file = XTS_TEST_VECTORS_128;  // Pre AES-128 (predvolene)
   printf("AES-128 XTS Test\n");
 #endif
 
   printf("Pouziva sa testovaci subor: %s\n", test_vectors_file);
 
   // Otvorenie suboru s testovacimi vektormi
   FILE *fp = fopen(test_vectors_file, "r");
   if (!fp) {
     perror("Nepodarilo sa otvorit subor s testovacimi vektormi");
     return 1;  // Chybovy navratovy kod
   }
 
   // Inicializacia premennych pre testovanie
   int passed_count = 0;  // Pocitadlo uspesnych testov
   TestCaseData current_test = {0};  // Struktura pre aktualny test
   int processed_tests = 0;  // Pocitadlo spracovanych testov
 
   // Spracovanie testovacich vektorov v cykle
   while (parse_next_test_case(fp, &current_test)) {
     processed_tests++;  // Inkrementacia pocitadla testov
     process_test_case(&current_test, &passed_count);  // Spracovanie aktualneho testu
     free_test_case_data(&current_test);  // Uvolnenie dat aktualneho testu
   }
 
   fclose(fp);  // Zatvorenie suboru
 
   // Vyhodnotenie celkovej uspesnosti testov
   bool success = (processed_tests > 0 && passed_count == processed_tests);  // True ak vsetky testy presli
 
   // Vypis celkovej statistiky
   printf("\nCelkove vysledky:\n");
   printf("Spracovanych testov: %d\n", processed_tests);  // Celkovy pocet testov
   printf("Uspesnych testov: %d/%d\n", passed_count, processed_tests);  // Pomer uspesnych testov
   printf("Celkovy vysledok: %s\n", success ? XTS_MSG_SUCCESS : XTS_MSG_FAILURE);  // Celkovy vysledok
 
   return success ? 0 : 1;  // Vrati 0 ak vsetky testy presli, inak 1
 }