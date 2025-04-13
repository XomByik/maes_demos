/************************************************************************
 * Nazov projektu: Demonstracia funkcnosti rezimov AES-u z kniznice micro-AES
 * -----------------------------------------------------------------------
 * Subor: eax_demo.c
 * Verzia: 1.1
 * Datum: 13.4.2025
 *
 * Autor: Kamil Berecky
 *
 * Popis: Program demonstruje funkcnost rezimu AES-EAX pomocou oficialnych
 * testovacich vektorov. Implementuje autentifikovane sifrovanie a desifrovanie
 * s overovanim prislusnosti dat pomocou micro-AES kniznice a porovnava vysledky
 * s ocakavanymi hodnotami. Program podporuje AES-128.
 * 
 * Vyuzite zdroje:
 * - micro-AES kniznica: 
 *   https://github.com/polfosol/micro-AES
 * - EAX specifikacia: 
 *   https://csrc.nist.gov/publications/detail/sp/800-38d/final
 *
 * Pre viac info pozri README.md
 **********************************************************************/

 #include "../header_files/eax.h"

 /**
  * Enum pre rozlisenie typov riadkov v testovacom subore
  */
 typedef enum { 
     KEY,      // Riadok obsahujuci kluc
     NONCE,    // Riadok obsahujuci nonce hodnotu
     HEADER,   // Riadok obsahujuci hlavicku (AAD)
     MSG,      // Riadok obsahujuci plaintext spravu
     CIPHER,   // Riadok obsahujuci ciphertext a tag
     COUNT,    // Riadok obsahujuci cislo testu
     FAIL      // Riadok oznacujuci ocakavane zlyhanie
 } LineType;
 
 /**
  * Urci typ riadku v testovacom subore
  *
  * Popis: Funkcia analyzuje vstupny riadok a urcuje jeho typ podla
  * obsiahnurych klucovych slov.
  *
  * Proces:
  * 1. Kontrola, ci riadok obsahuje specificke klucove slovo
  * 2. Vratenie zodpovedajuceho typu riadku
  *
  * Parametre:
  * @param line - Vstupny riadok na analyzu
  *
  * Navratova hodnota:
  * @return LineType - Enum hodnota reprezentujuca typ riadku, -1 ak nezodpoveda ziadnemu typu
  */
 static LineType get_line_type(const char *line) {
   if (strstr(line, EAX_PREFIX_KEY))
     return KEY;  // Riadok s klucom
   if (strstr(line, EAX_PREFIX_NONCE))
     return NONCE;  // Riadok s nonce
   if (strstr(line, EAX_PREFIX_HEADER))
     return HEADER;  // Riadok s hlavickou (associated data)
   if (strstr(line, EAX_PREFIX_MSG))
     return MSG;  // Riadok s plaintextom
   if (strstr(line, EAX_PREFIX_CIPHER))
     return CIPHER;  // Riadok s ciphertextom a tagom
   if (strstr(line, EAX_PREFIX_COUNT))
     return COUNT;  // Riadok s cislom testu
   if (strstr(line, EAX_PREFIX_FAIL))
     return FAIL;  // Riadok oznacujuci ocakavane zlyhanie
   return -1;  // Neznamy typ riadku
 }
 
 /**
  * Extrahuje hodnotu za danym prefixom v riadku
  *
  * Popis: Funkcia hlada zadany prefix v riadku a vracia kopiu retazca,
  * ktora nasleduje za nim, s odstranenym odsadenim.
  *
  * Proces:
  * 1. Najde poziciu prefixu v riadku
  * 2. Preskoci prefix a vsetky medzery za nim
  * 3. Vrati ocisteny vysledny retazec
  *
  * Parametre:
  * @param line - Vstupny riadok na spracovanie
  * @param prefix - Hladany prefix
  *
  * Navratova hodnota:
  * @return char* - Novo-alokovany retazec s hodnotou, alebo NULL ak prefix nebol najdeny
  */
 static char *get_line_value(const char *line, const char *prefix) {
   const char *start = strstr(line, prefix);  // Najdenie pozicie prefixu
   if (!start)
     return NULL;  // Prefix nebol najdeny
 
   start += strlen(prefix);  // Preskocenie prefixu
   while (isspace(*start))
     start++;  // Preskocenie medzier za prefixom
 
   char *temp = strdup(start);  // Vytvorenie kopie retazca
   if (!temp)
     return NULL;  // Zlyhanie alokacie
 
   char *trimmed = trim(temp);  // Odstranenie medzier na zaciatku a konci
   if (trimmed != temp) {
     memmove(temp, trimmed, strlen(trimmed) + 1);  // Ak trim zmenil zaciatok, presunut obsah
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
     
   free(data->key_hex);  // Uvolnenie kluca
   free(data->nonce_hex);  // Uvolnenie nonce
   free(data->header_hex);  // Uvolnenie hlavicky
   free(data->pt_hex);  // Uvolnenie plaintextu
   free(data->ct_hex);  // Uvolnenie ciphertextu
   free(data->tag_hex);  // Uvolnenie tagu
   
   memset(data, 0, sizeof(TestCaseData));  // Vynulovanie celej struktury pre bezpecnost
 }
 
 /**
  * Nacita nasledujuci testovaci vektor zo suboru
  *
  * Popis: Funkcia cita testovacie data zo suboru riadok po riadku,
  * spracovava rozne typy riadkov a buduje kompletny testovaci vektor.
  *
  * Proces:
  * 1. Inicializacia premennych a uvolnenie predoslych dat
  * 2. Citanie riadku a urcenie jeho typu
  * 3. Spracovanie hodnot podla typu riadku
  * 4. Detekcia kompletneho testovacieho vektora
  *
  * Parametre:
  * @param fp - Pointer na otvoreny subor na citanie
  * @param data - Struktura na ulozenie dat testovacieho vektora
  *
  * Navratova hodnota:
  * @return bool - true ak sa podarilo nacitat kompletny testovaci vektor, false inak
  */
 bool parse_next_test_case(FILE *fp, TestCaseData *data) {
   char line[EAX_LINE_BUFFER_SIZE];  // Buffer pre citanie riadku
   char *value;  // Pomocna premenna na uchovanie nacitanej hodnoty
   bool in_test_case = false;  // Priznak, ci uz sme vo vnutri testovacieho vektora
   long start_pos = ftell(fp);  // Ulozenie aktualnej pozicie v subore
   bool fail_tag_seen = false;  // Priznak, ci sme narazili na FAIL tag
   static int current_count = 0;  // Staticke pocitadlo testov
 
   free_test_case_data(data);  // Uvolnenie predoslych dat
 
   // Citanie suboru riadok po riadku
   while (fgets(line, sizeof(line), fp)) {
     char *trimmed = trim(line);  // Odstranenie medzier zo zaciatku a konca
     
     // Preskocenie prazdnych riadkov a komentarov
     if (!trimmed || strlen(trimmed) == 0 || trimmed[0] == '#') {
       // Ak sme na prazdnom riadku a mame vsetky potrebne data, vratime test
       if (in_test_case && data->key_hex && data->nonce_hex &&
           data->pt_hex && data->ct_hex) {
         // Kompletny testovaci vektor, mozeme sa vratit
         data->should_fail = fail_tag_seen;
         if (data->count == 0) {
           data->count = ++current_count;  // Automaticke cislovanie
         }
         return true;
       }
       if (in_test_case)
         start_pos = ftell(fp);  // Aktualizacia pozicie na zaciatok dalsieho riadku
       continue;
     }
 
     LineType type = get_line_type(trimmed);  // Urcenie typu riadku
     value = NULL;  // Reset pomocnej premennej
 
     // Spracovanie riadku podla jeho typu
     switch (type) {
     case COUNT:
       value = get_line_value(trimmed, EAX_PREFIX_COUNT);
       // Ak sme uz v testovacom vektor a mame vsetky potrebne data,
       // vratime test
       if (in_test_case && data->key_hex && data->nonce_hex && data->ct_hex) {
         fseek(fp, start_pos, SEEK_SET);  // Vratenie kurzora na zaciatok tohto riadku
         free(value);  // Uvolnenie nepouzitej hodnoty
         data->should_fail = fail_tag_seen;  // Nastavenie priznaku zlyhania
         if (data->count == 0) {
           data->count = ++current_count;  // Automaticke cislovanie ak chyba
         }
         return true;
       }
       data->count = atoi(value);  // Konverzia stringu na integer
       current_count = data->count;  // Aktualizacia globalneho pocitadla
       in_test_case = true;  // Zaciatok noveho testu
       fail_tag_seen = false;  // Reset priznaku zlyhania
       free(value);  // Uvolnenie docasnej hodnoty
       break;
 
     case KEY:
       value = get_line_value(trimmed, EAX_PREFIX_KEY);
       if (!data->key_hex) {
         data->key_hex = value;  // Ulozenie kluca
         in_test_case = true;  // Novy testovaci vektor moze zacat aj KEYom
       } else {
         free(value);  // Uz mame kluc, uvolnime novy
       }
       break;
 
     case NONCE:
       value = get_line_value(trimmed, EAX_PREFIX_NONCE);
       if (!data->nonce_hex) // Kontrola, ci uz mame nonce
         data->nonce_hex = value;  // Ulozenie nonce
       else
         free(value); // Uz mame nonce, uvolnime novy
       break;
 
     case HEADER:
       value = get_line_value(trimmed, EAX_PREFIX_HEADER);
       if (!data->header_hex)
         data->header_hex = value;  // Ulozenie hlavicky (AAD)
       else
         free(value);  // Uz mame header, uvolnime novy
       break;
 
     case MSG:
       value = get_line_value(trimmed, EAX_PREFIX_MSG);
       if (!data->pt_hex) {
         data->pt_hex = value;  // Ulozenie plaintextu
         in_test_case = true;  // Novy testovaci vektor moze zacat aj MSGom
       } else {
         free(value);  // Uz mame plaintext, uvolnime novy
       }
       break;
 
     case CIPHER:
       value = get_line_value(trimmed, EAX_PREFIX_CIPHER);
       if (value && strlen(value) >= EAX_MIN_TAG_LENGTH_HEX) {
         // Predpokladame standardny 16B tag (32 hex znakov)
         size_t len = strlen(value);
         size_t tag_len_hex = EAX_TAG_LENGTH_HEX;  // Tag ma vzdy 16 bajtov (32 hex znakov)
 
         // CT je vsetko okrem poslednych tag_len_hex znakov
         size_t ct_len_hex = len - tag_len_hex;
 
         // Rozdelenie na CT a tag
         data->ct_hex = malloc(ct_len_hex + 1);  // +1 pre null terminator
         data->tag_hex = malloc(tag_len_hex + 1);  // +1 pre null terminator
 
         if (data->ct_hex && data->tag_hex) {
           if (ct_len_hex > 0) {
             strncpy(data->ct_hex, value, ct_len_hex);  // Kopirovanie CT casti
             data->ct_hex[ct_len_hex] = '\0';  // Ukoncenie retazca
           } else {
             data->ct_hex[0] = '\0';  // Prazdny CT
           }
 
           // Kopirovanie tag casti
           strncpy(data->tag_hex, value + ct_len_hex, tag_len_hex);
           data->tag_hex[tag_len_hex] = '\0';  // Ukoncenie retazca
         } else {
           // Zlyhanie alokacie, uvolnime pamat
           free(data->ct_hex);
           free(data->tag_hex);
           data->ct_hex = NULL;
           data->tag_hex = NULL;
         }
       } else if (value) {
         // Ak CIPHER nie je dostatocne dlhy na tag, predpokladajme ze cele je tag
         data->tag_hex = value;  // Pouzijeme ako tag
         data->ct_hex = strdup("");  // Vytvorime prazdny CT
         value = NULL;  // Zamedzime uvolneniu tagu
       }
       free(value);  // Uvolnenie docasnej hodnoty
 
       // Po spracovani CIPHER skontrolujeme, ci mame kompletny testovaci vektor
       if (data->key_hex && data->nonce_hex && data->tag_hex) {
         // Ak nemame plaintext, nastavime prazdny
         if (!data->pt_hex) {
           data->pt_hex = strdup("");
         }
         data->should_fail = fail_tag_seen;  // Nastavenie priznaku zlyhania
         if (data->count == 0) {
           data->count = ++current_count;  // Automaticke cislovanie ak chyba
         }
         return true;  // Vratime kompletny test
       }
       break;
 
     case FAIL:
       fail_tag_seen = true;  // Zaznamenanie FAIL tagu
       break;
     }
     start_pos = ftell(fp);  // Aktualizacia pozicie pre dalsi riadok
   }
 
   // Koniec suboru, vratime posledny test ak existuje
   if (in_test_case && data->key_hex && data->nonce_hex && data->ct_hex) {
     data->should_fail = fail_tag_seen;  // Nastavenie priznaku zlyhania
     if (data->count == 0) {
       data->count = ++current_count;  // Automaticke cislovanie ak chyba
     }
     return true;
   }
 
   return false;  // Nenasiel sa ziadny dalsi platny test
 }
 
 /**
  * Spracuje a vyhodnoti jeden testovaci vektor
  *
  * Popis: Hlavna funkcia, ktora vykonava samotne testovanie jedneho EAX
  * testovacieho vektora. Obsahuje sifrovanie, desifrovanie a porovnanie
  * vysledkov s ocakavanymi hodnotami.
  *
  * Proces:
  * 1. Kontrola platnosti vstupnych dat
  * 2. Konverzia hexadecimalnych retazcov na binarne data
  * 3. Vykonanie EAX sifrovania a porovnanie s ocakavanymi hodnotami
  * 4. Vykonanie EAX desifrovania a verifikacia tagu
  * 5. Vyhodnotenie uspesnosti testu
  *
  * Parametre:
  * @param data - Struktura obsahujuca testovacie data
  * @param passed_encrypt - Pointer na pocitadlo uspesnych encrypt testov
  * @param passed_decrypt - Pointer na pocitadlo uspesnych decrypt testov
  *
  * Navratova hodnota:
  * @return bool - true ak sa test uspesne spracoval (nezavisle od vysledkov)
  */
 bool process_test_case(const TestCaseData *data, int *passed_encrypt,
                        int *passed_decrypt) {
   // Kontrola existencie povinnych dat
   if (!data->key_hex || !data->nonce_hex || !data->tag_hex) {
     printf("Nekompletne testovacie data\n");
     return false;
   }
 
   // Vypocitanie dlzok jednotlivych komponentov
   size_t lens[] = {
     strlen(data->key_hex) / 2,  // Dlzka kluca v bajtoch
     strlen(data->nonce_hex) / 2,  // Dlzka nonce v bajtoch
     data->header_hex ? strlen(data->header_hex) / 2 : 0,  // Dlzka hlavicky v bajtoch
     data->pt_hex ? strlen(data->pt_hex) / 2 : 0,  // Dlzka plaintextu v bajtoch
     data->ct_hex ? strlen(data->ct_hex) / 2 : 0,  // Dlzka ciphertextu v bajtoch
     strlen(data->tag_hex) / 2  // Dlzka tagu v bajtoch
   };
 
   // Alokacia bufferov pre binarne data
   uint8_t *bufs[] = {
       calloc(lens[0] + 1, 1),  // Buffer pre kluc
       calloc(lens[1] + 1, 1),  // Buffer pre nonce
       calloc(lens[2] + 1, 1),  // Buffer pre hlavicku
       calloc(lens[3] + 1, 1),  // Buffer pre plaintext
       calloc(lens[4] + 1, 1),  // Buffer pre ciphertext
       calloc(lens[5] + 1, 1)   // Buffer pre tag
   };
 
   // Kontrola uspesnosti alokacii
   for (int i = 0; i < 6; i++) {
     if (!bufs[i])
       goto cleanup;  // Pri zlyhani alokacie preskocime na cistenie
   }
 
   // Pomocne pole hexadecimalnych retazcov pre konverziu
   const char *hexs[] = {
       data->key_hex,     // Kluc v hex formate
       data->nonce_hex,   // Nonce v hex formate
       data->header_hex,  // Hlavicka v hex formate
       data->pt_hex,      // Plaintext v hex formate
       data->ct_hex,      // Ciphertext v hex formate
       data->tag_hex      // Tag v hex formate
   };
 
   // Konverzia vsetkych hexadecimalnych dat na binarne
   for (int i = 0; i < 6; i++) {
     if (hexs[i] && lens[i] > 0 &&
         hex_to_bin(hexs[i], bufs[i], lens[i]) != 0)
       goto cleanup;  // Pri zlyhani konverzie preskocime na cistenie
   }
 
   // Vypis informacii o teste
   printf("=== Test #%d ===\n", data->count);
   printf("Vstupne data:\n");
   printf("  Kluc: ");
   print_limited(data->key_hex, EAX_MAX_LINE_LENGTH);
   printf("  Nonce: ");
   print_limited(data->nonce_hex, EAX_MAX_LINE_LENGTH);
   if (data->header_hex) {
     printf("  Hlavicka: ");
     print_limited(data->header_hex, EAX_MAX_LINE_LENGTH);
   }
   printf("  Plaintext (pre sifrovanie): ");
   print_limited(data->pt_hex, EAX_MAX_LINE_LENGTH);
   printf("  Ciphertext (pre desifrovanie): ");
   print_limited(data->ct_hex, EAX_MAX_LINE_LENGTH);
 
   // Vykoname test sifrovania aj desifrovania
   // 1. Test sifrovania (encrypt)
   printf("\nTest sifrovania:\n");
   if (data->pt_hex) {
     // Alokacia pamate pre vysledky
     uint8_t *result_ct = calloc(lens[3] + 1, 1);  // Buffer pre vypocitany ciphertext
     uint8_t *result_tag = calloc(lens[5] + 1, 1);  // Buffer pre vypocitany tag
 
     if (!result_ct || !result_tag) {
       // Zlyhanie alokacie, uvolnime pamat
       free(result_ct);
       free(result_tag);
       goto cleanup;
     }
 
     // Vykonanie EAX sifrovania
     AES_EAX_encrypt(bufs[0], bufs[1], bufs[3], lens[3], bufs[2], lens[2],
                     result_ct, result_tag);
 
     // Vypis ocakavanych hodnot samostatne
     if (data->ct_hex) {
       printf("  Ocakavany ciphertext: ");
       print_limited(data->ct_hex, EAX_MAX_LINE_LENGTH);
     }
     printf("  Ocakavany tag: ");
     print_limited(data->tag_hex, EAX_MAX_LINE_LENGTH);
 
     // Vypocitany ciphertext || tag vypis spolocne
     char *result_combined_hex = calloc((lens[3] + lens[5]) * 2 + 1, 1);
     if (result_combined_hex) {
       // Konverzia ciphertext na hex
       for (size_t i = 0; i < lens[3]; i++) {
         sprintf(result_combined_hex + (i * 2), "%02x", result_ct[i]);  // CT -> hex retazec
       }
 
       // Konverzia tag na hex a pridanie za ciphertext
       for (size_t i = 0; i < lens[5]; i++) {
         sprintf(result_combined_hex + (lens[3] * 2) + (i * 2), "%02x",
                 result_tag[i]);  // Tag -> hex retazec
       }
 
       printf("  Vypocitany ciphertext || tag: ");
       print_limited(result_combined_hex, EAX_MAX_LINE_LENGTH);
       free(result_combined_hex);  // Uvolnenie docasneho retazca
     }
 
     // Porovnanie s ocakavanymi hodnotami
     bool tag_match = (memcmp(result_tag, bufs[5], lens[5]) == 0);  // Porovnanie tagov
     bool ct_match = (!data->ct_hex || lens[4] == 0 ||
                      memcmp(result_ct, bufs[4], lens[4]) == 0);  // Porovnanie ciphertextov
     bool ok = tag_match && ct_match;  // Uspesny test iba ak oba sedla
 
     if (ok)
       (*passed_encrypt)++;  // Inkrementacia uspesnych testov sifrovania
     printf("  Vysledok sifrovania: %s\n\n", ok ? "USPESNY" : "NEUSPESNY");
 
     free(result_ct);  // Uvolnenie vysledkov
     free(result_tag);
   } else {
     printf("  (Ziadny plaintext na zasifrovanie)\n\n");
   }
 
   // 2. Test desifrovania (decrypt)
   printf("Test desifrovania:\n");
   if (data->ct_hex) {
     printf("  Tag: ");
     print_limited(data->tag_hex, EAX_MAX_LINE_LENGTH);
 
     // Alokacia bufferov pre desifrovanie
     uint8_t *combined_ct_tag = calloc(lens[4] + lens[5], 1);  // Buffer pre spojeny CT a tag
     uint8_t *decrypted = calloc(lens[4] + 1, 1);  // Buffer pre desifrovane data
 
     if (!combined_ct_tag || !decrypted) {
       // Zlyhanie alokacie, uvolnime pamat
       free(combined_ct_tag);
       free(decrypted);
       goto cleanup;
     }
 
     // Spojenie ciphertextu a tagu do jedneho bloku
     memcpy(combined_ct_tag, bufs[4], lens[4]);  // Skopirovanie CT
     memcpy(combined_ct_tag + lens[4], bufs[5], lens[5]);  // Pridanie tagu za CT
 
     // Vykonanie EAX desifrovania
     int decrypt_stav =
         AES_EAX_decrypt(bufs[0], bufs[1], combined_ct_tag, lens[4],
                         bufs[2], lens[2], lens[5], decrypted);
                         
     printf("  Ocakavany stav desifrovania: %s\n",
            data->should_fail ? "ZLYHANIE (Tag neplatny)"
                              : "USPESNE (Tag platny)");
 
     printf("  Skutocny stav desifrovania: %s\n",
            decrypt_stav == 0 ? "USPSNE (Tag platny)"
                              : "ZLYHANIE (Tag neplatny)");
 
     // Ak desifrovanie bolo uspesne, zobraz plaintext
     if (decrypt_stav == 0 && data->pt_hex) {
       printf("  Ocakavany plaintext: ");
       print_hex(bufs[3], lens[3]);  // Vypis ocakavaneho plaintextu
       printf("  Vypocitany plaintext: ");
       print_hex(decrypted, lens[3]);  // Vypis vypocitaneho plaintextu
     }
 
     // Vyhodnotenie testu desifrovania
     bool ok = data->should_fail
                   ? (decrypt_stav != 0)  // Ak ma zlyhat, mal by mat nenulovy navratovy kod
                   : (decrypt_stav == 0 &&  // Inak uspesny kod a zhoda plaintextov
                      (!data->pt_hex ||
                       memcmp(decrypted, bufs[3], lens[3]) == 0));
 
     if (ok)
       (*passed_decrypt)++;  // Inkrementacia uspesnych testov desifrovania
     printf("  Vysledok desifrovania: %s\n\n",
            ok ? "USPESNY" : "NEUSPESNY");
 
     free(combined_ct_tag);  // Uvolnenie bufferov
     free(decrypted);
   } else {
     printf("  (Ziadny ciphertext na desifrovanie)\n\n");
   }
 
 cleanup:
   // Uvolnenie vsetkych alokovanych bufferov
   for (int i = 0; i < 6; i++) {
     free(bufs[i]);
   }
   return true;  // Vratime true, aj ked test nemusel byt uspesny
 }
 
 /**
  * Hlavna funkcia programu
  *
  * Popis: Hlavna funkcia inicializuje program, otvara subor s testovacimi
  * vektormi, spusta spracovanie a testovanie jednotlivych vektorov,
  * a na zaver zobrazuje celkovu statistiku uspesnosti testov.
  *
  * Proces:
  * 1. Definovanie nazvu testovacieho suboru
  * 2. Otvorenie suboru a kontrola chyb
  * 3. Spracovanie testovacich vektorov v cykle
  * 4. Vypis celkovej statistiky testov
  * 5. Vratenie navratoveho kodu podla uspesnosti testov
  *
  * Navratova hodnota:
  * @return int - 0 ak boli vsetky testy uspesne, 1 ak nie
  */
 int main() {
   // Definovanie testovacieho suboru
   const char *test_vectors_file = EAX_TEST_VECTORS_FILE;
   printf("AES-128 EAX Test\n");
 
   printf("Pouziva sa testovaci subor: %s\n", test_vectors_file);
 
   // Otvorenie testovacieho suboru
   FILE *fp = fopen(test_vectors_file, "r");
   if (!fp) {
     perror("Nepodarilo sa otvorit subor s testovacimi vektormi");
     return 1;  // Chybovy navratovy kod
   }
 
   // Inicializacia premmenych pre testovanie
   int tests_passed_encrypt = 0;  // Pocitadlo uspesnych testov sifrovania
   int tests_passed_decrypt = 0;  // Pocitadlo uspesnych testov desifrovania
   TestCaseData current_test = {0};  // Struktura pre aktualny test
   int processed_tests = 0;  // Pocitadlo spraocvanych testov
 
   // Spracovanie testovacich vektorov v cykle
   while (parse_next_test_case(fp, &current_test)) {
     processed_tests++;  // Inkrementacia pocitadla testov
     process_test_case(&current_test, &tests_passed_encrypt,
                       &tests_passed_decrypt);  // Spracovanie testu
     free_test_case_data(&current_test);  // Uvolnenie dat
   }
 
   fclose(fp);  // Zatvorenie suboru
 
   // Vyhodnotenie uspesnosti testov
   bool success =
       (processed_tests > 0 &&
        tests_passed_encrypt + tests_passed_decrypt == processed_tests * 2);
 
   // Vypis celkoveho vysledku
   printf("\nCelkove vysledky:\n");
   printf("Spracovanych testov: %d\n", processed_tests);
   printf("Uspesnych testov sifrovania: %d\n", tests_passed_encrypt);
   printf("Uspesnych testov desifrovania: %d\n", tests_passed_decrypt);
   printf("Celkovy vysledok: %s\n", success ? "USPESNY" : "NEUSPESNY");
 
   return success ? 0 : 1;  // Vratenie navratoveho kodu podla uspesnosti
 }