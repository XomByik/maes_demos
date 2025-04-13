/************************************************************************
 * Nazov projektu: Demonstracia funkcnosti rezimov AES-u z kniznice micro-AES
 * -----------------------------------------------------------------------
 * Subor: gcm_demo.c
 * Verzia: 1.1
 * Datum: 13.4.2025
 *
 * Autor: Kamil Berecky
 *
 * Popis: Program demonstruje funkcnost rezimu AES-GCM pomocou oficialnych
 * testovacich vektorov. Implementuje autentifikovane sifrovanie a desifrovanie
 * s overenim integrity dat pomocou autentifikacneho tagu. Program podporuje
 * rozne velkosti klucov (128, 192, 256 bitov) a inicializacne vektory.
 * 
 * Vyuzite zdroje:
 * - micro-AES kniznica: 
 *   https://github.com/polfosol/micro-AES
 * - NIST SP 800-38D (2011): 
 *   https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
 *
 * Pre viac info pozri README.md
 **********************************************************************/

 #include "../header_files/gcm.h"

 /**
  * Enum pre rozlisenie typov riadkov v testovacom subore
  */
 typedef enum { 
     KEY,      // Riadok obsahujuci kluc
     IV,       // Riadok obsahujuci inicializacny vektor
     AAD,      // Riadok obsahujuci pridane autentifikacne data
     PT,       // Riadok obsahujuci plaintext
     CT,       // Riadok obsahujuci ciphertext
     TAG,      // Riadok obsahujuci autentifikacny tag
     COUNT,    // Riadok obsahujuci cislo testu
     FAIL      // Riadok oznacujuci ocakavane zlyhanie
 } LineType;
 
 /**
  * Urci typ riadku v testovacom subore
  *
  * Popis: Funkcia analyzuje vstupny riadok a urcuje jeho typ na zaklade
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
   if (strstr(line, GCM_PREFIX_KEY))
     return KEY;  // Riadok obsahuje kluc
   if (strstr(line, GCM_PREFIX_IV))
     return IV;   // Riadok obsahuje inicializacny vektor
   if (strstr(line, GCM_PREFIX_AAD))
     return AAD;  // Riadok obsahuje pridane autentifikacne data
   if (strstr(line, GCM_PREFIX_PT))
     return PT;   // Riadok obsahuje plaintext
   if (strstr(line, GCM_PREFIX_CT))
     return CT;   // Riadok obsahuje ciphertext
   if (strstr(line, GCM_PREFIX_TAG))
     return TAG;  // Riadok obsahuje autentifikacny tag
   if (strstr(line, GCM_PREFIX_COUNT))
     return COUNT;  // Riadok obsahuje cislo testu
   if (strstr(line, GCM_PREFIX_FAIL))
     return FAIL;  // Riadok oznacuje ocakavane zlyhanie
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
   if (strncmp(line, prefix, prefix_len) == 0) {  // Ak riadok zacina prefixom
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
   free(data->hex_iv);   // Uvolnenie inicializacneho vektora
   free(data->hex_aad);  // Uvolnenie pridanych autentifikacnych dat
   free(data->hex_plaintext);  // Uvolnenie plaintextu
   free(data->hex_ciphertext);  // Uvolnenie ciphertextu
   free(data->hex_tag);  // Uvolnenie autentifikacneho tagu
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
  * 2. Citanie riadkov zo suboru a ich spracovanie podla typu
  * 3. Detekcia kompletneho testovacieho vektora
  * 4. Nastavenie priznakov podla charakteru testu (sifrovanie/desifrovanie)
  *
  * Parametre:
  * @param fp - Pointer na otvoreny subor na citanie
  * @param data - Struktura pre ulozenie dat testovacieho vektora
  *
  * Navratova hodnota:
  * @return bool - true ak sa podarilo nacitat kompletny testovaci vektor, false inak
  */
 bool parse_next_test_case(FILE *fp, TestCaseData *data) {
   char line[GCM_LINE_BUFFER_SIZE];  // Buffer pre citanie riadku
   char *value;  // Pomocna premenna pre extrahovane hodnoty
   bool in_test_case = false;  // Priznak, ci sme vo vnutri testovacieho vektora
   long start_pos = ftell(fp);  // Zapamatanie aktualnej pozicie v subore
   bool fail_tag_seen = false;  // Priznak, ci sme narazili na FAIL flag
   bool type_determined = false;  // Priznak, ci sme uz urcili typ testu (sifrovanie/desifrovanie)
 
   free_test_case_data(data);  // Uvolnenie predchadzajucich dat
   data->is_decrypt = false;  // Predvolena hodnota je sifrovanie
 
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
     case COUNT:
       value = get_line_value(trimmed, GCM_PREFIX_COUNT);
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
       type_determined = false;  // Reset priznaku typu testu
       data->should_fail = false;  // Predvolena hodnota - neocakava sa zlyhanie
       data->is_decrypt = false;  // Predvolena hodnota - sifrovanie
       free(value);  // Uvolnenie docasnej hodnoty
       break;
 
     case KEY:
       value = get_line_value(trimmed, GCM_PREFIX_KEY);
       if (!data->hex_key)
         data->hex_key = value;  // Ulozenie kluca
       else
         free(value);  // Uz mame kluc, uvolnime duplikat
       break;
 
     case IV:
       value = get_line_value(trimmed, GCM_PREFIX_IV);
       if (!data->hex_iv)
         data->hex_iv = value;  // Ulozenie inicializacneho vektora
       else
         free(value);  // Uz mame IV, uvolnime duplikat
       break;
 
     case AAD:
       value = get_line_value(trimmed, GCM_PREFIX_AAD);
       if (!data->hex_aad)
         data->hex_aad = value;  // Ulozenie pridanych autentifikacnych dat
       else
         free(value);  // Uz mame AAD, uvolnime duplikat
       break;
 
     case PT:
       value = get_line_value(trimmed, GCM_PREFIX_PT);
       if (!type_determined) {
         data->is_decrypt = false;  // Test obsahuje plaintext - ide o sifrovanie
         type_determined = true;  // Oznacenie, ze typ testu bol urceny
       }
       if (!data->hex_plaintext)
         data->hex_plaintext = value;  // Ulozenie plaintextu
       else
         free(value);  // Uz mame plaintext, uvolnime duplikat
       break;
 
     case CT:
       value = get_line_value(trimmed, GCM_PREFIX_CT);
       if (!type_determined) {
         data->is_decrypt = true;  // Test obsahuje ciphertext - ide o desifrovanie
         type_determined = true;  // Oznacenie, ze typ testu bol urceny
       }
       if (!data->hex_ciphertext)
         data->hex_ciphertext = value;  // Ulozenie ciphertextu
       else
         free(value);  // Uz mame ciphertext, uvolnime duplikat
       break;
 
     case TAG:
       value = get_line_value(trimmed, GCM_PREFIX_TAG);
       if (!data->hex_tag)
         data->hex_tag = value;  // Ulozenie autentifikacneho tagu
       else
         free(value);  // Uz mame tag, uvolnime duplikat
       break;
 
     case FAIL:
       fail_tag_seen = true;  // Zaznamenanie FAIL flagu
       break;
     }
     start_pos = ftell(fp);  // Aktualizacia pozicie pre dalsi riadok
   }
 
   // Koniec suboru - nastavenie priznakov a vratenie kompletneho testu, ak existuje
   if (in_test_case) {
     data->should_fail = fail_tag_seen;  // Nastavenie priznaku zlyhania
   }
   return in_test_case;  // Vratime true, iba ak sme nasli aspon zaciatok testu
 }
 
 /**
  * Spracuje a vyhodnoti jeden testovaci vektor
  *
  * Popis: Hlavna funkcia, ktora vykonava samotne testovanie jedneho GCM
  * testovacieho vektora. Obsahuje sifrovanie, desifrovanie, overenie integrity
  * a porovnanie vysledkov s ocakavanymi hodnotami.
  *
  * Proces:
  * 1. Konverzia hexadecimalnych retazcov na binarne hodnoty
  * 2. Vykonanie sifrovania alebo desifrovania podla typu testu
  * 3. Porovnanie vysledkov s ocakavanymi hodnotami
  * 4. Aktualizacia statistiky uspesnosti testov
  *
  * Parametre:
  * @param data - Struktura obsahujuca testovacie data
  * @param passed_encrypt - Pointer na pocitadlo uspesnych encrypt testov
  * @param passed_decrypt - Pointer na pocitadlo uspesnych decrypt testov
  *
  * Navratova hodnota:
  * @return bool - true ak sa test uspesne vykonal, false pri chybe
  */
 bool process_test_case(const TestCaseData *data, int *passed_encrypt,
                        int *passed_decrypt) {
   // Vypocet velkosti jednotlivych komponentov v bajtoch
   size_t lens[] = {
       strlen(data->hex_key) / 2,  // Dlzka kluca v bajtoch
       strlen(data->hex_iv) / 2,   // Dlzka IV v bajtoch
       data->hex_aad ? strlen(data->hex_aad) / 2 : 0,  // Dlzka AAD v bajtoch
       data->hex_plaintext ? strlen(data->hex_plaintext) / 2 : 0,  // Dlzka plaintextu v bajtoch
       data->hex_ciphertext ? strlen(data->hex_ciphertext) / 2 : 0,  // Dlzka ciphertextu v bajtoch
       strlen(data->hex_tag) / 2   // Dlzka tagu v bajtoch
   };
 
   // Alokacia bufferov pre binarne reprezentacie dat
   uint8_t *bufs[] = {
       calloc(lens[0] + 1, 1),  // Buffer pre kluc
       calloc(lens[1] + 1, 1),  // Buffer pre IV
       calloc(lens[2] + 1, 1),  // Buffer pre AAD
       calloc(lens[3] + 1, 1),  // Buffer pre plaintext
       calloc(lens[4] + 1, 1),  // Buffer pre ciphertext
       calloc(lens[5] + 1, 1)   // Buffer pre tag
   };
 
   // Kontrola uspesnosti alokacie bufferov
   for (int i = 0; i < 6; i++) {
     if (!bufs[i])
       goto cleanup;  // Pri zlyhani alokacie skocime na cistenie
   }
 
   // Pole s pointrami na hex retazce pre konverziu
   const char *hexs[] = {
       data->hex_key,        // Kluc v hex formate
       data->hex_iv,         // IV v hex formate
       data->hex_aad,        // AAD v hex formate
       data->hex_plaintext,  // Plaintext v hex formate
       data->hex_ciphertext, // Ciphertext v hex formate
       data->hex_tag         // Tag v hex formate
   };
 
   // Konverzia hex retazcov na binarne data
   for (int i = 0; i < 6; i++) {
     if (hexs[i] && hex_to_bin(hexs[i], bufs[i], lens[i]) != 0)
       goto cleanup;  // Pri zlyhani konverzie skocime na cistenie
   }
 
   // Vypis informacii o teste
   printf("=== Test #%d ===\n", data->count);
   printf("Vstupne data:\n");
   printf("  IV: ");
   print_limited(data->hex_iv, GCM_MAX_LINE_LENGTH);  // Vypis IV s obmedzenim dlzky
   if (data->hex_aad) {
     printf("  AAD: ");
     print_limited(data->hex_aad, GCM_MAX_LINE_LENGTH);  // Vypis AAD s obmedzenim dlzky
   }
 
   // Vetva pre desifrovanie (decrypt)
   if (data->is_decrypt) {
     printf("  Zasifrovane data: ");
     print_limited(data->hex_ciphertext, GCM_MAX_LINE_LENGTH);  // Vypis ciphertextu
     printf("  Autentifikacny tag: %s\n", data->hex_tag);  // Vypis tagu
     if (data->hex_plaintext) {
       printf("  Ocakavany plaintext: ");
       print_limited(data->hex_plaintext, GCM_MAX_LINE_LENGTH);  // Vypis ocakavaneho plaintextu
     }
 
     // Test desifrovania
     printf("\nTest desifrovania:\n");
     uint8_t *combined = calloc(lens[4] + lens[5] + 1, 1);  // Buffer pre kombinovany CT a tag
     uint8_t *decrypted = calloc(lens[4] + 1, 1);  // Buffer pre desifrovane data
 
     // Kontrola alokacie
     if (!combined || !decrypted) {
       free(combined);
       free(decrypted);
       goto cleanup;  // Pri zlyhani alokacie skocime na cistenie
     }
 
     // Spojenie ciphertextu a tagu do jedneho bloku
     memcpy(combined, bufs[4], lens[4]);  // Najprv ciphertext
     memcpy(combined + lens[4], bufs[5], lens[5]);  // Za nim tag
 
     // Vykonanie GCM desifrovania
     uint8_t status = AES_GCM_decrypt(bufs[0], bufs[1], combined, lens[4],
                                      bufs[2], lens[2], lens[5], decrypted);
 
     // Vyhodnotenie vysledku testu
     bool ok = data->should_fail
                 ? (status == AUTHENTICATION_FAILURE)  // Ak ma zlyhat, ocakavame chybu autentifikacie
                 : (status == NO_ERROR_RETURNED &&  // Inak ocakavame uspesny status...
                    (!data->hex_plaintext ||  // ...a bud nema ocakavany plaintext...
                     memcmp(decrypted, bufs[3], lens[3]) == 0));  // ...alebo sa zhoduje s ocakavanym
 
     // Vypis vysledkov desifrovania
     printf("  Autentifikacia: %s\n",
            status == NO_ERROR_RETURNED ? "OK" : "ZLYHALA");
     printf("  Ocakavana autentifikacia: %s\n",
            data->should_fail ? "ZLYHALA" : "OK");
     if (status == NO_ERROR_RETURNED && data->hex_plaintext) {
       printf("  Vypocitany plaintext: ");
       print_hex(decrypted, lens[3]);
       printf("  Ocakavany plaintext: ");
       print_hex(bufs[3], lens[3]);
     }
     printf("  Vysledok: %s\n\n", ok ? "USPESNY" : "NEUSPESNY");
 
     // Aktualizacia statistiky
     if (ok)
       (*passed_decrypt)++;  // Inkrementacia uspesnych decrypt testov
     free(combined);  // Uvolnenie pomocnych bufferov
     free(decrypted);
   } 
   // Vetva pre sifrovanie (encrypt)
   else {
     printf("  Plaintext: ");
     print_limited(data->hex_plaintext ? data->hex_plaintext : "(prazdny)",
                  GCM_MAX_LINE_LENGTH);  // Vypis plaintextu
     printf("  Ocakavany ciphertext: ");
     print_limited(data->hex_ciphertext ? data->hex_ciphertext : "(ziadny)",
                  GCM_MAX_LINE_LENGTH);  // Vypis ocakavaneho ciphertextu
     printf("  Ocakavany tag: %s\n", data->hex_tag);  // Vypis ocakavaneho tagu
 
     // Test sifrovania
     printf("\nTest sifrovania:\n");
     uint8_t *res_ct = calloc(lens[3] + 1, 1);  // Buffer pre vypocitany ciphertext
     uint8_t *res_tag = calloc(lens[5] + 1, 1);  // Buffer pre vypocitany tag
 
     // Kontrola alokacie
     if (!res_ct || !res_tag) {
       free(res_ct);
       free(res_tag);
       goto cleanup;  // Pri zlyhani alokacie skocime na cistenie
     }
 
     // Vykonanie GCM sifrovania
     AES_GCM_encrypt(bufs[0], bufs[1], bufs[3], lens[3], bufs[2], lens[2],
                     res_ct, res_tag);
 
     // Vypis vysledkov sifrovania
     printf("  Vypocitany ciphertext: ");
     print_hex(res_ct, lens[3]);
     printf("  Ocakavany ciphertext: ");
     print_hex(bufs[4], lens[4]);
     printf("  Vypocitany tag: ");
     print_hex(res_tag, lens[5]);
     printf("  Ocakavany tag: ");
     print_hex(bufs[5], lens[5]);
 
     // Vyhodnotenie vysledku testu
     bool tag_match = (memcmp(res_tag, bufs[5], lens[5]) == 0);  // Zhoda tagov
     bool ct_match =
         (!data->hex_ciphertext || memcmp(res_ct, bufs[4], lens[4]) == 0);  // Zhoda ciphertextov
     bool ok = tag_match && ct_match;  // Uspesne iba ak oba sedeli
 
     // Aktualizacia statistiky
     if (ok)
       (*passed_encrypt)++;  // Inkrementacia uspesnych encrypt testov
     printf("  Vysledok: %s\n\n", ok ? "USPESNY" : "NEUSPESNY");
 
     // Uvolnenie pomocnych bufferov
     free(res_ct);
     free(res_tag);
   }
 
 cleanup:
   // Uvolnenie vsetkych alokovanych bufferov
   for (int i = 0; i < 6; i++) {
     free(bufs[i]);
   }
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
  * 1. Vyberie spravny testovaci subor podla velkosti kluca a nonce
  * 2. Otvori testovaci subor a kontroluje chyby
  * 3. Spracuje testovacie vektory v cykle
  * 4. Zobrazi celkovu statistiku testov
  * 5. Vrati navratovy kod podla uspesnosti testov
  *
  * Navratova hodnota:
  * @return int - 0 ak boli vsetky testy uspesne, 1 ak nie
  */
 int main() {
   const char *test_vectors_file;  // Nazov suboru s testovacimi vektormi
 
   // Vyberie spravny testovaci subor podla velkosti kluca a dlzky nonce
 #if defined(GCM_NONCE_LEN) && GCM_NONCE_LEN == 128
   // Testy s 1024-bitovym nonce
 #if AES___ == 256
   test_vectors_file = GCM_TEST_VECTORS_1024_256;  // AES-256 s 1024-bitovym nonce
 #elif AES___ == 192
   test_vectors_file = GCM_TEST_VECTORS_1024_192;  // AES-192 s 1024-bitovym nonce
 #else
   test_vectors_file = GCM_TEST_VECTORS_1024_128;  // AES-128 s 1024-bitovym nonce
 #endif
 #else
   // Testy so standardnym nonce
 #if AES___ == 256
   test_vectors_file = GCM_TEST_VECTORS_256;  // AES-256 so standardnym nonce
 #elif AES___ == 192
   test_vectors_file = GCM_TEST_VECTORS_192;  // AES-192 so standardnym nonce
 #else
   test_vectors_file = GCM_TEST_VECTORS_128;  // AES-128 so standardnym nonce
 #endif
 #endif
 
   printf("AES-%d GCM Test\n", AES_KEY_SIZE * 8);  // Vypis velkosti kluca
   printf("Testovaci subor: %s\n", test_vectors_file);  // Vypis pouzivaneho suboru
 
   // Otvorenie testovacieho suboru
   FILE *fp = fopen(test_vectors_file, "rb");
   if (!fp) {
     perror("Nepodarilo sa otvorit subor s testovacimi vektormi");
     return 1;  // Chybovy navratovy kod
   }
 
   // Inicializacia premennych pre testovanie
   int tests_passed_encrypt = 0;  // Pocitadlo uspesnych encrypt testov
   int tests_passed_decrypt = 0;  // Pocitadlo uspesnych decrypt testov
   TestCaseData current_test = {0};  // Struktura pre aktualny test
   int processed_tests = 0;  // Pocitadlo spracovanych testov
 
   // Spracovanie testovacich vektorov v cykle
   while (parse_next_test_case(fp, &current_test)) {
     processed_tests++;  // Inkrementacia pocitadla testov
     process_test_case(&current_test, &tests_passed_encrypt,
                      &tests_passed_decrypt);  // Spracovanie testu
     current_test.should_fail = false;  // Reset priznaku zlyhania pre dalsi test
   }
 
   // Vypocet celkovej uspesnosti
   int total_passed = tests_passed_encrypt + tests_passed_decrypt;  // Celkovy pocet uspesnych testov
   bool success = (processed_tests > 0 && total_passed == processed_tests);  // Vsetky testy musia byt uspesne
 
   // Vypis celkoveho vysledku
   printf("\nCelkove vysledky:\n");
   printf("Spracovanych testov: %d\n", processed_tests);
   printf("Uspesnych testov sifrovania: %d\n", tests_passed_encrypt);
   printf("Uspesnych testov desifrovania: %d\n", tests_passed_decrypt);
   printf("Celkovy vysledok: %s\n", success ? "USPESNY" : "NEUSPESNY");
 
   // Zatvorenie suboru a vratenie vysledku
   fclose(fp);
 
   return success ? 0 : 1;  // Vratime 0 pri uspesnom dokonceni, 1 pri neuspesnom
 }