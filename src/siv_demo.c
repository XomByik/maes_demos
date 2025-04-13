/************************************************************************
 * Nazov projektu: Demonstracia funkcnosti rezimov AES-u z kniznice micro-AES
 * -----------------------------------------------------------------------
 * Subor: siv_demo.c
 * Verzia: 1.1
 * Datum: 13.4.2025
 *
 * Autor: Kamil Berecky
 *
 * Popis: Program demonstruje funkcnost rezimu AES-SIV pomocou oficialnych
 * testovacich vektorov. Implementuje autentifikovane sifrovanie
 * a desifrovanie s ochranou integrity dat a asociovanych dat (AD).
 * SIV mod poskytuje deterministicke sifrovanie, co znamena, ze rovnake 
 * vstupy produkuju rovnake vystupy, bezpecnost je zabezpecena
 * pomocou CMAC.
 * 
 * Vyuzite zdroje:
 * - micro-AES kniznica: 
 *   https://github.com/polfosol/micro-AES
 * - RFC 5297 (Synthetic Initialization Vector):
 *   https://tools.ietf.org/html/rfc5297
 * 
 * Pre viac info pozri README.md
 **********************************************************************/

 #include "../header_files/siv.h"

 /**
  * Urci typ riadku v testovacom subore
  *
  * Popis: Funkcia analyzuje vstupny riadok a urcuje jeho typ podla
  * obsahu klucovych slov v riadku.
  *
  * Parametre:
  * @param line - Vstupny riadok na analyzu
  *
  * Navratova hodnota:
  * @return LineType - Enum hodnota reprezentujuca typ riadku
  */
 static LineType get_line_type(const char *line) {
   if (strstr(line, SIV_PREFIX_KEY_1) || strstr(line, SIV_PREFIX_KEY_2))
     return KEY_T;  // Riadok obsahuje kluc
   if (strstr(line, SIV_PREFIX_AD_1) || strstr(line, SIV_PREFIX_AD_2))
     return AD_T;  // Riadok obsahuje asociovane data
   if (strstr(line, SIV_PREFIX_PT_1) || strstr(line, SIV_PREFIX_PT_2))
     return PT_T;  // Riadok obsahuje plaintext
   if (strstr(line, SIV_PREFIX_CT_1) || strstr(line, SIV_PREFIX_CT_2))
     return CT_T;  // Riadok obsahuje ciphertext
   if (strstr(line, SIV_PREFIX_CMAC))
     return CMAC_T;  // Riadok obsahuje CMAC (IV)
   if (strstr(line, SIV_PREFIX_IV_C))
     return IV_C_T;  // Riadok obsahuje kombinaciu IV a ciphertextu
   if (strstr(line, SIV_PREFIX_COUNT))
     return COUNT_T;  // Riadok obsahuje cislo testu
   if (strstr(line, SIV_PREFIX_FAIL))
     return FAIL_T;  // Riadok oznacuje ocakavane zlyhanie
   return -1;  // Neznamy typ riadku
 }
 
 /**
  * Extrahuje hodnotu za prefixom v riadku
  *
  * Popis: Funkcia hlada zadany prefix v riadku a vracia kopiu retazca,
  * ktora nasleduje za nim, s odstranenym odsadenim.
  *
  * Parametre:
  * @param line - Vstupny riadok na spracovanie
  * @param prefix - Hladany prefix
  *
  * Navratova hodnota:
  * @return char* - Novo-alokovany retazec s hodnotou, NULL ak prefix nebol najdeny
  */
 static char *get_line_value(const char *line, const char *prefix) {
   // Hladanie prefixu v riadku
   const char *start = strstr(line, prefix);
   if (!start)
     return NULL;  // Prefix sa nenasiel
 
   // Presun za prefix a preskocenie medzier
   start += strlen(prefix);  // Posun za prefix
   while (isspace(*start))   // Preskocenie medzier za prefixom
     start++;
 
   // Vytvorenie kopie retazca a odstranenie medzier
   char *temp = strdup(start);  // Vytvorenie kopie retazca
   if (!temp)
     return NULL;  // Zlyhanie alokacie
   
   // Odstranenie medzier zo zaciatku a konca
   char *trimmed = trim(temp);  // Funkcia trim() je definovana v common.h
   if (trimmed != temp) {
     // Ak trim zmenil zaciatok retazca, presunieme ho na zaciatok
     memmove(temp, trimmed, strlen(trimmed) + 1);
   }
 
   return temp;  // Vratenie upraveneho retazca
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
   
   // Uvolnenie vsetkych alokovanych retazcov
   free(data->hex_key);          // Uvolnenie kluca
   free(data->hex_ad);           // Uvolnenie asociovanych dat
   free(data->hex_plaintext);    // Uvolnenie plaintextu
   free(data->hex_expected_iv);  // Uvolnenie ocakavaneho IV
   free(data->hex_expected_ct);  // Uvolnenie ocakavaneho ciphertextu
   
   // Vynulovanie celej struktury pre bezpecnost
   memset(data, 0, sizeof(TestCaseData));
 }
 
 /**
  * Nacita nasledujuci testovaci vektor zo suboru
  *
  * Popis: Funkcia cita testovacie data zo suboru riadok po riadku,
  * spracovava rozne typy riadkov a zostavuje kompletny testovaci vektor.
  *
  * Parametre:
  * @param fp - Pointer na otvoreny subor na citanie
  * @param data - Struktura pre ulozenie dat testovacieho vektora
  *
  * Navratova hodnota:
  * @return bool - true ak sa podarilo nacitat kompletny testovaci vektor, false inak
  */
 bool parse_next_test_case(FILE *fp, TestCaseData *data) {
   char line[SIV_LINE_BUFFER_SIZE];  // Buffer pre citanie riadku
   char *value;                      // Pomocna premenna pre extrahovane hodnoty
   bool in_test_case = false;        // Priznak ci sme vo vnutri testovacieho vektora
   long start_pos = ftell(fp);       // Zapamatanie aktualnej pozicie v subore
   bool fail_tag_seen = false;       // Priznak ci sme narazili na FAIL flag
 
   // Inicializacia a uvolnenie predchadzajucich dat
   free_test_case_data(data);        // Uvolnenie predoslych dat
   data->is_decrypt = false;         // Predvolena hodnota - test sifrovania
   data->count = 0;                  // Vychodzi pocet testu = 0
 
   // Citanie suboru riadok po riadku
   while (fgets(line, sizeof(line), fp)) {
     char *trimmed = trim(line);     // Odstranenie medzier zo zaciatku a konca
     if (!trimmed || strlen(trimmed) == 0) {
       continue;                      // Preskocenie prazdnych riadkov
     }
 
     // Kontrola specialnych znaciek pre zaciatky sekcii
     if (strstr(trimmed, SIV_PREFIX_INPUT)) {
       if (in_test_case) {
         // Ak uz spracovavame testovaci vektor a narazime na novy, vratime sa spat
         fseek(fp, start_pos, SEEK_SET);  // Vratenie kurzora na zaciatok riadku
         data->should_fail = fail_tag_seen;  // Nastavenie priznaku ocakavaneho zlyhania
         return true;  // Vratime kompletny testovaci vektor
       }
       in_test_case = true;  // Zacali sme citat novy testovaci vektor
       continue;  // Pokracujeme dalej
     }
 
     // Preskocene oznacenia sekcie vystupov
     if (strstr(trimmed, SIV_PREFIX_OUTPUT)) {
       continue;  // Preskocime tuto znacku a pokracujeme
     }
 
     // Identifikacia typu riadku a spracovanie hodnoty
     LineType type = get_line_type(trimmed);
     value = NULL;  // Reset pomocnej premennej
 
     // Spracovanie riadkov podla ich typu
     switch (type) {
     case COUNT_T:  // Riadok s cislom testu
       value = get_line_value(trimmed, SIV_PREFIX_COUNT);
       data->count = atoi(value);  // Konverzia retazca na cislo
       free(value);  // Uvolnenie docasnej hodnoty
       break;
 
     case KEY_T:  // Riadok s klucom
       value = get_line_value(trimmed, SIV_PREFIX_KEY_1);
       if (!value)
         value = get_line_value(trimmed, SIV_PREFIX_KEY_2);
       if (!data->hex_key)
         data->hex_key = value;  // Ulozenie kluca
       else
         free(value);  // Uz mame kluc, uvolnime duplikat
       break;
 
     case AD_T:  // Riadok s asociovanymi datami
       value = get_line_value(trimmed, SIV_PREFIX_AD_1);
       if (!value)
         value = get_line_value(trimmed, SIV_PREFIX_AD_2);
       if (!data->hex_ad)
         data->hex_ad = value;  // Ulozenie asociovanych dat
       else
         free(value);  // Uz mame AD, uvolnime duplikat
       break;
 
     case PT_T:  // Riadok s plaintextom
       value = get_line_value(trimmed, SIV_PREFIX_PT_1);
       if (!value)
         value = get_line_value(trimmed, SIV_PREFIX_PT_2);
       if (!data->hex_plaintext)
         data->hex_plaintext = value;  // Ulozenie plaintextu
       else
         free(value);  // Uz mame plaintext, uvolnime duplikat
       break;
 
     case CT_T:  // Riadok s ciphertextom
       value = get_line_value(trimmed, SIV_PREFIX_CT_1);
       if (!value)
         value = get_line_value(trimmed, SIV_PREFIX_CT_2);
       if (!data->hex_expected_ct)
         data->hex_expected_ct = value;  // Ulozenie ocakavaneho ciphertextu
       else
         free(value);  // Uz mame ciphertext, uvolnime duplikat
       break;
 
     case CMAC_T:  // Riadok s CMAC (IV)
       value = get_line_value(trimmed, SIV_PREFIX_CMAC);
       if (!data->hex_expected_iv)
         data->hex_expected_iv = value;  // Ulozenie ocakavaneho IV
       else
         free(value);  // Uz mame IV, uvolnime duplikat
       break;
 
     case FAIL_T:  // Riadok oznacujuci ocakavane zlyhanie
       fail_tag_seen = true;  // Nastavenie priznaku zlyhania
       break;
 
     default:  // Neznamy typ riadku
       // Ignorujeme nepodporovane typy riadkov
       break;
     }
     start_pos = ftell(fp);  // Aktualizacia pozicie pre dalsi riadok
   }
 
   // Ak sme nacitali aspon kluc a plaintext, povazujeme to za platny testovaci vektor
   if (in_test_case && data->hex_key && data->hex_plaintext) {
     data->should_fail = fail_tag_seen;  // Nastavenie priznaku ocakavaneho zlyhania
     return true;  // Vratime kompletny testovaci vektor
   }
   return false;  // Nenasli sme kompletny testovaci vektor
 }
 
 /**
  * Spracuje a vyhodnoti jeden testovaci vektor
  *
  * Popis: Hlavna funkcia, ktora vykonava samotne testovanie jedneho SIV
  * testovacieho vektora. Obsahuje sifrovanie, desifrovanie a porovnanie
  * vysledkov s ocakavanymi hodnotami.
  *
  * Parametre:
  * @param data - Struktura obsahujuca testovacie data
  * @param passed_encrypt - Pointer na pocitadlo uspesnych encrypt testov
  * @param passed_decrypt - Pointer na pocitadlo uspesnych decrypt testov
  *
  * Navratova hodnota:
  * @return bool - true ak test bol uspesne vykonany, false pri kritickom zlyhaní
  */
 bool process_test_case(const TestCaseData *data, int *passed_encrypt,
                        int *passed_decrypt) {
   // Kontrola ci mame vsetky potrebne data
   if (!data->hex_key || !data->hex_expected_iv || !data->hex_plaintext ||
       !data->hex_expected_ct) {
     printf("Nekompletne testovacie data\n");
     return false;  // Nekompletne testovacie data
   }
 
   // Vypocet velkosti jednotlivych komponentov
   size_t lens[] = {
     strlen(data->hex_key) / 2,           // Kluc (v SIV musi byt dvojnasobnej dlzky oproti AES)
     strlen(data->hex_expected_iv) / 2,   // Ocakavany IV
     data->hex_ad ? strlen(data->hex_ad) / 2 : 0,  // Asociovane data (volitelne)
     data->hex_plaintext ? strlen(data->hex_plaintext) / 2 : 0,  // Plaintext
     data->hex_expected_ct ? strlen(data->hex_expected_ct) / 2 : 0,  // Ocakavany ciphertext
     SIV_TAG_LEN                          // Dlzka tagu - fixny parameter, nepouzity v SIV
   };
 
   // Kontrola spravnej dlzky kluca pre SIV rezim
   if (lens[0] != 2 * (AES_KEY_SIZE)) {
     printf("Chyba: Nespravna dlzka kluca pre SIV rezim. Ocakavana dlzka: "
            "%d bajtov (dvojnasobok AES kluca)\n",
            2 * AES_KEY_SIZE);
     return false;  // Neplatna dlzka kluca
   }
 
   // Alokacia pamate pre buffery
   uint8_t *bufs[] = {
     calloc(lens[0] + 1, 1),  // Kluc (dvojnasobna dlzka oproti standardnemu AES)
     calloc(lens[1] + 1, 1),  // Ocakavany IV
     calloc(lens[2] + 1, 1),  // Asociovane data
     calloc(lens[3] + 1, 1),  // Plaintext
     calloc(lens[4] + 1, 1),  // Ocakavany ciphertext
     calloc(lens[5] + 1, 1)   // Nie je pouzity v SIV
   };
 
   // Alokacia pomocnych bufferov pre vysledky
   uint8_t *actual_iv = calloc(SIV_TAG_LEN, 1);       // Buffer pre vypocitany IV
   uint8_t *actual_ct = calloc(lens[3] + 1, 1);       // Buffer pre vypocitany ciphertext
   uint8_t *decrypted_pt = calloc(lens[4] + 1, 1);    // Buffer pre desifrovany plaintext
 
   // Kontrola uspesnosti alokacie
   if (!actual_iv || !actual_ct || !decrypted_pt)
     goto cleanup;  // Pri chybe alokacie preskocime na cistenie
 
   // Kontrola uspesnosti alokacie vsetkych bufferov
   for (int i = 0; i < 6; i++) {
     if (!bufs[i])
       goto cleanup;  // Pri chybe alokacie preskocime na cistenie
   }
 
   // Konverzia hex retazcov na binarne data
   const char *hexs[] = {
     data->hex_key,           // Kluc
     data->hex_expected_iv,   // Ocakavany IV
     data->hex_ad,            // Asociovane data
     data->hex_plaintext,     // Plaintext
     data->hex_expected_ct,   // Ocakavany ciphertext
     NULL                     // Nepoužívany buffer
   };
 
   // Konverzia vsetkych hex retazcov na binarne data
   for (int i = 0; i < 5; i++) {
     if (hexs[i] && hex_to_bin(hexs[i], bufs[i], lens[i]) != 0)
       goto cleanup;  // Pri chybe konverzie preskocime na cistenie
   }
 
   // Vypis informacii o testovanom vektore
   printf("=== Test #%d ===\n", data->count);
   printf("Vstupne data:\n");
   printf("  Kluc (%zu bajtov - dvojnasobna dlzka kluca pre SIV): ",
          lens[0]);
   print_limited(data->hex_key, SIV_MAX_LINE_LENGTH);
   if (data->hex_ad) {
     printf("  Associated Data (AD): ");
     print_limited(data->hex_ad, SIV_MAX_LINE_LENGTH);
   }
   printf("  Plaintext: ");
   print_limited(data->hex_plaintext ? data->hex_plaintext : "(prazdny)",
                 SIV_MAX_LINE_LENGTH);
 
   // --- Test sifrovania (encrypt) ---
   printf("\nTest sifrovania:\n");
 
   // Pouzijeme lokalny IV buffer, pretoze funkcia AES_SIV_encrypt ocakava pole, nie pointer
   uint8_t iv_buffer[SIV_TAG_LEN] = {0};  // Lokalny buffer pre IV
   
   // Vykonanie operacie sifrovania
   AES_SIV_encrypt(bufs[0], bufs[3], lens[3], bufs[2], lens[2], iv_buffer,
                   actual_ct);
   
   // Skopirujeme vysledok pre porovnanie
   memcpy(actual_iv, iv_buffer, SIV_TAG_LEN);
 
   // Vypiseme vysledky sifrovania
   printf("  Vypocitany IV (CMAC): ");
   print_hex(actual_iv, lens[1]);
   printf("  Ocakavany IV (CMAC): ");
   print_hex(bufs[1], lens[1]);
 
   printf("  Vypocitany ciphertext: ");
   print_hex(actual_ct, lens[3]);
   printf("  Ocakavany ciphertext: ");
   print_hex(bufs[4], lens[4]);
 
   // Porovnanie vysledkov sifrovania s ocakavanymi hodnotami
   bool iv_match = (memcmp(actual_iv, bufs[1], lens[1]) == 0);  // Zhoda IV
   bool ct_match = (memcmp(actual_ct, bufs[4], lens[4]) == 0);  // Zhoda ciphertextu
   bool encrypt_ok = iv_match && ct_match;  // Celkova uspesnost sifrovania
 
   // Aktualizacia pocitadla uspesnych testov sifrovania
   if (encrypt_ok)
     (*passed_encrypt)++;
     
   // Vypis vysledku testu sifrovania
   printf("  Vysledok sifrovania: %s\n",
          encrypt_ok ? SIV_MSG_SUCCESS : SIV_MSG_FAILURE);
 
   // --- Test desifrovania (decrypt) ---
   printf("\nTest desifrovania:\n");
 
   // Vykonanie operacie desifrovania
   uint8_t decrypt_status = AES_SIV_decrypt(
       bufs[0], bufs[1], bufs[4], lens[4], bufs[2], lens[2], decrypted_pt);
 
   // Vyhodnotenie uspesnosti autentifikacie a desifrovania
   bool auth_ok = (decrypt_status == 0);  // Uspesna autentifikacia
   bool decrypt_match =
       auth_ok && (memcmp(decrypted_pt, bufs[3], lens[3]) == 0);  // Zhoda plaintextu
 
   // Vypis vysledkov autentifikacie
   printf("  Autentifikacia: %s\n", auth_ok ? SIV_MSG_AUTH_SUCCESS : SIV_MSG_AUTH_FAILURE);
 
   // Ak autentifikacia prebehla uspesne, vypiseme desifrovany plaintext
   if (auth_ok) {
     printf("  Vypocitany plaintext: ");
     print_hex(decrypted_pt, lens[3]);
     printf("  Ocakavany plaintext: ");
     print_hex(bufs[3], lens[3]);
   } else {
     printf("  Plaintext nedostupny (zlyhala autentifikacia)\n");
   }
 
   // Vypis vysledku testu desifrovania
   printf("  Vysledok desifrovania: %s\n\n",
          decrypt_match ? SIV_MSG_SUCCESS : SIV_MSG_FAILURE);
 
   // Aktualizacia pocitadla uspesnych testov desifrovania
   if (decrypt_match)
     (*passed_decrypt)++;
 
 cleanup:
   // Uvolnenie vsetkych alokovanych bufferov
   for (int i = 0; i < 6; i++) {
     free(bufs[i]);
   }
   free(actual_iv);
   free(actual_ct);
   free(decrypted_pt);
   return true;  // Vratenie uspesneho vykonania testu
 }
 
 /**
  * Hlavna funkcia programu
  *
  * Popis: Hlavna funkcia inicializuje program, otvara subor s testovacimi
  * vektormi, spusta spracovanie a testovanie jednotlivych vektorov,
  * a na zaver zobrazuje celkovu statistiku uspesnosti testov.
  *
  * Navratova hodnota:
  * @return int - 0 ak vsetky testy boli uspesne, 1 ak nie
  */
 int main() {
   // Definicie suborov s testovacimi vektormi podla velkosti kluca
   #define SIV_TEST_VECTORS_128 "test_vectors/siv_128.txt"  // Testovaci subor pre AES-128-SIV
   #define SIV_TEST_VECTORS_192 "test_vectors/siv_192.txt"  // Testovaci subor pre AES-192-SIV
   #define SIV_TEST_VECTORS_256 "test_vectors/siv_256.txt"  // Testovaci subor pre AES-256-SIV
 
   // Vyber spravneho testovacieho suboru podla kompilacnych nastaveni
   const char *test_vectors_file = SIV_TEST_VECTORS_128;  // Predvoleny testovaci subor
   
   // Vypis informacii o testovacom programe
   #if AES___ == 128
     printf("AES-256-SIV Test (pouziva kluc dlhy %d bajtov)\n",
            2 * AES_KEY_SIZE);  // Pre AES-128-SIV (kluc ma 256 bitov = 32 bajtov)
   #elif AES___ == 192
     test_vectors_file = SIV_TEST_VECTORS_192;
     printf("AES-192-SIV Test (pouziva kluc dlhy %d bajtov)\n",
            2 * AES_KEY_SIZE);  // Pre AES-192-SIV
   #elif AES___ == 256
     test_vectors_file = SIV_TEST_VECTORS_256;
     printf("AES-128-SIV Test (pouziva kluc dlhy %d bajtov)\n",
            2 * AES_KEY_SIZE);  // Pre AES-256-SIV
   #endif
 
   printf("Pouziva sa testovaci subor: %s\n", test_vectors_file);
 
   // Otvorenie suboru s testovacimi vektormi
   FILE *fp = fopen(test_vectors_file, "r");
   
   // Inicializacia pocitadiel pre testovanie
   int tests_passed_encrypt = 0;  // Pocitadlo uspesnych encrypt testov
   int tests_passed_decrypt = 0;  // Pocitadlo uspesnych decrypt testov
   TestCaseData current_test = {0};  // Struktura pre aktualny testovaci vektor
   int processed_tests = 0;  // Pocitadlo spracovanych testovacich vektorov
 
   // Kontrola ci sa podarilo otvorit subor
   if (!fp) {
     perror("Nepodarilo sa otvorit subor s testovacimi vektormi");
     return 1;  // Chybovy navratovy kod
   }
 
   // Spracovanie testovacich vektorov v cykle
   while (parse_next_test_case(fp, &current_test)) {
     processed_tests++;  // Inkrementacia pocitadla testov
     process_test_case(&current_test, &tests_passed_encrypt,
                       &tests_passed_decrypt);  // Spracovanie aktualneho testu
     free_test_case_data(&current_test);  // Uvolnenie pamate aktualneho testu
   }
 
   fclose(fp);  // Zatvorenie suboru
 
   // Kontrola ci boli nacitane nejake testovacie vektory
   if (processed_tests == 0) {
     printf("Zo suboru neboli nacitane ziadne testovacie vektory\n");
     return 1;  // Chybovy navratovy kod
   }
 
   // Vypocet celkovej uspesnosti testov
   int total_passed = tests_passed_encrypt + tests_passed_decrypt;
   int total_tests =
       processed_tests * 2;  // 1 sifrovanie + 1 desifrovanie pre kazdy test
   bool success = (processed_tests > 0 && total_passed == total_tests);
 
   // Vypis celkovych vysledkov
   printf("\nCelkove vysledky:\n");
   printf("Spracovanych testovacich vektorov: %d\n", processed_tests);
   printf("Uspesnych testov sifrovania: %d/%d\n", tests_passed_encrypt,
          processed_tests);
   printf("Uspesnych testov desifrovania: %d/%d\n", tests_passed_decrypt,
          processed_tests);
   printf("Celkovy vysledok: %s\n", success ? SIV_MSG_SUCCESS : SIV_MSG_FAILURE);
 
   return success ? 0 : 1;  // Navratovy kod: 0 pre uspech, 1 pre neuspech
 }