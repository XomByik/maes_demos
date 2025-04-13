/************************************************************************
 * Nazov projektu: Demonštracia funkcnosti rezimov AES-u z kniznice micro-AES
 * -----------------------------------------------------------------------
 * Subor: gcm_siv_demo.c
 * Verzia: 1.1
 * Datum: 13.4.2025
 *
 * Autor: Kamil Berecky
 *
 * Popis: Program demonstruje funkcnost rezimu AES-GCM-SIV pomocou oficialnych
 * testovacich vektorov. Implementuje autentifikovane sifrovanie a desifrovanie
 * podla RFC 8452 s ochranou proti neopravnenemu zasahu do dat a nonce reuse.
 * Program podporuje rozne velkosti klucov (128, 256 bitov).
 * 
 * Vyuzite zdroje:
 * - micro-AES kniznica: 
 *   https://github.com/polfosol/micro-AES
 * - RFC 8452:
 *   https://tools.ietf.org/html/rfc8452
 *
 * Pre viac info pozri README.md
 **********************************************************************/

 #include "../header_files/gcm_siv.h"

 /**
  * Enum pre rozlisenie typov riadkov v testovacom subore
  */
 typedef enum { 
     KEY,       // Riadok obsahujuci kluc
     NONCE,     // Riadok obsahujuci nonce (IV)
     AAD,       // Riadok obsahujuci pridane autentifikacne data
     PT,        // Riadok obsahujuci plaintext
     CT,        // Riadok obsahujuci ciphertext a tag
     COUNT      // Riadok obsahujuci cislo testovacieho vektora
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
   if (strstr(line, GCM_SIV_PREFIX_KEY))
     return KEY;  // Riadok obsahuje kluc
   if (strstr(line, GCM_SIV_PREFIX_NONCE))
     return NONCE;  // Riadok obsahuje nonce (IV)
   if (strstr(line, GCM_SIV_PREFIX_AAD))
     return AAD;  // Riadok obsahuje AAD
   if (strstr(line, GCM_SIV_PREFIX_PT))
     return PT;  // Riadok obsahuje plaintext
   if (strstr(line, GCM_SIV_PREFIX_CT))
     return CT;  // Riadok obsahuje ciphertext a tag
   if (strstr(line, GCM_SIV_PREFIX_COUNT))
     return COUNT;  // Riadok obsahuje cislo testovacieho vektora
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
  * zo struktury TestCaseData a resetuje strukturu.
  *
  * Proces:
  * 1. Kontrola ci vstupny pointer nie je NULL
  * 2. Uvolnenie vsetkych alokovanych retazcov
  * 3. Vynulovanie celej struktury a nastavenie vychodzich hodnot
  *
  * Parametre:
  * @param data - Pointer na strukturu s testovacimi datami
  */
 void free_test_case_data(TestCaseData *data) {
   if (!data)
     return;  // Ochrana pred NULL pointerom
     
   free(data->hex_key);  // Uvolnenie kluca
   free(data->hex_nonce);  // Uvolnenie nonce
   free(data->hex_aad);  // Uvolnenie AAD
   free(data->hex_plaintext);  // Uvolnenie plaintextu
   free(data->hex_ciphertext);  // Uvolnenie ciphertextu
   free(data->hex_tag);  // Uvolnenie tagu
   memset(data, 0, sizeof(TestCaseData));  // Vynulovanie celej struktury pre bezpecnost
   data->count = -1;  // Nastavenie pociatocnej hodnoty pre count
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
  * 3. Spracovanie specialneho pripadu CT, ktory obsahuje aj ciphertext aj tag
  * 4. Zabezpecenie, ze vsetky volitelne polia maju aspon prazdne retazce
  *
  * Parametre:
  * @param fp - Pointer na otvoreny subor na citanie
  * @param data - Struktura pre ulozenie dat testovacieho vektora
  *
  * Navratova hodnota:
  * @return bool - true ak sa podarilo nacitat kompletny testovaci vektor, false inak
  */
 bool parse_next_test_case(FILE *fp, TestCaseData *data) {
   char line[GCM_SIV_LINE_BUFFER_SIZE];  // Buffer pre citanie riadku
   char *value;  // Pomocna premenna pre extrahovane hodnoty
   bool in_test_case = false;  // Priznak, ci sme vo vnutri testovacieho vektora
   long start_pos = ftell(fp);  // Zapamatanie aktualnej pozicie v subore
 
   free_test_case_data(data);  // Uvolnenie predchadzajucich dat
 
   // Citanie suboru po riadkoch
   while (fgets(line, sizeof(line), fp)) {
     char *trimmed = trim(line);  // Odstranenie medzier zo zaciatku a konca
     if (!trimmed || strlen(trimmed) == 0) {
       start_pos = ftell(fp);  // Aktualizacia pozicie pre prazdne riadky
       continue;  // Preskocenie prazdnych riadkov
     }
 
     LineType type = get_line_type(trimmed);  // Urcenie typu riadku
     value = NULL;  // Reset pomocnej premennej
 
     // Spracovanie riadku podla typu
     switch (type) {
     case COUNT:  // Riadok s cislom testovacieho vektora
       value = get_line_value(trimmed, GCM_SIV_PREFIX_COUNT);
       if (value) {
         if (in_test_case) {
           // Ak uz spracovavame test a narazime na novy Count,
           // vratime sa spat a ukoncime spracovanie aktualneho testu
           fseek(fp, start_pos, SEEK_SET);  // Vratenie kurzora na zaciatok riadku
           free(value);  // Uvolnenie docasnej hodnoty
           goto finish_test_case;  // Skok na dokoncenie spracovania testu
         }
         data->count = atoi(value);  // Konverzia na cislo
         in_test_case = true;  // Oznacenie zaciatku noveho testu
         free(value);  // Uvolnenie docasnej hodnoty
       }
       break;
 
     case KEY:  // Riadok s klucom
       if (in_test_case) {
         value = get_line_value(trimmed, GCM_SIV_PREFIX_KEY);
         if (!data->hex_key)
           data->hex_key = value;  // Ulozenie kluca
         else
           free(value);  // Uz mame kluc, uvolnime duplikat
       }
       break;
 
     case NONCE:  // Riadok s nonce (IV)
       if (in_test_case) {
         value = get_line_value(trimmed, GCM_SIV_PREFIX_NONCE);
         if (!data->hex_nonce)
           data->hex_nonce = value;  // Ulozenie nonce
         else
           free(value);  // Uz mame nonce, uvolnime duplikat
       }
       break;
 
     case AAD:  // Riadok s AAD
       if (in_test_case) {
         value = get_line_value(trimmed, GCM_SIV_PREFIX_AAD);
         if (!data->hex_aad)
           data->hex_aad = value;  // Ulozenie AAD
         else
           free(value);  // Uz mame AAD, uvolnime duplikat
       }
       break;
 
     case PT:  // Riadok s plaintextom
       if (in_test_case) {
         value = get_line_value(trimmed, GCM_SIV_PREFIX_PT);
         if (!data->hex_plaintext)
           data->hex_plaintext = value;  // Ulozenie plaintextu
         else
           free(value);  // Uz mame plaintext, uvolnime duplikat
       }
       break;
 
     case CT:  // Riadok s ciphertextom a tagom
       if (in_test_case) {
         value = get_line_value(trimmed, GCM_SIV_PREFIX_CT);
         if (value) {
           size_t combined_len = strlen(value);  // Dlzka kombinovaneho CT+Tag
           size_t tag_hex_len = GCM_SIV_TAG_LEN * 2;  // Dlzka tagu v hex formate (16 bajtov = 32 znakov)
 
           // Rozdelenie kombinovaneho CT+Tag na samostatne hodnoty
           if (combined_len >= tag_hex_len) {
             size_t ct_hex_len = combined_len - tag_hex_len;  // Dlzka ciphertextu v hex formate
             data->hex_ciphertext = strdup(value);  // Kopirovanie celeho retazca
             if (data->hex_ciphertext) {
                 data->hex_ciphertext[ct_hex_len] = '\0';  // Ukoncenie retazca po ciphertexte
             }
             data->hex_tag = strdup(value + ct_hex_len);  // Kopirovanie cast retazca obsahujuci tag
           } else {
             data->hex_ciphertext = strdup("");  // Prazdny ciphertext
             data->hex_tag = strdup(value);  // Cely retazec je tag
           }
           free(value);  // Uvolnenie povodneho kombinovaneho retazca
         }
       }
       break;
     }
     start_pos = ftell(fp);  // Aktualizacia pozicie pre dalsi riadok
   }
 
 finish_test_case:
   // Kontrola ci mame vsetky potrebne data pre validny testovaci vektor
   if (in_test_case && data->hex_key && data->hex_nonce && data->hex_tag) {
     // Zabezpecenie, ze volitelne polia maju aspon prazdne retazce
     if (!data->hex_aad)
       data->hex_aad = strdup("");  // Prazdne AAD
     if (!data->hex_plaintext)
       data->hex_plaintext = strdup("");  // Prazdny plaintext
     if (!data->hex_ciphertext)
       data->hex_ciphertext = strdup("");  // Prazdny ciphertext
 
     // Kontrola ci vsetky alokacie uspeli
     if (data->hex_aad && data->hex_plaintext && data->hex_ciphertext) {
       return true;  // Vratime kompletny testovaci vektor
     }
   }
 
   free_test_case_data(data);  // Uvolnenie dat pri neuspesnom nacitani
   return false;  // Nepodarilo sa nacitat kompletny testovaci vektor
 }
 
 /**
  * Spracuje a vyhodnoti jeden testovaci vektor
  *
  * Popis: Hlavna funkcia, ktora vykonava samotne testovanie jedneho GCM-SIV
  * testovacieho vektora. Obsahuje sifrovanie, desifrovanie a porovnanie
  * vysledkov s ocakavanymi hodnotami.
  *
  * Proces:
  * 1. Vypocet a validacia velkosti vstupnych dat
  * 2. Alokacia pamate pre vstupne a vystupne buffery
  * 3. Konverzia hex retazcov na binarne data
  * 4. Vykonanie sifrovania a desifrovania
  * 5. Porovnanie vysledkov s ocakavanymi hodnotami
  * 6. Aktualizacia statistiky testov
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
       strlen(data->hex_nonce) / 2,  // Dlzka nonce v bajtoch
       data->hex_aad ? strlen(data->hex_aad) / 2 : 0,  // Dlzka AAD v bajtoch
       data->hex_plaintext ? strlen(data->hex_plaintext) / 2 : 0,  // Dlzka plaintextu v bajtoch
       data->hex_ciphertext ? strlen(data->hex_ciphertext) / 2 : 0,  // Dlzka ciphertextu v bajtoch
       strlen(data->hex_tag) / 2  // Dlzka tagu v bajtoch
   };
 
   // Validacia velkosti komponentov
   if (lens[0] != 16 && lens[0] != 24 && lens[0] != 32)
     return false;  // Neplatna velkost kluca (podporovane su len 128, 192 a 256 bitov)
   if (lens[1] != GCM_SIV_NONCE_LEN)
     return false;  // Neplatna velkost nonce
   if (lens[5] != GCM_SIV_TAG_LEN)
     return false;  // Neplatna velkost tagu
   if (lens[4] != lens[3])
     return false;  // Nezhoda velkosti plaintextu a ciphertextu
 
   // Alokacia bufferov pre binarne reprezentacie dat
   uint8_t *bufs[] = {
       calloc(lens[0] + 1, 1),  // Buffer pre kluc
       calloc(lens[1] + 1, 1),  // Buffer pre nonce
       calloc(lens[2] + 1, 1),  // Buffer pre AAD
       calloc(lens[3] + 1, 1),  // Buffer pre plaintext
       calloc(lens[4] + 1, 1),  // Buffer pre ocakavany ciphertext
       calloc(lens[5] + 1, 1)   // Buffer pre ocakavany tag
   };
 
   // Alokacia dodatocnych bufferov pre operacie sifrovania/desifrovania
   uint8_t *result_ct = calloc(lens[3] + 1, 1);  // Buffer pre vypocitany ciphertext
   uint8_t *result_tag = calloc(GCM_SIV_TAG_LEN + 1, 1);  // Buffer pre vypocitany tag
   uint8_t *combined = calloc(lens[4] + lens[5] + 1, 1);  // Buffer pre kombinovany CT+Tag
   uint8_t *decrypted = calloc(lens[3] + 1, 1);  // Buffer pre desifrovany plaintext
 
   // Kontrola uspesnosti alokacie vsetkych bufferov
   for (int i = 0; i < 6; i++) {
     if (!bufs[i])
       goto cleanup;  // Pri zlyhani alokacie skocime na cistenie
   }
   // Kontrola uspesnosti alokacie pomocnych bufferov
   if (!result_ct || !result_tag || !combined || !decrypted)
     goto cleanup;  // Pri zlyhani alokacie skocime na cistenie
 
   // Pole s pointrami na hex retazce pre konverziu
   const char *hexs[] = {data->hex_key,        data->hex_nonce,
                         data->hex_aad,        data->hex_plaintext,
                         data->hex_ciphertext, data->hex_tag};
 
   // Konverzia hex retazcov na binarne data
   for (int i = 0; i < 6; i++) {
     if (hexs[i] && hex_to_bin(hexs[i], bufs[i], lens[i]) != 0)
       goto cleanup;  // Pri zlyhani konverzie skocime na cistenie
   }
 
   // Vypis informacii o testovanom vektore
   printf("=== Test #%d ===\n", data->count);
   printf("Vstupne data:\n");
   printf("  Nonce: ");
   print_limited(data->hex_nonce, GCM_SIV_MAX_LINE_LENGTH);  // Vypis nonce s obmedzenim dlzky
   if (data->hex_aad && strlen(data->hex_aad) > 0) {
     printf("  AAD: ");
     print_limited(data->hex_aad, GCM_SIV_MAX_LINE_LENGTH);  // Vypis AAD s obmedzenim dlzky
   } else {
     printf("  AAD: (prazdne)\n");  // Informacia o prazdnom AAD
   }
   printf("  Plaintext: ");
   print_limited(data->hex_plaintext ? data->hex_plaintext : "(prazdny)",
                 GCM_SIV_MAX_LINE_LENGTH);  // Vypis plaintextu s obmedzenim dlzky
 
   // Test sifrovania
   printf("\nTest sifrovania:\n");
   GCM_SIV_encrypt(bufs[0], bufs[1], bufs[3], lens[3], bufs[2], lens[2],
                   result_ct, result_tag);  // Volanie funkcie na sifrovanie
 
   // Vypis vysledkov sifrovania
   printf("  Vypocitany ciphertext: ");
   print_hex(result_ct, lens[3]);  // Vypis vypocitaneho ciphertextu
   printf("  Ocakavany ciphertext: ");
   print_hex(bufs[4], lens[4]);  // Vypis ocakavaneho ciphertextu
   printf("  Vypocitany tag: ");
   print_hex(result_tag, GCM_SIV_TAG_LEN);  // Vypis vypocitaneho tagu
   printf("  Ocakavany tag: ");
   print_hex(bufs[5], lens[5]);  // Vypis ocakavaneho tagu
 
   // Vyhodnotenie vysledkov sifrovania
   bool ct_match_enc = (memcmp(result_ct, bufs[4], lens[3]) == 0);  // Zhoda ciphertextov
   bool tag_match_enc = (memcmp(result_tag, bufs[5], lens[5]) == 0);  // Zhoda tagov
   bool encrypt_ok = ct_match_enc && tag_match_enc;  // Celkova uspesnost sifrovania
 
   // Aktualizacia statistiky uspesnosti sifrovania
   if (encrypt_ok)
     (*passed_encrypt)++;  // Inkrementacia pocitadla uspesnych encrypt testov
   printf("  Vysledok: %s\n", encrypt_ok ? "USPESNY" : "NEUSPESNY");  // Vypis vysledku
 
   // Test desifrovania
   printf("\nTest desifrovania:\n");
   // Spojenie ciphertextu a tagu do jedneho bloku
   if (lens[4] > 0)
     memcpy(combined, bufs[4], lens[4]);  // Najprv ciphertext, ak existuje
   memcpy(combined + lens[4], bufs[5], lens[5]);  // Za nim tag
 
   // Vykonanie GCM-SIV desifrovania
   uint8_t decrypt_status =
       GCM_SIV_decrypt(bufs[0], bufs[1], combined, lens[4], bufs[2],
                       lens[2], lens[5], decrypted);
 
   // Vypis vysledkov desifrovania
   printf("  Vypocitany plaintext: ");
   if (decrypt_status == NO_ERROR_RETURNED) {
     print_hex(decrypted, lens[3]);  // Vypis desifrovaneho plaintextu
   } else {
     printf("(Nedostupny - chyba autentifikacie)\n");  // Informacia o chybe autentifikacie
   }
   printf("  Ocakavany plaintext: ");
   print_hex(bufs[3], lens[3]);  // Vypis ocakavaneho plaintextu
   printf("  Autentifikacia: %s\n",
          decrypt_status == NO_ERROR_RETURNED ? "OK" : "ZLYHALA");  // Vypis stavu autentifikacie
 
   // Vyhodnotenie vysledkov desifrovania
   bool decrypt_ok = (decrypt_status == NO_ERROR_RETURNED) &&
                     (memcmp(decrypted, bufs[3], lens[3]) == 0);  // Uspech len ak autentifikacia presla a plaintexty sa zhoduju
 
   // Aktualizacia statistiky uspesnosti desifrovania
   if (decrypt_ok)
     (*passed_decrypt)++;  // Inkrementacia pocitadla uspesnych decrypt testov
   printf("  Vysledok: %s\n\n", decrypt_ok ? "USPESNY" : "NEUSPESNY");  // Vypis vysledku
 
 cleanup:
   // Uvolnenie vsetkych alokovanych bufferov
   for (int i = 0; i < 6; i++) {
     free(bufs[i]);
   }
   free(result_ct);
   free(result_tag);
   free(combined);
   free(decrypted);
   return true;  // Vratime true, aj ked mohlo dojst k chyba (chovanie je konzistentne s ostatnymi modulmi)
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
 
   // Vyberie spravny testovaci subor podla velkosti kluca
 #if AES___ == 256
   test_vectors_file = GCM_SIV_TEST_VECTORS_256;  // Pre AES-256
   printf("AES-256 GCM-SIV Test\n");
 #else
   test_vectors_file = GCM_SIV_TEST_VECTORS_128;  // Pre AES-128
   printf("AES-128 GCM-SIV Test\n");
 #endif
 
   printf("Pouziva sa testovaci subor: %s\n", test_vectors_file);
 
   // Otvorenie testovacieho suboru
   FILE *fp = fopen(test_vectors_file, "r");
   if (!fp) {
     perror("Chyba pri otvarani testovaciho suboru");
     return 1;  // Chybovy navratovy kod
   }
 
   // Inicializacia premennych pre testovanie
   int tests_passed_encrypt = 0;  // Pocitadlo uspesnych encrypt testov
   int tests_passed_decrypt = 0;  // Pocitadlo uspesnych decrypt testov
   TestCaseData current_test = {.count = -1};  // Struktura pre aktualny testovaci vektor
   int processed_tests = 0;  // Pocitadlo spracovanych testovacich vektorov
 
   // Spracovanie testovacich vektorov v cykle
   while (parse_next_test_case(fp, &current_test)) {
     processed_tests++;  // Inkrementacia pocitadla testov
     process_test_case(&current_test, &tests_passed_encrypt,
                       &tests_passed_decrypt);  // Spracovanie a vyhodnotenie aktualneho testu
   }
 
   fclose(fp);  // Zatvorenie suboru
   free_test_case_data(&current_test);  // Uvolnenie pamate posledneho testu
 
   // Vyhodnotenie celkovej uspesnosti testov
   bool success =
       (processed_tests > 0 && tests_passed_encrypt == processed_tests &&
        tests_passed_decrypt == processed_tests);  // Uspesny iba ak vsetky testy presli
 
   // Vypis celkovej statistiky
   printf("\nCelkove vysledky:\n");
   printf("Spracovanych testovacich vektorov: %d\n", processed_tests);
   printf("Uspesnych testov sifrovania: %d\n", tests_passed_encrypt);
   printf("Uspesnych testov desifrovania: %d\n", tests_passed_decrypt);
   printf("Celkovy vysledok: %s\n", success ? "USPESNY" : "NEUSPESNY");
 
   return success ? 0 : 1;  // Navratovy kod podla celkovej uspesnosti
 }