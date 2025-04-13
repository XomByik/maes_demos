/************************************************************************
 * Nazov projektu: Demonštracia funkcnosti rezimov AES-u z kniznice micro-AES
 * -----------------------------------------------------------------------
 * Subor: ocb_demo.c
 * Verzia: 1.1
 * Datum: 13.4.2025
 *
 * Autor: Kamil Berecky
 *
 * Popis: Program demonstruje funkcnost rezimu AES-OCB pomocou oficialnych
 * testovacich vektorov. Implementuje autentifikovane sifrovanie a desifrovanie
 * podla RFC 7253. OCB poskytuje autentifikaciu a dovernost s minimalnou rezijou.
 * Program podporuje rozne velkosti klucov (128, 192, 256 bitov).
 * 
 * Vyuzite zdroje:
 * - micro-AES kniznica: 
 *   https://github.com/polfosol/micro-AES
 * - RFC 7253:
 *   https://doi.org/10.17487/RFC7253
 * 
 * Pre viac info pozri README.md
 **********************************************************************/

 #include "../header_files/ocb.h"

 /**
  * Enum pre rozlisenie typov riadkov v testovacom subore
  */
 typedef enum {
     KEY,       // Riadok obsahujuci kluc
     NONCE,     // Riadok obsahujuci nonce
     AAD,       // Riadok obsahujuci pridane autentifikacne data
     PT,        // Riadok obsahujuci plaintext
     CT,        // Riadok obsahujuci ciphertext a tag
     COUNT,     // Riadok obsahujuci cislo testovacieho vektora
     FAIL       // Riadok oznacujuci ocakavane zlyhanie
 } LineType;
 
 /**
  * Urci typ riadku v testovacom subore
  *
  * Popis: Funkcia analyzuje vstupny riadok a identifikuje jeho typ na zaklade
  * prefixov alebo klucovych slov na zaciatku riadku.
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
   if (strstr(line, OCB_PREFIX_KEY))
     return KEY;  // Riadok obsahuje kluc
   if (strncmp(line, OCB_PREFIX_NONCE_SHORT, strlen(OCB_PREFIX_NONCE_SHORT)) == 0 || 
       strncmp(line, OCB_PREFIX_NONCE_LONG, strlen(OCB_PREFIX_NONCE_LONG)) == 0)
     return NONCE;  // Riadok obsahuje nonce
   if (strncmp(line, OCB_PREFIX_AAD_SHORT, strlen(OCB_PREFIX_AAD_SHORT)) == 0 || 
       strncmp(line, OCB_PREFIX_AAD_LONG, strlen(OCB_PREFIX_AAD_LONG)) == 0)
     return AAD;  // Riadok obsahuje AAD
   if (strncmp(line, OCB_PREFIX_PT_SHORT, strlen(OCB_PREFIX_PT_SHORT)) == 0 || 
       strncmp(line, OCB_PREFIX_PT_LONG, strlen(OCB_PREFIX_PT_LONG)) == 0)
     return PT;  // Riadok obsahuje plaintext
   if (strncmp(line, OCB_PREFIX_CT_SHORT, strlen(OCB_PREFIX_CT_SHORT)) == 0 || 
       strncmp(line, OCB_PREFIX_CT_LONG, strlen(OCB_PREFIX_CT_LONG)) == 0)
     return CT;  // Riadok obsahuje ciphertext
   if (strstr(line, OCB_PREFIX_COUNT))
     return COUNT;  // Riadok obsahuje cislo testu
   if (strstr(line, OCB_PREFIX_FAIL))
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
  * 1. Kontrola ci riadok zacina danym prefixom
  * 2. Vytvorenie kopie retazca za prefixom
  * 3. Odstranenie medzier a formatovacich znakov
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
  * Extrahuje hodnotu za jednym z dvoch prefixov
  *
  * Popis: Funkcia hlada zadane prefixy v riadku a vracia kopiu retazca,
  * ktora nasleduje za jednym z nich. Podporuje kratky aj dlhy format prefixu.
  *
  * Proces:
  * 1. Skusi najskor dlhy prefix, potom kratky
  * 2. Pre najdeny prefix vytvori kopiu retazca za nim
  * 3. Odstrani medzery a formatovacie znaky
  *
  * Parametre:
  * @param line - Vstupny riadok na spracovanie
  * @param short_prefix - Kratky format prefixu (napr. "N:")
  * @param long_prefix - Dlhy format prefixu (napr. "N : ")
  *
  * Navratova hodnota:
  * @return char* - Novo-alokovany retazec s hodnotou, NULL ak prefix nebol najdeny
  */
 static char *get_ocb_value(const char *line, const char *short_prefix,
                            const char *long_prefix) {
   char *value = NULL;  // Pomocna premenna pre hodnotu
   char *trimmed = NULL;  // Pomocna premenna pre ocisteny retazec
 
   // Najskor skusime dlhy prefix
   if (strncmp(line, long_prefix, strlen(long_prefix)) == 0) {
     value = strdup(line + strlen(long_prefix));  // Kopirovanie retazca za dlhym prefixom
     if (value) {
       trimmed = trim(value);  // Odstranenie nadbytocnych medzier
       if (trimmed != value) {
         memmove(value, trimmed, strlen(trimmed) + 1);  // Presun ocisteneho retazca na zaciatok
       }
       return value;  // Vratenie vysledneho retazca
     }
   } 
   // Ak dlhy prefix nenajdeny, skusime kratky
   else if (strncmp(line, short_prefix, strlen(short_prefix)) == 0) {
     value = strdup(line + strlen(short_prefix));  // Kopirovanie retazca za kratkym prefixom
     if (value) {
       trimmed = trim(value);  // Odstranenie nadbytocnych medzier
       if (trimmed != value) {
         memmove(value, trimmed, strlen(trimmed) + 1);  // Presun ocisteneho retazca na zaciatok
       }
       return value;  // Vratenie vysledneho retazca
     }
   }
   return NULL;  // Ziadny prefix nebol najdeny
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
   free(data->hex_nonce);  // Uvolnenie nonce
   free(data->hex_aad);  // Uvolnenie AAD
   free(data->hex_plaintext);  // Uvolnenie plaintextu
   free(data->hex_ciphertext);  // Uvolnenie ciphertextu
   free(data->hex_tag);  // Uvolnenie tagu
   memset(data, 0, sizeof(TestCaseData));  // Vynulovanie celej struktury pre bezpecnost
 }
 
 /**
  * Nacita nasledujuci testovaci vektor zo suboru
  *
  * Popis: Funkcia cita testovacie data zo suboru riadok po riadku,
  * spracovava rozne typy riadkov a zostavuje kompletny testovaci vektor.
  * Podporuje globalny kluc, ktory moze byt pouzity pre viacero testov.
  *
  * Proces:
  * 1. Inicializacia premennych a uvolnenie predchadzajucich dat
  * 2. Citanie riadkov zo suboru a ich spracovanie podla typu
  * 3. Rozdelenie kombinovaneho ciphertextu a tagu na samostatne hodnoty
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
   char line[OCB_LINE_BUFFER_SIZE];  // Buffer pre citanie riadku
   char *value;  // Pomocna premenna pre extrahovane hodnoty
   bool in_test_case = false;  // Priznak, ci sme vo vnutri testovacieho vektora
   long start_pos = ftell(fp);  // Zapamatanie aktualnej pozicie v subore
   bool fail_tag_seen = false;  // Priznak, ci sme narazili na FAIL flag
   static char *global_key = NULL;  // Staticka premenna pre uchovanie globalneho kluca
 
   free_test_case_data(data);  // Uvolnenie predchadzajucich dat
 
   // Citanie suboru riadok po riadku
   while (fgets(line, sizeof(line), fp)) {
     char *trimmed = trim(line);  // Odstranenie medzier zo zaciatku a konca
     
     // Preskocenie prazdnych riadkov a komentarov
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
       value = get_line_value(trimmed, OCB_PREFIX_COUNT);
       if (value) {
         data->count = atoi(value);  // Konverzia retazca na cislo
         free(value);  // Uvolnenie docasnej hodnoty
       }
       break;
 
     case KEY:  // Riadok s klucom
       value = get_line_value(trimmed, OCB_PREFIX_KEY);
       if (value) {
         // Ulozenie globalneho kluca, ktory moze byt pouzity pre viacero testov
         free(global_key);  // Uvolnenie stareho globalneho kluca
         global_key = value;  // Nastavenie noveho globalneho kluca
         value = NULL;  // Zabranenie uvolneniu hodnoty kluca nizsie
       }
       break;
 
     case NONCE:  // Riadok s nonce
       if (!in_test_case && global_key) {
         // Zaciatok noveho testu - prve nonce po globalnom kluci
         in_test_case = true;  // Oznacenie zaciatku testu
         data->hex_key = strdup(global_key);  // Kopirovanie globalneho kluca
         data->hex_nonce = get_ocb_value(trimmed, OCB_PREFIX_NONCE_SHORT, OCB_PREFIX_NONCE_LONG);  // Nacitanie nonce
       } else if (in_test_case) {
         // Ak uz sme v teste a narazime na nove nonce, je to zaciatok noveho testu
         fseek(fp, start_pos, SEEK_SET);  // Vratime sa na zaciatok tohto riadku
         data->should_fail = fail_tag_seen;  // Nastavenie priznaku ocakavaneho zlyhania
         return true;  // Vratime kompletny testovaci vektor
       }
       break;
 
     case AAD:  // Riadok s AAD (Additional Authenticated Data)
       if (in_test_case) {
         value = get_ocb_value(trimmed, OCB_PREFIX_AAD_SHORT, OCB_PREFIX_AAD_LONG);
         if (value && strlen(value) > 0) {
           data->hex_aad = value;  // Ulozenie AAD
         } else {
           free(value);  // Uvolnenie prazdnej hodnoty
         }
       }
       break;
 
     case PT:  // Riadok s plaintextom
       if (in_test_case) {
         value = get_ocb_value(trimmed, OCB_PREFIX_PT_SHORT, OCB_PREFIX_PT_LONG);
         if (value && strlen(value) > 0) {
           data->hex_plaintext = value;  // Ulozenie plaintextu
         } else {
           free(value);  // Uvolnenie prazdnej hodnoty
         }
       }
       break;
 
     case CT:  // Riadok s ciphertextom a tagom
       if (in_test_case) {
         value = get_ocb_value(trimmed, OCB_PREFIX_CT_SHORT, OCB_PREFIX_CT_LONG);
         if (!value)
           break;  // Ak sa nepodarilo extrahovat hodnotu, preskocime dalej
 
         size_t c_len = strlen(value);  // Dlzka kombinovaneho ciphertextu a tagu
         
         // Kontrola ci mame dostatok znakov na rozdelenie
         if (c_len < OCB_TAG_LEN * 2) {
           free(value);  // Uvolnenie neplatnej hodnoty
           break;  // Prilis kratka hodnota, preskocime
         }
 
         // Rozdelenie kombinovanej hodnoty na ciphertext a tag
         size_t ct_len = c_len - (OCB_TAG_LEN * 2);  // Dlzka ciphertextu v znakoch
         data->hex_ciphertext = NULL;
         data->hex_tag = NULL;
 
         // Spracovanie ciphertextu, ak existuje
         if (ct_len > 0) {
           data->hex_ciphertext = malloc(ct_len + 1);  // Alokacia pamate pre ciphertext
           if (data->hex_ciphertext) {
             memcpy(data->hex_ciphertext, value, ct_len);  // Kopirovanie ciphertextu
             data->hex_ciphertext[ct_len] = '\0';  // Ukoncenie retazca
           }
         }
 
         // Spracovanie tagu, ktory je vzdy pritomny
         data->hex_tag = malloc(OCB_TAG_LEN * 2 + 1);  // Alokacia pamate pre tag
         if (data->hex_tag) {
           memcpy(data->hex_tag, value + ct_len, OCB_TAG_LEN * 2);  // Kopirovanie tagu
           data->hex_tag[OCB_TAG_LEN * 2] = '\0';  // Ukoncenie retazca
         }
 
         free(value);  // Uvolnenie povodnej kombinovanej hodnoty
       }
       break;
 
     case FAIL:  // Riadok oznacujuci ocakavane zlyhanie
       fail_tag_seen = true;  // Zaznamenanie FAIL flagu
       break;
     }
     start_pos = ftell(fp);  // Aktualizacia pozicie pre dalsi riadok
   }
 
   // Koniec suboru - vratime kompletny test, ak existuje
   if (in_test_case) {
     data->should_fail = fail_tag_seen;  // Nastavenie priznaku ocakavaneho zlyhania
     return true;  // Vratime kompletny testovaci vektor
   }
   return false;  // Nenasiel sa ziadny dalsi platny testovaci vektor
 }
 
 /**
  * Spracuje a vyhodnoti jeden testovaci vektor
  *
  * Popis: Hlavna funkcia, ktora vykonava samotne testovanie jedneho OCB
  * testovacieho vektora. Obsahuje sifrovanie, desifrovanie a porovnanie
  * vysledkov s ocakavanymi hodnotami.
  *
  * Proces:
  * 1. Vypocet velkosti vstupnych dat a alokacia bufferov
  * 2. Konverzia hex retazcov na binarne data
  * 3. Vykonanie OCB sifrovania a porovnanie vysledkov
  * 4. Vykonanie OCB desifrovania a porovnanie vysledkov
  * 5. Aktualizacia statistiky testov
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
       OCB_TAG_LEN  // Tag ma vzdy fixnu dlzku OCB_TAG_LEN (16 bajtov)
   };
 
   // Alokacia bufferov pre binarne reprezentacie dat
   uint8_t *bufs[] = {
       calloc(lens[0] + 1, 1),  // Buffer pre kluc
       calloc(lens[1] + 1, 1),  // Buffer pre nonce
       calloc(lens[2] + 1, 1),  // Buffer pre aad
       calloc(lens[3] + 1, 1),  // Buffer pre plaintext
       calloc(lens[4] + 1, 1),  // Buffer pre ciphertext
       calloc(lens[5] + 1, 1)   // Buffer pre tag
   };
 
   // Kontrola uspesnosti alokacie vsetkych bufferov
   for (int i = 0; i < 6; i++) {
     if (!bufs[i])
       goto cleanup;  // Pri zlyhani alokacie skocime na cistenie
   }
 
   // Pole s pointrami na hex retazce pre konverziu
   const char *hexs[] = {
       data->hex_key,        // Kluc v hex formate
       data->hex_nonce,      // Nonce v hex formate
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
   printf("=== Test ===\n");
   printf("Vstupne data:\n");
   printf("  Kluc: %s\n", data->hex_key);
   printf("  Nonce: %s\n", data->hex_nonce);
   if (data->hex_aad) {
     printf("  AAD: %s\n", data->hex_aad);
   } else {
     printf("  AAD: (prazdne)\n");  // Indikacia prazdneho AAD
   }
 
   // Test sifrovania (encrypt)
   {
     printf("\n--- Test Sifrovania ---\n");
     printf("  Plaintext: %s\n",
            data->hex_plaintext ? data->hex_plaintext : "(prazdne)");  // Vypis plaintextu s indikacou prazdnej hodnoty
 
     // Alokacia bufferov pre vysledky sifrovania
     uint8_t *res_ct = calloc(lens[3] + 1, 1);  // Buffer pre vypocitany ciphertext
     uint8_t *res_tag = calloc(lens[5] + 1, 1);  // Buffer pre vypocitany tag
 
     // Kontrola uspesnosti alokacie
     if (!res_ct || !res_tag) {
       free(res_ct);
       free(res_tag);
       goto cleanup;  // Pri zlyhani alokacie skocime na cistenie
     }
 
     // Vykonanie OCB sifrovania
     AES_OCB_encrypt(bufs[0],           // key
                     bufs[1],           // nonce
                     bufs[3], lens[3],  // plaintext, ptextLen
                     bufs[2], lens[2],  // aData, aDataLen
                     res_ct,            // crtxt
                     res_tag            // auTag
     );
 
     // Porovnanie vysledkov s ocakavanymi hodnotami
     bool ct_match =
         (lens[4] == 0 || memcmp(res_ct, bufs[4], lens[4]) == 0);  // Zhoda ciphertextov
     bool tag_match = memcmp(res_tag, bufs[5], lens[5]) == 0;  // Zhoda tagov
 
     // Vypis vysledkov sifrovania
     printf("  Ciphertext:\n");
     printf("    Ocakavany: %s\n",
            data->hex_ciphertext ? data->hex_ciphertext : "(prazdny)");  // Vypis ocakavaneho ciphertextu
     printf("    Vypocitany: ");
     if (lens[3] > 0) {
       print_hex(res_ct, lens[3]);  // Vypis vypocitaneho ciphertextu
     } else {
       printf("(prazdny)\n");  // Indikacia prazdneho ciphertextu
     }
 
     printf("  Tag:\n");
     printf("    Ocakavany: %s\n", data->hex_tag);  // Vypis ocakavaneho tagu
     printf("    Vypocitany: ");
     print_hex(res_tag, lens[5]);  // Vypis vypocitaneho tagu
 
     // Vyhodnotenie uspesnosti sifrovania
     bool encrypt_ok = ct_match && tag_match;  // Uspech len ak sa zhoduju ciphertext aj tag
     printf("  Vysledok sifrovania: %s\n",
            encrypt_ok ? "USPESNY" : "NEUSPESNY");  // Vypis vysledku
 
     // Aktualizacia statistiky uspesnych testov
     if (encrypt_ok)
       (*passed_encrypt)++;  // Inkrementacia pocitadla uspesnych encrypt testov
 
     // Uvolnenie pomocnych bufferov
     free(res_ct);
     free(res_tag);
   }
 
   // Test desifrovania (decrypt)
   {
     printf("\n--- Test Desifrovania ---\n");
     printf("  Ciphertext: %s\n",
            data->hex_ciphertext ? data->hex_ciphertext : "(prazdne)");  // Vypis ciphertextu s indikacou prazdnej hodnoty
     printf("  Tag: %s\n", data->hex_tag);  // Vypis tagu
 
     // Alokacia bufferov pre desifrovanie
     uint8_t *combined = NULL;  // Buffer pre kombinovany ciphertext a tag
     size_t combined_len = lens[4] + lens[5];  // Dlzka kombinovaneho buffera
     uint8_t *decrypted = calloc(lens[4] + 1, 1);  // Buffer pre desifrovany plaintext
 
     // Kontrola uspesnosti alokacie
     if (!decrypted) {
       goto decrypt_cleanup;  // Pri zlyhani alokacie skocime na cistenie decrypt casti
     }
 
     combined = calloc(combined_len + 1, 1);  // Alokacia buffera pre kombinovany ciphertext+tag
     if (!combined) {
       free(decrypted);
       goto decrypt_cleanup;  // Pri zlyhani alokacie skocime na cistenie decrypt casti
     }
 
     // Spojenie ciphertextu a tagu do jedneho bloku
     if (lens[4] > 0) {
       memcpy(combined, bufs[4], lens[4]);  // Najprv ciphertext, ak existuje
     }
     memcpy(combined + lens[4], bufs[5], lens[5]);  // Za nim tag
 
     // Vykonanie OCB desifrovania
     int decrypt_status = AES_OCB_decrypt(
         bufs[0],            // key
         bufs[1],            // nonce
         combined, lens[4],  // crtxt (combined data), crtxtLen
         bufs[2], lens[2],   // aData, aDataLen
         (uint8_t)lens[5],   // tagLen
         decrypted           // pntxt
     );
 
     // Vyhodnotenie vysledkov desifrovania
     bool auth_success = (decrypt_status == 0);  // 0 znamena uspesnu autentifikaciu
     bool decrypt_ok =
         auth_success &&
         (lens[3] == 0 || memcmp(decrypted, bufs[3], lens[3]) == 0);  // Uspech ak autentifikacia presla a plaintexty sa zhoduju
 
     // Vypis vysledku autentifikacie
     printf("  Autentifikacia: %s\n",
            auth_success ? "USPESNA" : "NEUSPESNA");
 
     // Vypis desifrovanych dat, ak autentifikacia bola uspesna
     if (auth_success) {
       printf("  Plaintext:\n");
       printf("    Ocakavany: %s\n",
              data->hex_plaintext ? data->hex_plaintext : "(prazdny)");  // Vypis ocakavaneho plaintextu
       printf("    Vypocitany: ");
       if (lens[3] > 0) {
         print_hex(decrypted, lens[3]);  // Vypis desifrovaneho plaintextu
       } else {
         printf("(prazdny)\n");  // Indikacia prazdneho plaintextu
       }
     }
 
     // Vypis celkoveho vysledku testu desifrovania
     printf("  Vysledok desifrovania: %s\n",
            decrypt_ok ? "USPESNY" : "NEUSPESNY");
 
     // Aktualizacia statistiky uspesnych testov
     if (decrypt_ok)
       (*passed_decrypt)++;  // Inkrementacia pocitadla uspesnych decrypt testov
 
     // Uvolnenie bufferov pouzitych pri desifrovani
     free(combined);
     free(decrypted);
   }
 
 decrypt_cleanup:
   printf("\n");  // Prazdny riadok pre oddlenie od dalsieho testu
 
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
 // Zistenie velkosti kluca z kompilacnych definicii
 #if AES___ == 256
   const int aes_bits = 256;  // 256-bitovy kluc
   const char *test_vectors_file = OCB_TEST_VECTORS_256;  // Subor pre AES-256
 #elif AES___ == 192
   const int aes_bits = 192;  // 192-bitovy kluc
   const char *test_vectors_file = OCB_TEST_VECTORS_192;  // Subor pre AES-192
 #else // Predvolene AES-128
   const int aes_bits = 128;  // 128-bitovy kluc (predvolene)
   const char *test_vectors_file = OCB_TEST_VECTORS_128;  // Subor pre AES-128
 #endif
 
   printf("AES-%d OCB Test\n", aes_bits);  // Vypis velkosti kluca
   printf("Pouziva sa subor s testovacimi vektormi: %s\n",
          test_vectors_file);  // Vypis nazvu pouziteho suboru
 
   // Otvorenie suboru s testovacimi vektormi
   FILE *fp = fopen(test_vectors_file, "r");
   if (!fp) {
     perror("Nepodarilo sa otvorit subor s testovacimi vektormi");  // Chybove hlasenie
     return 1;  // Chybovy navratovy kod
   }
 
   // Inicializacia premennych pre testovanie
   int tests_passed_encrypt = 0;  // Pocitadlo uspesnych encrypt testov
   int tests_passed_decrypt = 0;  // Pocitadlo uspesnych decrypt testov
   TestCaseData current_test = {0};  // Struktura pre aktualny testovaci vektor
   int processed_tests = 0;  // Pocitadlo spracovanych testov
 
   // Spracovanie testovacich vektorov v cykle
   while (parse_next_test_case(fp, &current_test)) {
     processed_tests++;  // Inkrementacia pocitadla spracovanych testov
     process_test_case(&current_test, &tests_passed_encrypt,
                       &tests_passed_decrypt);  // Spracovanie aktualneho testovacieho vektora
     free_test_case_data(&current_test);  // Uvolnenie dat aktualneho testu
   }
 
   fclose(fp);  // Zatvorenie suboru
 
   // Vypocet celkovej uspesnosti
   int total_passed = tests_passed_encrypt + tests_passed_decrypt;  // Celkovy pocet uspesnych testov
   int total_tests =
       processed_tests * 2;  // Celkovy pocet testov (kazdy test ma encrypt aj decrypt cast)
   bool success = (processed_tests > 0 && total_passed == total_tests);  // Uspech len ak vsetky testy presli
 
   // Vypis celkovej statistiky
   printf("\nCelkove vysledky:\n");
   printf("Spracovanych testovacich vektorov: %d\n", processed_tests);
   printf("Uspesnych testov sifrovania: %d/%d\n", tests_passed_encrypt,
          processed_tests);
   printf("Uspesnych testov desifrovania: %d/%d\n", tests_passed_decrypt,
          processed_tests);
   printf("Celkovy vysledok: %s\n", success ? "USPESNY" : "NEUSPESNY");
 
   return success ? 0 : 1;  // Vrati 0 ak vsetky testy uspesne, inak 1
 }