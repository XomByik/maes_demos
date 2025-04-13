/************************************************************************
 * Nazov projektu: Demonštracia funkcnosti rezimov AES-u z kniznice micro-AES
 * -----------------------------------------------------------------------
 * Subor: ccm_demo.c
 * Verzia: 1.1
 * Datum: 13.4.2025
 *
 * Autor: Kamil Berecky
 *
 * Popis: Program demonstruje funkcnost rezimu AES-CCM pomocou oficialnych
 * testovacich vektorov. Implementuje autentifikovane sifrovanie a desifrovanie
 * s overovanim pristinosti dat pomocou micro-AES kniznice a porovnava 
 * vysledky s ocakavanymi hodnotami zo NIST testovacich vektorov. Program 
 * podporuje rozne velkosti klucov (128, 192, 256 bitov).
 * 
 * Vyuzite zdroje:
 * - micro-AES kniznica: 
 *   https://github.com/polfosol/micro-AES
 * - NIST SP 800-38C (2004):
 *   https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/cavp-testing-block-cipher-modes#CCM
 *
 * Pre viac info pozri README.md
 **********************************************************************/

 #include "../header_files/ccm.h"

 /**
  * Urci typ riadku v testovacom subore
  *
  * Popis: Funkcia analyzuje vstupny riadok a urcuje jeho typ na zaklade
  * klucovych slov. To umoznuje spravne spracovanie roznych casti testovacich
  * vektorov, ako su kluc, nonce, payload a dalsie.
  *
  * Proces:
  * 1. Porovnava riadok s ocakavanymi prefixami definovanymi v ccm.h
  * 2. Vracia hodnotu enum typu LineType podla najdenej zhody
  * 3. Ak sa nenajde zhoda, vracia CCM_UNKNOWN
  *
  * Parametre:
  * @param line - Vstupny riadok na analyzu
  *
  * Navratova hodnota:
  * @return LineType - Enum hodnota reprezentujuca typ riadku
  */
 LineType get_line_type(const char *line) {
   if (strstr(line, CCM_PREFIX_COUNT))
     return CCM_COUNT;
   if (strstr(line, CCM_PREFIX_KEY))
     return CCM_KEY;
   if (strstr(line, CCM_PREFIX_NONCE))
     return CCM_NONCE;
   if (strstr(line, CCM_PREFIX_ADATA))
     return CCM_ADATA;
   if (strstr(line, CCM_PREFIX_PAYLOAD))
     return CCM_PAYLOAD;
   if (strstr(line, CCM_PREFIX_CT))
     return CCM_CT;
   if (strstr(line, CCM_PREFIX_ALEN))
     return CCM_ALEN;
   if (strstr(line, CCM_PREFIX_PLEN))
     return CCM_PLEN;
   if (strstr(line, CCM_PREFIX_NLEN))
     return CCM_NLEN;
   if (strstr(line, CCM_PREFIX_TLEN))
     return CCM_TLEN;
   return CCM_UNKNOWN;
 }
 
 /**
  * Extrahuje hodnotu za danym prefixom v riadku textu
  *
  * Popis: Funkcia hlada zadany prefix v riadku a vracia retazec,
  * ktory nasleduje za nim. Podporuje specialne formatovanie pre 
  * niektore parametre ako je NLEN, kde hodnoty mozu byt v hranatych zatvorkach.
  *
  * Proces:
  * 1. Orezanie medzier z riadku a detekcia prefixu
  * 2. Vratenie podretazca, ktory nasleduje za prefixom
  * 3. Specialna podpora pre hodnoty v hranatych zatvorkach
  *
  * Parametre:
  * @param line - Vstupny riadok na spracovanie
  * @param prefix - Hladany prefix
  *
  * Navratova hodnota:
  * @return char* - Retazec za prefixom, alebo NULL ak prefix nebol najdeny
  */
 static char *get_value_after_prefix(const char *line, const char *prefix) {
   size_t prefix_len = strlen(prefix);
   char *trimmed_line = trim((char *)line);
 
   // Standardny pripad - prefix na zaciatku riadku
   if (strncmp(trimmed_line, prefix, prefix_len) == 0) {
     return trim(trimmed_line + prefix_len);
   }
 
   // Specialny pripad pre NLEN v hranatych zatvorkach
   if (strcmp(prefix, CCM_PREFIX_NLEN) == 0 && trimmed_line[0] == '[') {
     if (strncmp(trimmed_line + 1, prefix, prefix_len) == 0) {
       char *value_start = trim(trimmed_line + 1 + prefix_len);
       char *end_bracket = strchr(value_start, ']');
       if (end_bracket) {
         *end_bracket = '\0'; // Ukoncenie retazca na zatvorke
         return value_start;
       }
     }
   }
   return NULL; // Prefix sa nenasiel
 }
 
 /**
  * Uvolni pamat alokovanu pre testovacie data
  *
  * Popis: Funkcia uvolnuje vsetky dynamicky alokovane retazce 
  * zo struktury TestCaseData a nastavuje pointre na NULL, co zabranuje 
  * pouzitiu po uvolneni.
  *
  * Proces:
  * 1. Kontrola na NULL pointer
  * 2. Uvolnenie kazdeho alokovaneho retazca
  * 3. Nastavenie vsetkych pointerov na NULL
  * 4. Resetovanie pocitadla testov
  *
  * Parametre:
  * @param data - Pointer na strukturu s testovacimi datami
  */
 void free_test_case_data(TestCaseData *data) {
   if (!data)
     return;  // Ochrana pred NULL pointerom
     
   free(data->hex_nonce);
   free(data->hex_adata);
   free(data->hex_payload);
   free(data->hex_ct_tag);
   
   // Nastavenie pointerov na NULL pre zabranenie double-free alebo use-after-free
   data->hex_nonce = NULL;
   data->hex_adata = NULL;
   data->hex_payload = NULL;
   data->hex_ct_tag = NULL;
   data->count = -1;  // Reset pocitadla
 }
 
 /**
  * Spracuje hlavickovu cast testu a zisti zakladne parametre
  *
  * Popis: Funkcia cita hlavickovu cast testu z testovacieho suboru
  * a extrahuje dolezite parametre ako dlzky adata, payload, nonce a tagu.
  * Tieto hodnoty su potrebne pre dalsi priebeh testovania.
  *
  * Proces:
  * 1. Citanie suboru riadok po riadku
  * 2. Zistenie dlzky asociovanych dat (Alen)
  * 3. Zistenie dlzky payloadu (Plen)
  * 4. Kontrola dlzky nonce a tagu s kompilovacimi nastaveniami
  * 5. Vratenie kurzorov suboru pred prvu instanciu Count/Key
  *
  * Parametre:
  * @param fp - Pointer na otvoreny subor na citanie
  * @param Alen - Pointer na premennu pre ulozenie dlzky asociovanych dat
  * @param Plen - Pointer na premennu pre ulozenie dlzky payloadu
  *
  * Navratova hodnota:
  * @return bool - true ak sa podarilo nacitat vsetky potrebne hodnoty
  */
 bool parse_header(FILE *fp, size_t *Alen, size_t *Plen) {
   char line[CCM_LINE_BUFFER_SIZE];
   size_t Nlen_file = 0, Tlen_file = 0;
   bool alen_found = false, plen_found = false;
   bool nlen_found = false, tlen_found = false;
   char *value_ptr;
 
   while (fgets(line, sizeof(line), fp)) {
     char *trimmed = trim(line);
     if (strlen(trimmed) == 0 || trimmed[0] == '#')
       continue;  // Preskocenie prazdnych riadkov a komentarov
 
     // Ak narazime na Count alebo Key, skoncime hlavickovu cast
     LineType type = get_line_type(trimmed);
     if (type == CCM_COUNT || type == CCM_KEY) {
       fseek(fp, -strlen(line), SEEK_CUR);  // Vratenie sa spat v subore
       break;
     }
 
     // Spracovanie parametrov hlavicky
     switch (type) {
       case CCM_ALEN:
         value_ptr = get_value_after_prefix(trimmed, CCM_PREFIX_ALEN);
         if (value_ptr) {
           *Alen = strtoul(value_ptr, NULL, 10);
           alen_found = true;
         }
         break;
         
       case CCM_PLEN:
         value_ptr = get_value_after_prefix(trimmed, CCM_PREFIX_PLEN);
         if (value_ptr) {
           *Plen = strtoul(value_ptr, NULL, 10);
           plen_found = true;
         }
         break;
         
       case CCM_NLEN:
         value_ptr = get_value_after_prefix(trimmed, CCM_PREFIX_NLEN);
         if (value_ptr) {
           Nlen_file = strtoul(value_ptr, NULL, 10);
           nlen_found = true;
         }
         break;
         
       case CCM_TLEN:
         value_ptr = get_value_after_prefix(trimmed, CCM_PREFIX_TLEN);
         if (value_ptr) {
           Tlen_file = strtoul(value_ptr, NULL, 10);
           tlen_found = true;
         }
         break;
         
       default:
         // Ignorujeme neznamy typ riadku
         break;
     }
 
     // Ak mame vsetky potrebne informacie, skoncime
     if (alen_found && plen_found && nlen_found && tlen_found) {
       printf("Hlavicka: Alen=%zu, Plen=%zu, Nlen=%zu, Tlen=%zu\n", *Alen,
              *Plen, Nlen_file, Tlen_file);
 
       // Kontrola ci nonce a tag dlzky su kompatibilne s kompilovanymi hodnotami
       if (Nlen_file != CCM_NONCE_LEN ||
           Tlen_file != CCM_TAG_LEN) {
         printf("Chyba: Nlen/Tlen v subore (%zu/%zu) != Kompilovane "
                "(%d/%d)\n",
                Nlen_file, Tlen_file, CCM_NONCE_LEN, CCM_TAG_LEN);
         return false;
       }
       return true;
     }
   }
   return false;  // Nenasli sme vsetky potrebne informacie
 }
 
 /**
  * Nacita a spracuje inicialny kluc
  *
  * Popis: Funkcia nacita inicialny kluc z testovacieho suboru
  * a prevedie ho z hexadecimalnej reprezentacie na binarnu pre
  * pouzitie v sifrovacich funkciach.
  *
  * Proces:
  * 1. Citanie suboru riadok po riadku, hladanie riadku s klucom
  * 2. Kontrola spravnej dlzky kluca
  * 3. Konverzia kluca z hexadecimalnej reprezentacie na binarnu
  * 4. Vypis nakonfigurovaneho kluca pre kontrolne ucely
  *
  * Parametre:
  * @param fp - Pointer na otvoreny subor na citanie
  * @param key - Buffer na ulozenie binarne reprezentacie kluca
  * @param key_size_bytes - Velkost kluca v bajtoch
  *
  * Navratova hodnota:
  * @return bool - true ak sa podarilo nacitat a spracovat kluc
  */
 bool parse_initial_key(FILE *fp, uint8_t *key, int key_size_bytes) {
   char line[CCM_LINE_BUFFER_SIZE];
   char *value_ptr;
 
   while (fgets(line, sizeof(line), fp)) {
     char *trimmed = trim(line);
     if (strlen(trimmed) == 0 || trimmed[0] == '#')
       continue;  // Preskocenie prazdnych riadkov a komentarov
 
     LineType type = get_line_type(trimmed);
     if (type == CCM_KEY) {
       value_ptr = get_value_after_prefix(trimmed, CCM_PREFIX_KEY);
       if (value_ptr) {
         // Kontrola dlzky kluca
         if (strlen(value_ptr) / 2 != (size_t)key_size_bytes) {
           printf("Chyba: Neplatna dlzka kluca\n");
           return false;
         }
         
         // Konverzia hex na binarne data
         if (hex_to_bin(value_ptr, key, key_size_bytes) != 0) {
           printf("Chyba: Neplatny format kluca\n");
           return false;
         }
         
         // Vypis kluca pre kontrolu
         printf("Pociatocny kluc: ");
         print_hex(key, key_size_bytes);
         return true;
       }
     }
   }
   return false;  // Kluc sa nenasiel
 }
 
 /**
  * Nacita nasledujuci testovaci pripad zo suboru
  *
  * Popis: Funkcia postupne cita subor a extrahuje data pre jeden
  * testovaci pripad, vratane nonce, adata, payload a ocakavaneho
  * ciphertextu s tagom.
  *
  * Proces:
  * 1. Citanie suboru az po dalsie Count alebo koniec suboru
  * 2. Nacitanie cisla testu, nonce, adata, payload a CT+tag
  * 3. Vratenie false ak nie je mozne nacitat kompletny testovaci pripad
  * 4. Pri najdeni noveho testu sa navrati kurzor na jeho zaciatok
  *
  * Parametre:
  * @param fp - Pointer na otvoreny subor na citanie
  * @param data - Struktura pre ulozenie nacitanych dat
  * @param key - Buffer pre kluc, ktory moze byt aktualizovany
  * @param key_size_bytes - Velkost kluca v bajtoch
  *
  * Navratova hodnota:
  * @return bool - true ak sa podarilo nacitat kompletny testovaci pripad
  */
 bool parse_next_test_case(FILE *fp, TestCaseData *data, uint8_t *key,
                           int key_size_bytes) {
   char line[CCM_LINE_BUFFER_SIZE];
   char *value_ptr;
   bool in_test_case = false;  // Flag, ci uz sme vstupili do testovaciaho pripadu
 
   free_test_case_data(data);  // Uvolnenie predchadzajucich dat
 
   while (fgets(line, sizeof(line), fp)) {
     char *trimmed = trim(line);
     if (strlen(trimmed) == 0 || trimmed[0] == '#')
       continue;  // Preskocenie prazdnych riadkov a komentarov
 
     LineType type = get_line_type(trimmed);
     
     switch (type) {
       case CCM_COUNT:
         value_ptr = get_value_after_prefix(trimmed, CCM_PREFIX_COUNT);
         if (value_ptr) {
           if (in_test_case) {
             // Ak uz spracovavame test a narazime na dalsi Count,
             // vratime sa spat a ukoncime spracovanie
             fseek(fp, -strlen(line), SEEK_CUR);
             return true;
           }
           data->count = atoi(value_ptr);
           in_test_case = true;
         }
         break;
         
       case CCM_KEY:
         value_ptr = get_value_after_prefix(trimmed, CCM_PREFIX_KEY);
         if (value_ptr) {
           if (in_test_case) {
             // Ak uz spracovavame test a narazime na novy kluc,
             // vratime sa spat a ukoncime spracovanie
             fseek(fp, -strlen(line), SEEK_CUR);
             return true;
           }
           
           // Aktualizacia kluca ak ma spravnu dlzku
           if (strlen(value_ptr) / 2 == (size_t)key_size_bytes) {
             if (hex_to_bin(value_ptr, key, key_size_bytes) == 0) {
               printf("\nAktualizovany kluc: ");
               print_hex(key, key_size_bytes);
             }
           }
         }
         break;
         
       case CCM_NONCE:
         if (in_test_case) {
           value_ptr = get_value_after_prefix(trimmed, CCM_PREFIX_NONCE);
           if (value_ptr) {
             data->hex_nonce = strdup(value_ptr);
           }
         }
         break;
         
       case CCM_ADATA:
         if (in_test_case) {
           value_ptr = get_value_after_prefix(trimmed, CCM_PREFIX_ADATA);
           if (value_ptr) {
             data->hex_adata = strdup(value_ptr);
           }
         }
         break;
         
       case CCM_PAYLOAD:
         if (in_test_case) {
           value_ptr = get_value_after_prefix(trimmed, CCM_PREFIX_PAYLOAD);
           if (value_ptr) {
             data->hex_payload = strdup(value_ptr);
           }
         }
         break;
         
       case CCM_CT:
         if (in_test_case) {
           value_ptr = get_value_after_prefix(trimmed, CCM_PREFIX_CT);
           if (value_ptr) {
             data->hex_ct_tag = strdup(value_ptr);
             return true;  // Kompletny test pripad
           }
         }
         break;
         
       default:
         // Ignorujeme neznamy typ riadku
         break;
     }
   }
 
   // Vratime true iba ak sme nasli vsetky potrebne polozky pre test
   return in_test_case && data->hex_nonce && data->hex_adata &&
          data->hex_payload && data->hex_ct_tag;
 }
 
 /**
  * Spracuje testovaci pripad a vykona encrypt a decrypt testy
  *
  * Popis: Hlavna funkcia, ktora vykona samotne testovanie jedneho CCM
  * testovaciaho pripadu. Obsahuje sifrovanie, desifrovanie a porovnanie
  * vysledkov s ocakavanymi hodnotami.
  *
  * Proces:
  * 1. Alokacia pamate pre medzivysledky a buffers
  * 2. Konverzia hexadecimalnych stringov na binarne data
  * 3. Vykonanie CCM sifrovania
  * 4. Porovnanie vypocitaneho ciphertextu a tagu s ocakavanymi hodnotami
  * 5. Vykonanie CCM desifrovania 
  * 6. Verifikacia authentication tagu a porovnanie desifrovaneho plaintextu
  * 7. Aktualizacia pocitadiel uspesnych testov
  * 8. Uvolnenie pamate pred ukoncenim
  *
  * Parametre:
  * @param test_num - Cislo aktualneho testu
  * @param key - Kluc pre sifrovanie a desifrovanie
  * @param data - Struktura s testovacimi datami
  * @param Alen - Dlzka asociovanych dat
  * @param Plen - Dlzka payloadu
  * @param passed_encrypt - Pointer na pocitadlo uspesnych encrypt testov
  * @param passed_decrypt - Pointer na pocitadlo uspesnych decrypt testov
  *
  * Navratova hodnota:
  * @return bool - true ak sa test uspesne vykonal (nezavisle od vysledkov)
  */
 bool process_test_case(int test_num, const uint8_t *key,
                        const TestCaseData *data, size_t Alen, size_t Plen,
                        int *passed_encrypt, int *passed_decrypt) {
   printf("\n=== Test #%d ===\n", test_num);
   bool success = false;
   uint8_t *buffers[9] = {NULL};  // Array na sledovanie alokovanych bufferov
   int buf_idx = 0;
 
   // Alokacia pamate pre vsetky potrebne buffery
   uint8_t *current_nonce = malloc(CCM_NONCE_LEN);
   uint8_t *expected_tag = malloc(CCM_TAG_LEN);
   uint8_t *result_tag = malloc(CCM_TAG_LEN);
   uint8_t *current_adata = NULL;
   uint8_t *current_payload = NULL;
   uint8_t *current_ct_tag = NULL;
   uint8_t *expected_ct = NULL;
   uint8_t *result_ciphertext = NULL;
   uint8_t *result_plaintext = NULL;
 
   // Sledovanie alokovanych bufferov pre neskor cleanup
   buffers[buf_idx++] = current_nonce;
   buffers[buf_idx++] = expected_tag;
   buffers[buf_idx++] = result_tag;
 
   // Alokacia pamate pre pomocne buffery podla potreby
   if (Alen > 0) {
     current_adata = malloc(Alen);
     buffers[buf_idx++] = current_adata;
   }
 
   if (Plen > 0) {
     current_payload = malloc(Plen);
     expected_ct = malloc(Plen);
     result_ciphertext = malloc(Plen);
     result_plaintext = malloc(Plen);
     buffers[buf_idx++] = current_payload;
     buffers[buf_idx++] = expected_ct;
     buffers[buf_idx++] = result_ciphertext;
     buffers[buf_idx++] = result_plaintext;
   }
 
   // Velkost buffer na spojeny ciphertext+tag
   size_t ct_tag_len = Plen + CCM_TAG_LEN;
   if (ct_tag_len > 0) {
     current_ct_tag = malloc(ct_tag_len);
     buffers[buf_idx++] = current_ct_tag;
   }
 
   // Kontrola uspesnosti alokacie pamate
   for (int i = 0; i < buf_idx; i++) {
     if (!buffers[i]) {
       printf("Chyba alokacie pamate\n");
       goto cleanup;  // Skok na cistenie pamate
     }
   }
 
   // Konverzia hexadecimalnych retazcov na binarne data
   bool conversion_ok = (hex_to_bin(data->hex_nonce, current_nonce,
                                    CCM_NONCE_LEN) == 0);
   if (Alen > 0) {
     conversion_ok &=
         (hex_to_bin(data->hex_adata, current_adata, Alen) == 0);
   }
   if (Plen > 0) {
     conversion_ok &=
         (hex_to_bin(data->hex_payload, current_payload, Plen) == 0);
   }
   if (ct_tag_len > 0) {
     conversion_ok &=
         (hex_to_bin(data->hex_ct_tag, current_ct_tag, ct_tag_len) == 0);
   }
 
   if (!conversion_ok) {
     printf("Chyba konverzie hex dat\n");
     goto cleanup;
   }
 
   // Vypis vstupnych dat
   printf("Vstupne data:\n");
   printf("  Nonce: ");
   print_limited(data->hex_nonce, 75);
   if (Alen > 0) {
     printf("  AAD: ");
     print_limited(data->hex_adata, 75);
   }
   if (Plen > 0) {
     printf("  Data: ");
     print_limited(data->hex_payload, 75);
   }
   printf("  Ocakavany CT+Tag: ");
   print_limited(data->hex_ct_tag, 75);
 
   // Separacia ocakavaneho ciphertextu a tagu
   if (Plen > 0) {
     memcpy(expected_ct, current_ct_tag, Plen);
   }
   memcpy(expected_tag, current_ct_tag + Plen, CCM_TAG_LEN);
 
   // Test sifrovania
   printf("\nTest sifrovania:\n");
   AES_CCM_encrypt(key, current_nonce, current_payload, Plen, current_adata,
                   Alen, result_ciphertext, result_tag);
 
   printf("  Vypocitany ciphertext: ");
   print_hex(result_ciphertext, Plen);
   printf("  Ocakavany ciphertext: ");
   print_hex(expected_ct, Plen);
   printf("  Vypocitany tag: ");
   print_hex(result_tag, CCM_TAG_LEN);
   printf("  Ocakavany tag: ");
   print_hex(expected_tag, CCM_TAG_LEN);
 
   // Vyhodnotenie testu sifrovania
   bool encrypt_ok =
       (Plen == 0 || memcmp(result_ciphertext, expected_ct, Plen) == 0) &&
       memcmp(result_tag, expected_tag, CCM_TAG_LEN) == 0;
 
   printf("  Vysledok: %s\n", encrypt_ok ? "USPESNY" : "NEUSPESNY");
   if (encrypt_ok)
     (*passed_encrypt)++;
 
   // Test desifrovania
   printf("\nTest desifrovania:\n");
   uint8_t decrypt_status = AES_CCM_decrypt(
       key, current_nonce, current_ct_tag, Plen, current_adata, Alen,
       CCM_TAG_LEN, result_plaintext);
 
   printf("  Vypocitany plaintext: ");
   print_hex(result_plaintext, Plen);
   printf("  Ocakavany plaintext: ");
   print_hex(current_payload, Plen);
   printf("  Autentifikacia: %s\n",
          decrypt_status == NO_ERROR_RETURNED ? "OK" : "ZLYHALA");
 
   // Vyhodnotenie testu desifrovania
   bool decrypt_ok =
       (decrypt_status == NO_ERROR_RETURNED) &&
       (Plen == 0 || memcmp(result_plaintext, current_payload, Plen) == 0);
 
   printf("  Vysledok: %s\n", decrypt_ok ? "USPESNY" : "NEUSPESNY");
   if (decrypt_ok)
     (*passed_decrypt)++;
 
   success = true;
 
 cleanup:
   // Uvolnenie vsetkej alokovabej pamate
   for (int i = 0; i < buf_idx; i++) {
     free(buffers[i]);
   }
   return success;
 }
 
 /**
  * Hlavna funkcia programu
  *
  * Popis: Funkcia inicializuje program, otvara subor s testovacimi 
  * vektormi, spusta spracovanie a testovanie jednotlivych pripadov,
  * a na zaver zobrazuje celkovu statistiku uspesnosti testov.
  *
  * Proces:
  * 1. Vyber spravneho testovaciho suboru podla velkosti kluca
  * 2. Otvorenie suboru a kontrola chyb
  * 3. Nacitanie hlavicky a inicialneho kluca
  * 4. Spracovanie testovacich pripadov v cykle
  * 5. Vypis celkovej statistiky testov
  * 6. Uvolnenie zdrojov
  *
  * Navratova hodnota:
  * @return int - 0 ak boli vsetky testy uspesne, 1 ak nastala chyba
  */
 int main() {
   // Vyber spravneho testovaciho suboru podla predkompilovanej velkosti kluca
 #if AES___ == 256
   const int aes_bits = 256;
   const char *test_vectors_file = "test_vectors/ccm_VNT256.txt";
 #elif AES___ == 192
   const int aes_bits = 192;
   const char *test_vectors_file = "test_vectors/ccm_VNT192.txt";
 #else
   const int aes_bits = 128;
   const char *test_vectors_file = "test_vectors/ccm_VNT128.txt";
 #endif
 
   FILE *fp = NULL;
   uint8_t key[32] = {0};  // Maximalne 32 bajtov (256 bitov)
   const int key_size_bytes = aes_bits / 8;
   size_t Alen = 0, Plen = 0;  // Dlzky asociovanych dat a payloadu
   int tests_total = 0, tests_passed_encrypt = 0, tests_passed_decrypt = 0;
   TestCaseData current_test = {0};
   bool success = false;
 
   printf("AES-%d CCM Test\n", aes_bits);
   printf("Pouziva sa testovaci subor: %s\n", test_vectors_file);
 
   // Otvorenie suboru s testovacimi vektormi
   fp = fopen(test_vectors_file, "r");
   if (!fp) {
     perror("Chyba pri otvarani testovaciho suboru");
     return 1;
   }
 
   // Nacitanie a kontrola hlavicky a kluca
   if (!parse_header(fp, &Alen, &Plen) ||
       !parse_initial_key(fp, key, key_size_bytes)) {
     printf("Chyba pri spracovani hlavicky alebo pociatocneho kluca\n");
     fclose(fp);
     return 1;
   }
 
   // Spracovanie testovacich pripadov v cykle
   while (parse_next_test_case(fp, &current_test, key, key_size_bytes)) {
     tests_total++;
     process_test_case(current_test.count, key, &current_test, Alen, Plen,
                       &tests_passed_encrypt, &tests_passed_decrypt);
   }
 
   // Vypis celkovej statistiky testov
   printf("\nCelkove vysledky:\n");
   printf("Spracovanych testov: %d\n", tests_total);
   printf("Uspesnych testov sifrovania: %d\n", tests_passed_encrypt);
   printf("Uspesnych testov desifrovania: %d\n", tests_passed_decrypt);
 
   // Celkove vyhodnotenie uspesnosti
   success = (tests_total > 0 && tests_passed_encrypt == tests_total &&
              tests_passed_decrypt == tests_total);
 
   printf("Celkovy vysledok: %s\n", success ? "USPESNY" : "NEUSPESNY");
 
   // Cistenie
   free_test_case_data(&current_test);
   fclose(fp);
 
   return success ? 0 : 1;
 }