/************************************************************************
 * Nazov projektu: Demonštracia funkcnosti rezimov AES-u z kniznice micro-AES
 * -----------------------------------------------------------------------
 * Subor: cfb_demo.c
 * Verzia: 1.1
 * Datum: 13.4.2025
 *
 * Autor: Kamil Berecky
 *
 * Popis: Program demonstruje funkcnost rezimu AES-CFB pomocou oficialnych
 * testovacich vektorov. Implementuje sifrovanie a desifrovanie s pouzitim
 * roznych velkosti segmentov (1-bit, 8-bit, 128-bit) a porovnava vysledky
 * s ocakavanymi hodnotami zo NIST testovacich vektorov. Program podporuje
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

 #include "../header_files/cfb.h"

 /**
  * Urci velkost segmentu podla nazvu suboru
  *
  * Popis: Funkcia analyzuje nazov suboru a urci velkost segmentu,
  * ktora sa ma pouzit pre CFB operacie (1-bit, 8-bit, alebo 128-bit).
  *
  * Proces:
  * 1. Hlada v nazve suboru indikatory specifickej velkosti segmentu
  * 2. Vracia prislusnu velkost v bitoch
  *
  * Parametre:
  * @param filename - Nazov suboru obsahujuci testovacie vektory
  *
  * Navratova hodnota:
  * @return int - Velkost segmentu v bitoch (1, 8, alebo 128)
  */
 static int get_segment_size(const char *filename) {
   if (strstr(filename, CFB_FILE_PREFIX_1BIT) != NULL)
     return CFB_SEGMENT_SIZE_1BIT;  // 1-bit CFB rezim
   else if (strstr(filename, CFB_FILE_PREFIX_8BIT) != NULL)
     return CFB_SEGMENT_SIZE_8BIT;  // 8-bit CFB rezim
   else
     return CFB_SEGMENT_SIZE_128BIT;  // Standardny 128-bit CFB rezim (cely blok)
 }
 
 /**
  * Urci typ riadku v testovacom subore
  *
  * Popis: Funkcia analyzuje vstupny riadok a urcuje jeho typ na zaklade
  * klucovych slov. To umoznuje spravne spracovanie roznych casti testovacich
  * vektorov, ako su kluc, inicializacny vektor, plaintext a ciphertext.
  *
  * Proces:
  * 1. Porovnava zaciatok riadku s ocakavanymi klucovymi slovami
  * 2. Vracia enum hodnotu reprezentujucu dany typ riadku
  *
  * Parametre:
  * @param line - Vstupny riadok na analyzu
  *
  * Navratova hodnota:
  * @return LineType - Enum hodnota reprezentujuca typ riadku
  */
 static LineType get_line_type(const char *line) {
   if (strncmp(line, CFB_PREFIX_KEY, strlen(CFB_PREFIX_KEY)) == 0)
     return KEY;  // Riadok obsahuje sifrovaci kluc
   if (strncmp(line, CFB_PREFIX_IV, strlen(CFB_PREFIX_IV)) == 0)
     return IV;  // Riadok obsahuje inicializacny vektor
   if (strncmp(line, CFB_PREFIX_SEGMENT, strlen(CFB_PREFIX_SEGMENT)) == 0)
     return SEGMENT;  // Riadok identifikuje cislo segmentu testu
   if (strncmp(line, CFB_PREFIX_INPUT_BLOCK, strlen(CFB_PREFIX_INPUT_BLOCK)) == 0)
     return INPUT_BLOCK;  // Riadok obsahuje vstupny blok pre CFB operaciu
   if (strncmp(line, CFB_PREFIX_OUTPUT_BLOCK, strlen(CFB_PREFIX_OUTPUT_BLOCK)) == 0)
     return OUTPUT_BLOCK;  // Riadok obsahuje vystupny blok po sifrovani
   if (strncmp(line, CFB_PREFIX_PLAINTEXT, strlen(CFB_PREFIX_PLAINTEXT)) == 0)
     return PLAINTEXT;  // Riadok obsahuje plaintext (nezasifrovane data)
   if (strncmp(line, CFB_PREFIX_CIPHERTEXT, strlen(CFB_PREFIX_CIPHERTEXT)) == 0)
     return CIPHERTEXT;  // Riadok obsahuje ciphertext (zasifrovane data)
   if (strstr(line, "CFB") != NULL)
     return MODE_CHANGE;  // Riadok indikuje zmenu modu (Encrypt/Decrypt)
   return UNKNOWN;  // Neznamy typ riadku, bude ignorovany
 }
 
 /**
  * Uvolni pamat alokovanu pre testovacie data
  *
  * Popis: Funkcia uvolnuje vsetku dynamicky alokovanu pamat, ktora
  * bola pouzita na ulozenie testovacich dat. Sluzi na cistenie
  * pamate a zabranenie memory leakom pred ukoncenim programu alebo
  * pri prechode na nove testovacie data.
  *
  * Proces:
  * 1. Kontrola ci vstupny pointer nie je NULL
  * 2. Uvolnenie alokovanych retazcov pre rozne casti testovacieho vektora
  * 3. Vynulovanie struktury pre zabranenie vyuzitia po uvolneni
  *
  * Parametre:
  * @param data - Pointer na strukturu s testovacimi datami na uvolnenie
  */
 void free_test_case_data(TestCaseData *data) {
   if (!data)
     return;  // Ochrana pred NULL pointerom
   
   // Uvolnenie vsetkych retazcov v strukture
   free(data->hex_key);
   free(data->hex_iv);
   free(data->hex_input_block);
   free(data->hex_output_block);
   free(data->plaintext_str);
   free(data->ciphertext_str);
   
   // Vynulovanie celej struktury pre bezpecnost
   memset(data, 0, sizeof(TestCaseData));  // Zabranenie use-after-free
 }
 
 /**
  * Implementacia algoritmu CFB pre rozne velkosti segmentov
  *
  * Popis: Funkcia implementuje rezim CFB (Cipher Feedback) s podporou
  * roznych velkosti segmentov (1-bit, 8-bit, 128-bit). Vykonava sifrovanie
  * alebo desifrovanie podla parametrov a aktualizuje inicializacny vektor.
  *
  * Proces:
  * 1. Vyber spravania na zaklade velkosti segmentu
  * 2. Pre 1-bit CFB: posun IV o 1 bit a spracovanie jednotlivych bitov
  * 3. Pre 8-bit CFB: posun IV o 1 bajt a spracovanie po bajtoch
  * 4. Pre 128-bit CFB: spracovanie celeho 128-bitoveho bloku naraz
  * 5. Aktualizacia inicializacneho vektora podla standardu CFB
  *
  * Parametre:
  * @param key - Sifrovaci kluc
  * @param iv - Inicializacny vektor (aktualizovany pocas operacie)
  * @param input - Vstupne data na zasifrovanie/desifrovanie
  * @param output - Vystupne data (zasifrovane/desifrovane)
  * @param segment_size - Velkost segmentu v bitoch (1, 8, alebo 128)
  * @param encrypt - true pre sifrovanie, false pre desifrovanie
  */
 void process_cfb(uint8_t *key, uint8_t *iv, const void *input,
                 void *output, int segment_size, bool encrypt) {
   if (segment_size == CFB_SEGMENT_SIZE_1BIT) {
     // Implementacia 1-bit CFB modu
     uint8_t temp_input[CFB_BLOCK_SIZE] = {0};  // Docasny buffer pre vstup sifrovanej operacie
     uint8_t temp_output[CFB_BLOCK_SIZE] = {0};  // Docasny buffer pre vystup sifrovanej operacie
     uint8_t bit_in = *(uint8_t *)input & 0x01;  // Extrakcia vstupneho bitu (len najnizsi bit)
     uint8_t *bit_out = (uint8_t *)output;  // Pointer na vystupny bit
 
     // Sifrujeme IV pre ziskanie keystreamu
     AES_CFB_encrypt(key, iv, temp_input, CFB_BLOCK_SIZE, temp_output);
 
     // Pouzitie iba najvyssieho bitu z prveho bajtu keystreamu
     uint8_t cipher_bit = (temp_output[0] >> 7) & 0x01;  // MSB prveho bajtu
     *bit_out = cipher_bit ^ bit_in;  // XOR operacia pre sifrovanie/desifrovanie
 
     // Posun IV dolava o 1 bit s prenosom carry medzi bajtmi
     uint8_t carry = 0;  // Inicializacia prenosoveho bitu
     for (int i = 0; i < CFB_BLOCK_SIZE; i++) {
       uint8_t nextCarry = (iv[i] & 0x80) ? 1 : 0;  // Ulozenie najvyssieho bitu ako dalsieho prenosu
       iv[i] = (iv[i] << 1) | carry;  // Posun dolava a pridanie prenosoveho bitu
       carry = nextCarry;  // Aktualizacia prenosoveho bitu pre dalsi bajt
     }
 
     // Pri sifrovani sa pripaja vystupny bit, pri desifrovani vstupny bit
     iv[CFB_BLOCK_SIZE - 1] |= (encrypt ? *bit_out : bit_in) & 0x01;  // Pridanie bitu na najnizsiu poziciu
   } else if (segment_size == CFB_SEGMENT_SIZE_8BIT) {
     // Implementacia 8-bit CFB modu (1 bajt)
     uint8_t byte_in = *(uint8_t *)input;  // Vstupny bajt
     uint8_t *byte_out = (uint8_t *)output;  // Vystupny bajt
 
     if (encrypt) {
       // Sifrujeme IV a xorujeme so vstupnym bajtom (sifrovanie)
       uint8_t temp_input[1] = {byte_in};  // Docasny buffer pre 1 bajt vstupu
       uint8_t temp_output[1] = {0};  // Docasny buffer pre 1 bajt vystupu
 
       AES_CFB_encrypt(key, iv, temp_input, 1, temp_output);
       *byte_out = temp_output[0];  // Ulozenie vysledku
     } else {
       // Desifrujeme ciphertext (desifrovanie)
       uint8_t temp_input[1] = {byte_in};  // Docasny buffer pre 1 bajt vstupu
       uint8_t temp_output[1] = {0};  // Docasny buffer pre 1 bajt vystupu
 
       AES_CFB_decrypt(key, iv, temp_input, 1, temp_output);
       *byte_out = temp_output[0];  // Ulozenie vysledku
     }
 
     // Posun IV dolava o 1 bajt a pridanie noveho bajtu na koniec
     memmove(iv, iv + 1, CFB_BLOCK_SIZE - 1);  // Posun bajtov IV (odstranenie prveho bajtu)
     iv[CFB_BLOCK_SIZE - 1] = byte_in;  // Pridanie vstupneho bajtu na koniec IV
   } else {
     // Standardny 128-bit CFB mod (cely blok)
     if (encrypt) {
       // Sifrovanie celeho bloku naraz
       AES_CFB_encrypt(key, iv, input, CFB_BLOCK_SIZE, output);
     } else {
       // Desifrovanie celeho bloku naraz
       AES_CFB_decrypt(key, iv, input, CFB_BLOCK_SIZE, output);
     }
     // Aktualizacia IV pre dalsi blok - pri 128-bit CFB sa použije celý vstupný blok
     memcpy(iv, input, CFB_BLOCK_SIZE);  // Kopirovanie vstupneho bloku do IV
   }
 }
 
 /**
  * Spracuje a vyhodnoti jeden testovaci pripad
  *
  * Popis: Funkcia vykonava spracovanie jedneho testovacieho vektora,
  * vykonava sifrovacie alebo desifovacie operacie podla parametrov 
  * a vyhodnocuje uspesnost testu porovnanim s ocakavanymi hodnotami.
  *
  * Proces:
  * 1. Kontrola zhody aktualneho stavu IV so vstupnym blokom
  * 2. Spracovanie testu podla velkosti segmentu (1-bit, 8-bit, 128-bit)
  * 3. Vykonanie prislusnej operacie (sifrovanie/desifrovanie)
  * 4. Porovnanie vysledkov s ocakavanymi hodnotami
  * 5. Aktualizacia pocitadla uspesnych testov
  *
  * Parametre:
  * @param data - Testovacie data obsahujuce vstupy a ocakavane vystupy
  * @param key - Sifrovaci kluc pouzity pre test
  * @param iv - Aktualny inicializacny vektor
  * @param passed_count - Pointer na pocitadlo uspesnych testov
  *
  * Navratova hodnota:
  * @return bool - true ak test prebehol uspesne, false inak
  */
 bool process_test_case(const TestCaseData *data, uint8_t *key, uint8_t *iv,
                        int *passed_count) {
   printf("\nTest #%d (Segment #%d):\n", data->count, data->segment_number);
 
   // Kontrola ci aktualny IV zodpoveda ocakavaniemu vstupnemu bloku
   uint8_t input_block_bytes[CFB_BLOCK_SIZE];
   hex_to_bin(data->hex_input_block, input_block_bytes, CFB_BLOCK_SIZE);  // Konverzia hex na bin
   if (memcmp(iv, input_block_bytes, CFB_BLOCK_SIZE) != 0) {
     printf("!!! CHYBA: Vstupny blok nezodpoveda aktualnemu IV !!!\n");
   }
 
   bool success = false;  // Inicializacia vysledku testu
 
   if (data->segment_size == CFB_SEGMENT_SIZE_1BIT) {
     // Test pre 1-bit CFB rezim
     uint8_t plaintext_bit = 0;  // Jeden bit plaintextu
     uint8_t ciphertext_bit = 0;  // Jeden bit ciphertextu
     uint8_t result_bit = 0;  // Vysledny bit po operacii
 
     // Spracovanie hodnot z retazcov na bity
     if (data->plaintext_str && strlen(data->plaintext_str) > 0) {
       plaintext_bit = atoi(data->plaintext_str) & 0x01;  // Konverzia na 0/1
     }
 
     if (data->ciphertext_str && strlen(data->ciphertext_str) > 0) {
       ciphertext_bit = atoi(data->ciphertext_str) & 0x01;  // Konverzia na 0/1
     }
 
     if (data->is_encrypt) {
       // Sifrovanie - vstup je plaintext, ocakavany vystup je ciphertext
       printf("Plaintext: %d\n", plaintext_bit);
       printf("Ocakavany vstupny blok (IV): %s\n", data->hex_input_block);
       printf("Aktualny vstupny blok (IV): ");
       print_hex(iv, CFB_BLOCK_SIZE);  // Vypis IV v hex formate pre kontrolu
 
       // Vykonanie CFB sifrovacej operacie
       process_cfb(key, iv, &plaintext_bit, &result_bit, data->segment_size,
                   true);
 
       printf("Ocakavany ciphertext: %d\n", ciphertext_bit);
       printf("Vypocitany ciphertext: %d\n", result_bit);
 
       success = (result_bit == ciphertext_bit);  // Kontrola spravnosti vysledku
     } else {
       // Desifrovanie - vstup je ciphertext, ocakavany vystup je plaintext
       printf("Ciphertext: %d\n", ciphertext_bit);
       printf("Ocakavany vstupny blok (IV): %s\n", data->hex_input_block);
       printf("Aktualny vstupny blok (IV): ");
       print_hex(iv, CFB_BLOCK_SIZE);  // Vypis IV v hex formate pre kontrolu
 
       // Vykonanie CFB desifrovacej operacie
       process_cfb(key, iv, &ciphertext_bit, &result_bit,
                   data->segment_size, false);
 
       printf("Ocakavany plaintext: %d\n", plaintext_bit);
       printf("Vypocitany plaintext: %d\n", result_bit);
 
       success = (result_bit == plaintext_bit);  // Kontrola spravnosti vysledku
     }
   } else if (data->segment_size == CFB_SEGMENT_SIZE_8BIT) {
     // Test pre 8-bit CFB rezim (1 bajt)
     uint8_t plaintext_byte = 0;  // Jeden bajt plaintextu
     uint8_t expected_ciphertext_byte = 0;  // Jeden bajt ciphertextu
     uint8_t result_byte = 0;  // Vysledny bajt po operacii
     unsigned int byte_val;  // Pomocna premenna pre konverziu z hex
 
     // Konverzia plaintext retazca na binarne data
     if (data->plaintext_str && strlen(data->plaintext_str) >= 2) {
       if (sscanf(data->plaintext_str, "%2x", &byte_val) == 1) {  // Citanie 2 hex znakov
         plaintext_byte = (uint8_t)byte_val;  // Konverzia na bajt
       } 
     }
 
     // Konverzia ciphertext retazca na binarne data
     if (data->ciphertext_str && strlen(data->ciphertext_str) >= 2) {
       if (sscanf(data->ciphertext_str, "%2x", &byte_val) == 1) {  // Citanie 2 hex znakov
         expected_ciphertext_byte = (uint8_t)byte_val;  // Konverzia na bajt
       } 
      }
 
     if (data->is_encrypt) {
       // Sifrovanie - vstup je plaintext, ocakavany vystup je ciphertext
       printf("Plaintext: %02x\n", plaintext_byte);  // Vypis v hex formate
 
       printf("Ocakavany vstupny blok (IV): %s\n", data->hex_input_block);
       printf("Aktualny vstupny blok (IV): ");
       print_hex(iv, CFB_BLOCK_SIZE);  // Vypis IV v hex formate pre kontrolu
 
       // Vykonanie CFB sifrovacej operacie
       process_cfb(key, iv, &plaintext_byte, &result_byte,
                   data->segment_size, true);
 
       printf("Ocakavany ciphertext: %02x\n", expected_ciphertext_byte);  // Vypis v hex formate
       printf("Vypocitany ciphertext: %02x\n", result_byte);  // Vypis v hex formate
 
       success = (result_byte == expected_ciphertext_byte);  // Kontrola spravnosti vysledku
     } else {
       // Desifrovanie - vstup je ciphertext, ocakavany vystup je plaintext
       printf("Ciphertext: %02x\n", expected_ciphertext_byte);  // Vypis v hex formate
 
       printf("Ocakavany vstupny blok (IV): %s\n", data->hex_input_block);
       printf("Aktualny vstupny blok (IV): ");
       print_hex(iv, CFB_BLOCK_SIZE);  // Vypis IV v hex formate pre kontrolu
 
       // Vykonanie CFB desifrovacej operacie
       process_cfb(key, iv, &expected_ciphertext_byte, &result_byte,
                   data->segment_size, false);
 
       printf("Ocakavany plaintext: %02x\n", plaintext_byte);  // Vypis v hex formate
       printf("Vypocitany plaintext: %02x\n", result_byte);  // Vypis v hex formate
 
       success = (result_byte == plaintext_byte);  // Kontrola spravnosti vysledku
     }
   } else {
     // Test pre 128-bit CFB rezim (cely blok)
     uint8_t plaintext_bytes[CFB_BLOCK_SIZE] = {0};  // Buffer pre plaintext
     uint8_t expected_ciphertext_bytes[CFB_BLOCK_SIZE] = {0};  // Buffer pre ciphertext
     uint8_t result_bytes[CFB_BLOCK_SIZE] = {0};  // Buffer pre vysledok operacie
 
     // Konverzia plaintext retazca na binarne data
     if (data->plaintext_str && strlen(data->plaintext_str) >= 2 * CFB_BLOCK_SIZE) {  // 16 bajtov = 32 hex znakov
       hex_to_bin(data->plaintext_str, plaintext_bytes, CFB_BLOCK_SIZE);
     }
 
     // Konverzia ciphertext retazca na binarne data
     if (data->ciphertext_str && strlen(data->ciphertext_str) >= 2 * CFB_BLOCK_SIZE) {  // 16 bajtov = 32 hex znakov
       hex_to_bin(data->ciphertext_str, expected_ciphertext_bytes, CFB_BLOCK_SIZE);
     }
 
     if (data->is_encrypt) {
       // Sifrovanie - vstup je plaintext, ocakavany vystup je ciphertext
       printf("Plaintext: ");
       print_hex(plaintext_bytes, CFB_BLOCK_SIZE);  // Vypis plaintextu v hex formate
 
       printf("Ocakavany vstupny blok (IV): %s\n", data->hex_input_block);
       printf("Aktualny vstupny blok (IV): ");
       print_hex(iv, CFB_BLOCK_SIZE);  // Vypis IV v hex formate pre kontrolu
 
       // Vykonanie CFB sifrovacej operacie
       process_cfb(key, iv, plaintext_bytes, result_bytes,
                   data->segment_size, true);
 
       printf("Ocakavany ciphertext: ");
       print_hex(expected_ciphertext_bytes, CFB_BLOCK_SIZE);  // Vypis ocakavaneho ciphertextu
 
       printf("Vypocitany ciphertext: ");
       print_hex(result_bytes, CFB_BLOCK_SIZE);  // Vypis vypocitaneho ciphertextu
 
       success = (memcmp(result_bytes, expected_ciphertext_bytes, CFB_BLOCK_SIZE) == 0);  // Porovnanie vysledkov
     } else {
       // Desifrovanie - vstup je ciphertext, ocakavany vystup je plaintext
       printf("Ciphertext: ");
       print_hex(expected_ciphertext_bytes, CFB_BLOCK_SIZE);  // Vypis ciphertextu v hex formate
 
       printf("Ocakavany vstupny blok (IV): %s\n", data->hex_input_block);
       printf("Aktualny vstupny blok (IV): ");
       print_hex(iv, CFB_BLOCK_SIZE);  // Vypis IV v hex formate pre kontrolu
 
       // Vykonanie CFB desifrovacej operacie
       process_cfb(key, iv, expected_ciphertext_bytes, result_bytes,
                   data->segment_size, false);
 
       printf("Ocakavany plaintext: ");
       print_hex(plaintext_bytes, CFB_BLOCK_SIZE);  // Vypis ocakavaneho plaintextu
 
       printf("Vypocitany plaintext: ");
       print_hex(result_bytes, CFB_BLOCK_SIZE);  // Vypis vypocitaneho plaintextu
 
       success = (memcmp(result_bytes, plaintext_bytes, CFB_BLOCK_SIZE) == 0);  // Porovnanie vysledkov
     }
   }
 
   // Vyhodnotenie uspesnosti testu
   if (success) {
     (*passed_count)++;  // Inkrementacia pocitadla uspesnych testov
     printf("Test USPESNY\n");
   } else {
     printf("Test NEUSPESNY\n");
   }
 
   return success;
 }
 
 /**
  * Spracovanie testovacich dat zo suboru
  *
  * Popis: Funkcia cita testovacie vektory zo suboru, spracovava riadky
  * a vykona testovanie, ked ma dostatok udajov na zostavenie kompletneho testu.
  * Aktualizuje pocitadlo uspesnych testov na zaklade vysledkov.
  *
  * Proces:
  * 1. Nacitavanie suboru po riadkoch a klasifikacia typov riadkov
  * 2. Spracovanie dat podla ich typu (kluc, IV, plaintext, ciphertext...)
  * 3. Aktualizacia stavu IV a pocitadiel segmentov
  * 4. Vykonavanie testov ked su k dispozicii vsetky potrebne data
  *
  * Parametre:
  * @param fp - Pointer na otvoreny subor s testovacimi vektormi
  * @param data - Struktura pre ulozenie testovacich dat
  * @param key - Pole pre ulozenie sifrovacieho kluca
  * @param iv - Pole pre ulozenie aktualneho inicializacneho vektora
  * @param original_iv - Pole pre ulozenie povodneho inicializacneho vektora
  * @param test_count - Pointer na pocitadlo vykonanych testov
  * @param passed_count - Pointer na pocitadlo uspesnych testov
  * @param segment_size - Velkost segmentu v bitoch (1, 8 alebo 128)
  * @param first_segment_in_file - Flag indikujuci prvy segment v subore
  *
  * Navratova hodnota:
  * @return bool - Typicky false, ked sa dosiahne koniec suboru
  */
 bool parse_test_data(FILE *fp, TestCaseData *data, uint8_t *key,
                      uint8_t *iv, uint8_t *original_iv, int *test_count,
                      int *passed_count, int segment_size,
                      bool *first_segment_in_file) {
   char line[CFB_LINE_BUFFER_SIZE];  // Buffer pre citanie riadkov
   static bool encrypt_mode = true;  // Defaultne sme v rezime sifrovania
 
   while (fgets(line, sizeof(line), fp)) {  // Citanie po riadkoch
     // Odstranenie koncovych znakov (newline, carriage return)
     size_t len = strlen(line);
     while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
       line[--len] = '\0';
 
     if (len == 0)
       continue;  // Preskocenie prazdnych riadkov
 
     char *trimmed = trim(line);  // Odstranenie medzier zo zaciatku a konca
     LineType type = get_line_type(trimmed);  // Identifikacia typu riadku
 
     switch (type) {
     case MODE_CHANGE:
       // Prepinanie medzi sifrovacim a desifrovacim modom
       if (strstr(trimmed, "Encrypt") != NULL) {
         encrypt_mode = true;  // Nastavenie sifrovacieho modu
         *first_segment_in_file = true;  // Resetovanie segmentu
         printf("\n--- Testovanie sifrovania (Encrypt) ---\n");
       } else if (strstr(trimmed, "Decrypt") != NULL) {
         encrypt_mode = false;  // Nastavenie desifrovacieho modu
         *first_segment_in_file = true;  // Resetovanie segmentu
         printf("\n--- Testovanie desifrovania (Decrypt) ---\n");
       }
       break;
 
     case KEY:
       // Spracovanie kluca (Key = ...)
       free(data->hex_key);  // Uvolnenie predchadzajuceho kluca
       data->hex_key = strdup(trim(line + CFB_PREFIX_LEN_KEY));  // Kopirovanie hodnoty kluca (preskocenie "Key ")
       hex_to_bin(data->hex_key, key, strlen(data->hex_key) / 2);  // Konverzia na binarny format
       printf("\nKluc: %s\n", data->hex_key);  // Vypis kluca pre kontrolu
       break;
 
     case IV:
       // Spracovanie inicializacneho vektora (IV = ...)
       free(data->hex_iv);  // Uvolnenie predchadzajuceho IV
       data->hex_iv = strdup(trim(line + CFB_PREFIX_LEN_IV));  // Kopirovanie hodnoty IV (preskocenie "IV ")
       hex_to_bin(data->hex_iv, iv, CFB_BLOCK_SIZE);  // Konverzia na binarny format (16 bajtov)
       memcpy(original_iv, iv, CFB_BLOCK_SIZE);  // Zachovanie povodneho IV pre nove segmenty
       printf("IV: %s\n", data->hex_iv);  // Vypis IV pre kontrolu
       break;
 
     case SEGMENT:
       // Spracovanie indikatora segmentu (Segment # ...)
       data->segment_number = atoi(line + CFB_PREFIX_LEN_SEGMENT);  // Cislo segmentu je za "Segment #"
 
       // Pre segment #1 alebo prvy segment v subore resetujeme IV na povodny
       if (data->segment_number == 1 || *first_segment_in_file) {
         memcpy(iv, original_iv, CFB_BLOCK_SIZE);  // Obnovenie povodneho IV
         *first_segment_in_file = false;  // Uz nie je prvy segment
       }
       break;
 
     case INPUT_BLOCK:
       // Spracovanie vstupneho bloku (Input Block = ...)
       free(data->hex_input_block);  // Uvolnenie predchadzajuceho vstupneho bloku
       data->hex_input_block = strdup(trim(line + CFB_PREFIX_LEN_INPUT_BLOCK));  // Kopirovanie hodnoty (preskocenie "Input Block ")
 
       // Pre segmenty vyssi ako 1 pouzijeme vstupny blok ako novy IV
       if (data->segment_number > 1) {
         hex_to_bin(data->hex_input_block, iv, CFB_BLOCK_SIZE);  // Konverzia a aktualizacia IV
       }
       break;
 
     case OUTPUT_BLOCK:
       // Spracovanie vystupneho bloku (Output Block = ...)
       free(data->hex_output_block);  // Uvolnenie predchadzajuceho vystupneho bloku
       data->hex_output_block = strdup(trim(line + CFB_PREFIX_LEN_OUTPUT_BLOCK));  // Kopirovanie hodnoty (preskocenie "Output Block ")
       break;
 
     case PLAINTEXT:
       // Spracovanie plaintextu (Plaintext = ...)
       free(data->plaintext_str);  // Uvolnenie predchadzajuceho plaintextu
       data->plaintext_str = strdup(trim(line + CFB_PREFIX_LEN_PLAINTEXT));  // Kopirovanie hodnoty (preskocenie "Plaintext ")
       break;
 
     case CIPHERTEXT:
       // Spracovanie ciphertextu (Ciphertext = ...)
       free(data->ciphertext_str);  // Uvolnenie predchadzajuceho ciphertextu
       data->ciphertext_str = strdup(trim(line + CFB_PREFIX_LEN_CIPHERTEXT));  // Kopirovanie hodnoty (preskocenie "Ciphertext ")
 
       // Ak mame vsetky potrebne data, vykoname test
       if (data->hex_key && data->hex_iv && data->hex_input_block &&
           data->hex_output_block && data->plaintext_str &&
           data->ciphertext_str) {
 
         (*test_count)++;  // Inkrementujeme pocitadlo testov
         data->count = *test_count;  // Nastavenie cisla testu v strukture
         data->is_encrypt = encrypt_mode;  // Nastavenie modu (sifrovanie/desifrovanie)
         data->segment_size = segment_size;  // Nastavenie velkosti segmentu
 
         // Vykonanie testu a aktualizacia poctu uspesnych testov
         process_test_case(data, key, iv, passed_count);
       }
       break;
 
     case UNKNOWN:
       // Neznamy typ riadku - preskakujeme
       break;
     }
   }
 
   return false;  // Koniec suboru alebo nedostatocne data pre novy test
 }
 
 /**
  * Hlavna funkcia programu
  *
  * Popis: Hlavna funkcia inicializuje program a spusta testovanie trojich
  * variantov CFB rezimu: 1-bit CFB, 8-bit CFB a 128-bit CFB. Automaticky
  * vyberie spravne testovacie subory podla kompilovanej velkosti kluca.
  *
  * Proces:
  * 1. Detekcia velkosti kluca podla kompilacnych parametrov
  * 2. Postupne testovanie vsetkych troch variantov CFB (1-bit, 8-bit, 128-bit)
  * 3. Spracovanie testov zo suborov a vyhodnotenie vysledkov
  * 4. Zobrazenie celkovych vysledkov pre kazdy variant
  *
  * Navratova hodnota:
  * @return int - 0 pri uspesnom dokonceni, 1 pri kritickom zlyhaní
  */
 int main() {
   // Detekcia kompilovanej velkosti kluca pomocou preprocesorovych direktiv
 #if AES___ == 256
 #define AES_BITS_STR "256"  // Retazcova reprezentacia pre nazvy suborov
   printf("Program skompilovany pre AES-256 CFB rezim\n");
 #elif AES___ == 192
 #define AES_BITS_STR "192"  // Retazcova reprezentacia pre nazvy suborov
   printf("Program skompilovany pre AES-192 CFB rezim\n");
 #else
 #define AES_BITS_STR "128"  // Defaultna velkost kluca (128 bitov)
   printf("Program skompilovany pre AES-128 CFB rezim\n");
 #endif
 
   // Nazvy suborov s testovacimi vektormi pre rozne velkosti segmentov
   const char *test_vectors_files[] = {
       "test_vectors/" CFB_FILE_PREFIX_1BIT AES_BITS_STR ".txt",   // 1-bit CFB
       "test_vectors/" CFB_FILE_PREFIX_8BIT AES_BITS_STR ".txt",   // 8-bit CFB
       "test_vectors/" CFB_FILE_PREFIX_128BIT "_" AES_BITS_STR ".txt"};   // 128-bit CFB
 
   // Cloveku zrozumitelne nazvy modov pre vypis
   const char *cfb_mode_names[] = {"CFB-1 (1-bit segment dat)",
                                  "CFB-8 (8-bitovy segment dat)",
                                  "CFB-128 (128-bitovy segment dat)"};
 
   // Inicializacia hlavnych bufferov
   uint8_t key[CFB_MAX_KEY_SIZE] = {0};  // Buffer pre kluc (maximalna velkost 32 bajtov)
   uint8_t iv[CFB_BLOCK_SIZE] = {0};     // Buffer pre aktualny IV
   uint8_t original_iv[CFB_BLOCK_SIZE] = {0};  // Buffer pre zachovanie povodneho IV
 
   // Iteracia cez vsetky tri varianty CFB modu
   for (int file_idx = 0; file_idx < CFB_MODE_VARIANTS_COUNT; file_idx++) {
     const char *test_vectors_file = test_vectors_files[file_idx];  // Aktualny testovaci subor
 
     // Kontrola existencie suboru
     FILE *fp = fopen(test_vectors_file, "r");
     if (!fp) {
       printf("Subor %s sa nenasiel, preskakujem...\n", test_vectors_file);
       continue;  // Prejdeme na dalsi subor
     }
     fclose(fp);  // Zatvorime subor, otvorime ho znovu neskor
 
     // Urcenie velkosti segmentu podla suboru
     int segment_size = get_segment_size(test_vectors_file);  // 1, 8 alebo 128 bitov
 
     // Vypis informacii o aktualnom testovanom mode
     printf("\n=== Testovanie %s ===\n", cfb_mode_names[file_idx]);
     printf("Pouziva sa testovaci subor: %s\n", test_vectors_file);
 
     // Otvorenie suboru pre citanie testovacich vektorov
     fp = fopen(test_vectors_file, "r");
     if (!fp) {
       perror("Nepodarilo sa otvorit subor s testovacimi vektormi");
       return 1;  // Kriticka chyba, ukoncenie programu
     }
 
     // Inicializacia struktur a pocitadiel pre testovanie
     TestCaseData test_data = {0};  // Struktura pre testovacie data
     int test_count = 0;            // Pocitadlo vykonanych testov
     int passed_count = 0;          // Pocitadlo uspesnych testov
     bool first_segment_in_file = true;  // Flag pre prvy segment v subore
 
     // Nastavenie velkosti segmentu v strukture dat
     test_data.segment_size = segment_size;
 
     // Spracovanie testovacich vektorov zo suboru
     parse_test_data(fp, &test_data, key, iv, original_iv, &test_count,
                     &passed_count, segment_size, &first_segment_in_file);
 
     // Uvolnenie zdrojov
     fclose(fp);  // Zatvorenie suboru
     free_test_case_data(&test_data);  // Uvolnenie testovacich dat
 
     // Vypis vysledkov testovania pre aktualny mod
     printf("\nTestovanie %s dokoncene: %d/%d uspesnych\n",
            cfb_mode_names[file_idx], passed_count, test_count);
   }
 
   return 0;  // Uspesne dokoncenie programu
 }