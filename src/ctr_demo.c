/************************************************************************
 * Nazov projektu: Demonstracia funkcnosti rezimov AES-u z kniznice micro-AES
 * -----------------------------------------------------------------------
 * Subor: ctr_demo.c
 * Verzia: 1.1
 * Datum: 13.4.2025
 *
 * Autor: Kamil Berecky
 *
 * Popis: Program demonstruje funkcnost rezimu AES-CTR pomocou oficialnych
 * testovacich vektorov. Implementuje sifrovanie a desifrovanie s pouzitim
 * pocitadla (counter) a porovnava vysledky s ocakavanymi hodnotami zo
 * NIST testovacich vektorov. Program podporuje rozne velkosti klucov
 * (128, 192, 256 bitov).
 * 
 * Vyuzite zdroje:
 * - micro-AES kniznica: 
 *   https://github.com/polfosol/micro-AES
 * - NIST SP 800-38A (2001): 
 *   https://doi.org/10.6028/NIST.SP.800-38A
 *
 * Pre viac info pozri README.md
 **********************************************************************/

#include "../header_files/ctr.h"

/**
 * Urci typ riadku v testovacom subore
 *
 * Popis: Funkcia analyzuje vstupny riadok a urcuje jeho typ na zaklade
 * klucovych slov. To umoznuje spravne spracovanie roznych casti testovacich
 * vektorov, ako su kluc, pocitadlo, plaintext a ciphertext.
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
  if (strncmp(line, "Key", 3) == 0)
    return KEY;  // Riadok obsahuje sifrovaci kluc
  if (strncmp(line, "Init. Counter", 13) == 0)
    return COUNTER;  // Riadok obsahuje initialny counter
  if (strncmp(line, "Block #", 7) == 0)
    return BLOCK;  // Riadok oznacuje cislo bloku
  if (strncmp(line, "Input Block", 11) == 0)
    return INPUT_BLOCK;  // Riadok obsahuje vstupny blok pre CTR operaciu
  if (strncmp(line, "Output Block", 12) == 0)
    return OUTPUT_BLOCK;  // Riadok obsahuje vystupny blok po sifrovani
  if (strncmp(line, "Plaintext", 9) == 0)
    return PLAINTEXT;  // Riadok obsahuje plaintext (nezasifrovane data)
  if (strncmp(line, "Ciphertext", 10) == 0)
    return CIPHERTEXT;  // Riadok obsahuje ciphertext (zasifrovane data)
  if (strstr(line, "CTR-AES") != NULL)
    return MODE_CHANGE;  // Riadok indikuje zmenu modu (sifrovanie/desifrovanie)
  return UNKNOWN;  // Neznamy typ riadku, bude ignorovany
}

/**
 * Inicializuje strukturu pre testovacie data
 *
 * Popis: Funkcia inicializuje strukturu TestCaseData nastavenim vsetkych
 * hodnot na predvolene stavy a nastavi mod na sifrovanie.
 *
 * Proces:
 * 1. Vynulovanie celej struktury pomocou memset
 * 2. Nastavenie predvoleneho modu na sifrovanie
 *
 * Parametre:
 * @param data - Pointer na strukturu, ktoru chceme inicializovat
 */
static void init_test_case_data(TestCaseData *data) {
  memset(data, 0, sizeof(TestCaseData));  // Vynulovanie vsetkych hodnot
  data->is_encrypt_mode = true;  // Predvoleny mod je sifrovanie
}

/**
 * Uvolni pamat alokovanu pre testovacie data
 *
 * Popis: Funkcia uvolnuje vsetky dynamicky alokovane retazce
 * zo struktury TestCaseData a vynuluje celu strukturu.
 *
 * Proces:
 * 1. Uvolnenie alokovanych retazcov (kluc, counter)
 * 2. Vynulovanie struktury pre bezpecnost
 *
 * Parametre:
 * @param data - Pointer na strukturu s testovacimi datami
 */
void free_test_case_data(TestCaseData *data) {
  free(data->hex_key);  // Uvolnenie kluca
  free(data->hex_counter);  // Uvolnenie counteru
  memset(data, 0, sizeof(TestCaseData));  // Vynulovanie pre bezpecnost
}

/**
 * Spracuje a vyhodnosti jeden testovaci vektor
 *
 * Popis: Funkcia vykonava sifrovanie alebo desifrovanie pre dany testovaci
 * vektor a porovnava vysledky s ocakavanymi hodnotami.
 *
 * Proces:
 * 1. Priprava dat (konverzia z hex na binarne hodnoty)
 * 2. Volanie prislusnej operacie (sifrovanie/desifrovanie)
 * 3. Porovnanie vysledkov s ocakavanymi hodnotami
 * 4. Aktualizacia statistiky testov
 *
 * Parametre:
 * @param test - Testovaci vektor obsahujuci vstupy a ocakavane vystupy
 * @param key - Sifrovaci kluc
 * @param is_encrypt - true pre sifrovanie, false pre desifrovanie
 * @param test_count - Ukazovatel na pocitadlo vykonanych testov
 * @param passed_count - Ukazovatel na pocitadlo uspesnych testov
 *
 * Navratova hodnota:
 * @return bool - true ak test prebehol uspesne (vysledok sa zhodoval s ocakavanym)
 */
static bool process_test_vector(const TestVector *test, const uint8_t *key,
                                bool is_encrypt, int *test_count,
                                int *passed_count) {
  uint8_t plaintext[CTR_MAX_BUFFER_SIZE];  // Buffer pre plaintext
  uint8_t ciphertext[CTR_MAX_BUFFER_SIZE];  // Buffer pre ciphertext
  uint8_t result[CTR_MAX_BUFFER_SIZE];  // Buffer pre vysledok operacie
  uint8_t counter[CTR_BLOCK_SIZE];  // Buffer pre counter
  size_t data_len;  // Dlzka dat na spracovanie
  bool success = true;  // Predvoleny vysledok je uspesny

  (*test_count)++;  // Inkrementacia pocitadla testov
  printf("\nTest #%d (Block #%d):\n", *test_count, test->block_number);

  // Konverzia countertu z hex retazca na binarne data
  hex_to_bin(test->hex_input_block, counter, CTR_BLOCK_SIZE);

  if (is_encrypt) {
    // Kod pre sifrovanie
    data_len = strlen(test->hex_plaintext) / 2;  // Polovicna dlzka (hex -> bin)
    hex_to_bin(test->hex_plaintext, plaintext, data_len);  // Konverzia plaintextu
    hex_to_bin(test->hex_ciphertext, ciphertext, data_len);  // Konverzia ocakavaneho ciphertextu

    printf("Plaintext: ");
    print_hex(plaintext, data_len);  // Vypis vstupneho plaintextu

    // Volanie funkcie na sifrovanie v CTR rezime
    AES_CTR_encrypt(key, counter, plaintext, data_len, result);

    printf("Vypocitany ciphertext: ");
    print_hex(result, data_len);  // Vypis vypocitaneho ciphertextu
    printf("Ocakavany ciphertext: ");
    print_hex(ciphertext, data_len);  // Vypis ocakavaneho ciphertextu
  } else {
    // Kod pre desifrovanie
    data_len = strlen(test->hex_ciphertext) / 2;  // Polovicna dlzka (hex -> bin)
    hex_to_bin(test->hex_ciphertext, ciphertext, data_len);  // Konverzia ciphertextu
    hex_to_bin(test->hex_plaintext, plaintext, data_len);  // Konverzia ocakavaneho plaintextu

    printf("Ciphertext: ");
    print_hex(ciphertext, data_len);  // Vypis vstupneho ciphertextu

    // Volanie funkcie na desifrovanie v CTR rezime
    AES_CTR_decrypt(key, counter, ciphertext, data_len, result);

    printf("Vypocitany plaintext: ");
    print_hex(result, data_len);  // Vypis vypocitaneho plaintextu
    printf("Ocakavany plaintext: ");
    print_hex(plaintext, data_len);  // Vypis ocakavaneho plaintextu
  }

  printf("Vstupny blok (Counter): ");
  print_hex(counter, CTR_BLOCK_SIZE);  // Vypis pouziteho counteru

  // Porovnanie vysledkov s ocakavanymi hodnotami
  uint8_t *expected = is_encrypt ? ciphertext : plaintext;  // Vyber ocakavaneho vysledku podla modu
  if (memcmp(result, expected, data_len) != 0) {
    // Nezhoda medzi vysledkom a ocakavanou hodnotou
    printf("!!! CHYBA: Vypocitany %s sa nezhoduje s ocakavanym !!!\n",
          is_encrypt ? "ciphertext" : "plaintext");
    success = false;
  }

  // Aktualizacia statistiky a vypis vysledku testu
  if (success) {
    (*passed_count)++;  // Inkrementacia uspesnych testov
    printf("Test USPESNY\n");
  } else {
    printf("Test NEUSPESNY\n");
  }

  return success;
}

/**
 * Spracuje jeden riadok zo vstupneho suboru
 *
 * Popis: Funkcia spracuje jeden riadok zo vstupneho suboru, identifikuje
 * jeho typ a aktualizuje prislusne data v strukture TestCaseData.
 *
 * Proces:
 * 1. Odstranenie koncovych znakov noveho riadku a navratov
 * 2. Urcenie typu riadku
 * 3. Aktualizacia dat v strukture podla typu riadku
 *
 * Parametre:
 * @param line - Vstupny riadok na spracovanie
 * @param data - Struktura pre uchovanie testovacich dat
 * @param block_number - Ukazovatel na aktualne cislo bloku
 * @param key - Buffer pre ulozenie kluca v binarnej forme
 * @param key_size - Velkost kluca v bajtoch
 */
static void process_line(char *line, TestCaseData *data, int *block_number,
                         uint8_t *key, size_t key_size) {
  // Odstranenie koncovych znakov noveho riadku a navratu vozika
  size_t len = strlen(line);
  while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
    line[--len] = '\0';
  }
  if (len == 0)
    return;  // Preskocenie prazdnych riadkov

  LineType type = get_line_type(line);  // Zistenie typu riadku
  char *value;  // Pomocna premenna pre hodnoty

  switch (type) {
  case MODE_CHANGE:
    // Zmena modu operacie (sifrovanie/desifrovanie)
    data->is_encrypt_mode = (strstr(line, "Encrypt") != NULL);  // Kontrola ci je to sifrovaci mod
    printf("\n=== %s ===\n",
          data->is_encrypt_mode
              ? "Nacitavanie sifrovacich testovacich vektorov"
              : "Nacitavanie desifrovacich testovacich vektorov");
    break;

  case KEY:
    // Spracovanie kluca (Key = ...)
    free(data->hex_key);  // Uvolnenie predchadzajuceho kluca
    data->hex_key = strdup(trim(line + CTR_PREFIX_LEN_KEY));  // Ulozenie kluca bez "Key "
    hex_to_bin(data->hex_key, key, key_size);  // Konverzia na binarny format
    printf("\nKluc: %s\n", data->hex_key);  // Vypis kluca pre kontrolu
    break;

  case COUNTER:
    // Spracovanie inicialneho counteru (Init. Counter = ...)
    free(data->hex_counter);  // Uvolnenie predchadzajuceho counteru
    data->hex_counter = strdup(trim(line + CTR_PREFIX_LEN_COUNTER));  // Ulozenie counteru bez "Init. Counter "
    printf("Inicialny counter: %s\n", data->hex_counter);  // Vypis counteru pre kontrolu
    break;

  case BLOCK:
    // Spracovanie cisla bloku (Block # ...)
    *block_number = atoi(line + CTR_PREFIX_LEN_BLOCK);  // Konverzia cisla bloku na integer
    break;

  case INPUT_BLOCK:
    // Spracovanie vstupneho bloku (Input Block = ...)
    value = strdup(trim(line + CTR_PREFIX_LEN_INPUT));  // Kopirovanie hodnoty bez "Input Block "
    if (*block_number >= 1 && *block_number <= CTR_MAX_TEST_VECTORS) {
      // Urcenie cieloveho vektoru podla aktualneho modu
      TestVector *target = data->is_encrypt_mode
                            ? &data->encrypt_tests[*block_number - 1]
                            : &data->decrypt_tests[*block_number - 1];
      strncpy(target->hex_input_block, value, CTR_INPUT_BLOCK_HEX_LEN);  // Kopirovanie hodnoty do ciela
      target->hex_input_block[CTR_INPUT_BLOCK_HEX_LEN] = '\0';  // Ukoncenie retazca
      target->block_number = *block_number;  // Nastavenie cisla bloku
      
      // Aktualizacia poctu testov podla modu
      if (data->is_encrypt_mode) {
        if (*block_number > data->encrypt_test_count)
          data->encrypt_test_count = *block_number;  // Aktualizacia najvyssieho cisla bloku
      } else {
        if (*block_number > data->decrypt_test_count)
          data->decrypt_test_count = *block_number;  // Aktualizacia najvyssieho cisla bloku
      }
    }
    free(value);  // Uvolnenie docasnej kopie
    break;

  case OUTPUT_BLOCK:
    // Spracovanie vystupneho bloku (Output Block = ...)
    value = strdup(trim(line + CTR_PREFIX_LEN_OUTPUT));  // Kopirovanie hodnoty bez "Output Block "
    if (*block_number >= 1 && *block_number <= CTR_MAX_TEST_VECTORS) {
      // Urcenie cieloveho vektoru podla aktualneho modu
      TestVector *target = data->is_encrypt_mode
                            ? &data->encrypt_tests[*block_number - 1]
                            : &data->decrypt_tests[*block_number - 1];
      strncpy(target->hex_output_block, value, CTR_OUTPUT_BLOCK_HEX_LEN);  // Kopirovanie hodnoty do ciela
      target->hex_output_block[CTR_OUTPUT_BLOCK_HEX_LEN] = '\0';  // Ukoncenie retazca
    }
    free(value);  // Uvolnenie docasnej kopie
    break;

  case PLAINTEXT:
    // Spracovanie plaintextu (Plaintext = ...)
    value = strdup(trim(line + CTR_PREFIX_LEN_PLAINTEXT));  // Kopirovanie hodnoty bez "Plaintext "
    if (*block_number >= 1 && *block_number <= CTR_MAX_TEST_VECTORS) {
      // Urcenie cieloveho vektoru podla aktualneho modu
      TestVector *target = data->is_encrypt_mode
                            ? &data->encrypt_tests[*block_number - 1]
                            : &data->decrypt_tests[*block_number - 1];
      strncpy(target->hex_plaintext, value, CTR_PLAINTEXT_HEX_LEN);  // Kopirovanie hodnoty do ciela
      target->hex_plaintext[CTR_PLAINTEXT_HEX_LEN] = '\0';  // Ukoncenie retazca
    }
    free(value);  // Uvolnenie docasnej kopie
    break;

  case CIPHERTEXT:
    // Spracovanie ciphertextu (Ciphertext = ...)
    value = strdup(trim(line + CTR_PREFIX_LEN_CIPHERTEXT));  // Kopirovanie hodnoty bez "Ciphertext "
    if (*block_number >= 1 && *block_number <= CTR_MAX_TEST_VECTORS) {
      // Urcenie cieloveho vektoru podla aktualneho modu
      TestVector *target = data->is_encrypt_mode
                            ? &data->encrypt_tests[*block_number - 1]
                            : &data->decrypt_tests[*block_number - 1];
      strncpy(target->hex_ciphertext, value, CTR_CIPHERTEXT_HEX_LEN);  // Kopirovanie hodnoty do ciela
      target->hex_ciphertext[CTR_CIPHERTEXT_HEX_LEN] = '\0';  // Ukoncenie retazca
    }
    free(value);  // Uvolnenie docasnej kopie
    break;

  default:
    // Ignorujeme neznamy typ riadku
    break;
  }
}

/**
 * Hlavna funkcia programu
 *
 * Popis: Hlavna funkcia inicializuje program, otvara subor s testovacimi
 * vektormi, spracuje testovacie vektory a spusti testy pre sifrovanie
 * a desifrovanie v CTR rezime.
 *
 * Proces:
 * 1. Vyberie spravny testovaci subor podla velkosti kluca
 * 2. Otvori testovaci subor a spracuje jeho obsah
 * 3. Vykona testy pre sifrovanie a desifrovanie
 * 4. Zobrazi celkove vysledky testov
 *
 * Navratova hodnota:
 * @return int - 0 ak vsetky testy uspesne, 1 ak niektory test zlyhal
 */
int main() {
  const char *test_vectors_file;  // Cesta k suboru s testovacimi vektormi
  
  // Zistenie velkosti kluca z kompilacnych definicii
  const int aes_bits =
#if AES___ == 256
      256  // AES-256
#elif AES___ == 192
      192  // AES-192
#else
      128  // Predvolene AES-128
#endif
      ;

  // Vyber spravneho testovacieho suboru podla velkosti kluca
  test_vectors_file =
#if AES___ == 256
      "test_vectors/ctr_256.txt"  // Pre AES-256
#elif AES___ == 192
      "test_vectors/ctr_192.txt"  // Pre AES-192
#else
      "test_vectors/ctr_128.txt"  // Pre AES-128
#endif
      ;

  printf("Program skompilovany pre AES-%d CTR rezim\n", aes_bits);
  printf("Pouziva sa testovaci subor: %s\n", test_vectors_file);

  // Otvorenie testovacieho suboru
  FILE *fp = fopen(test_vectors_file, "r");
  if (!fp) {
    perror("Nepodarilo sa otvorit subor s testovacimi vektormi");
    return 1;  // Chybovy navratovy kod
  }

  // Inicializacia struktury pre testovacie data
  TestCaseData data;
  init_test_case_data(&data);

  // Inicializacia pocitadiel a bufferov
  int block_number = 0;
  int test_count = 0, passed_count = 0;
  char line[CTR_MAX_LINE_LENGTH];
  uint8_t key[CTR_MAX_KEY_SIZE];
  size_t key_size = aes_bits / 8;  // Velkost kluca v bajtoch (16/24/32)

  // Citanie suboru po riadkoch a spracovanie dat
  while (fgets(line, sizeof(line), fp)) {
    process_line(line, &data, &block_number, key, key_size);
  }
  fclose(fp);  // Zatvorenie suboru po dokonceni citania

  // Spustenie testov sifrovania
  printf("\n=== Testovanie sifrovania (Encrypt) ===\n");
  for (int i = 0; i < data.encrypt_test_count; i++) {
    process_test_vector(&data.encrypt_tests[i], key, true, &test_count,
                        &passed_count);
  }

  // Spustenie testov desifrovania
  printf("\n=== Testovanie desifrovania (Decrypt) ===\n");
  for (int i = 0; i < data.decrypt_test_count; i++) {
    process_test_vector(&data.decrypt_tests[i], key, false, &test_count,
                        &passed_count);
  }

  // Uvolnenie zdrojov a zobrazenie celkoveho vysledku
  free_test_case_data(&data);
  printf("\nTestovanie CTR rezimu dokoncene: %d/%d uspesnych\n",
         passed_count, test_count);

  return (passed_count == test_count) ? 0 : 1;  // Uspesny kod ak vsetky testy presli
}