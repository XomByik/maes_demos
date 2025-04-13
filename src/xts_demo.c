#include "../header_files/xts.h"

typedef enum {
  KEY1_T,
  KEY2_T,
  TWEAK_T,
  PTX_T,
  CTX_T,
  COUNT_T,
  FAIL_T
} LineType;

static LineType get_line_type(const char *line) {
  if (strstr(line, "Key1"))
    return KEY1_T;
  if (strstr(line, "Key2"))
    return KEY2_T;
  if (strstr(line, "DUCN") || strstr(line, "Tweak"))
    return TWEAK_T; // Pridané rozpoznanie DUCN
  if (strstr(line, "PTX"))
    return PTX_T;
  if (strstr(line, "CTX"))
    return CTX_T;
  if (strstr(line, "Count = "))
    return COUNT_T;
  if (strstr(line, "FAIL"))
    return FAIL_T;
  return -1;
}

static char *get_line_value(const char *line, const char *prefix) {
  const char *start = strstr(line, prefix);
  if (!start) {
    // Ak nenájde prefix, skúsime alternativy (napr. DUCN vs Tweak)
    if (!strcmp(prefix, "Tweak") && strstr(line, "DUCN")) {
      start = strstr(line, "DUCN");
    } else if (!strcmp(prefix, "DUCN") && strstr(line, "Tweak")) {
      start = strstr(line, "Tweak");
    } else {
      return NULL;
    }
  }

  start +=
      strlen(start) - strlen(strchr(start, ' ')); // presunúť na medzeru
  while (isspace(*start))
    start++; // preskočiť medzery

  char *temp = strdup(start);
  if (!temp)
    return NULL;

  char *trimmed = trim(temp);
  if (trimmed != temp) {
    memmove(temp, trimmed, strlen(trimmed) + 1);
  }

  return temp;
}

void free_test_case_data(TestCaseData *data) {
  if (!data)
    return;
  free(data->hex_key1);
  free(data->hex_key2);
  free(data->hex_tweak);
  free(data->hex_plaintext);
  free(data->hex_ciphertext);
  memset(data, 0, sizeof(TestCaseData));
}

bool parse_next_test_case(FILE *fp, TestCaseData *data) {
  char line[XTS_LINE_BUFFER_SIZE];
  char *value;
  bool in_test_case = false;
  bool in_ctx_section = false;
  long start_pos = ftell(fp);
  bool fail_tag_seen = false;
  static int current_count =
      0; // Statické počítadlo pre automatické číslovanie

  free_test_case_data(data);
  data->count = 0;

  while (fgets(line, sizeof(line), fp)) {
    char *trimmed = trim(line);
    if (!trimmed || strlen(trimmed) == 0 || trimmed[0] == '#' ||
        trimmed[0] == '/') {
      if (in_test_case && in_ctx_section && data->hex_key1 &&
          data->hex_key2 && data->hex_tweak && data->hex_plaintext &&
          data->hex_ciphertext) {
        data->should_fail = fail_tag_seen;
        if (data->count == 0)
          data->count = ++current_count; // Automatické číslovanie
        return true;
      }
      // Ak máme všetky dáta a prázdny riadok, pravdepodobne koniec testu
      if (in_test_case && data->hex_key1 && data->hex_key2 &&
          data->hex_tweak && data->hex_plaintext && data->hex_ciphertext) {
        data->should_fail = fail_tag_seen;
        if (data->count == 0)
          data->count = ++current_count; // Automatické číslovanie
        return true;
      }
      continue;
    }

    LineType type = get_line_type(trimmed);
    value = NULL;

    switch (type) {
    case COUNT_T:
      value = get_line_value(trimmed, "Count = ");
      if (value) {
        if (in_test_case) {
          fseek(fp, start_pos, SEEK_SET);
          free(value);
          data->should_fail = fail_tag_seen;
          if (data->count == 0)
            data->count = ++current_count; // Automatické číslovanie
          return true;
        }
        data->count = atoi(value);
        current_count = data->count; // Aktualizovať aj globálne počítadlo
        in_test_case = true;
        fail_tag_seen = false;
        free(value);
      }
      break;

    case KEY1_T:
      value = get_line_value(trimmed, "Key1");
      if (!data->hex_key1) {
        data->hex_key1 = value;
        in_test_case = true; // Začiatok nového testu
      } else
        free(value);
      break;

    case KEY2_T:
      value = get_line_value(trimmed, "Key2");
      if (!data->hex_key2)
        data->hex_key2 = value;
      else
        free(value);
      break;

    case TWEAK_T:
      value = get_line_value(trimmed, "DUCN"); // Skúsime najprv DUCN
      if (!value)
        value = get_line_value(trimmed,
                               "Tweak"); // Ak neúspešne, skúsime Tweak
      if (!data->hex_tweak)
        data->hex_tweak = value;
      else
        free(value);
      break;

    case PTX_T:
      value = get_line_value(trimmed, "PTX");
      if (!data->hex_plaintext) {
        data->hex_plaintext = value;
      } else {
        // Pridanie do existujuceho plaintextu
        size_t current_len = strlen(data->hex_plaintext);
        size_t append_len = strlen(value);
        char *new_ptx =
            realloc(data->hex_plaintext, current_len + append_len + 1);
        if (new_ptx) {
          data->hex_plaintext = new_ptx;
          strcat(data->hex_plaintext, value);
        }
        free(value);
      }
      break;

    case CTX_T:
      in_ctx_section = true;
      value = get_line_value(trimmed, "CTX");
      if (!data->hex_ciphertext) {
        data->hex_ciphertext = value;
      } else {
        // Pridanie do existujuceho ciphertextu
        size_t current_len = strlen(data->hex_ciphertext);
        size_t append_len = strlen(value);
        char *new_ctx =
            realloc(data->hex_ciphertext, current_len + append_len + 1);
        if (new_ctx) {
          data->hex_ciphertext = new_ctx;
          strcat(data->hex_ciphertext, value);
        }
        free(value);
      }
      break;

    case FAIL_T:
      fail_tag_seen = true;
      break;

    default:
      // Ak ide o nový key1, to znamená nový test
      if (strstr(trimmed, "Key1") && in_test_case) {
        fseek(fp, start_pos, SEEK_SET);
        data->should_fail = fail_tag_seen;
        if (data->count == 0)
          data->count = ++current_count; // Automatické číslovanie
        return true;
      }
      break;
    }
    start_pos = ftell(fp);
  }

  // Ak sme na konci suboru a este mame neukonceny testovaci pripad
  if (in_test_case && data->hex_key1 && data->hex_key2 &&
      data->hex_tweak && data->hex_plaintext && data->hex_ciphertext) {
    data->should_fail = fail_tag_seen;
    if (data->count == 0)
      data->count = ++current_count; // Automatické číslovanie
    return true;
  }

  return false;
}

bool process_test_case(const TestCaseData *data, int *passed_count) {
  if (!data->hex_key1 || !data->hex_key2 || !data->hex_tweak ||
      !data->hex_plaintext || !data->hex_ciphertext) {
    printf("Nekompletne testovacie data\n");
    return false;
  }

  // Zistenie velkosti AES kluca
  size_t lens[] = {strlen(data->hex_key1) / 2, strlen(data->hex_key2) / 2,
                   strlen(data->hex_tweak) / 2,
                   strlen(data->hex_plaintext) / 2,
                   strlen(data->hex_ciphertext) / 2};

  uint8_t *bufs[] = {
      calloc(lens[0] + 1, 1),          // key1
      calloc(lens[1] + 1, 1),          // key2
      calloc(lens[2] + 1, 1),          // tweak
      calloc(lens[3] + 1, 1),          // plaintext
      calloc(lens[4] + 1, 1),          // ciphertext
      calloc(lens[0] + lens[1] + 1, 1) // combined key
  };

  // Vytvorime buffer pre vysledok
  uint8_t *result = calloc(lens[3] + 1, 1);
  if (!result)
    goto cleanup;

  // Kontrola alokacie
  for (int i = 0; i < 6; i++) {
    if (!bufs[i])
      goto cleanup;
  }

  // Konverzia hex retazcov na binarne data
  const char *hexs[] = {data->hex_key1,       data->hex_key2,
                        data->hex_tweak,      data->hex_plaintext,
                        data->hex_ciphertext, NULL};

  for (int i = 0; i < 5; i++) {
    if (hex_to_bin(hexs[i], bufs[i], lens[i]) != 0)
      goto cleanup;
  }

  // Vytvorenie kombinovaneho kluca
  memcpy(bufs[5], bufs[0], lens[0]);
  memcpy(bufs[5] + lens[0], bufs[1], lens[1]);

  printf("=== Test #%d ===\n", data->count);
  printf("Vstupne data:\n");
  printf("  Kluc1 (%zu bajtov): ", lens[0]);
  print_limited(data->hex_key1, 75);
  printf("  Kluc2 (%zu bajtov): ", lens[1]);
  print_limited(data->hex_key2, 75);
  printf("  DUCN: ");
  print_limited(data->hex_tweak, 75);
  printf("  PTX (%zu bajtov): ", lens[3]);
  print_limited(data->hex_plaintext, 75);
  // Nebudeme vypisovať očakávaný CTX medzi vstupnými dátami

  printf("\nTest sifrovania:\n");
  char status =
      AES_XTS_encrypt(bufs[5], bufs[2], bufs[3], lens[3], result);

  if (status != 0) {
    printf("  Sifrovanie zlyhalo so statusom %d\n", status);
    goto cleanup;
  }

  // Kontrola kompletného výsledku
  bool match = (memcmp(result, bufs[4], lens[4]) == 0);

  // Konvertujeme výsledok do hex reťazca pre výpis
  char *result_hex = calloc(lens[3] * 2 + 1, 1);
  if (!result_hex)
    goto cleanup;

  // Konvertujeme výsledok na hex reťazec
  for (size_t i = 0; i < lens[3]; i++) {
    sprintf(result_hex + (i * 2), "%02x", result[i]);
  }

  printf("  Vypocitany CTX: ");
  print_limited(result_hex, 75);
  printf("  Ocakavany CTX: ");
  print_limited(data->hex_ciphertext, 75);

  if (match) {
    (*passed_count)++;
    printf("  Vysledok: USPESNY\n\n");
  } else {
    printf("  Vysledok: NEUSPESNY\n\n");
  }

  free(result_hex);

cleanup:
  for (int i = 0; i < 6; i++) {
    free(bufs[i]);
  }
  free(result);
  return true;
}

int main() {
  const char *test_vectors_file;

#if AES___ == 256
  test_vectors_file = "test_vectors/xts_256.txt";
  printf("AES-256 XTS Test\n");
#else
  test_vectors_file = "test_vectors/xts_128.txt";
  printf("AES-128 XTS Test\n");
#endif

  printf("Pouziva sa testovaci subor: %s\n", test_vectors_file);

  FILE *fp = fopen(test_vectors_file, "r");
  if (!fp) {
    perror("Nepodarilo sa otvorit subor s testovacimi vektormi");
    return 1;
  }

  int passed_count = 0;
  TestCaseData current_test = {0};
  int processed_tests = 0;

  while (parse_next_test_case(fp, &current_test)) {
    processed_tests++;
    process_test_case(&current_test, &passed_count);
    free_test_case_data(&current_test);
  }

  fclose(fp);

  bool success = (processed_tests > 0 && passed_count == processed_tests);

  printf("\nCelkove vysledky:\n");
  printf("Spracovanych testov: %d\n", processed_tests);
  printf("Uspesnych testov: %d/%d\n", passed_count, processed_tests);
  printf("Celkovy vysledok: %s\n", success ? "USPESNY" : "NEUSPESNY");

  return success ? 0 : 1;
}