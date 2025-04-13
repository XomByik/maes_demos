#include "../header_files/ecb.h"

typedef enum {
  KEY,
  PLAINTEXT,
  CIPHERTEXT,
  BLOCK,
  MODE_CHANGE,
  UNKNOWN
} LineType;

static LineType get_line_type(const char *line) {
  if (strncmp(line, "Key", 3) == 0)
    return KEY;
  if (strncmp(line, "Plaintext", 9) == 0)
    return PLAINTEXT;
  if (strncmp(line, "Ciphertext", 10) == 0)
    return CIPHERTEXT;
  if (strncmp(line, "Block #", 7) == 0)
    return BLOCK;
  if (strstr(line, "ECB-AES") != NULL)
    return MODE_CHANGE;
  return UNKNOWN;
}

static char *get_line_value(const char *line, const char *prefix) {
  const char *start = strstr(line, prefix);
  if (!start)
    return NULL;
  start += strlen(prefix);
  while (isspace(*start))
    start++;

  char *temp = strdup(start);
  if (temp) {
    char *trimmed = trim(temp);
    if (trimmed != temp) {
      memmove(temp, trimmed, strlen(trimmed) + 1);
    }
  }
  return temp;
}

void free_test_case_data(TestCaseData *data) {
  if (!data)
    return;
  free(data->hex_key);
  free(data->hex_plaintext);
  free(data->hex_ciphertext);
  memset(data, 0, sizeof(TestCaseData));
}

bool parse_next_test_case(FILE *fp, TestCaseData *data) {
  char line[ECB_LINE_BUFFER_SIZE];
  static int current_count = 0;
  static bool is_encrypt = false;
  static char *current_key = NULL;
  char *value = NULL;
  bool in_test_case = false;
  long start_pos;

  // Uchovaj si predchádzajúci kľúč
  char *prev_key = data->hex_key ? strdup(data->hex_key) : NULL;
  free_test_case_data(data);

  // Nastav kľúč z predchádzajúceho behu alebo globálneho kľúča
  data->hex_key =
      prev_key ? prev_key : (current_key ? strdup(current_key) : NULL);
  data->is_encrypt = is_encrypt;

  while (fgets(line, sizeof(line), fp)) {
    char *trimmed = trim(line);
    if (!trimmed || !*trimmed)
      continue;

    start_pos = ftell(fp);
    LineType type = get_line_type(trimmed);

    switch (type) {
    case MODE_CHANGE:
      is_encrypt = (strstr(trimmed, "Encrypt") != NULL);
      data->is_encrypt = is_encrypt;
      data->block_number = 0;
      in_test_case = true;
      free(current_key);
      current_key = NULL;
      break;

    case BLOCK:
      // Ak máme kompletný test, vráť ho pred spracovaním nového bloku
      if (in_test_case && data->hex_key && data->hex_plaintext &&
          data->hex_ciphertext) {
        fseek(fp, start_pos, SEEK_SET);
        if (!data->count)
          data->count = ++current_count;
        return true;
      }
      data->block_number = atoi(trimmed + 7);
      break;

    case KEY:
      value = get_line_value(trimmed, "Key");
      if (value) {
        free(current_key);
        current_key = strdup(value);
        free(data->hex_key);
        data->hex_key = value;
        value = NULL;
      }
      break;

    case PLAINTEXT:
      value = get_line_value(trimmed, "Plaintext");
      if (value) {
        free(data->hex_plaintext);
        data->hex_plaintext = value;
        value = NULL;
      }
      break;

    case CIPHERTEXT:
      value = get_line_value(trimmed, "Ciphertext");
      if (value) {
        free(data->hex_ciphertext);
        data->hex_ciphertext = value;
        value = NULL;
      }
      break;
    case UNKNOWN:

      break;
    }

    free(value);

    // Kontrola či máme kompletný test
    if (data->hex_key && data->block_number > 0 && data->hex_plaintext &&
        data->hex_ciphertext) {
      if (!data->count)
        data->count = ++current_count;
      return true;
    }
  }

  // Koniec súboru, skontrolujeme či máme kompletný test
  if (data->hex_key && data->block_number > 0 && data->hex_plaintext &&
      data->hex_ciphertext) {
    if (!data->count)
      data->count = ++current_count;
    return true;
  }

  free(prev_key);
  return false;
}

bool process_test_case(const TestCaseData *data, int *passed_encrypt,
                       int *passed_decrypt) {
  size_t key_len = strlen(data->hex_key) / 2;
  size_t pt_len =
      data->hex_plaintext ? strlen(data->hex_plaintext) / 2 : 0;
  size_t ct_len =
      data->hex_ciphertext ? strlen(data->hex_ciphertext) / 2 : 0;

  if (pt_len != 16 || ct_len != 16) {
    printf("Neplatná veľkosť bloku - musí byť 16 bajtov\n");
    return false;
  }

  uint8_t key[32] = {0};
  uint8_t plaintext[16] = {0};
  uint8_t ciphertext[16] = {0};
  uint8_t result[16] = {0};
  bool success = false;

  // Konverzia hex na binárne hodnoty
  if (hex_to_bin(data->hex_key, key, key_len) != 0 ||
      hex_to_bin(data->hex_plaintext, plaintext, pt_len) != 0 ||
      hex_to_bin(data->hex_ciphertext, ciphertext, ct_len) != 0) {
    return false;
  }

  printf("=== Test #%d (Block #%d) ===\n", data->count,
         data->block_number);
  printf("Vstupne data:\n");
  printf("  Kluc: ");
  print_limited(data->hex_key, 75);

  if (data->is_encrypt) {
    printf("\nTest sifrovania:\n");
    printf("  Plaintext: ");
    print_limited(data->hex_plaintext, 75);

    AES_ECB_encrypt(key, plaintext, 16, result);

    printf("  Vypocitany ciphertext: ");
    print_hex(result, 16);
    printf("  Ocakavany ciphertext: ");
    print_hex(ciphertext, 16);

    success = (memcmp(result, ciphertext, 16) == 0);
    if (success)
      (*passed_encrypt)++;

  } else {
    printf("\nTest desifrovania:\n");
    printf("  Ciphertext: ");
    print_limited(data->hex_ciphertext, 75);

    char status = AES_ECB_decrypt(key, ciphertext, 16, result);

    if (status != 0) {
      printf("  Desifrovanie zlyhalo so statusom %d\n", status);
      return true;
    }

    printf("  Vypocitany plaintext: ");
    print_hex(result, 16);
    printf("  Ocakavany plaintext: ");
    print_hex(plaintext, 16);

    success = (memcmp(result, plaintext, 16) == 0);
    if (success)
      (*passed_decrypt)++;
  }

  printf("  Vysledok: %s\n\n", success ? "USPESNY" : "NEUSPESNY");
  return true;
}

int main() {
  const char *test_vectors_file;

#if AES___ == 256
  test_vectors_file = "test_vectors/ecb_256.txt";
  printf("AES-256 ECB Test\n");
#elif AES___ == 192
  test_vectors_file = "test_vectors/ecb_192.txt";
  printf("AES-192 ECB Test\n");
#else
  test_vectors_file = "test_vectors/ecb_128.txt";
  printf("AES-128 ECB Test\n");
#endif

  printf("Pouziva sa testovaci subor: %s\n", test_vectors_file);

  FILE *fp = fopen(test_vectors_file, "r");
  if (!fp) {
    perror("Nepodarilo sa otvorit subor s testovacimi vektormi");
    return 1;
  }

  int tests_passed_encrypt = 0;
  int tests_passed_decrypt = 0;
  TestCaseData current_test = {0};
  int processed_tests = 0;

  while (parse_next_test_case(fp, &current_test)) {
    processed_tests++;
    process_test_case(&current_test, &tests_passed_encrypt,
                      &tests_passed_decrypt);
    free_test_case_data(&current_test);
  }

  fclose(fp);

  int total_passed = tests_passed_encrypt + tests_passed_decrypt;
  bool success = (processed_tests > 0 && total_passed == processed_tests);

  printf("\nCelkove vysledky:\n");
  printf("Spracovanych testov: %d\n", processed_tests);
  printf("Uspesnych testov sifrovania: %d\n", tests_passed_encrypt);
  printf("Uspesnych testov desifrovania: %d\n", tests_passed_decrypt);
  printf("Celkovy vysledok: %s\n", success ? "USPESNY" : "NEUSPESNY");

  return success ? 0 : 1;
}