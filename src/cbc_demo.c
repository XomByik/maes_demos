#include "../header_files/cbc.h"

static LineType get_line_type(const char *line) {
  if (strncmp(line, "Key", 3) == 0)
    return KEY;
  if (strncmp(line, "IV", 2) == 0)
    return IV;
  if (strncmp(line, "Block #", 7) == 0)
    return BLOCK;
  if (strncmp(line, "Plaintext", 9) == 0)
    return PLAINTEXT;
  if (strncmp(line, "Ciphertext", 10) == 0)
    return CIPHERTEXT;
  if (strstr(line, "CBC-AES") != NULL)
    return MODE_CHANGE;
  return UNKNOWN;
}

void free_test_case_data(TestCaseData *data) {
  if (!data)
    return;
  free(data->hex_key);
  free(data->hex_iv);
  free(data->hex_plaintext);
  free(data->hex_ciphertext);
  memset(data, 0, sizeof(TestCaseData));
}

bool process_test_case(const TestCaseData *data, uint8_t *key, uint8_t *iv,
                       uint8_t *prev_ciphertext, int *passed_count,
                       bool *is_first_block) {
  printf("\nTest #%d (Block #%d, %s):\n", data->count, data->block_number,
         data->is_encrypt ? "Encrypt" : "Decrypt");

  uint8_t current_iv[16];
  uint8_t plaintext[16] = {0};
  uint8_t ciphertext[16] = {0};
  uint8_t result[16] = {0};

  if (*is_first_block) {
    memcpy(current_iv, iv, 16);
    *is_first_block = false;
  } else {
    memcpy(current_iv, prev_ciphertext, 16);
  }

  bool success = false;

  if (data->is_encrypt) {
    if (hex_to_bin(data->hex_plaintext, plaintext, 16) != 0) {
      fprintf(stderr, "Error parsing PLAINTEXT hex for test %d.\n",
              data->count);
      return false;
    }

    printf("Kluc: ");
    print_hex(key, strlen(data->hex_key) / 2);
    printf("IV/Predchadzajuci ciphertext: ");
    print_hex(current_iv, 16);
    printf("Plaintext: ");
    print_hex(plaintext, 16);

    AES_CBC_encrypt(key, current_iv, plaintext, 16, result);
    memcpy(prev_ciphertext, result, 16);

    printf("Vypocitany ciphertext: ");
    print_hex(result, 16);

    uint8_t expected_ciphertext[16];
    if (hex_to_bin(data->hex_ciphertext, expected_ciphertext, 16) != 0) {
      fprintf(stderr,
              "Error parsing expected CIPHERTEXT hex for test %d.\n",
              data->count);
      return false;
    }

    printf("Ocakavany ciphertext: ");
    print_hex(expected_ciphertext, 16);

    success = (memcmp(result, expected_ciphertext, 16) == 0);
  } else {
    if (hex_to_bin(data->hex_ciphertext, ciphertext, 16) != 0) {
      fprintf(stderr, "Error parsing CIPHERTEXT hex for test %d.\n",
              data->count);
      return false;
    }

    memcpy(prev_ciphertext, ciphertext, 16);

    printf("Kluc: ");
    print_hex(key, strlen(data->hex_key) / 2);
    printf("IV/Predchadzajuci ciphertext: ");
    print_hex(current_iv, 16);
    printf("Ciphertext: ");
    print_hex(ciphertext, 16);

    char status = AES_CBC_decrypt(key, current_iv, ciphertext, 16, result);
    if (status != 0) {
      printf("Desifrovanie zlyhalo so statusom %d\n", status);
      return false;
    }

    printf("Vypocitany plaintext: ");
    print_hex(result, 16);

    uint8_t expected_plaintext[16];
    if (hex_to_bin(data->hex_plaintext, expected_plaintext, 16) != 0) {
      fprintf(stderr,
              "Error parsing expected PLAINTEXT hex for test %d.\n",
              data->count);
      return false;
    }

    printf("Ocakavany plaintext: ");
    print_hex(expected_plaintext, 16);

    success = (memcmp(result, expected_plaintext, 16) == 0);
  }

  if (success) {
    (*passed_count)++;
    printf("Test USPESNY\n");
  } else {
    printf("Test NEUSPESNY\n");
  }

  return success;
}

bool parse_test_data(FILE *fp, TestCaseData *data, uint8_t *key,
                     uint8_t *iv, uint8_t *prev_ciphertext,
                     int *test_count, int *passed_count,
                     bool *is_first_block) {
  char line[CBC_LINE_BUFFER_SIZE];
  static bool encrypt_mode = true;

  while (fgets(line, sizeof(line), fp)) {
    size_t len = strlen(line);
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
      line[--len] = '\0';

    if (len == 0)
      continue;

    char *trimmed = trim(line);
    LineType type = get_line_type(trimmed);

    switch (type) {
    case MODE_CHANGE:
      if (strstr(trimmed, "Encrypt") != NULL) {
        encrypt_mode = true;
        *is_first_block = true;
        printf("\n=== Testovanie sifrovania (Encrypt) ===\n");
      } else if (strstr(trimmed, "Decrypt") != NULL) {
        encrypt_mode = false;
        *is_first_block = true;
        printf("\n=== Testovanie desifrovania (Decrypt) ===\n");
      }
      break;

    case KEY:
      free(data->hex_key);
      data->hex_key = strdup(trim(line + 4));
      hex_to_bin(data->hex_key, key, strlen(data->hex_key) / 2);
      break;

    case IV:
      free(data->hex_iv);
      data->hex_iv = strdup(trim(line + 3));
      if (hex_to_bin(data->hex_iv, iv, 16) != 0) {
        fprintf(
            stderr,
            "Error parsing IV hex. Skipping tests until next valid IV.\n");
        free(data->hex_iv);
        data->hex_iv = NULL;
      }
      *is_first_block = true;
      break;

    case BLOCK:
      data->block_number = atoi(line + 7);
      if (data->block_number == 1) {
        *is_first_block = true;
      }
      break;

    case PLAINTEXT:
      if (encrypt_mode) {
        free(data->hex_plaintext);
        data->hex_plaintext = strdup(trim(line + 10));
      } else {
        free(data->hex_plaintext);
        data->hex_plaintext = strdup(trim(line + 10));

        if (data->hex_key && data->hex_iv && data->hex_ciphertext &&
            data->hex_plaintext) {
          (*test_count)++;
          data->count = *test_count;
          data->is_encrypt = encrypt_mode;

          process_test_case(data, key, iv, prev_ciphertext, passed_count,
                            is_first_block);
        }
      }
      break;

    case CIPHERTEXT:
      if (!encrypt_mode) {
        free(data->hex_ciphertext);
        data->hex_ciphertext = strdup(trim(line + 11));
      } else {
        free(data->hex_ciphertext);
        data->hex_ciphertext = strdup(trim(line + 11));

        if (data->hex_key && data->hex_iv && data->hex_plaintext &&
            data->hex_ciphertext) {
          (*test_count)++;
          data->count = *test_count;
          data->is_encrypt = encrypt_mode;

          process_test_case(data, key, iv, prev_ciphertext, passed_count,
                            is_first_block);
        }
      }
      break;

    case UNKNOWN:
      break;
    }
  }

  return false;
}

int main() {
#if AES___ == 256
  const char *test_vectors_file = "test_vectors/cbc_256.txt";
  printf("Program skompilovany pre AES-256 CBC rezim\n");
#elif AES___ == 192
  const char *test_vectors_file = "test_vectors/cbc_192.txt";
  printf("Program skompilovany pre AES-192 CBC rezim\n");
#else
  const char *test_vectors_file = "test_vectors/cbc_128.txt";
  printf("Program skompilovany pre AES-128 CBC rezim\n");
#endif

  printf("Pouziva sa testovaci subor: %s\n", test_vectors_file);

  FILE *fp = fopen(test_vectors_file, "r");
  if (!fp) {
    perror("Nepodarilo sa otvorit subor s testovacimi vektormi");
    return 1;
  }

  uint8_t key[32] = {0}; // Max 256 bits (32 bytes)
  uint8_t iv[16] = {0};  // IV je vzdy 16 bajtov
  uint8_t prev_ciphertext[16] = {
      0}; // Pre ulozenie predchadzajuceho ciphertextu

  TestCaseData test_data = {0};
  int test_count = 0;
  int passed_count = 0;
  bool is_first_block = true;

  parse_test_data(fp, &test_data, key, iv, prev_ciphertext, &test_count,
                  &passed_count, &is_first_block);

  fclose(fp);
  free_test_case_data(&test_data);

  printf("\nTestovanie dokoncene: %d/%d uspesnych\n", passed_count,
         test_count);

  return 0;
}