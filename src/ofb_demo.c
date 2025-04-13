#include "../header_files/ofb_config.h"

typedef enum {
  KEY,
  IV,
  BLOCK,
  INPUT_BLOCK,
  OUTPUT_BLOCK,
  PLAINTEXT,
  CIPHERTEXT,
  MODE_CHANGE,
  UNKNOWN
} LineType;

static LineType get_line_type(const char *line) {
  if (strncmp(line, "Key", 3) == 0)
    return KEY;
  if (strncmp(line, "IV", 2) == 0)
    return IV;
  if (strncmp(line, "Block #", 7) == 0)
    return BLOCK;
  if (strncmp(line, "Input Block", 11) == 0)
    return INPUT_BLOCK;
  if (strncmp(line, "Output Block", 12) == 0)
    return OUTPUT_BLOCK;
  if (strncmp(line, "Plaintext", 9) == 0)
    return PLAINTEXT;
  if (strncmp(line, "Ciphertext", 10) == 0)
    return CIPHERTEXT;
  if (strstr(line, "OFB") != NULL)
    return MODE_CHANGE;
  return UNKNOWN;
}

void free_test_case_data(TestVector *test) {
  if (!test)
    return;
  memset(test, 0, sizeof(TestVector));
}

void generate_keystream(uint8_t *key, uint8_t *iv, uint8_t *keystream) {
  // Používame AES_OFB_encrypt s nulovým blokom pre generovanie keystreamu
  uint8_t zero_block[16] = {0};
  AES_OFB_encrypt(key, iv, zero_block, 16, keystream);
}

bool parse_test_vectors(FILE *fp, TestVector encrypt_tests[],
                        TestVector decrypt_tests[],
                        int *encrypt_test_count, int *decrypt_test_count,
                        uint8_t *key) {
  char line[OFB_LINE_BUFFER_SIZE];
  char *hex_key = NULL, *hex_iv = NULL;
  char *hex_input_block = NULL, *hex_output_block = NULL;
  char *hex_plaintext = NULL, *hex_ciphertext = NULL;
  int block_number = 0;
  int current_mode = 0; // 0 = nespecifikovany, 1 = encrypt, 2 = decrypt

  *encrypt_test_count = 0;
  *decrypt_test_count = 0;

  while (fgets(line, sizeof(line), fp)) {
    // Odstranenie koncoveho znaku noveho riadka a CR znaku (Windows)
    size_t len = strlen(line);
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
      line[--len] = '\0';

    // Preskocenie prazdnych riadkov
    if (len == 0)
      continue;

    char *trimmed = trim(line);
    LineType type = get_line_type(trimmed);

    switch (type) {
    case MODE_CHANGE:
      current_mode = (strstr(trimmed, "Encrypt") != NULL)   ? 1
                     : (strstr(trimmed, "Decrypt") != NULL) ? 2
                                                            : 0;

      printf("\n--- Testovanie %s ---\n",
             (current_mode == 1)   ? "sifrovania (Encrypt)"
             : (current_mode == 2) ? "desifrovania (Decrypt)"
                                   : "neznameho rezimu");
      break;

    case KEY:
      free(hex_key);
      hex_key = strdup(trim(trimmed + 4));
      if (hex_to_bin(hex_key, key, AES_KEY_SIZE) != 0) {
        fprintf(stderr, "Error parsing Key hex.\n");
        free(hex_key);
        hex_key = NULL;
      } else {
        printf("\nKluc: %s\n", hex_key);
      }
      break;

    case IV:
      free(hex_iv);
      hex_iv = strdup(trim(trimmed + 3));
      break;

    case BLOCK:
      block_number = atoi(trimmed + 7);
      break;

    case INPUT_BLOCK:
      free(hex_input_block);
      hex_input_block = strdup(trim(trimmed + 12));

      if (block_number > 0 && block_number <= OFB_MAX_BLOCKS) {
        TestVector *target =
            (current_mode == 1)   ? &encrypt_tests[block_number - 1]
            : (current_mode == 2) ? &decrypt_tests[block_number - 1]
                                  : NULL;

        if (target) {
          strncpy(target->hex_input_block, hex_input_block,
                  OFB_HEX_BUFFER_SIZE - 1);
          target->block_number = block_number;

          if (current_mode == 1 && block_number > *encrypt_test_count)
            *encrypt_test_count = block_number;
          else if (current_mode == 2 && block_number > *decrypt_test_count)
            *decrypt_test_count = block_number;
        }
      }
      break;

    case OUTPUT_BLOCK:
      free(hex_output_block);
      hex_output_block = strdup(trim(trimmed + 13));

      if (block_number > 0 && block_number <= OFB_MAX_BLOCKS) {
        TestVector *target =
            (current_mode == 1)   ? &encrypt_tests[block_number - 1]
            : (current_mode == 2) ? &decrypt_tests[block_number - 1]
                                  : NULL;

        if (target) {
          strncpy(target->hex_output_block, hex_output_block,
                  OFB_HEX_BUFFER_SIZE - 1);
        }
      }
      break;

    case PLAINTEXT:
      free(hex_plaintext);
      hex_plaintext = strdup(trim(trimmed + 10));

      if (block_number > 0 && block_number <= OFB_MAX_BLOCKS) {
        TestVector *target =
            (current_mode == 1)   ? &encrypt_tests[block_number - 1]
            : (current_mode == 2) ? &decrypt_tests[block_number - 1]
                                  : NULL;

        if (target) {
          strncpy(target->hex_plaintext, hex_plaintext,
                  OFB_HEX_BUFFER_SIZE - 1);
        }
      }
      break;

    case CIPHERTEXT:
      free(hex_ciphertext);
      hex_ciphertext = strdup(trim(trimmed + 11));

      if (block_number > 0 && block_number <= OFB_MAX_BLOCKS) {
        TestVector *target =
            (current_mode == 1)   ? &encrypt_tests[block_number - 1]
            : (current_mode == 2) ? &decrypt_tests[block_number - 1]
                                  : NULL;

        if (target) {
          strncpy(target->hex_ciphertext, hex_ciphertext,
                  OFB_HEX_BUFFER_SIZE - 1);
        }
      }
      break;

    case UNKNOWN:
      // Neznámy typ riadka, preskakujeme
      break;
    }
  }

  // Uvoľnenie zdrojov
  free(hex_key);
  free(hex_iv);
  free(hex_input_block);
  free(hex_output_block);
  free(hex_plaintext);
  free(hex_ciphertext);

  return (*encrypt_test_count > 0 || *decrypt_test_count > 0);
}

bool process_ofb_test_case(uint8_t *key, TestVector *test,
                           int *passed_count, int test_count,
                           bool is_encrypt) {
  uint8_t iv[16], keystream[16];
  uint8_t input[OFB_MAX_DATA_SIZE], expected[OFB_MAX_DATA_SIZE],
      result[OFB_MAX_DATA_SIZE];
  uint8_t expected_output[16];
  size_t input_len, expected_len;

  // Nastavime IV podla Input Block zo suboru
  hex_to_bin(test->hex_input_block, iv, 16);

  printf("\nTest #%d (Block #%d):\n", test_count, test->block_number);
  printf("Vstupny blok (IV): %s\n", test->hex_input_block);

  // Generujeme keystream pomocou OFB s nulovým blokom
  uint8_t zero_block[16] = {0};
  AES_OFB_encrypt(key, iv, zero_block, 16, keystream);

  printf("Generovany keystream: ");
  print_hex(keystream, 16);

  // Kontrola zhodnosti keystream-u s ocakavanym output blokom
  hex_to_bin(test->hex_output_block, expected_output, 16);

  bool keystream_match = (memcmp(keystream, expected_output, 16) == 0);
  if (!keystream_match) {
    printf("!!! CHYBA: Keystream sa nezhoduje s ocakavanym vystupnym "
           "blokom !!!\n");
    printf("Ocakavany vystupny blok: %s\n", test->hex_output_block);
  }

  if (is_encrypt) {
    // Ziskam plaintext a ocakavany ciphertext
    input_len = strlen(test->hex_plaintext) / 2;
    expected_len = strlen(test->hex_ciphertext) / 2;

    hex_to_bin(test->hex_plaintext, input, input_len);
    hex_to_bin(test->hex_ciphertext, expected, expected_len);

    printf("Plaintext: ");
    print_hex(input, input_len);

    // XOR plaintext s keystream pre ziskanie ciphertext
    for (size_t j = 0; j < input_len; j++) {
      result[j] = input[j] ^ keystream[j];
    }

    printf("Vypocitany ciphertext: ");
    print_hex(result, input_len);

    printf("Ocakavany ciphertext: ");
    print_hex(expected, expected_len);
  } else {
    // Ziskam ciphertext a ocakavany plaintext
    input_len = strlen(test->hex_ciphertext) / 2;
    expected_len = strlen(test->hex_plaintext) / 2;

    hex_to_bin(test->hex_ciphertext, input, input_len);
    hex_to_bin(test->hex_plaintext, expected, expected_len);

    printf("Ciphertext: ");
    print_hex(input, input_len);

    // XOR ciphertext s keystream pre ziskanie plaintext
    for (size_t j = 0; j < input_len; j++) {
      result[j] = input[j] ^ keystream[j];
    }

    printf("Vypocitany plaintext: ");
    print_hex(result, input_len);

    printf("Ocakavany plaintext: ");
    print_hex(expected, expected_len);
  }

  // Kontrola zhody výsledku
  bool success = (memcmp(result, expected, expected_len) == 0);
  if (success) {
    (*passed_count)++;
    printf("Test USPESNY\n");
  } else {
    printf("Test NEUSPESNY\n");
  }

  return success;
}

int main() {
// Zistenie velkosti kluca z kompilacnych definicii
#if AES___ == 256
  const int aes_bits = 256;
  const char *test_vectors_file = "test_vectors/ofb_256.txt";
#elif AES___ == 192
  const int aes_bits = 192;
  const char *test_vectors_file = "test_vectors/ofb_192.txt";
#else // Predvolene AES-128
  const int aes_bits = 128;
  const char *test_vectors_file = "test_vectors/ofb_128.txt";
#endif

  printf("AES-%d OFB Test\n", aes_bits);
  printf("Pouziva sa subor s testovacimi vektormi: %s\n",
         test_vectors_file);

  // Alokujeme pamat pre kluc
  uint8_t key[AES_KEY_SIZE] = {0};

  // Inicializacia testovacich vektorov
  TestVector encrypt_tests[OFB_MAX_BLOCKS] = {0};
  TestVector decrypt_tests[OFB_MAX_BLOCKS] = {0};
  int encrypt_test_count = 0;
  int decrypt_test_count = 0;

  FILE *fp = fopen(test_vectors_file, "r");
  if (!fp) {
    perror("Nepodarilo sa otvorit subor s testovacimi vektormi");
    return 1;
  }

  // Parsovanie suboru a nacitanie testov
  if (!parse_test_vectors(fp, encrypt_tests, decrypt_tests,
                          &encrypt_test_count, &decrypt_test_count, key)) {
    printf("Nepodarilo sa nacitat ziadne testovacie vektory.\n");
    fclose(fp);
    return 1;
  }

  fclose(fp);

  // Vykonavanie testov
  int test_count = 0;
  int passed_count = 0;

  // Spracovanie sifrovacich testov
  if (encrypt_test_count > 0) {
    printf("\n--- Vykonavanie sifrovacich testov ---\n");
    for (int i = 0; i < encrypt_test_count; i++) {
      test_count++;
      process_ofb_test_case(key, &encrypt_tests[i], &passed_count,
                            test_count, true);
    }
  }

  // Spracovanie desifrovacich testov
  if (decrypt_test_count > 0) {
    printf("\n--- Vykonavanie desifrovacich testov ---\n");
    for (int i = 0; i < decrypt_test_count; i++) {
      test_count++;
      process_ofb_test_case(key, &decrypt_tests[i], &passed_count,
                            test_count, false);
    }
  }

  bool success = (test_count > 0 && passed_count == test_count);

  printf("\nCelkove vysledky:\n");
  printf("Spracovanych testov: %d\n", test_count);
  printf("Uspesnych testov: %d\n", passed_count);
  printf("Celkovy vysledok: %s\n", success ? "USPESNY" : "NEUSPESNY");

  return success ? 0 : 1;
}