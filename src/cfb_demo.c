#include "../header_files/cfb.h"

static int get_segment_size(const char *filename) {
  if (strstr(filename, "cfb1_") != NULL)
    return 1;
  else if (strstr(filename, "cfb8_") != NULL)
    return 8;
  else
    return 128;
}

static LineType get_line_type(const char *line) {
  if (strncmp(line, "Key", 3) == 0)
    return KEY;
  if (strncmp(line, "IV", 2) == 0)
    return IV;
  if (strncmp(line, "Segment #", 9) == 0)
    return SEGMENT;
  if (strncmp(line, "Input Block", 11) == 0)
    return INPUT_BLOCK;
  if (strncmp(line, "Output Block", 12) == 0)
    return OUTPUT_BLOCK;
  if (strncmp(line, "Plaintext", 9) == 0)
    return PLAINTEXT;
  if (strncmp(line, "Ciphertext", 10) == 0)
    return CIPHERTEXT;
  if (strstr(line, "CFB") != NULL)
    return MODE_CHANGE;
  return UNKNOWN;
}

void free_test_case_data(TestCaseData *data) {
  if (!data)
    return;
  free(data->hex_key);
  free(data->hex_iv);
  free(data->hex_input_block);
  free(data->hex_output_block);
  free(data->plaintext_str);
  free(data->ciphertext_str);
  memset(data, 0, sizeof(TestCaseData));
}

void process_cfb(uint8_t *key, uint8_t *iv, const void *input,
                 void *output, int segment_size, bool encrypt) {
  if (segment_size == 1) {
    uint8_t temp_input[16] = {0};
    uint8_t temp_output[16] = {0};
    uint8_t bit_in = *(uint8_t *)input & 0x01;
    uint8_t *bit_out = (uint8_t *)output;

    AES_CFB_encrypt(key, iv, temp_input, 16, temp_output);

    uint8_t cipher_bit = (temp_output[0] >> 7) & 0x01;
    *bit_out = cipher_bit ^ bit_in;

    uint8_t carry = 0;
    for (int i = 0; i < 16; i++) {
      uint8_t nextCarry = (iv[i] & 0x80) ? 1 : 0;
      iv[i] = (iv[i] << 1) | carry;
      carry = nextCarry;
    }

    iv[15] |= (encrypt ? *bit_out : bit_in) & 0x01;
  } else if (segment_size == 8) {
    uint8_t byte_in = *(uint8_t *)input;
    uint8_t *byte_out = (uint8_t *)output;

    if (encrypt) {
      uint8_t temp_input[1] = {byte_in};
      uint8_t temp_output[1] = {0};

      AES_CFB_encrypt(key, iv, temp_input, 1, temp_output);
      *byte_out = temp_output[0];
    } else {
      uint8_t temp_input[1] = {byte_in};
      uint8_t temp_output[1] = {0};

      AES_CFB_decrypt(key, iv, temp_input, 1, temp_output);
      *byte_out = temp_output[0];
    }

    memmove(iv, iv + 1, 15);
    iv[15] = byte_in;
  } else {
    if (encrypt) {
      AES_CFB_encrypt(key, iv, input, 16, output);
    } else {
      AES_CFB_decrypt(key, iv, input, 16, output);
    }
    memcpy(iv, input, 16);
  }
}

bool process_test_case(const TestCaseData *data, uint8_t *key, uint8_t *iv,
                       int *passed_count) {
  printf("\nTest #%d (Segment #%d):\n", data->count, data->segment_number);

  uint8_t input_block_bytes[16];
  hex_to_bin(data->hex_input_block, input_block_bytes, 16);
  if (memcmp(iv, input_block_bytes, 16) != 0) {
    printf("!!! CHYBA: Vstupny blok nezodpoveda aktualnemu IV !!!\n");
  }

  bool success = false;

  if (data->segment_size == 1) {
    uint8_t plaintext_bit = 0;
    uint8_t ciphertext_bit = 0;
    uint8_t result_bit = 0;

    if (data->plaintext_str && strlen(data->plaintext_str) > 0) {
      plaintext_bit = atoi(data->plaintext_str) & 0x01;
    }

    if (data->ciphertext_str && strlen(data->ciphertext_str) > 0) {
      ciphertext_bit = atoi(data->ciphertext_str) & 0x01;
    }

    if (data->is_encrypt) {
      printf("Plaintext: %d\n", plaintext_bit);
      printf("Ocakavany vstupny blok (IV): %s\n", data->hex_input_block);
      printf("Aktualny vstupny blok (IV): ");
      print_hex(iv, 16);

      process_cfb(key, iv, &plaintext_bit, &result_bit, data->segment_size,
                  true);

      printf("Ocakavany ciphertext: %d\n", ciphertext_bit);
      printf("Vypocitany ciphertext: %d\n", result_bit);

      success = (result_bit == ciphertext_bit);
    } else {
      printf("Ciphertext: %d\n", ciphertext_bit);
      printf("Ocakavany vstupny blok (IV): %s\n", data->hex_input_block);
      printf("Aktualny vstupny blok (IV): ");
      print_hex(iv, 16);

      process_cfb(key, iv, &ciphertext_bit, &result_bit,
                  data->segment_size, false);

      printf("Ocakavany plaintext: %d\n", plaintext_bit);
      printf("Vypocitany plaintext: %d\n", result_bit);

      success = (result_bit == plaintext_bit);
    }
  } else if (data->segment_size == 8) {
    uint8_t plaintext_byte = 0;
    uint8_t expected_ciphertext_byte = 0;
    uint8_t result_byte = 0;
    unsigned int byte_val;

    if (data->plaintext_str && strlen(data->plaintext_str) >= 2) {
      if (sscanf(data->plaintext_str, "%2x", &byte_val) == 1) {
        plaintext_byte = (uint8_t)byte_val;
      } else {
        fprintf(stderr, "Error parsing plaintext hex: %s\n",
                data->plaintext_str);
      }
    }

    if (data->ciphertext_str && strlen(data->ciphertext_str) >= 2) {
      if (sscanf(data->ciphertext_str, "%2x", &byte_val) == 1) {
        expected_ciphertext_byte = (uint8_t)byte_val;
      } else {
        fprintf(stderr, "Error parsing ciphertext hex: %s\n",
                data->ciphertext_str);
      }
    }

    if (data->is_encrypt) {
      printf("Plaintext: %02x\n", plaintext_byte);

      printf("Ocakavany vstupny blok (IV): %s\n", data->hex_input_block);
      printf("Aktualny vstupny blok (IV): ");
      print_hex(iv, 16);

      process_cfb(key, iv, &plaintext_byte, &result_byte,
                  data->segment_size, true);

      printf("Ocakavany ciphertext: %02x\n", expected_ciphertext_byte);
      printf("Vypocitany ciphertext: %02x\n", result_byte);

      success = (result_byte == expected_ciphertext_byte);
    } else {
      printf("Ciphertext: %02x\n", expected_ciphertext_byte);

      printf("Ocakavany vstupny blok (IV): %s\n", data->hex_input_block);
      printf("Aktualny vstupny blok (IV): ");
      print_hex(iv, 16);

      process_cfb(key, iv, &expected_ciphertext_byte, &result_byte,
                  data->segment_size, false);

      printf("Ocakavany plaintext: %02x\n", plaintext_byte);
      printf("Vypocitany plaintext: %02x\n", result_byte);

      success = (result_byte == plaintext_byte);
    }
  } else {
    uint8_t plaintext_bytes[16] = {0};
    uint8_t expected_ciphertext_bytes[16] = {0};
    uint8_t result_bytes[16] = {0};

    if (data->plaintext_str && strlen(data->plaintext_str) >= 32) {
      hex_to_bin(data->plaintext_str, plaintext_bytes, 16);
    }

    if (data->ciphertext_str && strlen(data->ciphertext_str) >= 32) {
      hex_to_bin(data->ciphertext_str, expected_ciphertext_bytes, 16);
    }

    if (data->is_encrypt) {
      printf("Plaintext: ");
      print_hex(plaintext_bytes, 16);

      printf("Ocakavany vstupny blok (IV): %s\n", data->hex_input_block);
      printf("Aktualny vstupny blok (IV): ");
      print_hex(iv, 16);

      process_cfb(key, iv, plaintext_bytes, result_bytes,
                  data->segment_size, true);

      printf("Ocakavany ciphertext: ");
      print_hex(expected_ciphertext_bytes, 16);

      printf("Vypocitany ciphertext: ");
      print_hex(result_bytes, 16);

      success = (memcmp(result_bytes, expected_ciphertext_bytes, 16) == 0);
    } else {
      printf("Ciphertext: ");
      print_hex(expected_ciphertext_bytes, 16);

      printf("Ocakavany vstupny blok (IV): %s\n", data->hex_input_block);
      printf("Aktualny vstupny blok (IV): ");
      print_hex(iv, 16);

      process_cfb(key, iv, expected_ciphertext_bytes, result_bytes,
                  data->segment_size, false);

      printf("Ocakavany plaintext: ");
      print_hex(plaintext_bytes, 16);

      printf("Vypocitany plaintext: ");
      print_hex(result_bytes, 16);

      success = (memcmp(result_bytes, plaintext_bytes, 16) == 0);
    }
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
                     uint8_t *iv, uint8_t *original_iv, int *test_count,
                     int *passed_count, int segment_size,
                     bool *first_segment_in_file) {
  char line[CFB_LINE_BUFFER_SIZE];
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
        *first_segment_in_file = true;
        printf("\n--- Testovanie sifrovania (Encrypt) ---\n");
      } else if (strstr(trimmed, "Decrypt") != NULL) {
        encrypt_mode = false;
        *first_segment_in_file = true;
        printf("\n--- Testovanie desifrovania (Decrypt) ---\n");
      }
      break;

    case KEY:
      free(data->hex_key);
      data->hex_key = strdup(trim(line + 4));
      hex_to_bin(data->hex_key, key, strlen(data->hex_key) / 2);
      printf("\nKluc: %s\n", data->hex_key);
      break;

    case IV:
      free(data->hex_iv);
      data->hex_iv = strdup(trim(line + 3));
      hex_to_bin(data->hex_iv, iv, 16);
      memcpy(original_iv, iv, 16);
      printf("IV: %s\n", data->hex_iv);
      break;

    case SEGMENT:
      data->segment_number = atoi(line + 9);

      if (data->segment_number == 1 || *first_segment_in_file) {
        memcpy(iv, original_iv, 16);
        *first_segment_in_file = false;
      }
      break;

    case INPUT_BLOCK:
      free(data->hex_input_block);
      data->hex_input_block = strdup(trim(line + 12));

      if (data->segment_number > 1) {
        hex_to_bin(data->hex_input_block, iv, 16);
      }
      break;

    case OUTPUT_BLOCK:
      free(data->hex_output_block);
      data->hex_output_block = strdup(trim(line + 12));
      break;

    case PLAINTEXT:
      free(data->plaintext_str);
      data->plaintext_str = strdup(trim(line + 9));
      break;

    case CIPHERTEXT:
      free(data->ciphertext_str);
      data->ciphertext_str = strdup(trim(line + 10));

      if (data->hex_key && data->hex_iv && data->hex_input_block &&
          data->hex_output_block && data->plaintext_str &&
          data->ciphertext_str) {

        (*test_count)++;
        data->count = *test_count;
        data->is_encrypt = encrypt_mode;
        data->segment_size = segment_size;

        process_test_case(data, key, iv, passed_count);
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
#define AES_BITS_STR "256"
  printf("Program skompilovany pre AES-256 CFB rezim\n");
#elif AES___ == 192
#define AES_BITS_STR "192"
  printf("Program skompilovany pre AES-192 CFB rezim\n");
#else
#define AES_BITS_STR "128"
  printf("Program skompilovany pre AES-128 CFB rezim\n");
#endif

  const char *test_vectors_files[] = {
      "test_vectors/cfb1_" AES_BITS_STR ".txt",
      "test_vectors/cfb8_" AES_BITS_STR ".txt",
      "test_vectors/cfb_" AES_BITS_STR ".txt"};

  const char *cfb_mode_names[] = {"CFB-1 (1-bit segment dat)",
                                  "CFB-8 (8-bitovy segment dat)",
                                  "CFB-128 (128-bitovy segment dat)"};

  uint8_t key[32] = {0};
  uint8_t iv[16] = {0};
  uint8_t original_iv[16] = {0};

  for (int file_idx = 0; file_idx < 3; file_idx++) {
    const char *test_vectors_file = test_vectors_files[file_idx];

    FILE *fp = fopen(test_vectors_file, "r");
    if (!fp) {
      printf("Subor %s sa nenasiel, preskakujem...\n", test_vectors_file);
      continue;
    }
    fclose(fp);

    int segment_size = get_segment_size(test_vectors_file);

    printf("\n=== Testovanie %s ===\n", cfb_mode_names[file_idx]);
    printf("Pouziva sa testovaci subor: %s\n", test_vectors_file);

    fp = fopen(test_vectors_file, "r");
    if (!fp) {
      perror("Nepodarilo sa otvorit subor s testovacimi vektormi");
      return 1;
    }

    TestCaseData test_data = {0};
    int test_count = 0;
    int passed_count = 0;
    bool first_segment_in_file = true;

    test_data.segment_size = segment_size;

    parse_test_data(fp, &test_data, key, iv, original_iv, &test_count,
                    &passed_count, segment_size, &first_segment_in_file);

    fclose(fp);
    free_test_case_data(&test_data);

    printf("\nTestovanie %s dokoncene: %d/%d uspesnych\n",
           cfb_mode_names[file_idx], passed_count, test_count);
  }

  return 0;
}