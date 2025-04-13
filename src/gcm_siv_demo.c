#include "../header_files/gcm_siv.h"

typedef enum { KEY, NONCE, AAD, PT, CT, COUNT } LineType;

static LineType get_line_type(const char *line) {
  if (strstr(line, "key = "))
    return KEY;
  if (strstr(line, "iv = "))
    return NONCE;
  if (strstr(line, "aad = "))
    return AAD;
  if (strstr(line, "pt = "))
    return PT;
  if (strstr(line, "ct = "))
    return CT;
  if (strstr(line, "Count = "))
    return COUNT;
  return -1;
}

static char *get_line_value(const char *line, const char *prefix) {
  size_t prefix_len = strlen(prefix);
  if (strncmp(line, prefix, prefix_len) == 0) {
    char *temp = strdup(line + prefix_len);
    if (!temp)
      return NULL;
    char *trimmed = trim(temp);
    if (trimmed != temp) {
      memmove(temp, trimmed, strlen(trimmed) + 1);
    }
    return temp;
  }
  return NULL;
}

void free_test_case_data(TestCaseData *data) {
  if (!data)
    return;
  free(data->hex_key);
  free(data->hex_nonce);
  free(data->hex_aad);
  free(data->hex_plaintext);
  free(data->hex_ciphertext);
  free(data->hex_tag);
  memset(data, 0, sizeof(TestCaseData));
  data->count = -1;
}

bool parse_next_test_case(FILE *fp, TestCaseData *data) {
  char line[GCM_SIV_LINE_BUFFER_SIZE];
  char *value;
  bool in_test_case = false;
  long start_pos = ftell(fp);

  free_test_case_data(data);

  while (fgets(line, sizeof(line), fp)) {
    char *trimmed = trim(line);
    if (!trimmed || strlen(trimmed) == 0) {
      start_pos = ftell(fp);
      continue;
    }

    LineType type = get_line_type(trimmed);
    value = NULL;

    switch (type) {
    case COUNT:
      value = get_line_value(trimmed, "Count = ");
      if (value) {
        if (in_test_case) {
          fseek(fp, start_pos, SEEK_SET);
          free(value);
          goto finish_test_case;
        }
        data->count = atoi(value);
        in_test_case = true;
        free(value);
      }
      break;

    case KEY:
      if (in_test_case) {
        value = get_line_value(trimmed, "key = ");
        if (!data->hex_key)
          data->hex_key = value;
        else
          free(value);
      }
      break;

    case NONCE:
      if (in_test_case) {
        value = get_line_value(trimmed, "iv = ");
        if (!data->hex_nonce)
          data->hex_nonce = value;
        else
          free(value);
      }
      break;

    case AAD:
      if (in_test_case) {
        value = get_line_value(trimmed, "aad = ");
        if (!data->hex_aad)
          data->hex_aad = value;
        else
          free(value);
      }
      break;

    case PT:
      if (in_test_case) {
        value = get_line_value(trimmed, "pt = ");
        if (!data->hex_plaintext)
          data->hex_plaintext = value;
        else
          free(value);
      }
      break;

    case CT:
      if (in_test_case) {
        value = get_line_value(trimmed, "ct = ");
        if (value) {
          size_t combined_len = strlen(value);
          size_t tag_hex_len = GCM_SIV_TAG_LEN * 2;

          // Split CT+Tag into separate values
          if (combined_len >= tag_hex_len) {
            size_t ct_hex_len = combined_len - tag_hex_len;
            data->hex_ciphertext = strdup(value);
            if (data->hex_ciphertext) {
                data->hex_ciphertext[ct_hex_len] = '\0';
            }
            data->hex_tag = strdup(value + ct_hex_len);
          } else {
            data->hex_ciphertext = strdup("");
            data->hex_tag = strdup(value);
          }
          free(value);
        }
      }
      break;
    }
    start_pos = ftell(fp);
  }

finish_test_case:
  if (in_test_case && data->hex_key && data->hex_nonce && data->hex_tag) {
    // Ensure optional fields have empty strings if not set
    if (!data->hex_aad)
      data->hex_aad = strdup("");
    if (!data->hex_plaintext)
      data->hex_plaintext = strdup("");
    if (!data->hex_ciphertext)
      data->hex_ciphertext = strdup("");

    // Check if all allocations succeeded
    if (data->hex_aad && data->hex_plaintext && data->hex_ciphertext) {
      return true;
    }
  }

  free_test_case_data(data);
  return false;
}

bool process_test_case(const TestCaseData *data, int *passed_encrypt,
                       int *passed_decrypt) {
  size_t lens[] = {
      strlen(data->hex_key) / 2,
      strlen(data->hex_nonce) / 2,
      data->hex_aad ? strlen(data->hex_aad) / 2 : 0,
      data->hex_plaintext ? strlen(data->hex_plaintext) / 2 : 0,
      data->hex_ciphertext ? strlen(data->hex_ciphertext) / 2 : 0,
      strlen(data->hex_tag) / 2};

  // Validate lengths
  if (lens[0] != 16 && lens[0] != 24 && lens[0] != 32)
    return false;
  if (lens[1] != GCM_SIV_NONCE_LEN)
    return false;
  if (lens[5] != GCM_SIV_TAG_LEN)
    return false;
  if (lens[4] != lens[3])
    return false;

  uint8_t *bufs[] = {
      calloc(lens[0] + 1, 1), // key
      calloc(lens[1] + 1, 1), // nonce
      calloc(lens[2] + 1, 1), // aad
      calloc(lens[3] + 1, 1), // plaintext
      calloc(lens[4] + 1, 1), // expected ciphertext
      calloc(lens[5] + 1, 1)  // expected tag
  };

  // Additional buffers for encryption/decryption operations
  uint8_t *result_ct = calloc(lens[3] + 1, 1);
  uint8_t *result_tag = calloc(GCM_SIV_TAG_LEN + 1, 1);
  uint8_t *combined = calloc(lens[4] + lens[5] + 1, 1);
  uint8_t *decrypted = calloc(lens[3] + 1, 1);

  for (int i = 0; i < 6; i++) {
    if (!bufs[i])
      goto cleanup;
  }
  if (!result_ct || !result_tag || !combined || !decrypted)
    goto cleanup;

  const char *hexs[] = {data->hex_key,        data->hex_nonce,
                        data->hex_aad,        data->hex_plaintext,
                        data->hex_ciphertext, data->hex_tag};

  for (int i = 0; i < 6; i++) {
    if (hexs[i] && hex_to_bin(hexs[i], bufs[i], lens[i]) != 0)
      goto cleanup;
  }

  printf("=== Test #%d ===\n", data->count);
  printf("Vstupne data:\n");
  printf("  Nonce: ");
  print_limited(data->hex_nonce, 75);
  if (data->hex_aad && strlen(data->hex_aad) > 0) {
    printf("  AAD: ");
    print_limited(data->hex_aad, 75);
  } else {
    printf("  AAD: (prazdne)\n");
  }
  printf("  Plaintext: ");
  print_limited(data->hex_plaintext ? data->hex_plaintext : "(prazdny)",
                75);

  printf("\nTest sifrovania:\n");
  GCM_SIV_encrypt(bufs[0], bufs[1], bufs[3], lens[3], bufs[2], lens[2],
                  result_ct, result_tag);

  printf("  Vypocitany ciphertext: ");
  print_hex(result_ct, lens[3]);
  printf("  Ocakavany ciphertext: ");
  print_hex(bufs[4], lens[4]);
  printf("  Vypocitany tag: ");
  print_hex(result_tag, GCM_SIV_TAG_LEN);
  printf("  Ocakavany tag: ");
  print_hex(bufs[5], lens[5]);

  bool ct_match_enc = (memcmp(result_ct, bufs[4], lens[3]) == 0);
  bool tag_match_enc = (memcmp(result_tag, bufs[5], lens[5]) == 0);
  bool encrypt_ok = ct_match_enc && tag_match_enc;

  if (encrypt_ok)
    (*passed_encrypt)++;
  printf("  Vysledok: %s\n", encrypt_ok ? "USPESNY" : "NEUSPESNY");

  printf("\nTest desifrovania:\n");
  if (lens[4] > 0)
    memcpy(combined, bufs[4], lens[4]);
  memcpy(combined + lens[4], bufs[5], lens[5]);

  uint8_t decrypt_status =
      GCM_SIV_decrypt(bufs[0], bufs[1], combined, lens[4], bufs[2],
                      lens[2], lens[5], decrypted);

  printf("  Vypocitany plaintext: ");
  if (decrypt_status == NO_ERROR_RETURNED) {
    print_hex(decrypted, lens[3]);
  } else {
    printf("(Nedostupny - chyba autentifikacie)\n");
  }
  printf("  Ocakavany plaintext: ");
  print_hex(bufs[3], lens[3]);
  printf("  Autentifikacia: %s\n",
         decrypt_status == NO_ERROR_RETURNED ? "OK" : "ZLYHALA");

  bool decrypt_ok = (decrypt_status == NO_ERROR_RETURNED) &&
                    (memcmp(decrypted, bufs[3], lens[3]) == 0);

  if (decrypt_ok)
    (*passed_decrypt)++;
  printf("  Vysledok: %s\n\n", decrypt_ok ? "USPESNY" : "NEUSPESNY");

cleanup:
  for (int i = 0; i < 6; i++) {
    free(bufs[i]);
  }
  free(result_ct);
  free(result_tag);
  free(combined);
  free(decrypted);
  return true;
}

int main() {
  const char *test_vectors_file;

#if AES___ == 256
  test_vectors_file = "test_vectors/gcm_siv_256.txt";
  printf("AES-256 GCM-SIV Test\n");
#else
  test_vectors_file = "test_vectors/gcm_siv_128.txt";
  printf("AES-128 GCM-SIV Test\n");
#endif

  printf("Pouziva sa testovaci subor: %s\n", test_vectors_file);

  FILE *fp = fopen(test_vectors_file, "r");
  if (!fp) {
    perror("Chyba pri otvarani testovaciho suboru");
    return 1;
  }

  int tests_passed_encrypt = 0;
  int tests_passed_decrypt = 0;
  TestCaseData current_test = {.count = -1};
  int processed_tests = 0;

  while (parse_next_test_case(fp, &current_test)) {
    processed_tests++;
    process_test_case(&current_test, &tests_passed_encrypt,
                      &tests_passed_decrypt);
  }

  fclose(fp);
  free_test_case_data(&current_test);

  bool success =
      (processed_tests > 0 && tests_passed_encrypt == processed_tests &&
       tests_passed_decrypt == processed_tests);

  printf("\nCelkove vysledky:\n");
  printf("Spracovanych testov: %d\n", processed_tests);
  printf("Uspesnych testov sifrovania: %d\n", tests_passed_encrypt);
  printf("Uspesnych testov desifrovania: %d\n", tests_passed_decrypt);
  printf("Celkovy vysledok: %s\n", success ? "USPESNY" : "NEUSPESNY");

  return success ? 0 : 1;
}