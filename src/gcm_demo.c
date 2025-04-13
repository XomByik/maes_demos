#include "../header_files/gcm_config.h"

typedef enum { KEY, IV, AAD, PT, CT, TAG, COUNT, FAIL } LineType;

static LineType get_line_type(const char *line) {
  if (strstr(line, "Key = "))
    return KEY;
  if (strstr(line, "IV = "))
    return IV;
  if (strstr(line, "AAD = "))
    return AAD;
  if (strstr(line, "PT = "))
    return PT;
  if (strstr(line, "CT = "))
    return CT;
  if (strstr(line, "Tag = "))
    return TAG;
  if (strstr(line, "Count = "))
    return COUNT;
  if (strstr(line, "FAIL"))
    return FAIL;
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
  free(data->hex_iv);
  free(data->hex_aad);
  free(data->hex_plaintext);
  free(data->hex_ciphertext);
  free(data->hex_tag);
  memset(data, 0, sizeof(TestCaseData));
}

bool parse_next_test_case(FILE *fp, TestCaseData *data) {
  char line[GCM_LINE_BUFFER_SIZE];
  char *value;
  bool in_test_case = false;
  long start_pos = ftell(fp);
  bool fail_tag_seen = false;
  bool type_determined = false;

  free_test_case_data(data);
  data->is_decrypt = false;

  while (fgets(line, sizeof(line), fp)) {
    char *trimmed = trim(line);
    if (!trimmed || strlen(trimmed) == 0 || trimmed[0] == '#') {
      if (in_test_case)
        start_pos = ftell(fp);
      continue;
    }

    LineType type = get_line_type(trimmed);
    value = NULL;

    switch (type) {
    case COUNT:
      value = get_line_value(trimmed, "Count = ");
      if (in_test_case) {
        fseek(fp, start_pos, SEEK_SET);
        free(value);
        data->should_fail = fail_tag_seen;
        return true;
      }
      data->count = atoi(value);
      in_test_case = true;
      fail_tag_seen = false;
      type_determined = false;
      data->should_fail = false;
      data->is_decrypt = false;
      free(value);
      break;

    case KEY:
      value = get_line_value(trimmed, "Key = ");
      if (!data->hex_key)
        data->hex_key = value;
      else
        free(value);
      break;

    case IV:
      value = get_line_value(trimmed, "IV = ");
      if (!data->hex_iv)
        data->hex_iv = value;
      else
        free(value);
      break;

    case AAD:
      value = get_line_value(trimmed, "AAD = ");
      if (!data->hex_aad)
        data->hex_aad = value;
      else
        free(value);
      break;

    case PT:
      value = get_line_value(trimmed, "PT = ");
      if (!type_determined) {
        data->is_decrypt = false;
        type_determined = true;
      }
      if (!data->hex_plaintext)
        data->hex_plaintext = value;
      else
        free(value);
      break;

    case CT:
      value = get_line_value(trimmed, "CT = ");
      if (!type_determined) {
        data->is_decrypt = true;
        type_determined = true;
      }
      if (!data->hex_ciphertext)
        data->hex_ciphertext = value;
      else
        free(value);
      break;

    case TAG:
      value = get_line_value(trimmed, "Tag = ");
      if (!data->hex_tag)
        data->hex_tag = value;
      else
        free(value);
      break;

    case FAIL:
      fail_tag_seen = true;
      break;
    }
    start_pos = ftell(fp);
  }

  if (in_test_case) {
    data->should_fail = fail_tag_seen;
  }
  return in_test_case;
}

bool process_test_case(const TestCaseData *data, int *passed_encrypt,
                       int *passed_decrypt) {
  size_t lens[] = {
      strlen(data->hex_key) / 2,
      strlen(data->hex_iv) / 2,
      data->hex_aad ? strlen(data->hex_aad) / 2 : 0,
      data->hex_plaintext ? strlen(data->hex_plaintext) / 2 : 0,
      data->hex_ciphertext ? strlen(data->hex_ciphertext) / 2 : 0,
      strlen(data->hex_tag) / 2};

  uint8_t *bufs[] = {calloc(lens[0] + 1, 1), calloc(lens[1] + 1, 1),
                     calloc(lens[2] + 1, 1), calloc(lens[3] + 1, 1),
                     calloc(lens[4] + 1, 1), calloc(lens[5] + 1, 1)};

  for (int i = 0; i < 6; i++) {
    if (!bufs[i])
      goto cleanup;
  }

  const char *hexs[] = {data->hex_key,        data->hex_iv,
                        data->hex_aad,        data->hex_plaintext,
                        data->hex_ciphertext, data->hex_tag};

  for (int i = 0; i < 6; i++) {
    if (hexs[i] && hex_to_bin(hexs[i], bufs[i], lens[i]) != 0)
      goto cleanup;
  }

  printf("=== Test #%d ===\n", data->count);
  printf("Vstupne data:\n");
  printf("  IV: ");
  print_limited(data->hex_iv, 75);
  if (data->hex_aad) {
    printf("  AAD: ");
    print_limited(data->hex_aad, 75);
  }

  if (data->is_decrypt) {
    printf("  Zasifrovane data: ");
    print_limited(data->hex_ciphertext, 75);
    printf("  Autentifikacny tag: %s\n", data->hex_tag);
    if (data->hex_plaintext) {
      printf("  Ocakavany plaintext: ");
      print_limited(data->hex_plaintext, 75);
    }

    // Decrypt test
    printf("\nTest desifrovania:\n");
    uint8_t *combined = calloc(lens[4] + lens[5] + 1, 1);
    uint8_t *decrypted = calloc(lens[4] + 1, 1);

    if (!combined || !decrypted) {
      free(combined);
      free(decrypted);
      goto cleanup;
    }

    memcpy(combined, bufs[4], lens[4]);
    memcpy(combined + lens[4], bufs[5], lens[5]);

    uint8_t status = AES_GCM_decrypt(bufs[0], bufs[1], combined, lens[4],
                                     bufs[2], lens[2], lens[5], decrypted);

    bool ok = data->should_fail
                  ? (status == AUTHENTICATION_FAILURE)
                  : (status == NO_ERROR_RETURNED &&
                     (!data->hex_plaintext ||
                      memcmp(decrypted, bufs[3], lens[3]) == 0));

    printf("  Autentifikacia: %s\n",
           status == NO_ERROR_RETURNED ? "OK" : "ZLYHALA");
    printf("  Ocakavana autentifikacia: %s\n",
           data->should_fail ? "ZLYHALA" : "OK");
    if (status == NO_ERROR_RETURNED && data->hex_plaintext) {
      printf("  Vypocitany plaintext: ");
      print_hex(decrypted, lens[3]);
      printf("  Ocakavany plaintext: ");
      print_hex(bufs[3], lens[3]);
    }
    printf("  Vysledok: %s\n\n", ok ? "USPESNY" : "NEUSPESNY");

    if (ok)
      (*passed_decrypt)++;
    free(combined);
    free(decrypted);
  } else {
    printf("  Plaintext: ");
    print_limited(data->hex_plaintext ? data->hex_plaintext : "(prazdny)",
                  75);
    printf("  Ocakavany ciphertext: ");
    print_limited(data->hex_ciphertext ? data->hex_ciphertext : "(ziadny)",
                  75);
    printf("  Ocakavany tag: %s\n", data->hex_tag);

    printf("\nTest sifrovania:\n");
    uint8_t *res_ct = calloc(lens[3] + 1, 1);
    uint8_t *res_tag = calloc(lens[5] + 1, 1);

    if (!res_ct || !res_tag) {
      free(res_ct);
      free(res_tag);
      goto cleanup;
    }

    AES_GCM_encrypt(bufs[0], bufs[1], bufs[3], lens[3], bufs[2], lens[2],
                    res_ct, res_tag);

    printf("  Vypocitany ciphertext: ");
    print_hex(res_ct, lens[3]);
    printf("  Ocakavany ciphertext: ");
    print_hex(bufs[4], lens[4]);
    printf("  Vypocitany tag: ");
    print_hex(res_tag, lens[5]);
    printf("  Ocakavany tag: ");
    print_hex(bufs[5], lens[5]);

    bool tag_match = (memcmp(res_tag, bufs[5], lens[5]) == 0);
    bool ct_match =
        (!data->hex_ciphertext || memcmp(res_ct, bufs[4], lens[4]) == 0);
    bool ok = tag_match && ct_match;

    if (ok)
      (*passed_encrypt)++;
    printf("  Vysledok: %s\n\n", ok ? "USPESNY" : "NEUSPESNY");

    free(res_ct);
    free(res_tag);
  }

cleanup:
  for (int i = 0; i < 6; i++) {
    free(bufs[i]);
  }
  return true;
}

int main() {
  const char *test_vectors_file;

#if defined(GCM_NONCE_LEN) && GCM_NONCE_LEN == 128
#if AES___ == 256
  test_vectors_file = "test_vectors/gcm1024_256.txt";
#elif AES___ == 192
  test_vectors_file = "test_vectors/gcm1024_192.txt";
#else
  test_vectors_file = "test_vectors/gcm1024_128.txt";
#endif
#else
#if AES___ == 256
  test_vectors_file = "test_vectors/gcm_256.txt";
#elif AES___ == 192
  test_vectors_file = "test_vectors/gcm_192.txt";
#else
  test_vectors_file = "test_vectors/gcm_128.txt";
#endif
#endif

  printf("AES-%d GCM Test\n", AES_KEY_SIZE * 8);
  printf("Testovaci subor: %s\n", test_vectors_file);

  FILE *fp = fopen(test_vectors_file, "rb");
  if (!fp) {
    perror("Failed to open test vector file");
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
    current_test.should_fail = false;
  }

  int total_passed = tests_passed_encrypt + tests_passed_decrypt;
  bool success = (processed_tests > 0 && total_passed == processed_tests);

  printf("\nCelkove vysledky:\n");
  printf("Spracovanych testov: %d\n", processed_tests);
  printf("Uspesnych testov sifrovania: %d\n", tests_passed_encrypt);
  printf("Uspesnych testov desifrovania: %d\n", tests_passed_decrypt);
  printf("Celkovy vysledok: %s\n", success ? "USPESNY" : "NEUSPESNY");

  fclose(fp);

  return success ? 0 : 1;
}