#include "../header_files/ccm.h"

static char *get_value_after_prefix(const char *line, const char *prefix) {
  size_t prefix_len = strlen(prefix);
  char *trimmed_line = trim((char *)line);

  if (strncmp(trimmed_line, prefix, prefix_len) == 0) {
    return trim(trimmed_line + prefix_len);
  }

  if (strcmp(prefix, CCM_PREFIX_NLEN) == 0 && trimmed_line[0] == '[') {
    if (strncmp(trimmed_line + 1, prefix, prefix_len) == 0) {
      char *value_start = trim(trimmed_line + 1 + prefix_len);
      char *end_bracket = strchr(value_start, ']');
      if (end_bracket) {
        *end_bracket = '\0';
        return value_start;
      }
    }
  }
  return NULL;
}

void free_test_case_data(TestCaseData *data) {
  if (!data)
    return;
  free(data->hex_nonce);
  free(data->hex_adata);
  free(data->hex_payload);
  free(data->hex_ct_tag);
  data->hex_nonce = NULL;
  data->hex_adata = NULL;
  data->hex_payload = NULL;
  data->hex_ct_tag = NULL;
  data->count = -1;
}

bool parse_header(FILE *fp, size_t *Alen, size_t *Plen) {
  char line[CCM_LINE_BUFFER_SIZE];
  size_t Nlen_file = 0, Tlen_file = 0;
  bool alen_found = false, plen_found = false;
  bool nlen_found = false, tlen_found = false;
  char *value_ptr;

  while (fgets(line, sizeof(line), fp)) {
    char *trimmed = trim(line);
    if (strlen(trimmed) == 0 || trimmed[0] == '#')
      continue;

    if (strstr(trimmed, CCM_PREFIX_COUNT) ||
        strstr(trimmed, CCM_PREFIX_KEY)) {
      fseek(fp, -strlen(line), SEEK_CUR);
      break;
    }

    if ((value_ptr = get_value_after_prefix(trimmed, CCM_PREFIX_ALEN))) {
      *Alen = strtoul(value_ptr, NULL, 10);
      alen_found = true;
    } else if ((value_ptr =
                    get_value_after_prefix(trimmed, CCM_PREFIX_PLEN))) {
      *Plen = strtoul(value_ptr, NULL, 10);
      plen_found = true;
    } else if ((value_ptr =
                    get_value_after_prefix(trimmed, CCM_PREFIX_NLEN))) {
      Nlen_file = strtoul(value_ptr, NULL, 10);
      nlen_found = true;
    } else if ((value_ptr =
                    get_value_after_prefix(trimmed, CCM_PREFIX_TLEN))) {
      Tlen_file = strtoul(value_ptr, NULL, 10);
      tlen_found = true;
    }

    if (alen_found && plen_found && nlen_found && tlen_found) {
      printf("Hlavicka: Alen=%zu, Plen=%zu, Nlen=%zu, Tlen=%zu\n", *Alen,
             *Plen, Nlen_file, Tlen_file);

      if (Nlen_file != CCM_DEMO_NONCE_LEN ||
          Tlen_file != CCM_DEMO_TAG_LEN) {
        printf("Chyba: Nlen/Tlen v subore (%zu/%zu) != Kompilovane "
               "(%zu/%zu)\n",
               Nlen_file, Tlen_file, CCM_DEMO_NONCE_LEN, CCM_DEMO_TAG_LEN);
        return false;
      }
      return true;
    }
  }
  return false;
}

bool parse_initial_key(FILE *fp, uint8_t *key, int key_size_bytes) {
  char line[CCM_LINE_BUFFER_SIZE];
  char *value_ptr;

  while (fgets(line, sizeof(line), fp)) {
    char *trimmed = trim(line);
    if (strlen(trimmed) == 0 || trimmed[0] == '#')
      continue;

    if ((value_ptr = get_value_after_prefix(trimmed, CCM_PREFIX_KEY))) {
      if (strlen(value_ptr) / 2 != (size_t)key_size_bytes) {
        printf("Chyba: Neplatna dlzka kluca\n");
        return false;
      }
      if (hex_to_bin(value_ptr, key, key_size_bytes) != 0) {
        printf("Chyba: Neplatny format kluca\n");
        return false;
      }
      printf("Pociatocny kluc: ");
      print_hex(key, key_size_bytes);
      return true;
    }
  }
  return false;
}

bool parse_next_test_case(FILE *fp, TestCaseData *data, uint8_t *key,
                          int key_size_bytes) {
  char line[CCM_LINE_BUFFER_SIZE];
  char *value_ptr;
  bool in_test_case = false;

  free_test_case_data(data);

  while (fgets(line, sizeof(line), fp)) {
    char *trimmed = trim(line);
    if (strlen(trimmed) == 0 || trimmed[0] == '#')
      continue;

    if ((value_ptr = get_value_after_prefix(trimmed, CCM_PREFIX_COUNT))) {
      if (in_test_case) {
        fseek(fp, -strlen(line), SEEK_CUR);
        return true;
      }
      data->count = atoi(value_ptr);
      in_test_case = true;
      continue;
    }

    if ((value_ptr = get_value_after_prefix(trimmed, CCM_PREFIX_KEY))) {
      if (in_test_case) {
        fseek(fp, -strlen(line), SEEK_CUR);
        return true;
      }
      if (strlen(value_ptr) / 2 == (size_t)key_size_bytes) {
        if (hex_to_bin(value_ptr, key, key_size_bytes) == 0) {
          printf("\nAktualizovany kluc: ");
          print_hex(key, key_size_bytes);
        }
      }
      continue;
    }

    // Parse test case fields
    if (in_test_case) {
      if ((value_ptr =
               get_value_after_prefix(trimmed, CCM_PREFIX_NONCE))) {
        data->hex_nonce = strdup(value_ptr);
      } else if ((value_ptr =
                      get_value_after_prefix(trimmed, CCM_PREFIX_ADATA))) {
        data->hex_adata = strdup(value_ptr);
      } else if ((value_ptr = get_value_after_prefix(
                      trimmed, CCM_PREFIX_PAYLOAD))) {
        data->hex_payload = strdup(value_ptr);
      } else if ((value_ptr =
                      get_value_after_prefix(trimmed, CCM_PREFIX_CT))) {
        data->hex_ct_tag = strdup(value_ptr);
        return true;
      }
    }
  }

  return in_test_case && data->hex_nonce && data->hex_adata &&
         data->hex_payload && data->hex_ct_tag;
}

bool process_test_case(int test_num, const uint8_t *key,
                       const TestCaseData *data, size_t Alen, size_t Plen,
                       int *passed_encrypt, int *passed_decrypt) {
  printf("\n=== Test #%d ===\n", test_num);
  bool success = false;
  uint8_t *buffers[9] = {NULL};
  int buf_idx = 0;

  uint8_t *current_nonce = malloc(CCM_DEMO_NONCE_LEN);
  uint8_t *expected_tag = malloc(CCM_DEMO_TAG_LEN);
  uint8_t *result_tag = malloc(CCM_DEMO_TAG_LEN);
  uint8_t *current_adata = NULL;
  uint8_t *current_payload = NULL;
  uint8_t *current_ct_tag = NULL;
  uint8_t *expected_ct = NULL;
  uint8_t *result_ciphertext = NULL;
  uint8_t *result_plaintext = NULL;

  buffers[buf_idx++] = current_nonce;
  buffers[buf_idx++] = expected_tag;
  buffers[buf_idx++] = result_tag;

  // Alokacia pamate
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

  size_t ct_tag_len = Plen + CCM_DEMO_TAG_LEN;
  if (ct_tag_len > 0) {
    current_ct_tag = malloc(ct_tag_len);
    buffers[buf_idx++] = current_ct_tag;
  }

  for (int i = 0; i < buf_idx; i++) {
    if (!buffers[i]) {
      printf("Chyba alokacie pamate\n");
      goto cleanup;
    }
  }

  bool conversion_ok = (hex_to_bin(data->hex_nonce, current_nonce,
                                   CCM_DEMO_NONCE_LEN) == 0);
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

  if (Plen > 0) {
    memcpy(expected_ct, current_ct_tag, Plen);
  }
  memcpy(expected_tag, current_ct_tag + Plen, CCM_DEMO_TAG_LEN);

  printf("\nTest sifrovania:\n");
  AES_CCM_encrypt(key, current_nonce, current_payload, Plen, current_adata,
                  Alen, result_ciphertext, result_tag);

  printf("  Vypocitany ciphertext: ");
  print_hex(result_ciphertext, Plen);
  printf("  Ocakavany ciphertext: ");
  print_hex(expected_ct, Plen);
  printf("  Vypocitany tag: ");
  print_hex(result_tag, CCM_DEMO_TAG_LEN);
  printf("  Ocakavany tag: ");
  print_hex(expected_tag, CCM_DEMO_TAG_LEN);

  bool encrypt_ok =
      (Plen == 0 || memcmp(result_ciphertext, expected_ct, Plen) == 0) &&
      memcmp(result_tag, expected_tag, CCM_DEMO_TAG_LEN) == 0;

  printf("  Vysledok: %s\n", encrypt_ok ? "USPESNY" : "NEUSPESNY");
  if (encrypt_ok)
    (*passed_encrypt)++;

  printf("\nTest desifrovania:\n");
  uint8_t decrypt_status = AES_CCM_decrypt(
      key, current_nonce, current_ct_tag, Plen, current_adata, Alen,
      CCM_DEMO_TAG_LEN, result_plaintext);

  printf("  Vypocitany plaintext: ");
  print_hex(result_plaintext, Plen);
  printf("  Ocakavany plaintext: ");
  print_hex(current_payload, Plen);
  printf("  Autentifikacia: %s\n",
         decrypt_status == NO_ERROR_RETURNED ? "OK" : "ZLYHALA");

  bool decrypt_ok =
      (decrypt_status == NO_ERROR_RETURNED) &&
      (Plen == 0 || memcmp(result_plaintext, current_payload, Plen) == 0);

  printf("  Vysledok: %s\n", decrypt_ok ? "USPESNY" : "NEUSPESNY");
  if (decrypt_ok)
    (*passed_decrypt)++;

  success = true;

cleanup:
  for (int i = 0; i < buf_idx; i++) {
    free(buffers[i]);
  }
  return success;
}

int main() {

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
  uint8_t key[32] = {0};
  const int key_size_bytes = aes_bits / 8;
  size_t Alen = 0, Plen = 0;
  int tests_total = 0, tests_passed_encrypt = 0, tests_passed_decrypt = 0;
  TestCaseData current_test = {0};
  bool success = false;

  printf("AES-%d CCM Test\n", aes_bits);
  printf("Pouziva sa testovaci subor: %s\n", test_vectors_file);

  fp = fopen(test_vectors_file, "r");
  if (!fp) {
    perror("Chyba pri otvarani testovaciho suboru");
    return 1;
  }

  if (!parse_header(fp, &Alen, &Plen) ||
      !parse_initial_key(fp, key, key_size_bytes)) {
    printf("Chyba pri spracovani hlavicky alebo pociatocneho kluca\n");
    fclose(fp);
    return 1;
  }

  while (parse_next_test_case(fp, &current_test, key, key_size_bytes)) {
    tests_total++;
    process_test_case(current_test.count, key, &current_test, Alen, Plen,
                      &tests_passed_encrypt, &tests_passed_decrypt);
  }

  printf("\nCelkove vysledky:\n");
  printf("Spracovanych testov: %d\n", tests_total);
  printf("Uspesnych testov sifrovania: %d\n", tests_passed_encrypt);
  printf("Uspesnych testov desifrovania: %d\n", tests_passed_decrypt);

  success = (tests_total > 0 && tests_passed_encrypt == tests_total &&
             tests_passed_decrypt == tests_total);

  printf("Celkovy vysledok: %s\n", success ? "USPESNY" : "NEUSPESNY");

  free_test_case_data(&current_test);
  fclose(fp);

  return success ? 0 : 1;
}