#include "../header_files/ocb_config.h"

typedef enum { KEY, NONCE, AAD, PT, CT, COUNT, FAIL } LineType;

static LineType get_line_type(const char *line) {
  if (strstr(line, "K : "))
    return KEY;
  if (strncmp(line, "N:", 2) == 0 || strncmp(line, "N : ", 4) == 0)
    return NONCE;
  if (strncmp(line, "A:", 2) == 0 || strncmp(line, "A : ", 4) == 0)
    return AAD;
  if (strncmp(line, "P:", 2) == 0 || strncmp(line, "P : ", 4) == 0)
    return PT;
  if (strncmp(line, "C:", 2) == 0 || strncmp(line, "C : ", 4) == 0)
    return CT;
  if (strstr(line, "COUNT = "))
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

// Oprava funkcie get_ocb_value - vytvorí kópiu stringu pred použitím trim
static char *get_ocb_value(const char *line, const char *short_prefix,
                           const char *long_prefix) {
  char *value = NULL;
  char *trimmed = NULL;

  if (strncmp(line, long_prefix, strlen(long_prefix)) == 0) {
    value = strdup(line + strlen(long_prefix));
    if (value) {
      trimmed = trim(value);
      if (trimmed != value) {
        memmove(value, trimmed, strlen(trimmed) + 1);
      }
      return value;
    }
  } else if (strncmp(line, short_prefix, strlen(short_prefix)) == 0) {
    value = strdup(line + strlen(short_prefix));
    if (value) {
      trimmed = trim(value);
      if (trimmed != value) {
        memmove(value, trimmed, strlen(trimmed) + 1);
      }
      return value;
    }
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
}

bool parse_next_test_case(FILE *fp, TestCaseData *data) {
  char line[OCB_LINE_BUFFER_SIZE];
  char *value;
  bool in_test_case = false;
  long start_pos = ftell(fp);
  bool fail_tag_seen = false;
  static char *global_key = NULL; // Zachovanie globalneho kluca

  free_test_case_data(data);

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
      value = get_line_value(trimmed, "COUNT = ");
      if (value) {
        data->count = atoi(value);
        free(value);
      }
      break;

    case KEY:
      value = get_line_value(trimmed, "K : ");
      if (value) {
        // Uloženie globálneho kľúča
        free(global_key);
        global_key = value;
        value = NULL;
      }
      break;

    case NONCE:
      if (!in_test_case && global_key) {
        // Začiatok nového testu
        in_test_case = true;
        data->hex_key = strdup(global_key);
        data->hex_nonce = get_ocb_value(trimmed, "N:", "N : ");
      } else if (in_test_case) {
        // Koniec aktuálneho testu, začiatok nového
        fseek(fp, start_pos, SEEK_SET);
        data->should_fail = fail_tag_seen;
        return true;
      }
      break;

    case AAD:
      if (in_test_case) {
        value = get_ocb_value(trimmed, "A:", "A : ");
        if (value && strlen(value) > 0) {
          data->hex_aad = value;
        } else {
          free(value);
        }
      }
      break;

    case PT:
      if (in_test_case) {
        value = get_ocb_value(trimmed, "P:", "P : ");
        if (value && strlen(value) > 0) {
          data->hex_plaintext = value;
        } else {
          free(value);
        }
      }
      break;

    case CT:
      if (in_test_case) {
        value = get_ocb_value(trimmed, "C:", "C : ");
        if (!value)
          break;

        size_t c_len = strlen(value);
        if (c_len < OCB_TAG_LEN * 2) {
          free(value);
          break;
        }

        // Rozdelenie C na ciphertext a tag
        size_t ct_len = c_len - (OCB_TAG_LEN * 2);
        data->hex_ciphertext = NULL;
        data->hex_tag = NULL;

        if (ct_len > 0) {
          data->hex_ciphertext = malloc(ct_len + 1);
          if (data->hex_ciphertext) {
            memcpy(data->hex_ciphertext, value, ct_len);
            data->hex_ciphertext[ct_len] = '\0';
          }
        }

        data->hex_tag = malloc(OCB_TAG_LEN * 2 + 1);
        if (data->hex_tag) {
          memcpy(data->hex_tag, value + ct_len, OCB_TAG_LEN * 2);
          data->hex_tag[OCB_TAG_LEN * 2] = '\0';
        }

        free(value);
      }
      break;

    case FAIL:
      fail_tag_seen = true;
      break;
    }
    start_pos = ftell(fp);
  }

  if (in_test_case) {
    data->should_fail = fail_tag_seen;
    return true;
  }
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
      OCB_TAG_LEN // Tag length is always OCB_TAG_LEN (16 bytes)
  };

  uint8_t *bufs[] = {
      calloc(lens[0] + 1, 1), // key
      calloc(lens[1] + 1, 1), // nonce
      calloc(lens[2] + 1, 1), // aad
      calloc(lens[3] + 1, 1), // plaintext
      calloc(lens[4] + 1, 1), // ciphertext
      calloc(lens[5] + 1, 1)  // tag
  };

  for (int i = 0; i < 6; i++) {
    if (!bufs[i])
      goto cleanup;
  }

  const char *hexs[] = {data->hex_key,        data->hex_nonce,
                        data->hex_aad,        data->hex_plaintext,
                        data->hex_ciphertext, data->hex_tag};

  for (int i = 0; i < 6; i++) {
    if (hexs[i] && hex_to_bin(hexs[i], bufs[i], lens[i]) != 0)
      goto cleanup;
  }

  printf("=== Test ===\n");
  printf("Vstupne data:\n");
  printf("  Kluc: %s\n", data->hex_key);
  printf("  Nonce: %s\n", data->hex_nonce);
  if (data->hex_aad) {
    printf("  AAD: %s\n", data->hex_aad);
  } else {
    printf("  AAD: (prazdne)\n");
  }

  // Test sifrovania (encrypt)
  {
    printf("\n--- Test Sifrovania ---\n");
    printf("  Plaintext: %s\n",
           data->hex_plaintext ? data->hex_plaintext : "(prazdne)");

    uint8_t *res_ct = calloc(lens[3] + 1, 1);
    uint8_t *res_tag = calloc(lens[5] + 1, 1);

    if (!res_ct || !res_tag) {
      free(res_ct);
      free(res_tag);
      goto cleanup;
    }

    AES_OCB_encrypt(bufs[0],          // key
                    bufs[1],          // nonce
                    bufs[3], lens[3], // plaintext, ptextLen
                    bufs[2], lens[2], // aData, aDataLen
                    res_ct,           // crtxt
                    res_tag           // auTag
    );

    bool ct_match =
        (lens[4] == 0 || memcmp(res_ct, bufs[4], lens[4]) == 0);
    bool tag_match = memcmp(res_tag, bufs[5], lens[5]) == 0;

    printf("  Ciphertext:\n");
    printf("    Ocakavany: %s\n",
           data->hex_ciphertext ? data->hex_ciphertext : "(prazdny)");
    printf("    Vypocitany: ");
    if (lens[3] > 0) {
      print_hex(res_ct, lens[3]);
    } else {
      printf("(prazdny)\n");
    }

    printf("  Tag:\n");
    printf("    Ocakavany: %s\n", data->hex_tag);
    printf("    Vypocitany: ");
    print_hex(res_tag, lens[5]);

    bool encrypt_ok = ct_match && tag_match;
    printf("  Vysledok sifrovania: %s\n",
           encrypt_ok ? "USPESNY" : "NEUSPESNY");

    if (encrypt_ok)
      (*passed_encrypt)++;

    free(res_ct);
    free(res_tag);
  }

  // Test desifrovania (decrypt)
  {
    printf("\n--- Test Desifrovania ---\n");
    printf("  Ciphertext: %s\n",
           data->hex_ciphertext ? data->hex_ciphertext : "(prazdne)");
    printf("  Tag: %s\n", data->hex_tag);

    uint8_t *combined = NULL;
    size_t combined_len = lens[4] + lens[5];
    uint8_t *decrypted = calloc(lens[4] + 1, 1);

    if (!decrypted) {
      goto decrypt_cleanup;
    }

    combined = calloc(combined_len + 1, 1);
    if (!combined) {
      free(decrypted);
      goto decrypt_cleanup;
    }

    if (lens[4] > 0) {
      memcpy(combined, bufs[4], lens[4]);
    }
    memcpy(combined + lens[4], bufs[5], lens[5]);

    int decrypt_status = AES_OCB_decrypt(
        bufs[0],           // key
        bufs[1],           // nonce
        combined, lens[4], // crtxt (combined data), crtxtLen
        bufs[2], lens[2],  // aData, aDataLen
        (uint8_t)lens[5],  // tagLen
        decrypted          // pntxt
    );

    bool auth_success = (decrypt_status == 0); // 0 means success
    bool decrypt_ok =
        auth_success &&
        (lens[3] == 0 || memcmp(decrypted, bufs[3], lens[3]) == 0);

    printf("  Autentifikacia: %s\n",
           auth_success ? "USPESNA" : "NEUSPESNA");

    if (auth_success) {
      printf("  Plaintext:\n");
      printf("    Ocakavany: %s\n",
             data->hex_plaintext ? data->hex_plaintext : "(prazdny)");
      printf("    Vypocitany: ");
      if (lens[3] > 0) {
        print_hex(decrypted, lens[3]);
      } else {
        printf("(prazdny)\n");
      }
    }

    printf("  Vysledok desifrovania: %s\n",
           decrypt_ok ? "USPESNY" : "NEUSPESNY");

    if (decrypt_ok)
      (*passed_decrypt)++;

    free(combined);
    free(decrypted);
  }

decrypt_cleanup:
  printf("\n");

cleanup:
  for (int i = 0; i < 6; i++) {
    free(bufs[i]);
  }
  return true;
}

int main() {
// Zistenie velkosti kluca z kompilacnych definicii
#if AES___ == 256
  const int aes_bits = 256;
  const char *test_vectors_file = "test_vectors/ocb_256.txt";
#elif AES___ == 192
  const int aes_bits = 192;
  const char *test_vectors_file = "test_vectors/ocb_192.txt";
#else // Predvolene AES-128
  const int aes_bits = 128;
  const char *test_vectors_file = "test_vectors/ocb_128.txt";
#endif

  printf("AES-%d OCB Test\n", aes_bits);
  printf("Pouziva sa subor s testovacimi vektormi: %s\n",
         test_vectors_file);

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
  int total_tests =
      processed_tests * 2; // Každý test má encrypt aj decrypt časť
  bool success = (processed_tests > 0 && total_passed == total_tests);

  printf("\nCelkove vysledky:\n");
  printf("Spracovanych testovacich vektorov: %d\n", processed_tests);
  printf("Uspesnych testov sifrovania: %d/%d\n", tests_passed_encrypt,
         processed_tests);
  printf("Uspesnych testov desifrovania: %d/%d\n", tests_passed_decrypt,
         processed_tests);
  printf("Celkovy vysledok: %s\n", success ? "USPESNY" : "NEUSPESNY");

  return success ? 0 : 1;
}