#include "../header_files/eax_config.h"

typedef enum { KEY, NONCE, HEADER, MSG, CIPHER, COUNT, FAIL } LineType;

static LineType get_line_type(const char *line) {
  if (strstr(line, "KEY:"))
    return KEY;
  if (strstr(line, "NONCE:"))
    return NONCE;
  if (strstr(line, "HEADER:"))
    return HEADER;
  if (strstr(line, "MSG:"))
    return MSG;
  if (strstr(line, "CIPHER:"))
    return CIPHER;
  if (strstr(line, "Count = "))
    return COUNT;
  if (strstr(line, "FAIL"))
    return FAIL;
  return -1;
}

static char *get_line_value(const char *line, const char *prefix) {
  const char *start = strstr(line, prefix);
  if (!start)
    return NULL;

  start += strlen(prefix);
  while (isspace(*start))
    start++;

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
  free(data->key_hex);
  free(data->nonce_hex);
  free(data->header_hex);
  free(data->pt_hex);
  free(data->ct_hex);
  free(data->tag_hex);
  memset(data, 0, sizeof(TestCaseData));
}

bool parse_next_test_case(FILE *fp, TestCaseData *data) {
  char line[EAX_LINE_BUFFER_SIZE];
  char *value;
  bool in_test_case = false;
  long start_pos = ftell(fp);
  bool fail_tag_seen = false;
  static int current_count = 0;

  free_test_case_data(data);

  while (fgets(line, sizeof(line), fp)) {
    char *trimmed = trim(line);
    if (!trimmed || strlen(trimmed) == 0 || trimmed[0] == '#') {
      if (in_test_case && data->key_hex && data->nonce_hex &&
          data->pt_hex && data->ct_hex) {
        // Kompletný testovací prípad, môžeme sa vrátiť
        data->should_fail = fail_tag_seen;
        if (data->count == 0) {
          data->count = ++current_count;
        }
        return true;
      }
      if (in_test_case)
        start_pos = ftell(fp);
      continue;
    }

    LineType type = get_line_type(trimmed);
    value = NULL;

    switch (type) {
    case COUNT:
      value = get_line_value(trimmed, "Count = ");
      if (in_test_case && data->key_hex && data->nonce_hex &&
          data->ct_hex) {
        fseek(fp, start_pos, SEEK_SET);
        free(value);
        data->should_fail = fail_tag_seen;
        if (data->count == 0) {
          data->count = ++current_count;
        }
        return true;
      }
      data->count = atoi(value);
      current_count = data->count;
      in_test_case = true;
      fail_tag_seen = false;
      free(value);
      break;

    case KEY:
      value = get_line_value(trimmed, "KEY:");
      if (!data->key_hex) {
        data->key_hex = value;
        in_test_case = true; // Nový testovací prípad môže začať KEYom
      } else {
        free(value);
      }
      break;

    case NONCE:
      value = get_line_value(trimmed, "NONCE:");
      if (!data->nonce_hex)
        data->nonce_hex = value;
      else
        free(value);
      break;

    case HEADER:
      value = get_line_value(trimmed, "HEADER:");
      if (!data->header_hex)
        data->header_hex = value;
      else
        free(value);
      break;

    case MSG:
      value = get_line_value(trimmed, "MSG:");
      if (!data->pt_hex) {
        data->pt_hex = value;
        in_test_case = true; // Nový testovací prípad môže začať MSGom
      } else {
        free(value);
      }
      break;

    case CIPHER:
      value = get_line_value(trimmed, "CIPHER:");
      if (value &&
          strlen(value) >= 32) { // Predpokladáme 16B tag (32 znakov hex)
        size_t len = strlen(value);
        size_t tag_len_hex =
            32; // Tag je typicky 16 bajtov (32 hex znakov)

        // CT je všetko okrem posledných tag_len_hex znakov
        size_t ct_len_hex = len - tag_len_hex;

        // Rozdelenie na CT a tag
        data->ct_hex = malloc(ct_len_hex + 1);
        data->tag_hex = malloc(tag_len_hex + 1);

        if (data->ct_hex && data->tag_hex) {
          if (ct_len_hex > 0) {
            strncpy(data->ct_hex, value, ct_len_hex);
            data->ct_hex[ct_len_hex] = '\0';
          } else {
            data->ct_hex[0] = '\0'; // Prázdny CT
          }

          strncpy(data->tag_hex, value + ct_len_hex, tag_len_hex);
          data->tag_hex[tag_len_hex] = '\0';
        } else {
          free(data->ct_hex);
          free(data->tag_hex);
          data->ct_hex = NULL;
          data->tag_hex = NULL;
        }
      } else if (value) {
        // Ak CIPHER nie je dostatočne dlhý na tag, predpokladajme že celé
        // je tag
        data->tag_hex = value;
        data->ct_hex = strdup("");
        value = NULL;
      }
      free(value);

      // Po spracovaní CIPHER skontrolujeme, či máme kompletný testovací
      // prípad
      if (data->key_hex && data->nonce_hex && data->tag_hex) {
        // Ak nemáme plaintext, nastavíme prázdny
        if (!data->pt_hex) {
          data->pt_hex = strdup("");
        }
        data->should_fail = fail_tag_seen;
        if (data->count == 0) {
          data->count = ++current_count;
        }
        return true;
      }
      break;

    case FAIL:
      fail_tag_seen = true;
      break;
    }
    start_pos = ftell(fp);
  }

  // Koniec súboru, vrátime posledný test ak existuje
  if (in_test_case && data->key_hex && data->nonce_hex && data->ct_hex) {
    data->should_fail = fail_tag_seen;
    if (data->count == 0) {
      data->count = ++current_count;
    }
    return true;
  }

  return false;
}

bool process_test_case(const TestCaseData *data, int *passed_encrypt,
                       int *passed_decrypt) {
  if (!data->key_hex || !data->nonce_hex || !data->tag_hex) {
    printf("Nekompletne testovacie data\n");
    return false;
  }

  size_t lens[] = {strlen(data->key_hex) / 2,
                   strlen(data->nonce_hex) / 2,
                   data->header_hex ? strlen(data->header_hex) / 2 : 0,
                   data->pt_hex ? strlen(data->pt_hex) / 2 : 0,
                   data->ct_hex ? strlen(data->ct_hex) / 2 : 0,
                   strlen(data->tag_hex) / 2};

  uint8_t *bufs[] = {
      calloc(lens[0] + 1, 1), // key
      calloc(lens[1] + 1, 1), // nonce
      calloc(lens[2] + 1, 1), // header
      calloc(lens[3] + 1, 1), // plaintext
      calloc(lens[4] + 1, 1), // ciphertext
      calloc(lens[5] + 1, 1)  // tag
  };

  for (int i = 0; i < 6; i++) {
    if (!bufs[i])
      goto cleanup;
  }

  const char *hexs[] = {data->key_hex, data->nonce_hex, data->header_hex,
                        data->pt_hex,  data->ct_hex,    data->tag_hex};

  for (int i = 0; i < 6; i++) {
    if (hexs[i] && lens[i] > 0 &&
        hex_to_bin(hexs[i], bufs[i], lens[i]) != 0)
      goto cleanup;
  }

  printf("=== Test #%d ===\n", data->count);
  printf("Vstupne data:\n");
  printf("  Kluc: ");
  print_limited(data->key_hex, MAX_LINE_LENGTH);
  printf("  Nonce: ");
  print_limited(data->nonce_hex, MAX_LINE_LENGTH);
  if (data->header_hex) {
    printf("  Hlavicka: ");
    print_limited(data->header_hex, MAX_LINE_LENGTH);
  }
  printf("  Plaintext (pre sifrovanie): ");
  print_limited(data->pt_hex, MAX_LINE_LENGTH);
  printf("  Ciphertext (pre desifrovanie): ");
  print_limited(data->ct_hex, MAX_LINE_LENGTH);

  // Vykonáme test šifrovania aj dešifrovania
  // 1. Test šifrovania
  printf("\nTest sifrovania:\n");
  if (data->pt_hex) {

    uint8_t *result_ct = calloc(lens[3] + 1, 1);
    uint8_t *result_tag = calloc(lens[5] + 1, 1);

    if (!result_ct || !result_tag) {
      free(result_ct);
      free(result_tag);
      goto cleanup;
    }

    AES_EAX_encrypt(bufs[0], bufs[1], bufs[3], lens[3], bufs[2], lens[2],
                    result_ct, result_tag);

    // Vypíš očakávané hodnoty samostatne
    if (data->ct_hex) {
      printf("  Ocakavany ciphertext: ");
      print_limited(data->ct_hex, MAX_LINE_LENGTH);
    }
    printf("  Ocakavany tag: ");
    print_limited(data->tag_hex, MAX_LINE_LENGTH);

    // Vypočítaný ciphertext || tag vypíš spoločne
    char *result_combined_hex = calloc((lens[3] + lens[5]) * 2 + 1, 1);
    if (result_combined_hex) {
      // Konverzia ciphertext na hex
      for (size_t i = 0; i < lens[3]; i++) {
        sprintf(result_combined_hex + (i * 2), "%02x", result_ct[i]);
      }

      // Konverzia tag na hex a pridanie za ciphertext
      for (size_t i = 0; i < lens[5]; i++) {
        sprintf(result_combined_hex + (lens[3] * 2) + (i * 2), "%02x",
                result_tag[i]);
      }

      printf("  Vypocitany ciphertext || tag: ");
      print_limited(result_combined_hex, MAX_LINE_LENGTH);
      free(result_combined_hex);
    }

    bool tag_match = (memcmp(result_tag, bufs[5], lens[5]) == 0);
    bool ct_match = (!data->ct_hex || lens[4] == 0 ||
                     memcmp(result_ct, bufs[4], lens[4]) == 0);
    bool ok = tag_match && ct_match;

    if (ok)
      (*passed_encrypt)++;
    printf("  Vysledok sifrovania: %s\n\n", ok ? "USPESNY" : "NEUSPESNY");

    free(result_ct);
    free(result_tag);
  } else {
    printf("  (Ziadny plaintext na zasifrovanie)\n\n");
  }

  // 2. Test dešifrovania
  printf("Test desifrovania:\n");
  if (data->ct_hex) {
    printf("  Tag: ");
    print_limited(data->tag_hex, MAX_LINE_LENGTH);

    uint8_t *combined_ct_tag = calloc(lens[4] + lens[5], 1);
    uint8_t *decrypted = calloc(lens[4] + 1, 1);

    if (!combined_ct_tag || !decrypted) {
      free(combined_ct_tag);
      free(decrypted);
      goto cleanup;
    }

    memcpy(combined_ct_tag, bufs[4], lens[4]);
    memcpy(combined_ct_tag + lens[4], bufs[5], lens[5]);

    int decrypt_stav =
        AES_EAX_decrypt(bufs[0], bufs[1], combined_ct_tag, lens[4],
                        bufs[2], lens[2], lens[5], decrypted);
    printf("  Ocakavany stav desifrovania: %s\n",
           data->should_fail ? "ZLYHANIE (Tag neplatny)"
                             : "USPESNE (Tag platny)");

    printf("  Skutocny stav desifrovania: %s\n",
           decrypt_stav == 0 ? "USPSNE (Tag platny)"
                             : "ZLYHANIE (Tag neplatny)");

    if (decrypt_stav == 0 && data->pt_hex) {
      printf("  Ocakavany plaintext: ");
      print_hex(bufs[3], lens[3]);
      printf("  Vypocitany plaintext: ");
      print_hex(decrypted, lens[3]);
    }

    bool ok = data->should_fail
                  ? (decrypt_stav != 0)
                  : (decrypt_stav == 0 &&
                     (!data->pt_hex ||
                      memcmp(decrypted, bufs[3], lens[3]) == 0));

    if (ok)
      (*passed_decrypt)++;
    printf("  Vysledok desifrovania: %s\n\n",
           ok ? "USPESNY" : "NEUSPESNY");

    free(combined_ct_tag);
    free(decrypted);
  } else {
    printf("  (Ziadny ciphertext na desifrovanie)\n\n");
  }

cleanup:
  for (int i = 0; i < 6; i++) {
    free(bufs[i]);
  }
  return true;
}

int main() {
  const char *test_vectors_file;
  test_vectors_file = "test_vectors/eax_128.txt";
  printf("AES-128 EAX Test\n");

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

  // Odstránená nepoužitá premenná total_passed
  bool success =
      (processed_tests > 0 &&
       tests_passed_encrypt + tests_passed_decrypt == processed_tests * 2);

  printf("\nCelkove vysledky:\n");
  printf("Spracovanych testov: %d\n", processed_tests);
  printf("Uspesnych testov sifrovania: %d\n", tests_passed_encrypt);
  printf("Uspesnych testov desifrovania: %d\n", tests_passed_decrypt);
  printf("Celkovy vysledok: %s\n", success ? "USPESNY" : "NEUSPESNY");

  return success ? 0 : 1;
}