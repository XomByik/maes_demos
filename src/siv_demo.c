#include "../header_files/siv_config.h"

typedef enum {
  KEY_T,
  AD_T,
  PT_T,
  CT_T,
  CMAC_T,
  IV_C_T,
  COUNT_T,
  FAIL_T
} LineType;

static LineType get_line_type(const char *line) {
  if (strstr(line, "Key:") || strstr(line, "Key = "))
    return KEY_T;
  if (strstr(line, "AD:") || strstr(line, "AD = "))
    return AD_T;
  if (strstr(line, "Plaintext:") || strstr(line, "Plaintext = "))
    return PT_T;
  if (strstr(line, "Ciphertext:") || strstr(line, "Ciphertext = "))
    return CT_T;
  if (strstr(line, "CMAC(final):"))
    return CMAC_T;
  if (strstr(line, "IV || C:"))
    return IV_C_T;
  if (strstr(line, "Count = "))
    return COUNT_T;
  if (strstr(line, "FAIL"))
    return FAIL_T;
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
  free(data->hex_key);
  free(data->hex_ad);
  free(data->hex_plaintext);
  free(data->hex_expected_iv);
  free(data->hex_expected_ct);
  memset(data, 0, sizeof(TestCaseData));
}

bool parse_next_test_case(FILE *fp, TestCaseData *data) {
  char line[SIV_LINE_BUFFER_SIZE];
  char *value;
  bool in_test_case = false;
  long start_pos = ftell(fp);
  bool fail_tag_seen = false;

  free_test_case_data(data);
  data->is_decrypt = false;
  data->count = 0; // Default test case count

  while (fgets(line, sizeof(line), fp)) {
    char *trimmed = trim(line);
    if (!trimmed || strlen(trimmed) == 0) {
      continue;
    }

    if (strstr(trimmed, "Input:")) {
      if (in_test_case) {
        fseek(fp, start_pos, SEEK_SET);
        data->should_fail = fail_tag_seen;
        return true;
      }
      in_test_case = true;
      continue;
    }

    if (strstr(trimmed, "Output:")) {
      continue;
    }

    LineType type = get_line_type(trimmed);
    value = NULL;

    switch (type) {
    case COUNT_T:
      value = get_line_value(trimmed, "Count = ");
      data->count = atoi(value);
      free(value);
      break;

    case KEY_T:
      value = get_line_value(trimmed, "Key:");
      if (!value)
        value = get_line_value(trimmed, "Key = ");
      if (!data->hex_key)
        data->hex_key = value;
      else
        free(value);
      break;

    case AD_T:
      value = get_line_value(trimmed, "AD:");
      if (!value)
        value = get_line_value(trimmed, "AD = ");
      if (!data->hex_ad)
        data->hex_ad = value;
      else
        free(value);
      break;

    case PT_T:
      value = get_line_value(trimmed, "Plaintext:");
      if (!value)
        value = get_line_value(trimmed, "Plaintext = ");
      if (!data->hex_plaintext)
        data->hex_plaintext = value;
      else
        free(value);
      break;

    case CT_T:
      value = get_line_value(trimmed, "Ciphertext:");
      if (!value)
        value = get_line_value(trimmed, "Ciphertext = ");
      if (!data->hex_expected_ct)
        data->hex_expected_ct = value;
      else
        free(value);
      break;

    case CMAC_T:
      value = get_line_value(trimmed, "CMAC(final):");
      if (!data->hex_expected_iv)
        data->hex_expected_iv = value;
      else
        free(value);
      break;

    case FAIL_T:
      fail_tag_seen = true;
      break;

    default:
      // Ignorujeme nepodporovane typy riadkov
      break;
    }
    start_pos = ftell(fp);
  }

  // Ak sme nacitali aspon kluc a plaintext, povazujeme to za platny test
  if (in_test_case && data->hex_key && data->hex_plaintext) {
    data->should_fail = fail_tag_seen;
    return true;
  }
  return false;
}

bool process_test_case(const TestCaseData *data, int *passed_encrypt,
                       int *passed_decrypt) {
  if (!data->hex_key || !data->hex_expected_iv || !data->hex_plaintext ||
      !data->hex_expected_ct) {
    printf("Nekompletne testovacie data\n");
    return false;
  }

  size_t lens[] = {
      strlen(data->hex_key) /
          2, // Kluc (pozor: v SIV musi byt dvojnasobnej dlzky oproti AES)
      strlen(data->hex_expected_iv) / 2,
      data->hex_ad ? strlen(data->hex_ad) / 2 : 0,
      data->hex_plaintext ? strlen(data->hex_plaintext) / 2 : 0,
      data->hex_expected_ct ? strlen(data->hex_expected_ct) / 2 : 0,
      SIV_TAG_LEN};

  // SIV ocakava dvojnasobnu dlzku kluca pre sifrovanie aj autentifikaciu
  if (lens[0] != 2 * (AES_KEY_SIZE)) {
    printf("Chyba: Nespravna dlzka kluca pre SIV rezim. Ocakavana dlzka: "
           "%d bajtov (dvojnasobok AES kluca)\n",
           2 * AES_KEY_SIZE);
    return false;
  }

  uint8_t *bufs[] = {
      calloc(lens[0] + 1,
             1), // kluc (dvojnasobna dlzka oproti standardnemu AES)
      calloc(lens[1] + 1, 1), // ocakavany IV
      calloc(lens[2] + 1, 1), // additional data
      calloc(lens[3] + 1, 1), // plaintext
      calloc(lens[4] + 1, 1), // ocakavany ciphertext
      calloc(lens[5] + 1, 1)  // nie je pouzity v SIV
  };

  // Vytvorime pomocne buffer pre nase vysledky
  uint8_t *actual_iv = calloc(SIV_TAG_LEN, 1);
  uint8_t *actual_ct = calloc(lens[3] + 1, 1);
  uint8_t *decrypted_pt = calloc(lens[4] + 1, 1);

  if (!actual_iv || !actual_ct || !decrypted_pt)
    goto cleanup;

  // Kontrola alokacie
  for (int i = 0; i < 6; i++) {
    if (!bufs[i])
      goto cleanup;
  }

  // Konverzia hex retazcov na binarne data
  const char *hexs[] = {data->hex_key,         data->hex_expected_iv,
                        data->hex_ad,          data->hex_plaintext,
                        data->hex_expected_ct, NULL};

  for (int i = 0; i < 5; i++) {
    if (hexs[i] && hex_to_bin(hexs[i], bufs[i], lens[i]) != 0)
      goto cleanup;
  }

  printf("=== Test #%d ===\n", data->count);
  printf("Vstupne data:\n");
  printf("  Kluc (%zu bajtov - dvojnasobna dlzka kluca pre SIV): ",
         lens[0]);
  print_limited(data->hex_key, 75);
  if (data->hex_ad) {
    printf("  Associated Data (AD): ");
    print_limited(data->hex_ad, 75);
  }
  printf("  Plaintext: ");
  print_limited(data->hex_plaintext ? data->hex_plaintext : "(prazdny)",
                75);

  // Test sifrovania (encrypt)
  printf("\nTest sifrovania:\n");

  // Pouzijeme lokalny IV buffer, pretoze funkcia ocakava pole nie pointer
  uint8_t iv_buffer[16] = {0};
  AES_SIV_encrypt(bufs[0], bufs[3], lens[3], bufs[2], lens[2], iv_buffer,
                  actual_ct);
  // Skopirujeme vysledok pre porovnanie
  memcpy(actual_iv, iv_buffer, 16);

  // Vypiseme vysledky sifrovania
  printf("  Vypocitany IV (CMAC): ");
  print_hex(actual_iv, lens[1]);
  printf("  Ocakavany IV (CMAC): ");
  print_hex(bufs[1], lens[1]);

  printf("  Vypocitany ciphertext: ");
  print_hex(actual_ct, lens[3]);
  printf("  Ocakavany ciphertext: ");
  print_hex(bufs[4], lens[4]);

  bool iv_match = (memcmp(actual_iv, bufs[1], lens[1]) == 0);
  bool ct_match = (memcmp(actual_ct, bufs[4], lens[4]) == 0);
  bool encrypt_ok = iv_match && ct_match;

  if (encrypt_ok)
    (*passed_encrypt)++;
  printf("  Vysledok sifrovania: %s\n",
         encrypt_ok ? "USPESNY" : "NEUSPESNY");

  // Test desifrovania (decrypt)
  printf("\nTest desifrovania:\n");

  uint8_t decrypt_status = AES_SIV_decrypt(
      bufs[0], bufs[1], bufs[4], lens[4], bufs[2], lens[2], decrypted_pt);

  bool auth_ok = (decrypt_status == 0);
  bool decrypt_match =
      auth_ok && (memcmp(decrypted_pt, bufs[3], lens[3]) == 0);

  printf("  Autentifikacia: %s\n", auth_ok ? "USPESNA" : "NEUSPESNA");

  if (auth_ok) {
    printf("  Vypocitany plaintext: ");
    print_hex(decrypted_pt, lens[3]);
    printf("  Ocakavany plaintext: ");
    print_hex(bufs[3], lens[3]);
  } else {
    printf("  Plaintext nedostupny (zlyhala autentifikacia)\n");
  }

  printf("  Vysledok desifrovania: %s\n\n",
         decrypt_match ? "USPESNY" : "NEUSPESNY");

  if (decrypt_match)
    (*passed_decrypt)++;

cleanup:
  for (int i = 0; i < 6; i++) {
    free(bufs[i]);
  }
  free(actual_iv);
  free(actual_ct);
  free(decrypted_pt);
  return true;
}

int main() {

  const char *test_vectors_file = "test_vectors/siv_128.txt";
#if AES___ == 128
  printf("AES-256-SIV Test (pouziva kluc dlhy %d bajtov)\n",
         2 * AES_KEY_SIZE);
#elif AES___ == 192
  test_vectors_file = "test_vectors/siv_192.txt";
  printf("AES-192-SIV Test (pouziva kluc dlhy %d bajtov)\n",
         2 * AES_KEY_SIZE);
#elif AES___ == 256
  test_vectors_file = "test_vectors/siv_256.txt";
  printf("AES-128-SIV Test (pouziva kluc dlhy %d bajtov)\n",
         2 * AES_KEY_SIZE);
#endif

  printf("Pouziva sa testovaci subor: %s\n", test_vectors_file);

  FILE *fp = fopen(test_vectors_file, "r");
  int tests_passed_encrypt = 0;
  int tests_passed_decrypt = 0;
  TestCaseData current_test = {0};
  int processed_tests = 0;

  if (!fp) {
    perror("Nepodarilo sa otvorit subor s testovacimi vektormi");
    return 1;
  }

  while (parse_next_test_case(fp, &current_test)) {
    processed_tests++;
    process_test_case(&current_test, &tests_passed_encrypt,
                      &tests_passed_decrypt);
    free_test_case_data(&current_test);
  }

  fclose(fp);

  if (processed_tests == 0) {
    printf("Zo suboru neboli nacitane ziadne testovacie pripady\n");
    return 1;
  }

  int total_passed = tests_passed_encrypt + tests_passed_decrypt;
  int total_tests =
      processed_tests * 2; // 1 sifrovanie + 1 desifrovanie pre kazdy test
  bool success = (processed_tests > 0 && total_passed == total_tests);

  printf("\nCelkove vysledky:\n");
  printf("Spracovanych testov: %d\n", processed_tests);
  printf("Uspesnych testov sifrovania: %d/%d\n", tests_passed_encrypt,
         processed_tests);
  printf("Uspesnych testov desifrovania: %d/%d\n", tests_passed_decrypt,
         processed_tests);
  printf("Celkovy vysledok: %s\n", success ? "USPESNY" : "NEUSPESNY");

  return success ? 0 : 1;
}