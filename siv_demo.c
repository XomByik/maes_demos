#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include "libs/micro_aes.h"

#define SIV_TAG_LEN 16

// Helper function to convert hex string to binary data
// Returns 0 on success, -1 on error (invalid format or length)
int hex_to_bin(const char *hex, uint8_t *bin, size_t bin_len) {
    if (hex == NULL || bin == NULL) {
         fprintf(stderr, "Error: NULL pointer passed to hex_to_bin.\n");
         return -1;
    }
    size_t hex_len = strlen(hex);
    // Check if hex string length is exactly double the binary length
    if (hex_len != bin_len * 2) {
        // Allow empty string if bin_len is 0
        if (!(bin_len == 0 && hex_len == 0)) {
             fprintf(stderr, "Error: Hex string length (%zu) must be (%zu), double the expected binary length (%zu).\n", hex_len, bin_len*2, bin_len);
             return -1;
        }
    }
    if (bin_len == 0) {
        return 0; // Nothing to convert
    }

    for (size_t i = 0; i < bin_len; ++i) {
        // Ensure the characters being read are valid hex digits
        if (!isxdigit((unsigned char)hex[i * 2]) || !isxdigit((unsigned char)hex[i * 2 + 1])) {
             fprintf(stderr, "Error: Invalid non-hex character encountered in string '%s' at index %zu.\n", hex, i*2);
             return -1;
        }
        unsigned int byte_val;
        if (sscanf(hex + i * 2, "%2x", &byte_val) != 1) {
             fprintf(stderr, "Error: sscanf failed to parse hex byte from '%s' at index %zu.\n", hex, i*2);
             return -1; // Should not happen if isxdigit passed, but check anyway
        }
        bin[i] = (uint8_t)byte_val; // Cast to uint8_t
    }
    return 0; // Indicate success
}

static void bytesToHex(const uint8_t *bytes, size_t len, char *hex) {
    if (bytes == NULL || hex == NULL) return;
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + i * 2, "%02x", bytes[i]);
    }
    hex[len * 2] = '\0';
}

static int compareAndPrintHex(const char *title, const uint8_t *expected, const uint8_t *actual, size_t len) {
    if (len == 0) {
        printf("  %s: (prazdne)\n", title);
        return 1;
    }
    if (expected == NULL || actual == NULL) {
        printf("  %s: Chyba - NULL buffer\n", title);
        return 0;
    }

    char *expected_hex = malloc(len * 2 + 1);
    char *actual_hex = malloc(len * 2 + 1);
    if (!expected_hex || !actual_hex) {
        fprintf(stderr, "Chyba alokacie pamate pre hex retazce\n");
        free(expected_hex);
        free(actual_hex);
        return 0;
    }

    bytesToHex(expected, len, expected_hex);
    bytesToHex(actual, len, actual_hex);

    int match = (memcmp(expected, actual, len) == 0);

    printf("  %s:\n", title);
    printf("    Ocakavany : %s (%zu bajtov)\n", expected_hex, len);
    printf("    Vypocitany: %s (%zu bajtov)\n", actual_hex, len);
    printf("    Zhoda     : %s\n", match ? "ANO" : "NIE");

    free(expected_hex);
    free(actual_hex);
    return match;
}

typedef struct {
    const char *key_hex;
    const char *ad_hex;
    const char *plaintext_hex;
    const char *expected_iv_hex;
    const char *expected_c_hex;
} SIV_Test_Vector;

static int run_siv_test(const SIV_Test_Vector *vector) {

    size_t key_hex_len = strlen(vector->key_hex);
    size_t key_len = key_hex_len / 2;
    size_t ad_len = vector->ad_hex ? strlen(vector->ad_hex) / 2 : 0;
    size_t p_len = vector->plaintext_hex ? strlen(vector->plaintext_hex) / 2 : 0;
    size_t expected_iv_len = vector->expected_iv_hex ? strlen(vector->expected_iv_hex) / 2 : 0;
    size_t expected_c_len = vector->expected_c_hex ? strlen(vector->expected_c_hex) / 2 : 0;

    if (key_len != 32) {
        printf("Chyba: Neplatna dlzka kluca (%zu bajtov, ocakava sa 32 pre AES-256)\n", key_len);
        return 0;
    }
    if (expected_iv_len != SIV_TAG_LEN) {
         printf("Chyba: Očakavana dlzka IV/Tagu (%zu) nie je %d bajtov\n", expected_iv_len, SIV_TAG_LEN);
         return 0;
    }

    uint8_t *key = malloc(key_len);
    uint8_t *aData = ad_len > 0 ? malloc(ad_len) : NULL;
    uint8_t *p_data = p_len > 0 ? malloc(p_len) : NULL;
    uint8_t *expected_iv = malloc(expected_iv_len);
    uint8_t *expected_c = expected_c_len > 0 ? malloc(expected_c_len) : NULL;
    uint8_t *actual_iv = malloc(SIV_TAG_LEN);
    uint8_t *actual_c = p_len > 0 ? malloc(p_len) : NULL;
    uint8_t *decrypted_p = p_len > 0 ? malloc(p_len) : NULL;

    if (!key || (ad_len > 0 && !aData) || (p_len > 0 && !p_data) || !expected_iv || (expected_c_len > 0 && !expected_c) || !actual_iv || (p_len > 0 && !actual_c) || (p_len > 0 && !decrypted_p)) {
        printf("Chyba: Alokacia pamate zlyhala\n");
        free(key); free(aData); free(p_data); free(expected_iv); free(expected_c);
        free(actual_iv); free(actual_c); free(decrypted_p);
        return 0;
    }

    if (hex_to_bin(vector->key_hex, key, key_len) != 0) {
        free(key); free(aData); free(p_data); free(expected_iv); free(expected_c);
        free(actual_iv); free(actual_c); free(decrypted_p);
        return 0;
    }
    if (ad_len > 0 && hex_to_bin(vector->ad_hex, aData, ad_len) != 0) {
        free(key); free(aData); free(p_data); free(expected_iv); free(expected_c);
        free(actual_iv); free(actual_c); free(decrypted_p);
        return 0;
    }
    if (p_len > 0 && hex_to_bin(vector->plaintext_hex, p_data, p_len) != 0) {
        free(key); free(aData); free(p_data); free(expected_iv); free(expected_c);
        free(actual_iv); free(actual_c); free(decrypted_p);
        return 0;
    }
    if (expected_iv_len > 0 && hex_to_bin(vector->expected_iv_hex, expected_iv, expected_iv_len) != 0) {
        free(key); free(aData); free(p_data); free(expected_iv); free(expected_c);
        free(actual_iv); free(actual_c); free(decrypted_p);
        return 0;
    }
    if (expected_c_len > 0 && hex_to_bin(vector->expected_c_hex, expected_c, expected_c_len) != 0) {
        free(key); free(aData); free(p_data); free(expected_iv); free(expected_c);
        free(actual_iv); free(actual_c); free(decrypted_p);
        return 0;
    }

    printf("Vstupy:\n");
    char *temp_hex = malloc(key_len * 2 + 1);
    if (temp_hex) {
        bytesToHex(key, key_len, temp_hex);
        printf("  Kluc      : %s (%zu bajtov)\n", temp_hex, key_len);
        free(temp_hex);
    }
    temp_hex = ad_len > 0 ? malloc(ad_len * 2 + 1) : NULL;
    if (temp_hex) {
        bytesToHex(aData, ad_len, temp_hex);
        printf("  AD        : %s (%zu bajtov)\n", temp_hex, ad_len);
        free(temp_hex);
    } else {
        printf("  AD        : (prazdne) (0 bajtov)\n");
    }
    temp_hex = p_len > 0 ? malloc(p_len * 2 + 1) : NULL;
     if (temp_hex) {
        bytesToHex(p_data, p_len, temp_hex);
        printf("  Plaintext : %s (%zu bajtov)\n", temp_hex, p_len);
        free(temp_hex);
    } else {
        printf("  Plaintext : (prazdne) (0 bajtov)\n");
    }

    AES_SIV_encrypt(key, p_data, p_len, aData, ad_len, actual_iv, actual_c);

    printf("\nVystupy (Sifrovanie):\n");
    int iv_match = compareAndPrintHex("CMAC (IV)", expected_iv, actual_iv, SIV_TAG_LEN);
    int c_match = 1;
    if (p_len > 0) {
         if (expected_c_len != p_len) {
             printf("  Ciphertext:\n");
             printf("    Chyba: Ocakavana dlzka (%zu) sa lisi od dlzky plaintextu (%zu)\n", expected_c_len, p_len);
             c_match = 0;
         } else {
            c_match = compareAndPrintHex("Ciphertext", expected_c, actual_c, p_len);
         }
    } else {
         if (expected_c_len != 0) {
             printf("  Ciphertext: Varovanie - Plaintext prazdny, ocakavany ciphertext nie (%zu bajtov)\n", expected_c_len);
         } else {
             printf("  Ciphertext: (prazdne)\n");
         }
    }

    int enc_match = iv_match && c_match;

    printf("\nVystupy (Desifrovanie):\n");
    char dec_status = AES_SIV_decrypt(key, expected_iv, expected_c, expected_c_len, aData, ad_len, decrypted_p);

    int dec_match = 0;
    if (dec_status == 0) {
        printf("  Autentifikacia: USPESNA (Tag overeny)\n");
        if (p_len > 0) {
            dec_match = compareAndPrintHex("Plaintext", p_data, decrypted_p, p_len);
        } else {
             printf("  Plaintext: (prazdne)\n");
             dec_match = 1;
        }
    } else {
        printf("  Autentifikacia: NEUSPESNA (Nezhoda tagu alebo ina chyba, status: %d)\n", dec_status);
        printf("  Plaintext:\n");
        char *expected_p_hex = p_len > 0 ? malloc(p_len * 2 + 1) : NULL;
        if(expected_p_hex) {
           bytesToHex(p_data, p_len, expected_p_hex);
           printf("    Ocakavanie : %s (%zu bajtov)\n", expected_p_hex, p_len);
           free(expected_p_hex);
        } else if (p_len == 0) {
            printf("    Ocakavany : (prazdne) (0 bajtov)\n");
        } else {
            printf("    Ocakavany : (chyba alokacie)\n");
        }
        printf("    Vypocitane: (nedostupne kvoli chybe autentifikacie)\n");
        printf("    Zhoda     : NIE\n");
    }

    free(key); free(aData); free(p_data); free(expected_iv); free(expected_c);
    free(actual_iv); free(actual_c); free(decrypted_p);

    int overall_success = enc_match && dec_match;
    printf("\nCelkovy vysledok testu: %s\n", overall_success ? "USPESNY" : "NEUSPESNY");
    printf("-------------------------------------\n");
    return overall_success;
}

int main(void) {
    int passed_count = 0;

    printf("AES-SIV-CMAC-256 Demo\n");
    printf("===========================================\n");

    SIV_Test_Vector vector_a1 = {
        .key_hex = "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        .ad_hex = "101112131415161718191a1b1c1d1e1f2021222324252627",
        .plaintext_hex = "112233445566778899aabbccddee",
        .expected_iv_hex = "85632d07c6e8f37f950acd320a2ecc93",
        .expected_c_hex = "40c02b9690c4dc04daef7f6afe5c"
    };

    int result = run_siv_test(&vector_a1);

    if (result) {
        passed_count++;
    }

    return (passed_count == 1) ? 0 : 1;
}