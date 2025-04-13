#include "../header_files/common.h"

int hex_to_bin(const char *hex, uint8_t *bin, size_t bin_len) {
  if (hex == NULL || bin == NULL) {
    // Silently return on NULL pointers
    return -1;
  }

  size_t hex_len = strlen(hex);

  // Check if hex string length is exactly double the binary length
  // Allow empty string only if bin_len is also 0
  if (hex_len != bin_len * 2) {
    if (!(bin_len == 0 && hex_len == 0)) {
      // Silently return on length mismatch
      return -1;
    }
  }

  // Handle the case of zero length correctly
  if (bin_len == 0) {
    return 0; // Nothing to convert, success
  }

  for (size_t i = 0; i < bin_len; ++i) {
    // Ensure the characters being read are valid hex digits
    if (!isxdigit((unsigned char)hex[i * 2]) ||
        !isxdigit((unsigned char)hex[i * 2 + 1])) {
      // Silently return on invalid character
      return -1;
    }
    // Use %x with unsigned int
    unsigned int byte_val;
    if (sscanf(hex + i * 2, "%2x", &byte_val) != 1) {
      // Silently return on sscanf failure
      return -1;
    }
    // Check if the parsed value fits into uint8_t
    if (byte_val > 0xFF) {
      // Silently return on value out of range
      return -1;
    }
    bin[i] = (uint8_t)byte_val;
  }
  return 0; // Indicate success
}

void print_hex(const uint8_t *data, size_t len) {
  for (size_t i = 0; i < len; i++) {
    printf("%02x", data[i]);
  }
  printf("\n");
}

char *trim(char *str) {
  if (str == NULL) {
    return NULL;
  }
  char *end;

  // Trim leading space
  while (isspace((unsigned char)*str))
    str++;

  if (*str == 0) // All spaces?
    return str;

  // Trim trailing space
  end = str + strlen(str) - 1;
  while (end > str && isspace((unsigned char)*end))
    end--;

  // Write new null terminator character
  *(end + 1) = '\0';

  return str;
}

void print_limited(const char *data, size_t limit) {
  if (!data) {
    printf("(null)\n");
    return;
  }
  if (strlen(data) > limit) {
    // Print the first 'limit' characters followed by "..."
    printf("%.*s...\n", (int)limit, data);
  } else {
    printf("%s\n", data);
  }
}