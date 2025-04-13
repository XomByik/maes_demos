// filepath: /home/xombyik/maes_demos/common.h
#ifndef COMMON_H
#define COMMON_H

#define _GNU_SOURCE
#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


// Function declarations
int hex_to_bin(const char *hex, uint8_t *bin, size_t bin_len);
void print_hex(const uint8_t *data, size_t len);
char *trim(char *str);
void print_limited(const char *data,
                   size_t limit); // Ensure this declaration exists

#endif // COMMON_H