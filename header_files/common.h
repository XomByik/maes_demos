/************************************************************************
 * Nazov projektu: Demonštracia funkcnosti rezimov AES-u z kniznice micro-AES
 * -----------------------------------------------------------------------
 * Subor: common.h
 * Verzia: 1.1
 * Datum: 13.4.2025
 *
 * Autor: Kamil Berecky
 *
 * Popis: Hlavickovy subor so spolocnymi funkciami a konstantami pouzitymi
 * napriec demonstracnymi programami pre jednotlive AES rezimy. Obsahuje
 * funkcie pre konverziu medzi hexadecimalnymi retazcami a binarnymi datami,
 * zobrazovanie hodnot, a pomocne funkcie pre pracu s retazcami.
 * 
 * Pre viac info pozri README.md
 ***********************************************************************/

 #ifndef COMMON_H
 #define COMMON_H
 
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <stdint.h>
 #include <stdbool.h>
 #include <ctype.h>
 
 // Makra pre navratove kody
 #define COMMON_SUCCESS 0              // Navratovy kod pre uspesne vykonanie operacie
 #define COMMON_ERROR_GENERAL -1       // Vseobecny kod pre chybu
 #define COMMON_ERROR_NULL_POINTER -2  // Chyba - nulovy pointer
 #define COMMON_ERROR_INVALID_LENGTH -3 // Chyba - neplatna dlzka
 #define COMMON_ERROR_INVALID_CHAR -4  // Chyba - neplatny znak
 #define COMMON_ERROR_PARSE_FAIL -5    // Chyba - zlyhanie spracovania
 #define COMMON_ERROR_VALUE_RANGE -6   // Chyba - hodnota mimo rozsahu
 
 // Konstanty pre funkcne limity
 #define COMMON_MAX_PRINT_LENGTH 256   // Maximalna dlzka pre vypis retazcov

 // Deklaracie funkcii
 int hex_to_bin(const char *hex, uint8_t *bin, size_t bin_len);
 void print_hex(const uint8_t *data, size_t len);
 char *trim(char *str);
 void print_limited(const char *data, size_t limit);
 
 #endif // COMMON_H