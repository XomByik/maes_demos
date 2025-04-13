/************************************************************************
 * Nazov projektu: Demonštracia funkcnosti rezimov AES-u z kniznice micro-AES
 * -----------------------------------------------------------------------
 * Subor: common.c
 * Verzia: 1.1
 * Datum: 13.4.2025
 *
 * Autor: Kamil Berecky
 *
 * Popis: Implementacia spolocnych funkcii definovanych v common.h.
 * Obsahuje funkcie pre konverziu medzi hexadecimalnymi retazcami a binarnymi
 * datami, zobrazovanie hodnot, a pomocne funkcie pre pracu s retazcami.
 * 
 * Pre viac info pozri README.md
 ***********************************************************************/

 #include "../header_files/common.h"

 /**
  * Konvertuje hexadecimalny retazec na binarne data
  *
  * Popis: Funkcia prevadza hexadecimalny retazec na pole binarnych dat.
  * Hexadecimalne znaky musia byt v ASCII formate, kde pre kazdy bajt
  * su pouzite dva hexadecimalne znaky.
  *
  * Proces:
  * 1. Kontrola platnosti vstupnych parametrov (NULL pointery, dlzka)
  * 2. Konverzia hexa parov na jednotlive bajty
  * 3. Validacia hodnot a rozsahu
  *
  * Parametre:
  * @param hex - Vstupny hexadecimalny retazec, ukonceny nulou
  * @param bin - Vystupny buffer pre binarne data
  * @param bin_len - Ocakavana velkost vystupnych binarnych dat v bajtoch
  *
  * Navratova hodnota:
  * @return int - 0 pri uspesnej konverzii, nenulova hodnota pri chybe
  */
 int hex_to_bin(const char *hex, uint8_t *bin, size_t bin_len) {
   // Kontrola platnosti vstupnych parametrov
   if (hex == NULL || bin == NULL) {
     return COMMON_ERROR_NULL_POINTER;  // Chyba - NULL pointer
   }
 
   // Zistenie dlzky vstupneho hex retazca
   size_t hex_len = strlen(hex);  // Dlzka hex retazca v znakoch
 
   // Kontrola zhody dlzky hex retazca s ocakavanou velkostou binarnych dat
   // (Kazdy bajt vyzaduje dva hex znaky)
   if (hex_len != bin_len * 2) {
     // Specialny pripad: prazdny retazec na prazdny vystup
     if (!(bin_len == 0 && hex_len == 0)) {
       return COMMON_ERROR_INVALID_LENGTH;  // Chyba - nezhoda dlzky
     }
   }
 
   // Specialne spracovanie prazdneho retazca
   if (bin_len == 0) {
     return COMMON_SUCCESS;  // Uspech - nie je co konvertovat
   }
 
   // Konverzia po dvojiciach hex znakov na binarne bajty
   for (size_t i = 0; i < bin_len; ++i) {
     // Kontrola platnosti hex znakov (musia byt v rozsahu 0-9, A-F, a-f)
     if (!isxdigit((unsigned char)hex[i * 2]) ||
         !isxdigit((unsigned char)hex[i * 2 + 1])) {
       return COMMON_ERROR_INVALID_CHAR;  // Chyba - neplatny hex znak
     }
     
     // Konverzia hex retazca na ciselnu hodnotu
     unsigned int byte_val;  // Docasna premenna pre nacitanu hodnotu
     if (sscanf(hex + i * 2, "%2x", &byte_val) != 1) {
       return COMMON_ERROR_PARSE_FAIL;  // Chyba - zlyhanie spracovania
     }
     
     // Kontrola rozsahu hodnoty (musi sa zmestit do 8 bitov)
     if (byte_val > 0xFF) {
       return COMMON_ERROR_VALUE_RANGE;  // Chyba - hodnota mimo rozsahu
     }
     
     // Ulozenie skonvertovanej hodnoty do vystupneho buffera
     bin[i] = (uint8_t)byte_val;
   }
   
   return COMMON_SUCCESS;  // Uspesne dokoncenie konverzie
 }
 
 /**
  * Zobrazi binarne data v hexadecimalnom formate
  * 
  * Popis: Funkcia vypisuje binarne data ako hexadecimalny retazec
  * so standardnym formatovanim - dva znaky na bajt bez oddelovacov,
  * malymi pismenami. Na konci vypisu je automaticky pridany znak 
  * noveho riadku.
  *
  * Parametre:
  * @param data - Pole binarnych dat na zobrazenie
  * @param len - Dlzka dat v bajtoch
  */
 void print_hex(const uint8_t *data, size_t len) {
   // Kontrola platnosti vstupneho parametra
   if (data == NULL) {
     printf("(null)\n");  // Vypis informacie o NULL pointeri
     return;  // Ukoncenie funkcie
   }
   
   // Vypis jednotlivych bajtov v hex formate
   for (size_t i = 0; i < len; i++) {
     printf("%02x", data[i]);  // Vypis v hex formate (02 = 2 znaky s nulami na zaciatku)
   }
   
   printf("\n");  // Ukoncenie riadku po vypise vsetkych dat
 }
 
 /**
  * Odstrani biele znaky zo zaciatku a konca retazca
  *
  * Popis: Funkcia odstranuje biele znaky (medzery, tabulatory, znaky
  * noveho riadku) zo zaciatku a konca retazca. Modifikuje povodny retazec.
  *
  * Parametre:
  * @param str - Vstupny retazec na upravenie
  *
  * Navratova hodnota:
  * @return char* - Pointer na zaciatok upraveneho retazca (v ramci povodneho buffera)
  */
 char *trim(char *str) {
   // Kontrola platnosti vstupneho parametra
   if (str == NULL) {
     return NULL;  // Vrati NULL ak vstup je NULL
   }
   
   char *end;  // Pointer na koniec retazca
   
   // Odstranenie bielych znakov zo zaciatku retazca
   while (isspace((unsigned char)*str)) {
     str++;  // Posun pointera za biele znaky
   }
   
   // Ak po odstraneni zostal prazdny retazec, vratime ho bez dalsej upravy
   if (*str == 0) {
     return str;  // Vsetko boli medzery, vrat prazdny retazec
   }
   
   // Odstranenie bielych znakov z konca retazca
   end = str + strlen(str) - 1;  // Nastav pointer na posledny znak
   while (end > str && isspace((unsigned char)*end)) {
     end--;  // Posun pointer pred biele znaky
   }
   
   // Pridanie ukoncovacieho nuloveho znaku za posledny nebielny znak
   *(end + 1) = '\0';  // Ukoncenie retazca
   
   return str;  // Vratenie upraveneho retazca
 }
 
 /**
  * Zobrazi retazec s obmedzenim dlzky
  *
  * Popis: Funkcia zobrazuje retazec, ale ak je dlhsi ako stanoveny limit,
  * zobrazi len cast retazca nasledovanym "...". 
  *
  * Parametre:
  * @param data - Retazec na zobrazenie
  * @param limit - Maximalny pocet znakov na zobrazenie
  */
 void print_limited(const char *data, size_t limit) {
   // Kontrola platnosti vstupneho parametra
   if (data == NULL) {
     printf("(null)\n");  // Vypis informacie o NULL pointeri
     return;  // Ukoncenie funkcie
   }
   
   // Zistenie dlzky vstupneho retazca
   size_t data_len = strlen(data);  // Dlzka retazca v znakoch
   
   // Rozhodnutie ci vypisat cely retazec alebo len jeho cast
   if (data_len > limit) {
     // Retazec je dlhsi nez limit, vypiseme len cast + elipsu
     printf("%.*s...\n", (int)limit, data);  // %.*s = retazec s obmedzenou dlzkou
   } else {
     // Retazec sa zmesti do limitu, vypiseme ho cely
     printf("%s\n", data);  // Standardny vypis retazca
   }
 }