/*
 ==============================================================================
 Name        : micro_fpe.h
 Author      : polfosol
 Version     : 2.1.2.0
 Copyright   : copyright © 2022 - polfosol
 Description : demonstrating some sample alphabets for the FPE mode of μAES ™
 ==============================================================================
 */

#ifndef MICRO_FPE_H_
#define MICRO_FPE_H_

/******************************************************************************
 * If your desired alphabet contains non-ASCII characters, the CUSTOM_ALPHABET
 * macro 'must be' set to a double-digit number, e.g 21. In what follows, there
 * are some sample alphabets along with their corresponding macro definitions.
 * It is straightforward to define another alphabet according to these samples.
 */
#define NON_ASCII_CHARACTER_SET  (CUSTOM_ALPHABET >= 10)


/******************************************************************************
 * These strings are commonly used in ASCII-based alphabets. The declaration of
 * an alphabet must be followed by its number of characters (RADIX).
 */
#define DECIMALS  "0123456789"
#define LLETTERS  "abcdefghijklmnopqrstuvwxyz"
#define ULETTERS  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define HEXCHARS  DECIMALS "ABCDEFabcdef"

/**
 numbers
 */
#if CUSTOM_ALPHABET == 0
#define ALPHABET  DECIMALS
#define RADIX     10
#endif

/**
 binary numbers
 */
#if CUSTOM_ALPHABET == 1
#define ALPHABET  "01"
#define RADIX     2
#endif

/**
 lowercase english words
 */
#if CUSTOM_ALPHABET == 2
#define ALPHABET  LLETTERS
#define RADIX     26
#endif

/**
 lowercase alphanumeric strings
 */
#if CUSTOM_ALPHABET == 3
#define ALPHABET  DECIMALS LLETTERS
#define RADIX     36
#endif

/**
 the English alphabet
 */
#if CUSTOM_ALPHABET == 4
#define ALPHABET  ULETTERS LLETTERS
#define RADIX     52
#endif

/**
 base-64 encoded strings (RFC-4648), with no padding character
 */
#if CUSTOM_ALPHABET == 5
#define ALPHABET  ULETTERS LLETTERS DECIMALS "+/"
#define RADIX     64
#endif

/**
 base-85 encoded strings (RFC-1924)
 */
#if CUSTOM_ALPHABET == 6
#define ALPHABET  DECIMALS ULETTERS LLETTERS "!#$%&()*+-;<=>?@^_`{|}~"
#define RADIX     85
#endif

/**
 a character set with length 26, used by some test vectors
 */
#if CUSTOM_ALPHABET == 7
#define ALPHABET  DECIMALS "abcdefghijklmnop"
#define RADIX     26
#endif

/**
 base-64 character set with DIFFERENT ORDERING, used by some test vectors
 */
#if CUSTOM_ALPHABET == 8
#define ALPHABET  DECIMALS ULETTERS LLETTERS "+/"
#define RADIX     64
#endif

/**
 all printable ascii characters
 */
#if CUSTOM_ALPHABET == 9
#define ALPHABET  " !\"#$%&\'()*+,-./"DECIMALS":;<=>?@"ULETTERS"[\\]^_`"LLETTERS"{|}~"
#define RADIX     95
#endif


/******************************************************************************
 * Here goes non-ASCII alphabets. Note that C89/ANSI-C standard does not fully
 * support such characters, and the code may lose its compliance in this case.
 */
#if NON_ASCII_CHARACTER_SET
#include <locale.h>
#include <wchar.h>

#define  string_t  wchar_t*                      /* type of plain/cipher-text */
#else
#define  string_t  char*
#endif

/**
 Greek alphabet (LTR)
 */
#if CUSTOM_ALPHABET == 10
#define ALPHABET L"ΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩαβγδεζηθικλμνξοπρσςτυφϕχψω"
#define RADIX    50
#endif

/**
 Persian alphabet (RTL)
 */
#if CUSTOM_ALPHABET == 20
#define ALPHABET L"ءئؤآابپتثجچحخدذرزژسشصضطظعغفقکگلمنوهی"
#define RADIX    36
#endif


/******************************************************************************
 * It is mandatory to determine these constants for the alphabet. You can either
 * pre-calculate the logarithm value (with at least 10 significant digits) and
 * set it as a constant, or let it be calculated dynamically like this:
 */
#include <math.h>
#define LOGRDX  (log( RADIX ) / log( 2 ))        /* log2(RADIX) if std >= C99 */
#if FF_X == 3
#define MAXLEN  (2 * (int) (96.000001 / LOGRDX))
#endif
#define MINLEN  ((int) (19.931568 / LOGRDX + 1))


/******************************************************************************
 * or we can do something like this to set MINLEN:
 *
#if RADIX >= 32
#define MINLEN  (2 + (RADIX < 1000) + (RADIX < 100))
#elif RADIX > 5
#define MINLEN  (5 + (RADIX < 16) + (RADIX < 10) + (RADIX < 8))
#else
#define MINLEN  (40 / RADIX + RADIX / 5)
#endif
 */

#endif /* header guard */
