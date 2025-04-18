/*
 ==============================================================================
 Name        : micro_aes.h
 Author      : polfosol
 Version     : 10
 Copyright   : copyright © 2022 - polfosol
 Description : μAES ™ is a minimalist all-in-one library for AES encryption
 ==============================================================================
 */

#ifndef MICRO_AES_H_
#define MICRO_AES_H_

/**----------------------------------------------------------------------------
You can use different AES algorithms by changing this macro. Default is AES-128
 -----------------------------------------------------------------------------*/
#ifndef AES___
#define AES___     256     /* or 256 (or 192; not standardized in some modes) */
#endif

/**----------------------------------------------------------------------------
AES block-cipher modes of operation. The following modes can be enabled/disabled
 by setting their corresponding macros to TRUE (1) or FALSE (0).
 -----------------------------------------------------------------------------*/
#define BLOCKCIPHERS 1
#define AEAD_MODES   1     /* authenticated encryption with associated data.  */

#if BLOCKCIPHERS
#define ECB          1     /* electronic code-book (NIST SP 800-38A)          */
#define CBC          1     /* cipher block chaining (NIST SP 800-38A)         */
#define CFB          1     /* cipher feedback (NIST SP 800-38A)               */
#define OFB          1     /* output feedback (NIST SP 800-38A)               */
#define CTR          1     /* counter-block (NIST SP 800-38A)                 */
#define XEX          1     /* xor-encrypt-xor (NIST SP 800-38E)               */
#define KWA          1     /* key wrap with authentication (NIST SP 800-38F)  */
#define FPE          1     /* format-preserving encryption (NIST SP 800-38G)  */
#endif

#if AEAD_MODES
#define CMAC         1     /* message authentication code (NIST SP 800-38B)   */

#if CTR
#define CCM          1     /* counter with CBC-MAC (RFC-3610/NIST SP 800-38C) */
#define GCM          1     /* Galois/counter mode with GMAC (NIST SP 800-38D) */
#define EAX          1     /* encrypt-authenticate-translate (ANSI C12.22)    */
#define SIV          1     /* synthetic initialization vector (RFC-5297)      */
#define GCM_SIV      1     /* nonce misuse-resistant AES-GCM (RFC-8452)       */
#endif

#if XEX
#define OCB          1     /* offset codebook mode with PMAC (RFC-7253)       */
#endif

#define POLY1305     1     /* poly1305-AES mac (https://cr.yp.to/mac.html)    */
#endif

#if CBC
#define CTS          1     /* ciphertext stealing (CS3: unconditional swap)   */
#endif

#if XEX
#define XTS          1     /* XEX tweaked-codebook with ciphertext stealing   */
#endif

#if CTR
#define CTR_NA       1     /* pure counter mode, with no authentication       */
#endif

#if EAX
#define EAXP         0     /* EAX-prime, as specified by IEEE Std 1703        */
#endif

#define WTF ! (BLOCKCIPHERS | AEAD_MODES)
#define MICRO_RJNDL  WTF   /* none of above; just rijndael API. dude.., why?  */

/**----------------------------------------------------------------------------
Refer to the BOTTOM OF THIS DOCUMENT for some explanations about these macros:
 -----------------------------------------------------------------------------*/

#if ECB || (CBC && !CTS) || (XEX && !XTS)
#define AES_PADDING     0  /* standard values: (1) PKCS#7  (2) ISO/IEC7816-4  */
#endif

#if ECB || CBC || XEX || KWA || MICRO_RJNDL
#define DECRYPTION      1  /* rijndael decryption is NOT required otherwise.  */
#endif

#if FPE
#define CUSTOM_ALPHABET 0  /* if disabled, use default alphabet (digits 0..9) */
// Only define FF_X if it hasn't been defined externally (e.g., via command line)
#ifndef FF_X
#define FF_X            1  /* algorithm type:  (1) for FF1, or (3) for FF3-1  */
#endif // FF_X
#endif // FPE

#if CTR_NA
#define CTR_IV_LENGTH  16  /* for using the last 32 bits as counter           */
#define CTR_STARTVALUE  1  /* recommended value according to the RFC-3686.    */
#endif

#if CCM
#ifndef CCM_NONCE_LEN
#define CCM_NONCE_LEN  11  /* for 32-bit count (since one byte is reserved).  */
#endif
#ifndef CCM_TAG_LEN
#define CCM_TAG_LEN    16  /* 16 bytes = 128 bits */
#endif
#endif

#ifndef GCM_NONCE_LEN
#define GCM_NONCE_LEN  12  /* RECOMMENDED. but other values are supported.    */
#endif

#if EAX && !EAXP
#define EAX_NONCE_LEN  16  /* no specified limit; can be arbitrarily large.   */
#endif

#if OCB
#define OCB_NONCE_LEN  12  /* RECOMMENDED. must be positive and less than 16. */
#define OCB_TAG_LEN    16  /* again, please see the bottom of this document!  */
#endif

/**----------------------------------------------------------------------------
Since <stdint.h> is not a part of ANSI-C, we may need a 'trick' to use uint8_t
 -----------------------------------------------------------------------------*/
#include <string.h>
#if __STDC_VERSION__ > 199900L || __cplusplus > 201100L || defined(_MSC_VER)
#include <stdint.h>
#else
#include <limits.h>
#if CHAR_BIT == 8
typedef unsigned char  uint8_t;
#endif
#if INT_MAX > 200000L
typedef int   int32_t;
#else
typedef long  int32_t;
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**----------------------------------------------------------------------------
Encryption/decryption of a single block with Rijndael
 -----------------------------------------------------------------------------*/
#if MICRO_RJNDL
void AES_Cipher( const uint8_t* key,          /* encryption/decryption key    */
                 const char mode,             /* encrypt: 'E', decrypt: 'D'   */
                 const uint8_t x[16],         /* input bytes (or input block) */
                 uint8_t y[16] );             /* output block                 */
#endif

/**----------------------------------------------------------------------------
Main functions for ECB-AES block ciphering
 -----------------------------------------------------------------------------*/
#if ECB
void AES_ECB_encrypt( const uint8_t* key,     /* encryption key               */
                      const void* pntxt,      /* plaintext buffer             */
                      const size_t ptextLen,  /* length of input plain text   */
                      void* crtxt );          /* cipher-text result           */

char AES_ECB_decrypt( const uint8_t* key,     /* decryption key               */
                      const void* crtxt,      /* cipher-text buffer           */
                      const size_t crtxtLen,  /* length of input cipher text  */
                      void* pntxt );          /* plaintext result             */
#endif /* ECB */

/**----------------------------------------------------------------------------
Main functions for CBC-AES block ciphering
 -----------------------------------------------------------------------------*/
#if CBC
char AES_CBC_encrypt( const uint8_t* key,     /* encryption key               */
                      const uint8_t iVec[16], /* initialization vector        */
                      const void* pntxt,      /* plaintext buffer             */
                      const size_t ptextLen,  /* length of input plain text   */
                      void* crtxt );          /* cipher-text result           */

char AES_CBC_decrypt( const uint8_t* key,     /* decryption key               */
                      const uint8_t iVec[16], /* initialization vector        */
                      const void* crtxt,      /* cipher-text buffer           */
                      const size_t crtxtLen,  /* length of input cipher text  */
                      void* pntxt );          /* plaintext result             */
#endif /* CBC */

/**----------------------------------------------------------------------------
Main functions for CFB-AES block ciphering
 -----------------------------------------------------------------------------*/
#if CFB
void AES_CFB_encrypt( const uint8_t* key,     /* encryption key               */
                      const uint8_t iVec[16], /* initialization vector        */
                      const void* pntxt,      /* plaintext buffer             */
                      const size_t ptextLen,  /* length of input plain text   */
                      void* crtxt );          /* cipher-text result           */

void AES_CFB_decrypt( const uint8_t* key,     /* decryption key               */
                      const uint8_t iVec[16], /* initialization vector        */
                      const void* crtxt,      /* cipher-text buffer           */
                      const size_t crtxtLen,  /* length of input cipher text  */
                      void* pntxt );          /* plaintext result             */
#endif /* CFB */

/**----------------------------------------------------------------------------
Main functions for OFB-AES block ciphering
 -----------------------------------------------------------------------------*/
#if OFB
void AES_OFB_encrypt( const uint8_t* key,     /* encryption key               */
                      const uint8_t iVec[16], /* initialization vector        */
                      const void* pntxt,      /* plaintext buffer             */
                      const size_t ptextLen,  /* length of input plain text   */
                      void* crtxt );          /* cipher-text result           */

void AES_OFB_decrypt( const uint8_t* key,     /* decryption key               */
                      const uint8_t iVec[16], /* initialization vector        */
                      const void* crtxt,      /* cipher-text buffer           */
                      const size_t crtxtLen,  /* length of input cipher text  */
                      void* pntxt );          /* plaintext result             */
#endif /* OFB */

/**----------------------------------------------------------------------------
Main functions for XTS-AES block ciphering
 -----------------------------------------------------------------------------*/
#if XTS
char AES_XTS_encrypt( const uint8_t* keys,    /* encryption key pair          */
                      const uint8_t* tweak,   /* tweak value (unit/sector ID) */
                      const void* pntxt,      /* plaintext buffer             */
                      const size_t ptextLen,  /* length of input plain text   */
                      void* crtxt );          /* cipher-text result           */

char AES_XTS_decrypt( const uint8_t* keys,    /* decryption key pair          */
                      const uint8_t* tweak,   /* tweak value (unit/sector ID) */
                      const void* crtxt,      /* cipher-text buffer           */
                      const size_t crtxtLen,  /* length of input cipher text  */
                      void* pntxt );          /* plaintext result             */
#endif /* XTS */

/**----------------------------------------------------------------------------
Main functions for CTR-AES block ciphering
 -----------------------------------------------------------------------------*/
#if CTR_NA
void AES_CTR_encrypt( const uint8_t* key,     /* encryption key               */
                      const uint8_t* iv,      /* initialization vector/ nonce */
                      const void* pntxt,      /* plaintext buffer             */
                      const size_t ptextLen,  /* length of input plain text   */
                      void* crtxt );          /* cipher-text result           */

void AES_CTR_decrypt( const uint8_t* key,     /* decryption key               */
                      const uint8_t* iv,      /* initialization vector/ nonce */
                      const void* crtxt,      /* cipher-text buffer           */
                      const size_t crtxtLen,  /* length of input cipher text  */
                      void* pntxt );          /* plaintext result             */
#endif /* CTR */

/**----------------------------------------------------------------------------
Main functions for SIV-AES block ciphering
 -----------------------------------------------------------------------------*/
#if SIV
void AES_SIV_encrypt( const uint8_t* keys,    /* encryption key pair          */
                      const uint8_t* pntxt,   /* plain text                   */
                      const size_t ptextLen,  /* length of input plain text   */
                      const uint8_t* aData,   /* added authentication data    */
                      const size_t aDataLen,  /* size of authentication data  */
                      uint8_t iv[16],         /* synthesized initial-vector   */
                      uint8_t* crtxt );       /* cipher-text result           */

char AES_SIV_decrypt( const uint8_t* keys,    /* decryption key pair          */
                      const uint8_t iv[16],   /* provided initial-vector      */
                      const uint8_t* crtxt,   /* cipher text                  */
                      const size_t crtxtLen,  /* length of input cipher-text  */
                      const uint8_t* aData,   /* added authentication data    */
                      const size_t aDataLen,  /* size of authentication data  */
                      uint8_t* pntxt );       /* plain-text result            */
#endif /* SIV */

/**----------------------------------------------------------------------------
Main functions for GCM-AES block ciphering
 -----------------------------------------------------------------------------*/
#if GCM
void AES_GCM_encrypt( const uint8_t* key,     /* encryption key               */
                      const uint8_t* nonce,   /* a.k.a initialization vector  */
                      const uint8_t* pntxt,   /* plain text                   */
                      const size_t ptextLen,  /* length of input plain text   */
                      const uint8_t* aData,   /* added authentication data    */
                      const size_t aDataLen,  /* size of authentication data  */
                      uint8_t* crtxt,         /* cipher-text result           */
                      uint8_t auTag[16] );    /* message authentication tag   */

char AES_GCM_decrypt( const uint8_t* key,     /* decryption key               */
                      const uint8_t* nonce,   /* a.k.a initialization vector  */
                      const uint8_t* crtxt,   /* cipher text + appended tag   */
                      const size_t crtxtLen,  /* length of input cipher-text  */
                      const uint8_t* aData,   /* added authentication data    */
                      const size_t aDataLen,  /* size of authentication data  */
                      const uint8_t tagLen,   /* size of tag (if any)         */
                      uint8_t* pntxt );       /* plain-text result            */
#endif /* GCM */

/**----------------------------------------------------------------------------
Main functions for CCM-AES block ciphering
 -----------------------------------------------------------------------------*/
#if CCM
void AES_CCM_encrypt( const uint8_t* key,     /* encryption key               */
                      const uint8_t* nonce,   /* a.k.a initialization vector  */
                      const uint8_t* pntxt,   /* plain text                   */
                      const size_t ptextLen,  /* length of input plain text   */
                      const uint8_t* aData,   /* added authentication data    */
                      const size_t aDataLen,  /* size of authentication data  */
                      uint8_t* crtxt,         /* cipher-text result           */
                      uint8_t auTag[16] );    /* message authentication tag   */

char AES_CCM_decrypt( const uint8_t* key,     /* decryption key               */
                      const uint8_t* nonce,   /* a.k.a initialization vector  */
                      const uint8_t* crtxt,   /* cipher text + appended tag   */
                      const size_t crtxtLen,  /* length of input cipher-text  */
                      const uint8_t* aData,   /* added authentication data    */
                      const size_t aDataLen,  /* size of authentication data  */
                      const uint8_t tagLen,   /* size of tag (if any)         */
                      uint8_t* pntxt );       /* plain-text result            */
#endif /* CCM */

/**----------------------------------------------------------------------------
Main functions for OCB-AES block ciphering
 -----------------------------------------------------------------------------*/
#if OCB
void AES_OCB_encrypt( const uint8_t* key,     /* encryption key               */
                      const uint8_t* nonce,   /* a.k.a initialization vector  */
                      const uint8_t* pntxt,   /* plain text                   */
                      const size_t ptextLen,  /* length of input plain text   */
                      const uint8_t* aData,   /* added authentication data    */
                      const size_t aDataLen,  /* size of authentication data  */
                      uint8_t* crtxt,         /* cipher-text result           */
                      uint8_t auTag[16] );    /* message authentication tag   */

char AES_OCB_decrypt( const uint8_t* key,     /* decryption key               */
                      const uint8_t* nonce,   /* a.k.a initialization vector  */
                      const uint8_t* crtxt,   /* cipher text + appended tag   */
                      const size_t crtxtLen,  /* length of input cipher-text  */
                      const uint8_t* aData,   /* added authentication data    */
                      const size_t aDataLen,  /* size of authentication data  */
                      const uint8_t tagLen,   /* size of tag (if any)         */
                      uint8_t* pntxt );       /* plain-text result            */
#endif /* OCB */

/**----------------------------------------------------------------------------
Main functions for EAX-AES mode; more info at the bottom of this document.
 -----------------------------------------------------------------------------*/
#if EAX
void AES_EAX_encrypt( const uint8_t* key,     /* encryption key               */
                      const uint8_t* nonce,   /* arbitrary-size nonce array   */
                      const uint8_t* pntxt,   /* plain text                   */
                      const size_t ptextLen,  /* length of input plain text   */
#if EAXP
                      const size_t nonceLen,  /* size of provided nonce       */
                      uint8_t* crtxt );       /* cipher-text result + mac (4) */
#else
                      const uint8_t* aData,   /* added authentication data    */
                      const size_t aDataLen,  /* size of authentication data  */
                      uint8_t* crtxt,         /* cipher-text result           */
                      uint8_t auTag[16] );    /* message authentication tag   */
#endif

char AES_EAX_decrypt( const uint8_t* key,     /* decryption key               */
                      const uint8_t* nonce,   /* arbitrary-size nonce array   */
                      const uint8_t* crtxt,   /* cipher text + appended tag   */
                      const size_t crtxtLen,  /* length of input cipher-text  */
#if EAXP
                      const size_t nonceLen,  /* size of provided nonce       */
#else
                      const uint8_t* aData,   /* added authentication data    */
                      const size_t aDataLen,  /* size of authentication data  */
                      const uint8_t tagLen,   /* size of tag (if any)         */
#endif
                      uint8_t* pntxt );       /* plain-text result            */
#endif /* EAX */

/**----------------------------------------------------------------------------
Main functions for GCM-SIV-AES block ciphering
 -----------------------------------------------------------------------------*/
#if GCM_SIV
void GCM_SIV_encrypt( const uint8_t* key,     /* encryption key               */
                      const uint8_t* nonce,   /* provided 96-bit nonce        */
                      const uint8_t* pntxt,   /* plain text                   */
                      const size_t ptextLen,  /* length of input plain text   */
                      const uint8_t* aData,   /* added authentication data    */
                      const size_t aDataLen,  /* size of authentication data  */
                      uint8_t* crtxt,         /* cipher-text result           */
                      uint8_t auTag[16] );    /* 16-bytes mandatory tag       */

char GCM_SIV_decrypt( const uint8_t* key,     /* decryption key               */
                      const uint8_t* nonce,   /* provided 96-bit nonce        */
                      const uint8_t* crtxt,   /* cipher text + appended tag   */
                      const size_t crtxtLen,  /* length of input cipher-text  */
                      const uint8_t* aData,   /* added authentication data    */
                      const size_t aDataLen,  /* size of authentication data  */
                      const uint8_t tagLen,   /* size of tag (must be 16)     */
                      uint8_t* pntxt );       /* plain-text result            */
#endif /* GCM-SIV */

/**----------------------------------------------------------------------------
Main functions for AES key-wrapping
 -----------------------------------------------------------------------------*/
#if KWA
char AES_KEY_wrap( const uint8_t* kek,        /* key encryption key           */
                   const uint8_t* secret,     /* input secret to be wrapped   */
                   const size_t secretLen,    /* size of input                */
                   uint8_t* wrapped );        /* key-wrapped output           */

char AES_KEY_unwrap( const uint8_t* kek,      /* key encryption key           */
                     const uint8_t* wrapped,  /* key-wrapped secret           */
                     const size_t wrapLen,    /* size of input (secretLen +8) */
                     uint8_t* secret );       /* buffer for unwrapped key     */
#endif /* KWA */

/**----------------------------------------------------------------------------
Main functions for FPE-AES; more info at the bottom of this page.
 -----------------------------------------------------------------------------*/
#if FPE
char AES_FPE_encrypt( const uint8_t* key,     /* encryption key               */
                      const uint8_t* tweak,   /* tweak bytes                  */
#if FF_X == 3
#define FF3_TWEAK_LEN 8                       /* either 8 (FF3), or 7 (FF3-1) */
#else
                      const size_t tweakLen,  /* size of tweak array          */
#endif
                      const void* pntxt,      /* input plaintext string       */
                      const size_t ptextLen,  /* length of plaintext string   */
                      void* crtxt );          /* cipher-text result           */

char AES_FPE_decrypt( const uint8_t* key,     /* decryption key               */
                      const uint8_t* tweak,   /* tweak bytes                  */
#if FF_X != 3
                      const size_t tweakLen,  /* size of tweak array          */
#endif
                      const void* crtxt,      /* input ciphertext string      */
                      const size_t crtxtLen,  /* length of ciphertext string  */
                      void* pntxt );          /* plain-text result            */
#endif /* FPE */

/**----------------------------------------------------------------------------
Main function for Poly1305-AES message authentication code
 -----------------------------------------------------------------------------*/
#if POLY1305
void AES_Poly1305( const uint8_t* keys,       /* encryption/mixing key pair   */
                   const uint8_t nonce[16],   /* the 128-bit nonce            */
                   const void* data,          /* input data buffer            */
                   const size_t dataSize,     /* size of data in bytes        */
                   uint8_t mac[16] );         /* poly1305-AES mac of data     */
#endif

/**----------------------------------------------------------------------------
Main function for AES Cipher-based Message Authentication Code
 -----------------------------------------------------------------------------*/
#if CMAC
void AES_CMAC( const uint8_t* key,            /* encryption/cipher key        */
               const void* data,              /* input data buffer            */
               const size_t dataSize,         /* size of data in bytes        */
               uint8_t mac[16] );             /* CMAC result of input data    */
#endif

#ifdef __cplusplus
}
#endif

/**----------------------------------------------------------------------------
The error codes and key length should be defined here for external references:
 -----------------------------------------------------------------------------*/
#define ENCRYPTION_FAILURE       0x1E
#define DECRYPTION_FAILURE       0x1D
#define AUTHENTICATION_FAILURE   0x1A
#define NO_ERROR_RETURNED        0x00

#if AES___ == 0x100 || AES___ == 0xC0
#define AES_KEY_SIZE  (AES___ >> 3)
#else
#define AES_KEY_SIZE   16
#endif

#endif /* header guard */

/******************************************************************************\
¦               Notes and remarks about the above-defined macros               ¦
--------------------------------------------------------------------------------

* The only difference between the standard AES methods is in their key-expansion
    process. So for example, AES-128-GCM and AES-256-GCM are pretty much similar
    except for their key size and a minor change in the KeyExpansion function.

* In EBC/CBC/XEX modes, the size of input must be a multiple of block-size.
    Otherwise it needs to be padded. The simplest (default) padding mode is to
    fill the rest of block by zeros. Supported standard padding methods are
    PKCS#7 and ISO/IEC 7816-4, which can be enabled by the AES_PADDING macro.

* Many reference texts interchangeably use the words "nonce" and "initialization
    vector", but they are not the same at all. Sometimes nonce is a part of the
    I.V, which itself can either be a full block or a partial one. In CBC, CFB,
    and OFB modes, the provided I.V must be a full block. In pure CTR (CTR_NA)
    mode, you can either provide a full block I.V, or use a 96-bit one which is
    also called nonce, and then let the count start at CTR_STARTVALUE.

* In most functions, as you may notice, first the entire input data is copied
    to the output and then the encryption process is carried out on its buffer.
    This is a very useful feature especially when the memory is limited, as you
    can perform "in-place encryption" on the input data and there is no need to
    allocate a separate buffer for the output. But please note that the `memcpy`
    function has undefined behavior if its source and destination are the same.
    So if input and output buffers were the same, simply delete the memcpy line.

* In AEAD modes, the size of nonce and tag might be a parameter of the algorithm
    such that changing them affect the results. The GCM and EAX modes support
    arbitrary sizes for nonce. In CCM, the nonce length may vary from 8 to 13
    bytes. Also the tag size is an EVEN number between 4..16. In OCB, the nonce
    size is 1..15 and the tag is 0..16 bytes. Note that the "calculated" tag-
    size is always 16 bytes which can later be truncated to desired values. So
    in encryption functions, the provided authTag buffer must be 16 bytes long.

* For the EAX mode of operation, the IEEE-1703 standard defines EAX' which is a
    modified version that combines AAD and nonce. Also the tag size is fixed to
    4 bytes. So EAX-prime functions don't need to take additional authentication
    data and tag-size as separate parameters. It has been proven that EAX' has
    serious vulnerabilities and its usage is not recommended.

* In SIV mode, multiple separate units of authentication headers can be provided
    for the nonce synthesis. Here we assume that only one unit of AAD (aData) is
    sufficient, which is practically true.

* The FPE mode has two distinct NIST-approved algorithms, namely FF1 and FF3-1.
    Use the FF_X macro to change the encryption method, which is FF1 by default.
    The input and output strings must be consisted of a fixed set of characters
    called "the alphabet". The default alphabet is the set of digits {'0'..'9'}.
    If you want to use a different alphabet, set the CUSTOM_ALPHABET macro and
    refer to the <micro_fpe.h> header. This file is needed only when a custom
    alphabet has to be defined. It contains some illustrative examples and clear
    guidelines on how to do so.

* The key wrapping mode is also denoted by KW. In this mode, the input secret is
    divided into 64bit blocks. Number of blocks is at least 2, and it is assumed
    that no padding is required. For padding, the KWP mode must be used which is
    easily implementable, but left as an exercise! The key-wrapped output is an
    extra block (8 bytes) longer than the secret. In the NIST SP800-38F document
    you may find mentions of TKW which is based on 3DES and irrelevant here.

* Let me explain three extra options that are defined in the source file. If the
    length of the input cipher/plain text is 'always' less than 4KB, you can
    enable the SMALL_CIPHER macro to save a few bytes in the compiled code. This
    assumption is likely to be valid for some embedded systems and small-scale
    applications. Furthermore by enabling the DONT_USE_FUNCTIONS macro, you may
    witness a positive effect on the speed while increasing the size of compiled
    code. Nonetheless, others might get a different result from them.

    The INCREASE_SECURITY macro, as its name suggests, is dealing with security
    considerations. For example, since the RoundKey is declared as static array
    it might get exposed to some attacks. By enabling this macro, round-keys are
    wiped out at the end of ciphering operations. However, please keep in mind
    that this is NOT A GUARANTEE against side-channel attacks.

*/
