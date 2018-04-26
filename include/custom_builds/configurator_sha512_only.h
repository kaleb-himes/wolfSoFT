/* update-001 - Give your header a name
 * Example: AES_ONLY_H
 *
 * update-002 - unique pre-prended string for lengths
 * Example: AES_ONLY would result in AES_ONLY_C_HNUM, AES_ONLY_C_SNUM ... etc.
 *
 * update-003 - macro place holder for custom app file name
 * Example: AES_ONLY would result in AES_ONLY_TEST_FILE
 *
 * update-004 - name of the custom test app
 * Example: cfg_aes_only would result in cfg_aes_only.c
 *
 * update-005 - macro place holder for output directory of custom app
 * Example: AES_ONLY would result in AES_ONLY_DST
 *
 * update-006 - name of the custom test output directory
 * Example: aes_only would result in aes_only/ directory output
 *
 * update-007 - unique name prepend for array ID's
 * Example: aesOnly would result in aesOnlyCryptHeaders, aesOnlyCryptSrc... etc.
 *
 * Command that can be copy/pasted for new test case once search/replace and all
 * updates complete:
 * -----------------------------------------------------------------------------

    if (XSTRNCMP(SHA512_ONLY_DST, option, (int)XSTRLEN(option)) == 0) {
        printf("Alright! Building %s!\n", SHA512_ONLY_DST);

        cfg_build_custom_specific(SHA512_ONLY_TEST_FILE,
                                  SHA512_ONLY_DST,
                                  sha512OnlyCryptHeaders, SHA512_ONLY_C_HNUM,
                                  sha512OnlyCryptSrc, SHA512_ONLY_C_SNUM,
                                  sha512OnlyTlsHeaders, SHA512_ONLY_T_HNUM,
                                  sha512OnlyTlsSrc, SHA512_ONLY_T_SNUM,
                                  sha512OnlySettings);

    }

 * -----------------------------------------------------------------------------
 */

#ifndef SHA512_ONLY_H
#define SHA512_ONLY_H

#include "configurator_common.h"

/* Crypto */
#define SHA512_ONLY_C_HNUM 22 /* number of crypto header files */
#define SHA512_ONLY_C_SNUM 10 /* number of crypto source files */

/* TLS */
#define SHA512_ONLY_T_HNUM 4  /* number of tls header files */
#define SHA512_ONLY_T_SNUM 0  /* number of TLS source files */

#define SHA512_ONLY_TEST_FILE "cfg_sha512_only.c" //example myCustom.c
#define SHA512_ONLY_DST "sha512_only" // example myCustomDir

static char sha512OnlyCryptHeaders[SHA512_ONLY_C_HNUM][LONGEST_H_NAME] = {
    {"sha512.h"},
    {"error-crypt.h"},
    {"logging.h"},
    {"memory.h"},
    {"misc.h"},
    {"settings.h"},
    {"types.h"},
    {"visibility.h"},
    {"wc_port.h"},
    {"cpuid.h"},
    {"wc_encrypt.h"},
    {"chacha.h"},
    {"des3.h"},
    {"arc4.h"},
    {"hash.h"},
    {"asn.h"},
    {"coding.h"},
    {"pwdbased.h"},
    {"mem_track.h"},
    {"asn_public.h"},
    {"random.h"},
    {"aes.h"},
};

static char sha512OnlyCryptSrc[SHA512_ONLY_C_SNUM][LONGEST_S_NAME] = {
    {"sha512.c"},
    {"misc.c"},
    {"wc_encrypt.c"},
    {"memory.c"},
};

static char sha512OnlyTlsHeaders[SHA512_ONLY_T_HNUM][LONGEST_H_NAME] = {
    {"ssl.h"},
    {"version.h"},
    {"wolfio.h"},
    {"test.h"},
};

static char sha512OnlyTlsSrc[SHA512_ONLY_T_SNUM][LONGEST_S_NAME];

static char sha512OnlySettings[MOST_SETTINGS][LONGEST_PP_OPT] = {
{"NO_RSA"},
{"NO_SHA"},
{"WOLFCRYPT_ONLY"},
{"NO_DSA"},
{"NO_CODING"},
{"NO_RABBIT"},
{"NO_HMAC"},
{"NO_PWDBASED"},
{"NO_SHA256"},
{"WC_NO_HASHDRBG"},
{"WC_NO_RNG"},
{"CUSTOM_RAND_GENERATE_BLOCK"}, // This should not be required if WC_NO_HASHDRBG
                                //TODO: Why is random.h still failing check on
                                // line 96 without this setting ????
{"NO_DES3"},
{"NO_DES"},
{"NO_MD5"},
{"NO_MD4"},
{"NO_RC4"},
{"NO_ASN"},
{"NO_DH"},
{"NO_HC128"},
{"NO_AES"},
{"WOLFSSL_SHA512"},
{"HAVE_STACK_SIZE"},
{"WOLFSSL_TRACK_MEMORY"},

};


#endif /* SHA512_ONLY_H */
