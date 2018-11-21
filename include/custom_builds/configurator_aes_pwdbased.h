/*
 * Example: AES_ONLY_H
 *
 * update-002 - unique pre-prended string for lengths
 * Example: AES_ONLY would result in AES_ONLY_C_HNUM, AES_ONLY_C_SNUM ... etc.
 *
 * update-003 - name of the custom test app
 * Example: aes_only would result in cfg_aes_only.c and output dir of aes_only
 *
 * update-004 - unique name prepend for array ID's
 * Example: aesOnly would result in aesOnlyCryptHeaders, aesOnlyCryptSrc... etc.
 *
 * Command that can be copy/pasted for new test case once search/replace and all
 * updates complete:
 * -----------------------------------------------------------------------------

    if (XSTRNCMP(AES_PWDBASED_DST, option, (int)XSTRLEN(option)) == 0) {
        printf("Alright! Building %s!\n", AES_PWDBASED_DST);

        cfg_build_custom_specific(AES_PWDBASED_TEST_FILE,
                                  AES_PWDBASED_DST,
                                  aesPwdBasedCryptHeaders, AES_PWDBASED_C_HNUM,
                                  aesPwdBasedCryptSrc, AES_PWDBASED_C_SNUM,
                                  aesPwdBasedTlsHeaders, AES_PWDBASED_T_HNUM,
                                  aesPwdBasedTlsSrc, AES_PWDBASED_T_SNUM,
                                  aesPwdBasedSettings, toolChain);

    }

 * -----------------------------------------------------------------------------
 */

#ifndef AESPWDBASED_H
#define AESPWDBASED_H

#include "configurator_common.h"

/* Crypto */
#define AES_PWDBASED_C_HNUM 24 /* number of crypto header files */
#define AES_PWDBASED_C_SNUM 14 /* number of crypto source files */

/* TLS */
#define AES_PWDBASED_T_HNUM 4  /* number of tls header files */
#define AES_PWDBASED_T_SNUM 0  /* number of TLS source files */

#define AES_PWDBASED_TEST_FILE "cfg_aes_pwdbased.c"
#define AES_PWDBASED_DST "aes_pwdbased"

static char aesPwdBasedCryptHeaders[AES_PWDBASED_C_HNUM][LONGEST_H_NAME] = {
    {"aes.h"},
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
    {"hmac.h"},
    {"tfm.h"},
    {"wolfmath.h"},
};

static char aesPwdBasedCryptSrc[AES_PWDBASED_C_SNUM][LONGEST_S_NAME] = {
    {"aes.c"},
    {"misc.c"},
    {"wc_encrypt.c"},
    {"memory.c"},
    {"pwdbased.c"},
    {"hmac.c"},
    {"sha256.c"},
    {"hash.c"},
    {"asn.c"},
    {"tfm.c"},
    {"asm.c"},
    {"wolfmath.c"},
    {"wc_port.c"},
    {"logging.c"},
};

static char aesPwdBasedTlsHeaders[AES_PWDBASED_T_HNUM][LONGEST_H_NAME] = {
    {"ssl.h"},
    {"version.h"},
    {"wolfio.h"},
    {"test.h"},
};
static char aesPwdBasedTlsSrc[AES_PWDBASED_T_SNUM][LONGEST_S_NAME];

static char aesPwdBasedSettings[MOST_SETTINGS][LONGEST_PP_OPT] = {
    {"NO_RSA"},
    {"NO_SHA"},
    {"WOLFCRYPT_ONLY"},
    {"NO_DSA"},
    {"NO_CODING"},
    {"NO_RABBIT"},
    {"USE_FAST_MATH"},
//    {"NO_HMAC"},
//    {"NO_PWDBASED"},
//    {"NO_SHA256"},
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
//    {"NO_ASN"},
    {"NO_DH"},
    {"NO_HC128"},
//    {"HAVE_STACK_SIZE"},
//    {"WOLFSSL_TRACK_MEMORY"},
    {"WOLFSSL_NO_PEM"},
    {"TFM_TIMING_RESISTANT"},
    {"WC_RSA_BLINDING"},
    {"TFM_NO_ASM"},
    {"SINGLE_THREADED"},
    {"NO_ERROR_STRINGS"},
};

#endif /* AESO_H */
