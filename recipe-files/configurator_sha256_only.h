/* update-001 - Give your header a name
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

    if (XSTRNCMP(SHA256_ONLY_DST, option, (int)XSTRLEN(option)) == 0) {
        printf("Alright! Building %s!\n", SHA256_ONLY_DST);

        cfg_build_custom_specific(SHA256_ONLY_TEST_FILE,
                                  SHA256_ONLY_DST,
                                  sha256OnlyCryptHeaders, SHA256_ONLY_C_HNUM,
                                  sha256OnlyCryptSrc, SHA256_ONLY_C_SNUM,
                                  sha256OnlyTlsHeaders, SHA256_ONLY_T_HNUM,
                                  sha256OnlyTlsSrc, SHA256_ONLY_T_SNUM,
                                  sha256OnlySettings, toolChain);

    }

 * -----------------------------------------------------------------------------
 */

#ifndef SHA256_ONLY_H
#define SHA256_ONLY_H

#include "configurator_common.h"

/* Crypto */
#define SHA256_ONLY_C_HNUM 20 /* number of crypto header files */
#define SHA256_ONLY_C_SNUM 3 /* number of crypto source files */

/* TLS */
#define SHA256_ONLY_T_HNUM 0  /* number of tls header files */
#define SHA256_ONLY_T_SNUM 0  /* number of TLS source files */

#define SHA256_ONLY_TEST_FILE "cfg_sha256_only.c" //example myCustom.c

static char sha256OnlyCryptHeaders[SHA256_ONLY_C_HNUM][LONGEST_H_NAME] = {
    {"settings.h"},
    {"visibility.h"},
    {"sha256.h"},
    {"types.h"},
    {"wc_port.h"},
    {"memory.h"},
    {"error-crypt.h"},
    {"logging.h"},
    {"hash.h"},
    {"cpuid.h"},
    {"misc.h"},
    {"hmac.h"},
};

static char sha256OnlyCryptSrc[SHA256_ONLY_C_SNUM][LONGEST_S_NAME] = {
    {"sha256.c"},
    {"hash.c"},
    {"misc.c"},
};

static char sha256OnlyTlsHeaders[SHA256_ONLY_T_HNUM][LONGEST_H_NAME] = {
};

static char sha256OnlyTlsSrc[SHA256_ONLY_T_SNUM][LONGEST_S_NAME] = {
};

static char sha256OnlySettings[MOST_SETTINGS][LONGEST_PP_OPT] = {
    {"NO_RSA"},
    {"NO_SHA"},
    {"WOLFCRYPT_ONLY"},
    {"NO_DSA"},
    {"NO_CODING"},
    {"NO_RABBIT"},
    {"NO_HMAC"},
    {"NO_PWDBASED"},
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
//    {"HAVE_STACK_SIZE"},
//    {"WOLFSSL_TRACK_MEMORY"},
};


#endif /* SHA256_ONLY_H */
