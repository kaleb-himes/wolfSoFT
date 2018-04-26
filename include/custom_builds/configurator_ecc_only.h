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

    if (XSTRNCMP(ECC_ONLY_DST, option, (int)XSTRLEN(option)) == 0) {
        printf("Alright! Building %s!\n", ECC_ONLY_DST);

        cfg_build_custom_specific(ECC_ONLY_TEST_FILE,
                                  ECC_ONLY_DST,
                                  eccOnlyCryptHeaders, ECC_ONLY_C_HNUM,
                                  eccOnlyCryptSrc, ECC_ONLY_C_SNUM,
                                  eccOnlyTlsHeaders, ECC_ONLY_T_HNUM,
                                  eccOnlyTlsSrc, ECC_ONLY_T_SNUM,
                                  eccOnlySettings);

    }

 * -----------------------------------------------------------------------------
 */

#ifndef ECC_ONLY_H
#define ECC_ONLY_H

#include "configurator_common.h"

/* Crypto */
#define ECC_ONLY_C_HNUM 23 /* number of crypto header files */
#define ECC_ONLY_C_SNUM 5 /* number of crypto source files */

/* TLS */
#define ECC_ONLY_T_HNUM 4  /* number of tls header files */
#define ECC_ONLY_T_SNUM 0  /* number of TLS source files */

#define ECC_ONLY_TEST_FILE "cfg_ecc_only.c" //example myCustom.c
#define ECC_ONLY_DST "ecc_only" // example myCustomDir

static char eccOnlyCryptHeaders[ECC_ONLY_C_HNUM][LONGEST_H_NAME] = {
    {"ecc.h"},
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
    {"sha256.h"},
};

static char eccOnlyCryptSrc[ECC_ONLY_C_SNUM][LONGEST_S_NAME] = {
    {"ecc.c"},
    {"misc.c"},
    {"wc_encrypt.c"},
    {"memory.c"},
    {"sha256.c"},
};

static char eccOnlyTlsHeaders[ECC_ONLY_T_HNUM][LONGEST_H_NAME] = {
    {"ssl.h"},
    {"version.h"},
    {"wolfio.h"},
    {"test.h"},
};

static char eccOnlyTlsSrc[ECC_ONLY_T_SNUM][LONGEST_S_NAME];

static char eccOnlySettings[MOST_SETTINGS][LONGEST_PP_OPT] = {
    {"NO_RSA"},
    {"NO_SHA"},
    {"WOLFCRYPT_ONLY"},
    {"NO_DSA"},
    {"NO_CODING"},
    {"NO_RABBIT"},
    {"NO_HMAC"},
    {"NO_PWDBASED"},
    {"NO_DES3"},
    {"NO_DES"},
    {"NO_MD5"},
    {"NO_MD4"},
    {"NO_RC4"},
    {"NO_ASN"},
    {"NO_DH"},
    {"NO_HC128"},
    {"HAVE_STACK_SIZE"},
    {"WOLFSSL_TRACK_MEMORY"},
    {"NO_AES"},
};


#endif /* ECC_ONLY_H */
