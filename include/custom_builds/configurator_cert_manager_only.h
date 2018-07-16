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

    if (XSTRNCMP(CERT_MNGR_ONLY_DST, option, (int)XSTRLEN(option)) == 0) {
        printf("Alright! Building %s!\n", CERT_MNGR_ONLY_DST);

        cfg_build_custom_specific(CERT_MNGR_ONLY_TEST_FILE,
                                  CERT_MNGR_ONLY_DST,
                                  certMngrOnlyCryptHeaders, CERT_MNGR_ONLY_C_HNUM,
                                  certMngrOnlyCryptSrc, CERT_MNGR_ONLY_C_SNUM,
                                  certMngrOnlyTlsHeaders, CERT_MNGR_ONLY_T_HNUM,
                                  certMngrOnlyTlsSrc, CERT_MNGR_ONLY_T_SNUM,
                                  certMngrOnlySettings, toolChain);

    }

 * -----------------------------------------------------------------------------
 */

#ifndef CERT_MNGR_ONLY_H
#define CERT_MNGR_ONLY_H

#include "configurator_common.h"

/* Crypto */
#define CERT_MNGR_ONLY_C_HNUM 40 /* number of crypto header files */
#define CERT_MNGR_ONLY_C_SNUM 20 /* number of crypto source files */

/* TLS */
#define CERT_MNGR_ONLY_T_HNUM 20  /* number of tls header files */
#define CERT_MNGR_ONLY_T_SNUM 20  /* number of TLS source files */

#define CERT_MNGR_ONLY_TEST_FILE "cfg_cert_mngr_only.c" //example myCustom.c
#define CERT_MNGR_ONLY_DST "cert_mngr_only" // example myCustomDir

static char certMngrOnlyCryptHeaders[CERT_MNGR_ONLY_C_HNUM][LONGEST_H_NAME] = {
    {"misc.h"},
    {"types.h"},
    {"settings.h"},
    {"visibility.h"},
    {"logging.h"},
    {"wc_port.h"},
    {"memory.h"},
    {"asn_public.h"},
    {"random.h"},
    {"sha256.h"},
    {"asn.h"},
    {"integer.h"},
    {"tfm.h"},
    {"wolfmath.h"},
    {"dh.h"},
    {"dsa.h"},
    {"sha.h"},
    {"pkcs12.h"},
    {"aes.h"},
    {"hmac.h"},
    {"hash.h"},
    {"rsa.h"},
    {"wc_encrypt.h"},
    {"chacha.h"},
    {"des3.h"},
    {"arc4.h"},
    {"error-crypt.h"},
    {"coding.h"},
    {"md2.h"},
    {"pwdbased.h"},
    {"cpuid.h"},
    {"ecc.h"},
};

static char certMngrOnlyCryptSrc[CERT_MNGR_ONLY_C_SNUM][LONGEST_S_NAME] = {
    {"misc.c"},
    {"asn.c"},
    {"memory.c"},
    {"coding.c"},
    {"wc_port.c"},
    {"sha256.c"},
    {"ecc.c"},
    {"random.c"},
    {"aes.c"},
    {"hash.c"},
    {"tfm.c"},
    {"asm.c"},
    {"wc_encrypt.c"},
    {"error.c"},
    {"pwdbased.c"},
    {"hmac.c"},
    {"wolfmath.c"},
//    {"logging.c"},
//    {""},
};

static char certMngrOnlyTlsHeaders[CERT_MNGR_ONLY_T_HNUM][LONGEST_H_NAME] = {
    {"ssl.h"},
    {"internal.h"},
    {"version.h"},
    {"wolfio.h"},
    {"error-ssl.h"},
};

static char certMngrOnlyTlsSrc[CERT_MNGR_ONLY_T_SNUM][LONGEST_S_NAME] = {
    {"ssl.c"},
    {"internal.c"},
    {"tls.c"},
    {"wolfio.c"},
    {"keys.c"},
};

static char certMngrOnlySettings[MOST_SETTINGS][LONGEST_PP_OPT] = {
    {"NO_WOLFSSL_CLIENT"},
    {"TFM_TIMING_RESISTANT"},
    {"USE_FAST_MATH"},
    {"ECC_TIMING_RESISTANT"},
    {"WC_RSA_BLINDING"},
    {"NO_DES3"},
    {"NO_HC128"},
    {"NO_RABBIT"},
    {"NO_MD5"},
    {"NO_MD4"},
    {"NO_RC4"},
    {"NO_OLD_TLS"},
    {"NO_RSA"},
    {"HAVE_ECC"},
    {"NO_SHA"},
    {"NO_DH"},
    {"TFM_NO_ASM"},
//    {"DEBUG_WOLFSSL"},
};


#endif /* CERT_MNGR_ONLY_H */
