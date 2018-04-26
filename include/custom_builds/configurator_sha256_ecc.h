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

cfg_build_custom_specific(SHA256_ECC_TEST_FILE,
                          SHA256_ECC_DST,
                          sha256EccCryptHeaders, SHA256_ECC_C_HNUM,
                          sha256EccCryptSrc, SHA256_ECC_C_SNUM,
                          sha256EccTlsHeaders, SHA256_ECC_T_HNUM,
                          sha256EccTlsSrc, SHA256_ECC_T_SNUM,
                          sha256EccSettings);

 * -----------------------------------------------------------------------------
 */

#ifndef SHA256_ECC_ONLY_H
#define SHA256_ECC_ONLY_H

#include "configurator_common.h"

/* Crypto */
#define SHA256_ECC_C_HNUM 29 /* number of crypto header files */
#define SHA256_ECC_C_SNUM 13 /* number of crypto source files */

/* TLS */
#define SHA256_ECC_T_HNUM 5  /* number of tls header files */
#define SHA256_ECC_T_SNUM 0  /* number of TLS source files */

#define SHA256_ECC_TEST_FILE "cfg_sha256_ecc.c" //example myCustom.c
#define SHA256_ECC_DST "sha256_ecc" // example myCustomDir

static char sha256EccCryptHeaders[SHA256_ECC_C_HNUM][LONGEST_H_NAME] = {
    {"settings.h"},
    {"visibility.h"},
    {"ecc.h"},
    {"types.h"},
    {"wc_port.h"},
    {"memory.h"},
    {"random.h"},
    {"sha256.h"},
    {"error-crypt.h"},
    {"cpuid.h"},
    {"logging.h"},
    {"misc.h"},
    {"integer.h"},
    {"tfm.h"},
    {"wolfmath.h"},
    {"asn.h"},
    {"asn_public.h"},
    {"signature.h"},
    {"hash.h"},
    {"coding.h"},
    {"md2.h"},
    {"hmac.h"},
    {"pwdbased.h"},
    {"des3.h"},
    {"aes.h"},
    {"wc_encrypt.h"},
    {"chacha.h"},
    {"arc4.h"},
    {"mem_track.h"},
};

static char sha256EccCryptSrc[SHA256_ECC_C_SNUM][LONGEST_S_NAME] = {
    {"ecc.c"},
    {"sha256.c"},
    {"misc.c"},
    {"signature.c"},
    {"tfm.c"},
    {"asm.c"},
    {"asn.c"},
    {"coding.c"},
    {"wolfmath.c"},
    {"random.c"},
    {"hash.c"},
    {"wc_port.c"},
    {"memory.c"},
};

static char sha256EccTlsHeaders[SHA256_ECC_T_HNUM][LONGEST_H_NAME] = {
    {"certs_test.h"},
    {"ssl.h"},
    {"version.h"},
    {"wolfio.h"},
    {"test.h"},
};

static char sha256EccTlsSrc[SHA256_ECC_T_SNUM][LONGEST_S_NAME] = {
};

static char sha256EccSettings[MOST_SETTINGS][LONGEST_PP_OPT] = {
    {"NO_RSA"},
    {"HAVE_ECC"},
    {"USE_FAST_MATH"},
    {"ECC_TIMING_RESISTANT"},
    {"TFM_TIMING_RESISTANT"},
    {"USE_CERT_BUFFERS_256"},
    {"NO_DH"},
    {"NO_DSA"},
    {"NO_SHA"},
    {"NO_MD5"},
    {"NO_MD4"},
    {"WOLFCRYPT_ONLY"},
    {"NO_ASM"},
    {"NO_PWDBASED"},
    {"NO_DES3"},
    {"NO_AES"},
    {"NO_RC4"},
    {"TFM_NO_ASM"},
    {"HAVE_STACK_SIZE"},
    {"WOLFSSL_TRACK_MEMORY"},
};


#endif /* SHA256_ECC_ONLY_H */
