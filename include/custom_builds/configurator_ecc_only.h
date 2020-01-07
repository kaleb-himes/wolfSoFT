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
                                  eccOnlySettings, toolChain);

    }

 * -----------------------------------------------------------------------------
 */

#ifndef ECC_ONLY_H
#define ECC_ONLY_H

#include "configurator_common.h"

/* Crypto */
#define ECC_ONLY_C_HNUM 48 /* number of crypto header files */
#define ECC_ONLY_C_SNUM 17 /* number of crypto source files */

/* TLS */
#define ECC_ONLY_T_HNUM 5  /* number of tls header files */
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
    {"integer.h"},
    {"tfm.h"},
    {"wolfmath.h"},
    {"md2.h"},
    {"md5.h"},
    {"md4.h"},
    {"sha.h"},
    {"sha512.h"},
    {"arc4.h"},
    {"signature.h"},
    {"rsa.h"},
    {"cmac.h"},
    {"poly1305.h"},
    {"camellia.h"},
    {"hmac.h"},
    {"dh.h"},
    {"dsa.h"},
    {"srp.h"},
    {"idea.h"},
    {"hc128.h"},
    {"rabbit.h"},
    {"chacha20_poly1305.h"},
    {"ripemd.h"},
//    {"mpi_class.h"},
//    {"mpi_superclass.h"},
};

static char eccOnlyCryptSrc[ECC_ONLY_C_SNUM][LONGEST_S_NAME] = {
    {"ecc.c"},
    {"misc.c"},
    {"wc_encrypt.c"},
    {"memory.c"},
    {"sha256.c"},
    {"asn.c"},
//    {"integer.c"},
    {"tfm.c"},
    {"asm.c"},
    {"hash.c"},
    {"wolfmath.c"},
    {"signature.c"},
    {"coding.c"},
    {"random.c"},
    {"types.c"},
    {"wc_port.c"},
    {"error.c"},
    {"logging.c"},
};

static char eccOnlyTlsHeaders[ECC_ONLY_T_HNUM][LONGEST_H_NAME] = {
//    {"ssl.h"},
    {"version.h"},
    {"wolfio.h"},
    {"test.h"},
    {"certs_test.h"},
};

static char eccOnlyTlsSrc[ECC_ONLY_T_SNUM][LONGEST_S_NAME];

static char eccOnlySettings[MOST_SETTINGS][LONGEST_PP_OPT] = {
    {"NO_FILESYSTEM"},
    {"SINGLE_THREADED"},
    {"NO_RSA"},
    {"NO_SHA"},
    {"WOLFCRYPT_ONLY"},
    {"NO_DSA"},
    {"NO_RABBIT"},
    {"NO_HMAC"},
    {"NO_PWDBASED"},
    {"NO_DES3"},
    {"NO_DES"},
    {"NO_MD5"},
    {"NO_MD4"},
    {"NO_RC4"},
    {"NO_DH"},
    {"NO_HC128"},
    {"USE_SLOW_SHA256"},
//    {"HAVE_STACK_SIZE"},
//    {"WOLFSSL_TRACK_MEMORY"},
    {"NO_AES"},
    {"USE_FAST_MATH"},
    {"ECC_TIMING_RESISTANT"},
    {"TFM_TIMING_RESISTANT"},
    {"WC_RSA_BLINDING"},
    {"HAVE_ECC"},
    {"USE_CERT_BUFFERS_256"},
    {"FP_MAX_BITS 512"},
//    {"NO_INLINE"},
//    {"NO_CERTS"},
    {"ECC_USER_CURVES"},
    {"NO_ERROR_STRINGS"},
    {"NO_WOLFSSL_DIR"},
};


#endif /* ECC_ONLY_H */
