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

    if (XSTRNCMP(DSA_ONLY_DST, option, (int)XSTRLEN(option)) == 0) {
        printf("Alright! Building %s!\n", DSA_ONLY_DST);

        cfg_build_custom_specific(DSA_ONLY_TEST_FILE,
                                  DSA_ONLY_DST,
                                  dsaOnlyCryptHeaders, DSA_ONLY_C_HNUM,
                                  dsaOnlyCryptSrc, DSA_ONLY_C_SNUM,
                                  dsaOnlyTlsHeaders, DSA_ONLY_T_HNUM,
                                  dsaOnlyTlsSrc, DSA_ONLY_T_SNUM,
                                  dsaOnlySettings, toolChain);

    }

 * -----------------------------------------------------------------------------
 */

#ifndef DSA_ONLY_H
#define DSA_ONLY_H

#include "configurator_common.h"

/* Crypto */
#define DSA_ONLY_C_HNUM 50 /* number of crypto header files */
#define DSA_ONLY_C_SNUM 20 /* number of crypto source files */

/* TLS */
#define DSA_ONLY_T_HNUM 5  /* number of tls header files */
#define DSA_ONLY_T_SNUM 0  /* number of TLS source files */

#define DSA_ONLY_TEST_FILE "cfg_dsa_only.c" //example myCustom.c
#define DSA_ONLY_DST "dsa_only" // example myCustomDir

static char dsaOnlyCryptHeaders[DSA_ONLY_C_HNUM][LONGEST_H_NAME] = {
    {"settings.h"},
    {"visibility.h"},
    {"ecc.h"},
    {"types.h"},
    {"wc_port.h"},
    {"memory.h"},
    {"random.h"},
    {"sha256.h"},
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
    {"md4.h"},
    {"md5.h"},
    {"hmac.h"},
    {"des3.h"},
    {"aes.h"},
    {"wc_encrypt.h"},
    {"arc4.h"},
    {"mem_track.h"},
    {"sha.h"},
    {"sha512.h"},
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
    {"chacha.h"},
    {"chacha20_poly1305.h"},
    {"pwdbased.h"},
    {"ripemd.h"},
    {"error-crypt.h"},
};

static char dsaOnlyCryptSrc[DSA_ONLY_C_SNUM][LONGEST_S_NAME] = {
    {"dsa.c"},
    {"misc.c"},
    {"tfm.c"},
    {"asm.c"},
    {"coding.c"},
    {"hmac.c"},
    {"wolfmath.c"},
    {"sha.c"},
    {"sha256.c"},
    {"random.c"},
    {"hash.c"},
    {"memory.c"},
    {"asn.c"},
    {"wc_port.c"},
    {"error.c"},
    {"logging.c"},
};

static char dsaOnlyTlsHeaders[DSA_ONLY_T_HNUM][LONGEST_H_NAME] = {
    {"certs_test.h"},
    {"version.h"},
};

static char dsaOnlyTlsSrc[DSA_ONLY_T_SNUM][LONGEST_S_NAME] = {
};

static char dsaOnlySettings[MOST_SETTINGS][LONGEST_PP_OPT] = {
    {"WOLFCRYPT_ONLY"},
    {"USE_CERT_BUFFERS_2048"},
    {"TFM_TIMING_RESISTANT"},
    {"ECC_TIMING_RESISTANT"},
    {"WC_RSA_BLINDING"},
    {"NO_MD5"},
    {"USE_FAST_MATH"},
    {"SINGLE_THREADED"},
    {"TFM_NO_ASM"},
    {"NO_AES"},
    {"NO_RSA"},
    {"NO_PWDBASED"},
    {"NO_MD4"},
    {"NO_RC4"},
    {"NO_RABBIT"},
    {"NO_ASN_TIME"},
    {"NO_DH"},
    {"NO_DES3"},
    {"NO_DES3"},
};


#endif /* DSA_ONLY_H */
