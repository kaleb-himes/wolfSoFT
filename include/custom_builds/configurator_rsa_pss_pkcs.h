#ifndef RSA_PSS_PKCS_H
#define RSA_PSS_PKCS_H

#include "configurator_common.h"

/* Crypto */
#define RSA_PSS_PKCS_C_HNUM 45 /* number of crypto header files */
#define RSA_PSS_PKCS_C_SNUM 13 /* number of crypto source files */

/* TLS */
#define RSA_PSS_PKCS_T_HNUM 5  /* number of tls header files */
#define RSA_PSS_PKCS_T_SNUM 0  /* number of TLS source files */

#define RSA_PSS_PKCS_SV_NED_TEST_FILE "cfg_rsa_pss_pkcs_sv_ned.c"
#define RSA_PSS_PKCS_SV_NED_DST "rsa_pss_pkcs_sv_ned"

#define RSA_PSS_PKCS_TEST_FILE "cfg_rsa_pss_pkcs.c"
#define RSA_PSS_PKCS_DST "rsa_pss_pkcs"

static char rsaPssPkcsCryptHeaders[RSA_PSS_PKCS_C_HNUM][LONGEST_H_NAME] = {
    {"settings.h"},
    {"rsa.h"},
    {"error-crypt.h"},
    {"logging.h"},
    {"memory.h"},
    {"misc.h"},
    {"types.h"},
    {"visibility.h"},
    {"wc_port.h"},
    {"hash.h"},
    {"asn.h"},
    {"asn_public.h"},
    {"integer.h"},
    {"tfm.h"},
    {"random.h"},
    {"wolfmath.h"},
    {"sha256.h"},
    {"sha512.h"},
    {"signature.h"},
    {"coding.h"},
    {"md2.h"},
    {"hmac.h"},
    {"pwdbased.h"},
    {"des3.h"},
    {"aes.h"},
    {"wc_encrypt.h"},
    {"arc4.h"},
    {"chacha.h"},
    {"cpuid.h"},
    {"mem_track.h"},
    {"md5.h"},
    {"md4.h"},
    {"sha.h"},
    {"cmac.h"},
    {"poly1305.h"},
    {"camellia.h"},
    {"dh.h"},
    {"dsa.h"},
    {"srp.h"},
    {"idea.h"},
    {"hc128.h"},
    {"rabbit.h"},
    {"chacha20_poly1305.h"},
    {"ripemd.h"},
};

static char rsaPssPkcsCryptSrc[RSA_PSS_PKCS_C_SNUM][LONGEST_S_NAME] = {
    {"rsa.c"},
    {"misc.c"},
    {"signature.c"},
    {"tfm.c"},
    {"asm.c"},
    {"wolfmath.c"},
    {"asn.c"},
    {"coding.c"},
    {"random.c"},
    {"hash.c"},
    {"sha256.c"},
    {"memory.c"},
    {"wc_port.c"},
};

static char rsaPssPkcsTlsHeaders[RSA_PSS_PKCS_T_HNUM][LONGEST_H_NAME] = {
    {"certs_test.h"},
    {"ssl.h"},
    {"version.h"},
    {"wolfio.h"},
    {"test.h"},
};

static char rsaPssPkcsTlsSrc[RSA_PSS_PKCS_T_SNUM][LONGEST_S_NAME];

static char rsaPssPkcsSettings[MOST_SETTINGS][LONGEST_PP_OPT] = {
{"NO_DSA"},
{"NO_SHA"},
{"NO_DES"},
{"NO_MD5"},
{"NO_MD4"},
{"NO_RC4"},
{"NO_DH"},
{"NO_AES"},
{"NO_PSK"},
{"NO_DES3"},
{"NO_HMAC"},
{"NO_HC128"},
{"NO_64BIT"},
{"NO_RABBIT"},
{"NO_WRITEV"},
{"TFM_NO_ASM"},
{"WC_RSA_PSS"},
{"NO_PWDBASED"},
{"RSA_LOW_MEM"},
{"USE_FAST_MATH"},
{"NO_WOLFSSL_DIR"},
{"WOLFCRYPT_ONLY"},
{"BENCH_EMBEDDED"},
{"NO_SIG_WRAPPER"},
{"USE_SLOW_SHA256"},
{"WC_RSA_BLINDING"},
{"WOLFSSL_NO_SOCK"},
{"NO_ERROR_STRINGS"},
{"WOLFSSL_LOW_MEMORY"},
{"USE_WOLFSSL_MEMORY"},
{"NO_RSA_BOUNDS_CHECK"},
{"TFM_TIMING_RESISTANT"},
{"USE_CERT_BUFFERS_2048"},
{"NO_CURVED25519_128BIT"},
//
{"NO_FILESYSTEM"},
{"SINGLE_THREADED"},
//{"HAVE_STACK_SIZE"},
//{"WOLFSSL_TRACK_MEMORY"},
};


#endif /* RSA_PSS_PKCS_H */
