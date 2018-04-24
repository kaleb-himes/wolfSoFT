#ifndef RSA_PSS_PKCS_H
#define RSA_PSS_PKCS_H

#include "configurator_common.h"

/* Crypto */
#define RSA_PSS_PKCS_C_HNUM 29 /* number of crypto header files */
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
{"WC_RSA_PSS"},
{"WC_NO_HARDEN"},
{"NO_RSA_BOUNDS_CHECK"},
//{"WC_RSA_BLINDING"},
//{"TFM_TIMING_RESISTANT"},
{"USE_FAST_MATH"},
{"USE_CERT_BUFFERS_2048"},
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
{"USE_WOLFSSL_MEMORY"},
{"HAVE_STACK_SIZE"},
{"WOLFSSL_TRACK_MEMORY"},
};


#endif /* RSA_PSS_PKCS_H */
