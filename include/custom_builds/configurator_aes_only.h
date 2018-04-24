#ifndef AESO_H
#define AESO_H

#include "configurator_common.h"

/* Crypto */
#define AES_ONLY_C_HNUM 18 /* number of crypto header files */
#define AES_ONLY_C_SNUM 3 /* number of crypto source files */

/* TLS */
#define AES_ONLY_T_HNUM 0  /* number of tls header files */
#define AES_ONLY_T_SNUM 0  /* number of TLS source files */

#define AES_ONLY_TEST_FILE "cfg_aes_only.c"
#define AES_ONLY_DST "aes_only"

static char aesOnlyCryptHeaders[AES_ONLY_C_HNUM][LONGEST_H_NAME] = {
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
/* All the below are required due to poor include logic in wc_encrypt.c */
/* Should not be requiring a header if it's algo is not enabled */
  {"chacha.h"}, // SHOULD NOT be required when HAVE_CHACHA not defined TODO: fix
  {"des3.h"}, // SHOULD NOT be required when NO_DES3 TODO: fix
  {"arc4.h"}, // SHOULD NOT be required when NO_RC4 TODO: fix
  {"hash.h"}, // SHOULD NOT be required when not hash algos TODO: fix
  {"asn.h"}, // SHOULD NOT be required when NO_ASN TODO: fix
  {"coding.h"}, //SHOULD NOT be required when NO_CODING TODO: fix
  {"pwdbased.h"}, // SHOULD NOT be required when NO_PWDBASED TODO: fix
};

static char aesOnlyCryptSrc[AES_ONLY_C_SNUM][LONGEST_S_NAME] = {
  {"aes.c"},
  {"misc.c"},
  {"wc_encrypt.c"},
};

static char aesOnlyTlsHeaders[AES_ONLY_T_HNUM][LONGEST_H_NAME];
static char aesOnlyTlsSrc[AES_ONLY_T_SNUM][LONGEST_S_NAME];

static char aesOnlySettings[MOST_SETTINGS][LONGEST_PP_OPT] = {
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
};

#endif /* AESO_H */
