#ifndef C_CONF_PP_SPCFC
#define C_CONF_PP_SPCFC

/* a fixed array of C Pre Processor Macros to be ignore if found when scrubbing
 * files for pre-processor macros
 */

#define FAIL_CHK 0
#define SUCC_CHK 1
#define SKIP_CHK 2

#define END_ALERT "END_OF_IGNORE_PP_OPTS"

#define MOST_PP_IG 150          /* increase as needed */
#define MOST_PP_IG_PARTIALS 50  /* increase as needed */
#define MOST_PP_IG_SINGLE 50    /* increase as needed */

#define MOST_IGNORES 22
static char ignore_pp_opts[MOST_PP_IG][LONGEST_CONFIG] = {
/* 0 */
{"HAVE_CONFIG_H"},
{"__MACH__"},
{"__FreeBSD__"},
{"__linux__"},
{"max"},
/* 5 */
{"min"},
{"HAVE_ERRNO_H"},
{"_WIN32"},
{"_MSC_VER"},
{"__sun"},
/* 10 */
{"TRUE"},
{"FALSE"},
{"_WIN32_WCE"},
{"__x86_64__"},
{"_M_X64"},
{"__ILP32__"},
{"__ILP32__1"},
{"__GNUC__"},
{"__GNUC__4"},
{"__clang__"},
/* 20 */
{"__clang_major__3"},
{"__ELF__"},
{"__cplusplus"},
{"__ICCARM__"},
{"__GNUC_PREREQ"},
{"43"},
{"__thumb__"},
{"__hpux__"},
{"__MINGW32__"},
{"__INTEGRITY"},
/* 30 */
{"__PPU"},
{"errno"},
{"__IAR_SYSTEMS_ICC__"},
{"__XENON"},
{"__ia64__"},
{"__i386__"},
{"__INTEL_COMPILER"},
{"__BCPLUSPLUS__"},
{"__EMSCRIPTEN__"},
{"__alpha__"},
/* 40 */
{"_ARCH_PPC64"},
{"__mips64"},
{"sun"},
{"LP64"},
{"_LP64"},
{"__CORTEX_M3__"},
{"__SIZEOF_LONG_LONG"},
{"__aarch64__"},
{"__sparc64__"},
{"__MWERKS__"},
/* 50 */
{"__GNUC_MINOR__"},
{"__LP64__"},
{"__WOLFMATH_H__"},
/* 53 */
/* wolfSSL Header guards */
{"WOLFSSL_OPTIONS_H"},
{"WOLFSSL_INT_H"},
{"WOLFSSL_VERSION_H"},
{"WOLFSSL_CALLBACKS_H"},
{"WOLFSSL_CERTS_TEST_H"},
{"wolfSSL_TEST_H"},
{"WOLFSSL_IO_H"},
/* 60 */
{"WOLFSSL_SNIFFER_H"},
{"WOLFSSL_SSL_H"},
{"WOLFSSL_CRL_H"},
{"WOLFSSL_OCSP_H"},
{"WOLFSSL_SNIFFER_ERROR_H"},
{"WOLFSSL_ERROR_H"},
{"WOLF_CRYPT_SIGNATURE_H"},
{"WOLF_CRYPT_MD2_H"},
{"WOLF_CRYPT_SP_H"},
{"WOLF_CRYPT_FE_OPERATIONS_H"},
/* 70 */
{"WOLF_CRYPT_ENCRYPT_H"},
{"WOLFCRYPT_SELF_TEST_H"},
{"WOLF_CRYPT_ASN_H"},
{"WOLF_CRYPT_SHA_H"},
{"WOLF_CRYPT_CHACHA_H"},
{"WOLF_CRYPT_CPUID_H"},
{"WOLF_CRYPT_SETTINGS_H"},
{"WOLF_CRYPT_DES3_H"},
{"WOLF_CRYPT_TYPES_H"},
{"WOLF_CRYPT_DH_H"},
/* 80 */
{"WOLF_CRYPT_MISC_H"},
{"WOLF_CRYPT_POLY1305_H"},
{"WOLF_CRYPT_SHA3_H"},
{"WOLF_CRYPT_MD5_H"},
{"WOLF_CRYPT_ARC4_H"},
{"__WOLFMATH_H__"},
{"WOLF_CRYPT_SHA256_H"},
{"WOLF_CRYPT_CODING_H"},
{"WOLFSSL_LOGGING_H"},
{"WOLF_CRYPT_ERROR_H"},
/* 90 */
{"WOLF_CRYPT_PKCS12_H"},
{"_WOLF_EVENT_H_"},
{"WOLF_CRYPT_SHA512_H"},
{"WOLF_CRYPT_PKCS7_H"},
{"WOLFCRYPT_SRP_H"},
{"WOLF_CRYPT_CAMELLIA_H"},
{"WOLF_CRYPT_MD4_H"},
{"WOLFSSL_MEM_TRACK_H"},
{"WOLF_CRYPT_HMAC_H"},
{"WOLF_CRYPT_FIPS_TEST_H"},
/* 100 */
{"WOLF_CRYPT_AES_H"},
{"WOLF_CRYPT_BLAKE2_H"},
{"WOLF_CRYPT_PORT_H"},
{"WOLF_CRYPT_ASN_PUBLIC_H"},
{"WOLF_CRYPT_COMPRESS_H"},
{"WOLF_CRYPT_PWDBASED_H"},
{"WOLF_CRYPT_CHACHA20_POLY1305_H"},
{"WOLFSSL_MEMORY_H"},
{"WOLF_CRYPT_ED25519_H"},
{"WOLF_CRYPT_ECC_H"},
/* 110 */
{"WOLF_CRYPT_RSA_H"},
{"WOLF_CRYPT_RIPEMD_H"},
{"WOLF_CRYPT_CURVE25519_H"},
{"WOLF_CRYPT_VISIBILITY_H"},
{"WOLF_CRYPT_TFM_H"},
{"WOLF_CRYPT_DSA_H"},
{"WOLF_CRYPT_INTEGER_H"},
{"WOLFCRYPT_BLAKE2_IMPL_H"},
{"WOLF_CRYPT_GE_OPERATIONS_H"},
{"WOLF_CRYPT_CMAC_H"},
/* 120 */
{"WOLF_CRYPT_RABBIT_H"},
{"WOLF_CRYPT_HASH_H"},
{"WOLFCRYPT_BLAKE2_INT_H"},
{"WOLF_CRYPT_SP_INT_H"},
{"WOLF_CRYPT_RANDOM_H"},
{"WOLF_CRYPT_HC128_H"},
{"WOLF_CRYPT_IDEA_H"},
/* other ignores not header guards */
{"__SUNPRO_C"},
{"__SUNPRO_C0x550"},
/* 130 */
{"__BORLANDC__"},
{"_WIN64"},
{"__PPC__"},
{"END_OF_IGNORE_PP_OPTS"} /* ALWAYS LAST */
};

static char ignore_pp_opts_partial[MOST_PP_IG_PARTIALS][LONGEST_PP_OPT] = {
{"BUILD_TLS_"},
{"BUILD_WDM_"},
{"END_OF_IGNORE_PP_OPTS"} /* ALWAYS LAST */
};

static char ignore_pp_opts_single_testing[MOST_PP_IG_SINGLE][LONGEST_PP_OPT] = {
{"NO_DH"}, /* Requires HAVE_ECC else no cipher suites */
{"NO_ASN"}, /* Requires WOLFCRYPT_ONLY or no certs (PSK) */
{"NO_SHA"}, /* Requires NO_OLD_TLS */
{"NO_MD5"}, /* Requires NO_OLD_TLS */
{"NO_HMAC"}, /* Requires no hash drbg and custom RNG options */
{"NO_SHA256"}, /* Requires no hash drbg and custom RNG options */
{"HAVE_ED25519"}, /* Requires HAVE_SHA512 */
{"HAVE_CURVE25519"}, /* Requires HAVE_ECC */
{"WOLFSSL_MAX_STRENGTH"}, /* Requires other features */
/* This section contains pp macros for specific ports that are not yet
 * being tested with the wolfCFG tool
 */
{"USE_WINDOWS_API"},
{"THREADX"},
{"MICRIUM"},
{"FREERTOS"},
{"FREERTOS_TCP"},
{"WOLFSSL_SAFERTOS"},
{"EBSNET"},
{"FREESCALE_MQX"},
{"FREESCALE_KSDK_MQX"},
{"FREESCALE_FREE_RTOS"},
{"WOLFSSL_uITRON4"},
{"WOLFSSL_uTKERNEL2"},
{"WOLFSSL_CMSIS_RTOS"},
{"WOLFSSL_MDK_ARM"},
{"MBED"},
{"WOLFSSL_TIRTOS"},
{"INTIME_RTOS"},
{"WOLFSSL_NUCLEUS_1_2"},
{"WOLFSSL_APACHE_MYNEWT"},
{"WOLFSSL_LWIP"},
{"END_OF_IGNORE_PP_OPTS"} /* ALWAYS LAST */
};

#endif /* c_CONF_PP_SPCFC */

