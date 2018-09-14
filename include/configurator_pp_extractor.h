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
#define MOST_PP_IG_SINGLE 600    /* increase as needed */

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
/* 52 */
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
{"CHAR_BIT"},
{"END_OF_IGNORE_PP_OPTS"} /* ALWAYS LAST */
};

static char ignore_pp_opts_partial[MOST_PP_IG_PARTIALS][LONGEST_PP_OPT] = {
{"BUILD_TLS_"},
{"BUILD_WDM_"},
{"BUILD_SSL_"},
{"END_OF_IGNORE_PP_OPTS"} /* ALWAYS LAST */
};

static char ignore_pp_opts_single_testing[MOST_PP_IG_SINGLE][LONGEST_PP_OPT] = {

{"NO_AES_DECRYPT"}, /* NEEDS FIXED! There are multiple assumptions made in
                     * the file <wolf-root>/wolfcrypt/src/wc_encrypt.c that make
                     * no effort to check if features are on or not. One major
                     * problem is the function wc_CryptKey which doesn't bother
                     * checking for Des, Aes Decrypt or Encrypt and many other
                     * defines before compiling calls to API's dependent on
                     * those features */

/* The following defined would need to be set to an actual value, we would
 * need to add rule(s) when testing these defines such as:
 * "#define WOLFSSL_SESSION_TIMEOUT 20" etc...
 */
{"WOLFSSL_SESSION_TIMEOUT"}, /* any value should work, default is 500 */
{"WOLFSSL_MAX_MTU"}, /* any value should work, default is 1500 */
{"WOLFSSL_MIN_DHKEY_BITS"}, /* Should be 1024 modable, default is 2048 */
{"WOLFSSL_MAX_DHKEY_BITS"}, /* Same as min */
{"WOLFSSL_MIN_DOWNGRADE"}, /* Valid options: TLSv1_MINOR, TLSv1_1_MINOR,
                            * TLSv1_2_MINOR, TLSv1_3_MINOR */
{"WOLFSSL_MAX_SUITE_SZ"}, /* Need to test limits, default is 300 */
{"WOLFSSL_MAX_SIGALGO"}, /* Need to test limits, default is 32 */
{"WOLFSSL_MIN_ECC_BITS"}, /* Need to test ECC valid sizes, default is 256 */
{"WOLFSSL_MIN_RSA_BITS"}, /* Need to test RSA valid sizes, default is 2048 */
{"MAX_CHAIN_DEPTH"}, /* Need to test limits, default is 9 */
{"MAX_CERTIFICATE_SZ"}, /* Valid based on MAX_X509_SIZE + CERT_HEADER_SZ and
                         * multiplied by MAX_CHAIN_DEPTH */
{"MAX_HANDSHAKE_SZ"}, /* Valid based on MAX_CERTIFICATE_SZ above */
{"MAX_DATE_SIZE"}, /* Need to test limits, default is 32 */
{"CA_TABLE_SIZE"}, /* Need to test limits, default is 11 */

/* The following are not expected to work without other options being set */
{"NO_DH"}, /* Requires HAVE_ECC else no cipher suites */
{"NO_ASN"}, /* Requires WOLFCRYPT_ONLY or no certs (PSK) */
{"NO_SHA"}, /* Requires NO_OLD_TLS */
{"NO_MD5"}, /* Requires NO_OLD_TLS */
{"NO_HMAC"}, /* Requires no hash drbg and custom RNG options */
{"NO_SHA256"}, /* Requires no hash drbg and custom RNG options */
{"HAVE_ED25519"}, /* Requires HAVE_SHA512 */
{"HAVE_CURVE25519"}, /* Requires HAVE_ECC */
{"WOLFSSL_MAX_STRENGTH"}, /* Requires other features */
{"HAVE_LIBZ"}, /* Requires zlib, cannot always be assumed */
{"byte"}, /* There is a valid #ifndef byte check in wolfSSL, don't test it */
{"HAVE_QSH"}, /* depends on HAVE_TLS_EXTENSIONS also being set */
{"WOLFSSL_AEAD_ONLY"}, /* requires having an AEAD cipher enabled */
{"NO_TLS"}, /* Requires disabling other features such as tls master secret */
{"WOLFSSL_TLS13"}, /* depends on: HAVE_TLS_EXTENSIONS, HAVE_SUPPORTED_CURVES */
{"WOLFSSL_MULTICAST"}, /* depends on DTLS also being enabled */
{"WOLFSSL_SESSION_EXPORT"}, /* depends on DTLS */
{"WOLFSSL_SCTP"}, /* depends on DTLS */
{"NO_CERTS"}, /* Would need to disable TLS as well */
{"OPENSSL_ALL"}, /* depends on HAVE_SESSION_TICKET and possibly others */
{"HAVE_CERTIFICATE_STATUS_REQUEST"}, /* depends on HAVE_OCSP */
{"HAVE_CERTIFICATE_STATUS_REQUEST_V2"}, /* depends on HAVE_OCSP */
{"HAVE_SESSION_TICKET"}, /* depends on HAVE_TLS_EXTENSIONS */
{"HAVE_SNI"}, /* depends on HAVE_TLS_EXTENSIONS */
{"HAVE_MAX_FRAGMENT"}, /* depends on HAVE_TLS_EXTENSIONS */
{"HAVE_TRUNCATED_HMAC"}, /* depends on HAVE_TLS_EXTENSIONS */
{"HAVE_SUPPORTED_CURVES"}, /* depends on HAVE_TLS_EXTENSIONS */
{"HAVE_ALPN"}, /* depends on HAVE_TLS_EXTENSIONS */
{"HAVE_SECURE_RENEGOTIATION"}, /* depends on HAVE_TLS_EXTENSIONS */
{"HAVE_SERVER_RENEGOTIATION_INFO"}, /* depends on HAVE_TLS_EXTENSIONS */
{"BUILD_AESGCM"}, /* depends on HAVE_AESGCM */

/* The below options may or may not be expected to work but need evaluation */
{"WOLFSSL_NO_CLIENT_AUTH"},
{"ASN_NAME_MAX"},
{"MAX_DATE_SZ"},
{"EXTERNAL_SERIAL_SIZE"},
{"HAVE_NETX"},
{"WOLFSSL_STATIC_MEMORY"},
{"WOLFSSL_DTLS_DROP_STATS"},
{"WOLFSSL_KEIL_TCP_NET"},
{"WOLFSSL_VXWORKS"},
{"WOLFSSL_LEANPSK"},
{"WOLFSSL_HAVE_MIN"},
{"WOLFSSL_IAR_ARM"},
{"WOLFSSL_ROWLEY_ARM"},
{"WOLFSSL_NO_TLS12"},
{"HAVE_WNR"},
{"WOLFSSL_FORCE_MALLOC_FAIL_TEST"},
{"NO_MAIN_DRIVER"},
{"WOLFSSL_CHIBIOS"},
{"WOLFSSL_CONTIKI"},
{"WOLFSSL_ATMEL"},
{"WOLFSSL_PRCONNECT_PRO"},
{"WOLFSSL_SGX"},
{"WOLFSSL_NO_SOCK"},
{"HAVE_RTP_SYS"},
{"DEVKITPRO"},
{"WOLFSSL_PICOTCP"},
{"WOLFSSL_UIP"},
{"WOLFSSL_PREFIX"},
{"LIBWOLFSSL_VERSION_STRING"},
{"WOLFSSL_WOLFSSL_TYPE_DEFINED"},
{"WOLFSSL_WOLFSSL_CTX_TYPE_DEFINED"},
{"WOLFSSL_RSA_TYPE_DEFINED"},
{"WC_RNG_TYPE_DEFINED"},
{"WOLFSSL_EVP_TYPE_DEFINED"},
{"WOLFSSL_ASIO"},
{"WOLF_STACK_OF"},
{"WOLFSSL_EMBOS"},
{"WOLFSSL_FROSTED"},
{"HAVE_USER_RSA"},
{"HAVE_FAST_RSA"},
{"WOLFSSL_XILINX_CRYPT"},
{"WC_RSAKEY_TYPE_DEFINED"},
{"__STDC_VERSION__"},
{"WOLFSSL_ARDUINO"},
{"FREESCALE_MMCAU"},
{"WOLFSSL_MICROCHIP_PIC32MZ"},
{"WOLFSSL_CRYPT_HW_MUTEX"},
{"LSR_FS"},
{"MAX_FILENAME_SZ"},
{"USER_TIME"},
{"TIME_OVERRIDES"},
{"MICROCHIP_TCPIP_V5"},
{"FREESCALE_KSDK_BM"},
{"FREESCALE_KSDK_FREERTOS"},
{"XTIME"},
{"IDIRECT_DEV_TIME"},
{"HAVE_VALIDATE_DATE"},
{"USE_WOLF_TM"},
{"USE_WOLF_TIMEVAL_T"},
{"FILE_BUFFER_SIZE"},
{"NO_INLINE"},
{"NO_TIME_H"},
{"WC_ASN_NAME_MAX"},
{"HAVE_PKCS7"},
{"WOLFSSL_TEST_CERT"},
{"MAX_KEY_SIZE"},
{"MAX_UNICODE_SZ"},
{"FREESCALE_LTC_ECC"},
{"WOLFSSL_ATECC508A"},
{"WOLFSSL_IMX6_CAAM"},
{"WOLFSSL_AESNI"},
{"MICROCHIP_PIC32"},
{"WOLFSSL_EROAD"},
{"WOLFSSL_PICOTCP_DEMO"},
{"WOLFSSL_UTASKER"},
{"WOLFSSL_PB"},
{"XMALLOC_OVERRIDE"},
{"XMALLOC_USER"},
{"WOLFSSL_NRF5x"},
{"WOLFSSL_LSR"},
{"FREESCALE_COMMON"},
{"FREESCALE_USE_MMCAU_CLASSIC"},
{"FREESCALE_LTC_TFM_RSA_4096_ENABLE"},
{"WOLFSSL_STM32F2"},
{"WOLFSSL_STM32F4"},
{"WOLFSSL_STM32F7"},
{"WOLFSSL_STM32F1"},
{"WOLFSSL_STM32L4"},
{"STM32_CRYPTO"},
{"STM32_HASH"},
{"CUSTOM_RAND_GENERATE"},
{"WOLFSSL_QL"},
{"WOLFSSL_ARMASM"},
{"SIZEOF_LONG"},
{"SIZEOF_LONG_LONG"},
{"FREESCALE_MMCAU_CLASSIC"},
{"WOLFSSL_GENERAL_ALIGNMENT"},
{"WOLFSSL_SP_MATH"},
{"AES_MAX_KEY_SIZE"},
{"NO_AES_CBC"},
{"WOLFSSL_NO_DECODE_EXTRA"},
{"WOLFSSL_LEANTLS"},
{"HAVE_IO_POOL"},
{"NO_BIG_INT"},
{"HAVE_AES_KEYWRAP"},
{"WOLFSSL_ALERT_COUNT_MAX"},
{"WOLFSSL_CMAC"},
{"WOLFSSL_TYPES_DEFINED"},
{"WOLFSSL_AES_COUNTER"},
{"WC_NO_RNG"},
{"WOLFSSL_AFALG"},
{"HAVE_AES_ECB"},
{"HAVE_INTEL_AVX1"},
{"NO_64BIT"},
{"MIN"},
{"WOLFSSL_HAVE_SP_DH"},
{"WOLFSSL_HAVE_SP_ECC"},
{"RNG_MAX_BLOCK_LEN"},
{"DRBG_SEED_LEN"},
{"CUSTOM_RAND_GENERATE_BLOCK"},
{"WC_RESEED_INTERVAL"},
{"LTM2"},
{"WOLFSSL_TRACK_MEMORY"},
{"WOLFSSL_TI_HASH"},
{"WOLFSSL_PIC32MZ_HASH"},
{"MP_INT_DEFINED"},
{"FREESCALE_LTC_SHA"},
{"WOLFSSL_AFALG_HASH"},
{"WOLFSSL_BIGINT_TYPES"},
{"DIGIT_BIT"},
{"MP_PREC"},
{"MAX_INVMOD_SZ"},
{"WORDS_BIGENDIAN"},
{"BIG_ENDIAN_ORDER"},
{"byte"},
{"FALL_THROUGH"},
{"STRING_USER"},
{"CTYPE_USER"},
{"WOLFSSL_MAX_ERROR_SZ"},
{"WC_CTC_NAME_SIZE"},
{"WC_CTC_MAX_ALT_SIZE"},
{"USER_TICKS"},
{"WOLFSSL_HEAP_TEST"},
{"OLD_HELLO_ALLOWED"},
{"WOLFSSL_LOAD_VERIFY_DEFAULT_FLAGS"},
{"PRINT_SESSION_STATS"},
{"WOLFSSL_EXTRA"},
{"XSNPRINTF"},
{"FREESCALE_KSDK_2_0_TRNG"},
{"FREESCALE_KSDK_2_0_RNGA"},
{"NO_DEV_RANDOM"},
{"CUSTOM_RAND_GENERATE_SEED"},
{"WOLFSSL_GENSEED_FORTEST"},
{"HAVE_INTEL_RDRAND"},
{"HAVE_INTEL_RDSEED"},
{"CUSTOM_RAND_GENERATE_SEED_OS"},
{"STM32_RNG"},
{"WOLFSSL_NRF51"},
{"IDIRECT_DEV_RANDOM"},
{"WOLFSSL_IMX6_CAAM_RNG"},
{"WOLFSSL_LPC43xx"},
{"WOLFSSL_STM32F2xx"},
{"NO_DEV_URANDOM"},
{"USE_TEST_GENSEED"},
{"WOLFSSL_TI_CRYPT"},
{"HAVE_COLDFIRE_SEC"},
{"FREESCALE_LTC_DES"},
{"WOLFSSL_PIC32MZ_CRYPT"},
{"WOLF_CRYPT_MISC_C"},
{"INTEL_INTRINSICS"},
{"PPC_INTRINSICS"},
{"KEIL_INTRINSICS"},
{"FREESCALE_MMCAU_SHA"},
{"XTRANSFORM"},
{"MP_SET_CHUNK_BITS"},
{"WC_MP_TO_RADIX"},
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
{"WOLFSSL_ASYNC_CRYPT"},
{"HAVE_NTRU"},
{"WOLFSSL_DTLS_WINDOW_WORDS"},
{"WOLFSSL_MYSQL_COMPATIBLE"},
{"HAVE_FIPS"},
{"HAVE_FIPS_VERSION"},
{"HAVE_SELFTEST"},
{"HAVE_INTEL_AVX2"},
{"WOLFSSL_STSAFEA100"},
{"WOLFSSL_NO_MALLOC"},
{"NO_CODING"},
{"WC_CACHE_LINE_SZ"},
{"HAVE_MD5_CUST_API"},
{"USER_MATH_LIB}"},
{"WOLFSSL_SP_RSA"},
{"WOLFSSL_BEFORE_DATE_CLOCK_SKEW"},
{"WOLFSSL_AFTER_DATE_CLOCK_SKEW"},
{"HAVE_STUNNEL"},
{"WOLFSSL_NGINX"},
{"WOLFSSL_HAPROXY"},
{"HAVE_LIGHTY"},

{"END_OF_IGNORE_PP_OPTS"} /* ALWAYS LAST */
};



#endif /* c_CONF_PP_SPCFC */

