#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/wc_encrypt.h>
#include <wolfssl/wolfcrypt/mem_track.h>

#define HAVE_AES_CBC

#define HEAP_HINT NULL

static int devId = INVALID_DEVID;

/* only for stack size check */
#ifdef HAVE_STACK_SIZE
    #include <wolfssl/ssl.h>
    #define err_sys err_sys_remap /* remap err_sys */
    #include <wolfssl/test.h>
    #undef err_sys
#endif

#ifdef HAVE_STACK_SIZE
static THREAD_RETURN err_sys(const char* msg, int es)
#else
static int err_sys(const char* msg, int es)
#endif
{
    printf("%s error = %d\n", msg, es);

    EXIT_TEST(-1);
}

#ifndef HAVE_STACK_SIZE
/* func_args from test.h, so don't have to pull in other stuff */
typedef struct func_args {
    int    argc;
    char** argv;
    int    return_code;
} func_args;
#endif /* !HAVE_STACK_SIZE */

#ifndef NO_AES
#ifdef WOLFSSL_AES_CFB
    /* Test cases from NIST SP 800-38A, Recommendation for Block Cipher Modes of Operation Methods an*/
    static int aescfb_test(void)
    {
        Aes enc;
        byte cipher[AES_BLOCK_SIZE * 4];
    #ifdef HAVE_AES_DECRYPT
        Aes dec;
        byte plain [AES_BLOCK_SIZE * 4];
    #endif
        int  ret = 0;

        const byte iv[] = {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
            0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
        };

#ifdef WOLFSSL_AES_128
        const byte key1[] =
        {
            0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
            0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
        };

        const byte cipher1[] =
        {
            0x3b,0x3f,0xd9,0x2e,0xb7,0x2d,0xad,0x20,
            0x33,0x34,0x49,0xf8,0xe8,0x3c,0xfb,0x4a,
            0xc8,0xa6,0x45,0x37,0xa0,0xb3,0xa9,0x3f,
            0xcd,0xe3,0xcd,0xad,0x9f,0x1c,0xe5,0x8b,
            0x26,0x75,0x1f,0x67,0xa3,0xcb,0xb1,0x40,
            0xb1,0x80,0x8c,0xf1,0x87,0xa4,0xf4,0xdf
        };

        const byte msg1[] =
        {
            0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
            0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
            0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,
            0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
            0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,
            0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef
        };
#endif /* WOLFSSL_AES_128 */

#ifdef WOLFSSL_AES_192
        /* 192 size key test */
        const byte key2[] =
        {
            0x8e,0x73,0xb0,0xf7,0xda,0x0e,0x64,0x52,
            0xc8,0x10,0xf3,0x2b,0x80,0x90,0x79,0xe5,
            0x62,0xf8,0xea,0xd2,0x52,0x2c,0x6b,0x7b
        };

        const byte cipher2[] =
        {
            0xcd,0xc8,0x0d,0x6f,0xdd,0xf1,0x8c,0xab,
            0x34,0xc2,0x59,0x09,0xc9,0x9a,0x41,0x74,
            0x67,0xce,0x7f,0x7f,0x81,0x17,0x36,0x21,
            0x96,0x1a,0x2b,0x70,0x17,0x1d,0x3d,0x7a,
            0x2e,0x1e,0x8a,0x1d,0xd5,0x9b,0x88,0xb1,
            0xc8,0xe6,0x0f,0xed,0x1e,0xfa,0xc4,0xc9,
            0xc0,0x5f,0x9f,0x9c,0xa9,0x83,0x4f,0xa0,
            0x42,0xae,0x8f,0xba,0x58,0x4b,0x09,0xff
        };

        const byte msg2[] =
        {
            0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
            0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
            0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,
            0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
            0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,
            0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,
            0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,
            0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10
        };
#endif /* WOLFSSL_AES_192 */

#ifdef WOLFSSL_AES_256
        /* 256 size key simple test */
        const byte key3[] =
        {
            0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
            0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
            0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
            0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
        };

        const byte cipher3[] =
        {
            0xdc,0x7e,0x84,0xbf,0xda,0x79,0x16,0x4b,
            0x7e,0xcd,0x84,0x86,0x98,0x5d,0x38,0x60,
            0x39,0xff,0xed,0x14,0x3b,0x28,0xb1,0xc8,
            0x32,0x11,0x3c,0x63,0x31,0xe5,0x40,0x7b,
            0xdf,0x10,0x13,0x24,0x15,0xe5,0x4b,0x92,
            0xa1,0x3e,0xd0,0xa8,0x26,0x7a,0xe2,0xf9,
            0x75,0xa3,0x85,0x74,0x1a,0xb9,0xce,0xf8,
            0x20,0x31,0x62,0x3d,0x55,0xb1,0xe4,0x71
        };

        const byte msg3[] =
        {
            0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
            0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
            0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,
            0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
            0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,
            0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,
            0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,
            0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10
        };
#endif /* WOLFSSL_AES_256 */

#ifdef WOLFSSL_AES_128
        /* 128 key tests */
        ret = wc_AesSetKey(&enc, key1, AES_BLOCK_SIZE, iv, AES_ENCRYPTION);
        if (ret != 0)
            return -1101;
    #ifdef HAVE_AES_DECRYPT
        /* decrypt uses AES_ENCRYPTION */
        ret = wc_AesSetKey(&dec, key1, AES_BLOCK_SIZE, iv, AES_ENCRYPTION);
        if (ret != 0)
            return -1102;
    #endif

        XMEMSET(cipher, 0, sizeof(cipher));
        ret = wc_AesCfbEncrypt(&enc, cipher, msg1, AES_BLOCK_SIZE * 2);
        if (ret != 0)
            return -1105;

        if (XMEMCMP(cipher, cipher1, AES_BLOCK_SIZE * 2))
            return -1106;

        /* test restarting encryption process */
        ret = wc_AesCfbEncrypt(&enc, cipher + (AES_BLOCK_SIZE * 2),
                msg1 + (AES_BLOCK_SIZE * 2), AES_BLOCK_SIZE);
        if (ret != 0)
            return -1107;

        if (XMEMCMP(cipher + (AES_BLOCK_SIZE * 2),
                    cipher1 + (AES_BLOCK_SIZE * 2), AES_BLOCK_SIZE))
            return -1108;

    #ifdef HAVE_AES_DECRYPT
        ret = wc_AesCfbDecrypt(&dec, plain, cipher, AES_BLOCK_SIZE * 3);
        if (ret != 0)
            return -1109;

        if (XMEMCMP(plain, msg1, AES_BLOCK_SIZE * 3))
            return -1110;
    #endif /* HAVE_AES_DECRYPT */
#endif /* WOLFSSL_AES_128 */

#ifdef WOLFSSL_AES_192
        /* 192 key size test */
        ret = wc_AesSetKey(&enc, key2, sizeof(key2), iv, AES_ENCRYPTION);
        if (ret != 0)
            return -1111;
    #ifdef HAVE_AES_DECRYPT
        /* decrypt uses AES_ENCRYPTION */
        ret = wc_AesSetKey(&dec, key2, sizeof(key2), iv, AES_ENCRYPTION);
        if (ret != 0)
            return -1112;
    #endif

        XMEMSET(cipher, 0, sizeof(cipher));
        ret = wc_AesCfbEncrypt(&enc, cipher, msg2, AES_BLOCK_SIZE * 4);
        if (ret != 0)
            return -1113;

        if (XMEMCMP(cipher, cipher2, AES_BLOCK_SIZE * 4))
            return -1114;

    #ifdef HAVE_AES_DECRYPT
        ret = wc_AesCfbDecrypt(&dec, plain, cipher, AES_BLOCK_SIZE * 4);
        if (ret != 0)
            return -1115;

        if (XMEMCMP(plain, msg2, AES_BLOCK_SIZE * 4))
            return -1116;
    #endif /* HAVE_AES_DECRYPT */
#endif /* WOLFSSL_AES_192 */

#ifdef WOLFSSL_AES_256
        /* 256 key size test */
        ret = wc_AesSetKey(&enc, key3, sizeof(key3), iv, AES_ENCRYPTION);
        if (ret != 0)
            return -1117;
    #ifdef HAVE_AES_DECRYPT
        /* decrypt uses AES_ENCRYPTION */
        ret = wc_AesSetKey(&dec, key3, sizeof(key3), iv, AES_ENCRYPTION);
        if (ret != 0)
            return -1118;
    #endif

        /* test with data left overs, magic lengths are checking near edges */
        XMEMSET(cipher, 0, sizeof(cipher));
        ret = wc_AesCfbEncrypt(&enc, cipher, msg3, 4);
        if (ret != 0)
            return -1119;

        if (XMEMCMP(cipher, cipher3, 4))
            return -1120;

        ret = wc_AesCfbEncrypt(&enc, cipher + 4, msg3 + 4, 27);
        if (ret != 0)
            return -1121;

        if (XMEMCMP(cipher + 4, cipher3 + 4, 27))
            return -1122;

        ret = wc_AesCfbEncrypt(&enc, cipher + 31, msg3 + 31,
                (AES_BLOCK_SIZE * 4) - 31);
        if (ret != 0)
            return -1123;

        if (XMEMCMP(cipher, cipher3, AES_BLOCK_SIZE * 4))
            return -1124;

    #ifdef HAVE_AES_DECRYPT
        ret = wc_AesCfbDecrypt(&dec, plain, cipher, 4);
        if (ret != 0)
            return -1125;

        if (XMEMCMP(plain, msg3, 4))
            return -1126;

        ret = wc_AesCfbDecrypt(&dec, plain + 4, cipher + 4, 4);
        if (ret != 0)
            return -1127;

        ret = wc_AesCfbDecrypt(&dec, plain + 8, cipher + 8, 23);
        if (ret != 0)
            return -1128;

        if (XMEMCMP(plain + 4, msg3 + 4, 27))
            return -1129;

        ret = wc_AesCfbDecrypt(&dec, plain + 31, cipher + 31,
                (AES_BLOCK_SIZE * 4) - 31);
        if (ret != 0)
            return -1130;

        if (XMEMCMP(plain, msg3, AES_BLOCK_SIZE * 4))
            return -1131;
    #endif /* HAVE_AES_DECRYPT */
#endif /* WOLFSSL_AES_256 */

        return ret;
    }
#endif /* WOLFSSL_AES_CFB */

static int aes_key_size_test(void)
{
    int    ret;
    Aes    aes;
    byte   key16[] = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                       0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66 };
    byte   key24[] = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                       0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
                       0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37 };
    byte   key32[] = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                       0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
                       0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                       0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66 };
    byte   iv[]    = "1234567890abcdef";
#ifndef HAVE_FIPS
    word32 keySize;
#endif

#ifdef WC_INITAES_H
    ret = wc_InitAes_h(NULL, NULL);
    if (ret != BAD_FUNC_ARG)
        return -4000;
    ret = wc_InitAes_h(&aes, NULL);
    if (ret != 0)
        return -4001;
#endif

#ifndef HAVE_FIPS
    /* Parameter Validation testing. */
    ret = wc_AesGetKeySize(NULL, NULL);
    if (ret != BAD_FUNC_ARG)
        return -4002;
    ret = wc_AesGetKeySize(&aes, NULL);
    if (ret != BAD_FUNC_ARG)
        return -4003;
    ret = wc_AesGetKeySize(NULL, &keySize);
    if (ret != BAD_FUNC_ARG)
        return -4004;
    /* Crashes in FIPS */
    ret = wc_AesSetKey(NULL, key16, sizeof(key16), iv, AES_ENCRYPTION);
    if (ret != BAD_FUNC_ARG)
        return -4005;
#endif
    /* NULL IV indicates to use all zeros IV. */
    ret = wc_AesSetKey(&aes, key16, sizeof(key16), NULL, AES_ENCRYPTION);
#ifdef WOLFSSL_AES_128
    if (ret != 0)
#else
    if (ret != BAD_FUNC_ARG)
#endif
        return -4006;
    ret = wc_AesSetKey(&aes, key32, sizeof(key32) - 1, iv, AES_ENCRYPTION);
    if (ret != BAD_FUNC_ARG)
        return -4007;
#ifndef HAVE_FIPS
    /* Force invalid rounds */
    aes.rounds = 16;
    ret = wc_AesGetKeySize(&aes, &keySize);
    if (ret != BAD_FUNC_ARG)
        return -4008;
#endif

    ret = wc_AesSetKey(&aes, key16, sizeof(key16), iv, AES_ENCRYPTION);
#ifdef WOLFSSL_AES_128
    if (ret != 0)
#else
    if (ret != BAD_FUNC_ARG)
#endif
        return -4009;
#if !defined(HAVE_FIPS) && defined(WOLFSSL_AES_128)
    ret = wc_AesGetKeySize(&aes, &keySize);
    if (ret != 0 || keySize != sizeof(key16))
        return -4010;
#endif

    ret = wc_AesSetKey(&aes, key24, sizeof(key24), iv, AES_ENCRYPTION);
#ifdef WOLFSSL_AES_192
    if (ret != 0)
#else
    if (ret != BAD_FUNC_ARG)
#endif
        return -4011;
#if !defined(HAVE_FIPS) && defined(WOLFSSL_AES_192)
    ret = wc_AesGetKeySize(&aes, &keySize);
    if (ret != 0 || keySize != sizeof(key24))
        return -4012;
#endif

    ret = wc_AesSetKey(&aes, key32, sizeof(key32), iv, AES_ENCRYPTION);
#ifdef WOLFSSL_AES_256
    if (ret != 0)
#else
    if (ret != BAD_FUNC_ARG)
#endif
        return -4013;
#if !defined(HAVE_FIPS) && defined(WOLFSSL_AES_256)
    ret = wc_AesGetKeySize(&aes, &keySize);
    if (ret != 0 || keySize != sizeof(key32))
        return -4014;
#endif

    return 0;
}

#if defined(WOLFSSL_AES_XTS)
/* test vectors from http://csrc.nist.gov/groups/STM/cavp/block-cipher-modes.html */
#ifdef WOLFSSL_AES_128
static int aes_xts_128_test(void)
{
    XtsAes aes;
    int ret = 0;
    unsigned char buf[AES_BLOCK_SIZE * 2];
    unsigned char cipher[AES_BLOCK_SIZE * 2];

    /* 128 key tests */
    static unsigned char k1[] = {
        0xa1, 0xb9, 0x0c, 0xba, 0x3f, 0x06, 0xac, 0x35,
        0x3b, 0x2c, 0x34, 0x38, 0x76, 0x08, 0x17, 0x62,
        0x09, 0x09, 0x23, 0x02, 0x6e, 0x91, 0x77, 0x18,
        0x15, 0xf2, 0x9d, 0xab, 0x01, 0x93, 0x2f, 0x2f
    };

    static unsigned char i1[] = {
        0x4f, 0xae, 0xf7, 0x11, 0x7c, 0xda, 0x59, 0xc6,
        0x6e, 0x4b, 0x92, 0x01, 0x3e, 0x76, 0x8a, 0xd5
    };

    static unsigned char p1[] = {
        0xeb, 0xab, 0xce, 0x95, 0xb1, 0x4d, 0x3c, 0x8d,
        0x6f, 0xb3, 0x50, 0x39, 0x07, 0x90, 0x31, 0x1c
    };

    /* plain text test of partial block is not from NIST test vector list */
    static unsigned char pp[] = {
        0xeb, 0xab, 0xce, 0x95, 0xb1, 0x4d, 0x3c, 0x8d,
        0x6f, 0xb3, 0x50, 0x39, 0x07, 0x90, 0x31, 0x1c,
        0x6e, 0x4b, 0x92, 0x01, 0x3e, 0x76, 0x8a, 0xd5
    };

    static unsigned char c1[] = {
        0x77, 0x8a, 0xe8, 0xb4, 0x3c, 0xb9, 0x8d, 0x5a,
        0x82, 0x50, 0x81, 0xd5, 0xbe, 0x47, 0x1c, 0x63
    };

    static unsigned char k2[] = {
        0x39, 0x25, 0x79, 0x05, 0xdf, 0xcc, 0x77, 0x76,
        0x6c, 0x87, 0x0a, 0x80, 0x6a, 0x60, 0xe3, 0xc0,
        0x93, 0xd1, 0x2a, 0xcf, 0xcb, 0x51, 0x42, 0xfa,
        0x09, 0x69, 0x89, 0x62, 0x5b, 0x60, 0xdb, 0x16
    };

    static unsigned char i2[] = {
        0x5c, 0xf7, 0x9d, 0xb6, 0xc5, 0xcd, 0x99, 0x1a,
        0x1c, 0x78, 0x81, 0x42, 0x24, 0x95, 0x1e, 0x84
    };

    static unsigned char p2[] = {
        0xbd, 0xc5, 0x46, 0x8f, 0xbc, 0x8d, 0x50, 0xa1,
        0x0d, 0x1c, 0x85, 0x7f, 0x79, 0x1c, 0x5c, 0xba,
        0xb3, 0x81, 0x0d, 0x0d, 0x73, 0xcf, 0x8f, 0x20,
        0x46, 0xb1, 0xd1, 0x9e, 0x7d, 0x5d, 0x8a, 0x56
    };

    static unsigned char c2[] = {
        0xd6, 0xbe, 0x04, 0x6d, 0x41, 0xf2, 0x3b, 0x5e,
        0xd7, 0x0b, 0x6b, 0x3d, 0x5c, 0x8e, 0x66, 0x23,
        0x2b, 0xe6, 0xb8, 0x07, 0xd4, 0xdc, 0xc6, 0x0e,
        0xff, 0x8d, 0xbc, 0x1d, 0x9f, 0x7f, 0xc8, 0x22
    };

    XMEMSET(buf, 0, sizeof(buf));
    if (wc_AesXtsSetKey(&aes, k2, sizeof(k2), AES_ENCRYPTION,
            HEAP_HINT, devId) != 0)
        return -4000;
    ret = wc_AesXtsEncrypt(&aes, buf, p2, sizeof(p2), i2, sizeof(i2));
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &aes.aes.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    if (ret != 0)
        return -4001;
    if (XMEMCMP(c2, buf, sizeof(c2)))
        return -4002;

    XMEMSET(buf, 0, sizeof(buf));
    if (wc_AesXtsSetKey(&aes, k1, sizeof(k1), AES_ENCRYPTION,
            HEAP_HINT, devId) != 0)
        return -4003;
    ret = wc_AesXtsEncrypt(&aes, buf, p1, sizeof(p1), i1, sizeof(i1));
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &aes.aes.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    if (ret != 0)
        return -4004;
    if (XMEMCMP(c1, buf, AES_BLOCK_SIZE))
        return -4005;

    /* partial block encryption test */
    XMEMSET(cipher, 0, sizeof(cipher));
    ret = wc_AesXtsEncrypt(&aes, cipher, pp, sizeof(pp), i1, sizeof(i1));
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &aes.aes.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    if (ret != 0)
        return -4006;
    wc_AesXtsFree(&aes);

    /* partial block decrypt test */
    XMEMSET(buf, 0, sizeof(buf));
    if (wc_AesXtsSetKey(&aes, k1, sizeof(k1), AES_DECRYPTION,
            HEAP_HINT, devId) != 0)
        return -4007;
    ret = wc_AesXtsDecrypt(&aes, buf, cipher, sizeof(pp), i1, sizeof(i1));
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &aes.aes.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    if (ret != 0)
        return -4008;
    if (XMEMCMP(pp, buf, sizeof(pp)))
        return -4009;

    /* NIST decrypt test vector */
    XMEMSET(buf, 0, sizeof(buf));
    ret = wc_AesXtsDecrypt(&aes, buf, c1, sizeof(c1), i1, sizeof(i1));
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &aes.aes.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    if (ret != 0)
        return -4010;
    if (XMEMCMP(p1, buf, AES_BLOCK_SIZE))
        return -4011;

    /* fail case with decrypting using wrong key */
    XMEMSET(buf, 0, sizeof(buf));
    ret = wc_AesXtsDecrypt(&aes, buf, c2, sizeof(c2), i2, sizeof(i2));
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &aes.aes.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    if (ret != 0)
        return -4012;
    if (XMEMCMP(p2, buf, sizeof(p2)) == 0) /* fail case with wrong key */
        return -4013;

    /* set correct key and retest */
    XMEMSET(buf, 0, sizeof(buf));
    if (wc_AesXtsSetKey(&aes, k2, sizeof(k2), AES_DECRYPTION,
            HEAP_HINT, devId) != 0)
        return -4014;
    ret = wc_AesXtsDecrypt(&aes, buf, c2, sizeof(c2), i2, sizeof(i2));
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &aes.aes.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    if (ret != 0)
        return -4015;
    if (XMEMCMP(p2, buf, sizeof(p2)))
        return -4016;
    wc_AesXtsFree(&aes);

    return ret;
}
#endif /* WOLFSSL_AES_128 */


#ifdef WOLFSSL_AES_256
static int aes_xts_256_test(void)
{
    XtsAes aes;
    int ret = 0;
    unsigned char buf[AES_BLOCK_SIZE * 3];
    unsigned char cipher[AES_BLOCK_SIZE * 3];

    /* 256 key tests */
    static unsigned char k1[] = {
        0x1e, 0xa6, 0x61, 0xc5, 0x8d, 0x94, 0x3a, 0x0e,
        0x48, 0x01, 0xe4, 0x2f, 0x4b, 0x09, 0x47, 0x14,
        0x9e, 0x7f, 0x9f, 0x8e, 0x3e, 0x68, 0xd0, 0xc7,
        0x50, 0x52, 0x10, 0xbd, 0x31, 0x1a, 0x0e, 0x7c,
        0xd6, 0xe1, 0x3f, 0xfd, 0xf2, 0x41, 0x8d, 0x8d,
        0x19, 0x11, 0xc0, 0x04, 0xcd, 0xa5, 0x8d, 0xa3,
        0xd6, 0x19, 0xb7, 0xe2, 0xb9, 0x14, 0x1e, 0x58,
        0x31, 0x8e, 0xea, 0x39, 0x2c, 0xf4, 0x1b, 0x08
    };

    static unsigned char i1[] = {
        0xad, 0xf8, 0xd9, 0x26, 0x27, 0x46, 0x4a, 0xd2,
        0xf0, 0x42, 0x8e, 0x84, 0xa9, 0xf8, 0x75, 0x64
    };

    static unsigned char p1[] = {
        0x2e, 0xed, 0xea, 0x52, 0xcd, 0x82, 0x15, 0xe1,
        0xac, 0xc6, 0x47, 0xe8, 0x10, 0xbb, 0xc3, 0x64,
        0x2e, 0x87, 0x28, 0x7f, 0x8d, 0x2e, 0x57, 0xe3,
        0x6c, 0x0a, 0x24, 0xfb, 0xc1, 0x2a, 0x20, 0x2e
    };

    /* plain text test of partial block is not from NIST test vector list */
    static unsigned char pp[] = {
        0xeb, 0xab, 0xce, 0x95, 0xb1, 0x4d, 0x3c, 0x8d,
        0x6f, 0xb3, 0x50, 0x39, 0x07, 0x90, 0x31, 0x1c,
        0x6e, 0x4b, 0x92, 0x01, 0x3e, 0x76, 0x8a, 0xd5
    };

    static unsigned char c1[] = {
        0xcb, 0xaa, 0xd0, 0xe2, 0xf6, 0xce, 0xa3, 0xf5,
        0x0b, 0x37, 0xf9, 0x34, 0xd4, 0x6a, 0x9b, 0x13,
        0x0b, 0x9d, 0x54, 0xf0, 0x7e, 0x34, 0xf3, 0x6a,
        0xf7, 0x93, 0xe8, 0x6f, 0x73, 0xc6, 0xd7, 0xdb
    };

    static unsigned char k2[] = {
        0xad, 0x50, 0x4b, 0x85, 0xd7, 0x51, 0xbf, 0xba,
        0x69, 0x13, 0xb4, 0xcc, 0x79, 0xb6, 0x5a, 0x62,
        0xf7, 0xf3, 0x9d, 0x36, 0x0f, 0x35, 0xb5, 0xec,
        0x4a, 0x7e, 0x95, 0xbd, 0x9b, 0xa5, 0xf2, 0xec,
        0xc1, 0xd7, 0x7e, 0xa3, 0xc3, 0x74, 0xbd, 0x4b,
        0x13, 0x1b, 0x07, 0x83, 0x87, 0xdd, 0x55, 0x5a,
        0xb5, 0xb0, 0xc7, 0xe5, 0x2d, 0xb5, 0x06, 0x12,
        0xd2, 0xb5, 0x3a, 0xcb, 0x47, 0x8a, 0x53, 0xb4
    };

    static unsigned char i2[] = {
        0xe6, 0x42, 0x19, 0xed, 0xe0, 0xe1, 0xc2, 0xa0,
        0x0e, 0xf5, 0x58, 0x6a, 0xc4, 0x9b, 0xeb, 0x6f
    };

    static unsigned char p2[] = {
        0x24, 0xcb, 0x76, 0x22, 0x55, 0xb5, 0xa8, 0x00,
        0xf4, 0x6e, 0x80, 0x60, 0x56, 0x9e, 0x05, 0x53,
        0xbc, 0xfe, 0x86, 0x55, 0x3b, 0xca, 0xd5, 0x89,
        0xc7, 0x54, 0x1a, 0x73, 0xac, 0xc3, 0x9a, 0xbd,
        0x53, 0xc4, 0x07, 0x76, 0xd8, 0xe8, 0x22, 0x61,
        0x9e, 0xa9, 0xad, 0x77, 0xa0, 0x13, 0x4c, 0xfc
    };

    static unsigned char c2[] = {
        0xa3, 0xc6, 0xf3, 0xf3, 0x82, 0x79, 0x5b, 0x10,
        0x87, 0xd7, 0x02, 0x50, 0xdb, 0x2c, 0xd3, 0xb1,
        0xa1, 0x62, 0xa8, 0xb6, 0xdc, 0x12, 0x60, 0x61,
        0xc1, 0x0a, 0x84, 0xa5, 0x85, 0x3f, 0x3a, 0x89,
        0xe6, 0x6c, 0xdb, 0xb7, 0x9a, 0xb4, 0x28, 0x9b,
        0xc3, 0xea, 0xd8, 0x10, 0xe9, 0xc0, 0xaf, 0x92
    };

    XMEMSET(buf, 0, sizeof(buf));
    if (wc_AesXtsSetKey(&aes, k2, sizeof(k2), AES_ENCRYPTION,
            HEAP_HINT, devId) != 0)
        return -4017;
    ret = wc_AesXtsEncrypt(&aes, buf, p2, sizeof(p2), i2, sizeof(i2));
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &aes.aes.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    if (ret != 0)
        return -4018;
    if (XMEMCMP(c2, buf, sizeof(c2)))
        return -4019;

    XMEMSET(buf, 0, sizeof(buf));
    if (wc_AesXtsSetKey(&aes, k1, sizeof(k1), AES_ENCRYPTION,
            HEAP_HINT, devId) != 0)
        return -4020;
    ret = wc_AesXtsEncrypt(&aes, buf, p1, sizeof(p1), i1, sizeof(i1));
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &aes.aes.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    if (ret != 0)
        return -4021;
    if (XMEMCMP(c1, buf, AES_BLOCK_SIZE))
        return -4022;

    /* partial block encryption test */
    XMEMSET(cipher, 0, sizeof(cipher));
    ret = wc_AesXtsEncrypt(&aes, cipher, pp, sizeof(pp), i1, sizeof(i1));
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &aes.aes.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    if (ret != 0)
        return -4023;
    wc_AesXtsFree(&aes);

    /* partial block decrypt test */
    XMEMSET(buf, 0, sizeof(buf));
    if (wc_AesXtsSetKey(&aes, k1, sizeof(k1), AES_DECRYPTION,
            HEAP_HINT, devId) != 0)
        return -4024;
    ret = wc_AesXtsDecrypt(&aes, buf, cipher, sizeof(pp), i1, sizeof(i1));
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &aes.aes.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    if (ret != 0)
        return -4025;
    if (XMEMCMP(pp, buf, sizeof(pp)))
        return -4026;

    /* NIST decrypt test vector */
    XMEMSET(buf, 0, sizeof(buf));
    ret = wc_AesXtsDecrypt(&aes, buf, c1, sizeof(c1), i1, sizeof(i1));
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &aes.aes.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    if (ret != 0)
        return -4027;
    if (XMEMCMP(p1, buf, AES_BLOCK_SIZE))
        return -4028;

    XMEMSET(buf, 0, sizeof(buf));
    if (wc_AesXtsSetKey(&aes, k2, sizeof(k2), AES_DECRYPTION,
            HEAP_HINT, devId) != 0)
        return -4029;
    ret = wc_AesXtsDecrypt(&aes, buf, c2, sizeof(c2), i2, sizeof(i2));
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &aes.aes.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    if (ret != 0)
        return -4030;
    if (XMEMCMP(p2, buf, sizeof(p2)))
        return -4031;
    wc_AesXtsFree(&aes);

    return ret;
}
#endif /* WOLFSSL_AES_256 */


#if defined(WOLFSSL_AES_128) && defined(WOLFSSL_AES_256)
/* both 128 and 256 bit key test */
static int aes_xts_sector_test(void)
{
    XtsAes aes;
    int ret = 0;
    unsigned char buf[AES_BLOCK_SIZE * 2];

    /* 128 key tests */
    static unsigned char k1[] = {
        0xa3, 0xe4, 0x0d, 0x5b, 0xd4, 0xb6, 0xbb, 0xed,
        0xb2, 0xd1, 0x8c, 0x70, 0x0a, 0xd2, 0xdb, 0x22,
        0x10, 0xc8, 0x11, 0x90, 0x64, 0x6d, 0x67, 0x3c,
        0xbc, 0xa5, 0x3f, 0x13, 0x3e, 0xab, 0x37, 0x3c
    };

    static unsigned char p1[] = {
        0x20, 0xe0, 0x71, 0x94, 0x05, 0x99, 0x3f, 0x09,
        0xa6, 0x6a, 0xe5, 0xbb, 0x50, 0x0e, 0x56, 0x2c
    };

    static unsigned char c1[] = {
        0x74, 0x62, 0x35, 0x51, 0x21, 0x02, 0x16, 0xac,
        0x92, 0x6b, 0x96, 0x50, 0xb6, 0xd3, 0xfa, 0x52
    };
    word64 s1 = 141;

    /* 256 key tests */
    static unsigned char k2[] = {
        0xef, 0x01, 0x0c, 0xa1, 0xa3, 0x66, 0x3e, 0x32,
        0x53, 0x43, 0x49, 0xbc, 0x0b, 0xae, 0x62, 0x23,
        0x2a, 0x15, 0x73, 0x34, 0x85, 0x68, 0xfb, 0x9e,
        0xf4, 0x17, 0x68, 0xa7, 0x67, 0x4f, 0x50, 0x7a,
        0x72, 0x7f, 0x98, 0x75, 0x53, 0x97, 0xd0, 0xe0,
        0xaa, 0x32, 0xf8, 0x30, 0x33, 0x8c, 0xc7, 0xa9,
        0x26, 0xc7, 0x73, 0xf0, 0x9e, 0x57, 0xb3, 0x57,
        0xcd, 0x15, 0x6a, 0xfb, 0xca, 0x46, 0xe1, 0xa0
    };

    static unsigned char p2[] = {
        0xed, 0x98, 0xe0, 0x17, 0x70, 0xa8, 0x53, 0xb4,
        0x9d, 0xb9, 0xe6, 0xaa, 0xf8, 0x8f, 0x0a, 0x41,
        0xb9, 0xb5, 0x6e, 0x91, 0xa5, 0xa2, 0xb1, 0x1d,
        0x40, 0x52, 0x92, 0x54, 0xf5, 0x52, 0x3e, 0x75
    };

    static unsigned char c2[] = {
        0xca, 0x20, 0xc5, 0x5e, 0x8d, 0xc1, 0x49, 0x68,
        0x7d, 0x25, 0x41, 0xde, 0x39, 0xc3, 0xdf, 0x63,
        0x00, 0xbb, 0x5a, 0x16, 0x3c, 0x10, 0xce, 0xd3,
        0x66, 0x6b, 0x13, 0x57, 0xdb, 0x8b, 0xd3, 0x9d
    };
    word64 s2 = 187;

    XMEMSET(buf, 0, sizeof(buf));
    if (wc_AesXtsSetKey(&aes, k1, sizeof(k1), AES_ENCRYPTION,
            HEAP_HINT, devId) != 0)
        return -4032;
    ret = wc_AesXtsEncryptSector(&aes, buf, p1, sizeof(p1), s1);
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &aes.aes.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    if (ret != 0)
        return -4033;
    if (XMEMCMP(c1, buf, AES_BLOCK_SIZE))
        return -4034;

    /* decrypt test */
    XMEMSET(buf, 0, sizeof(buf));
    if (wc_AesXtsSetKey(&aes, k1, sizeof(k1), AES_DECRYPTION,
            HEAP_HINT, devId) != 0)
        return -4035;
    ret = wc_AesXtsDecryptSector(&aes, buf, c1, sizeof(c1), s1);
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &aes.aes.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    if (ret != 0)
        return -4036;
    if (XMEMCMP(p1, buf, AES_BLOCK_SIZE))
        return -4037;
    wc_AesXtsFree(&aes);

    /* 256 bit key tests */
    XMEMSET(buf, 0, sizeof(buf));
    if (wc_AesXtsSetKey(&aes, k2, sizeof(k2), AES_ENCRYPTION,
            HEAP_HINT, devId) != 0)
        return -4038;
    ret = wc_AesXtsEncryptSector(&aes, buf, p2, sizeof(p2), s2);
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &aes.aes.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    if (ret != 0)
        return -4039;
    if (XMEMCMP(c2, buf, sizeof(c2)))
        return -4040;

    /* decrypt test */
    XMEMSET(buf, 0, sizeof(buf));
    if (wc_AesXtsSetKey(&aes, k2, sizeof(k2), AES_DECRYPTION,
            HEAP_HINT, devId) != 0)
        return -4041;
    ret = wc_AesXtsDecryptSector(&aes, buf, c2, sizeof(c2), s2);
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &aes.aes.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    if (ret != 0)
        return -4042;
    if (XMEMCMP(p2, buf, sizeof(p2)))
        return -4043;
    wc_AesXtsFree(&aes);

    return ret;
}
#endif /* WOLFSSL_AES_128 && WOLFSSL_AES_256 */


#ifdef WOLFSSL_AES_128
/* testing of bad arguments */
static int aes_xts_args_test(void)
{
    XtsAes aes;
    int ret = 0;
    unsigned char buf[AES_BLOCK_SIZE * 2];

    /* 128 key tests */
    static unsigned char k1[] = {
        0xa3, 0xe4, 0x0d, 0x5b, 0xd4, 0xb6, 0xbb, 0xed,
        0xb2, 0xd1, 0x8c, 0x70, 0x0a, 0xd2, 0xdb, 0x22,
        0x10, 0xc8, 0x11, 0x90, 0x64, 0x6d, 0x67, 0x3c,
        0xbc, 0xa5, 0x3f, 0x13, 0x3e, 0xab, 0x37, 0x3c
    };

    static unsigned char p1[] = {
        0x20, 0xe0, 0x71, 0x94, 0x05, 0x99, 0x3f, 0x09,
        0xa6, 0x6a, 0xe5, 0xbb, 0x50, 0x0e, 0x56, 0x2c
    };

    static unsigned char c1[] = {
        0x74, 0x62, 0x35, 0x51, 0x21, 0x02, 0x16, 0xac,
        0x92, 0x6b, 0x96, 0x50, 0xb6, 0xd3, 0xfa, 0x52
    };
    word64 s1 = 141;

    if (wc_AesXtsSetKey(NULL, k1, sizeof(k1), AES_ENCRYPTION,
            HEAP_HINT, devId) == 0)
        return -4044;
    if (wc_AesXtsSetKey(&aes, NULL, sizeof(k1), AES_ENCRYPTION,
            HEAP_HINT, devId) == 0)
        return -4045;

    /* encryption operations */
    if (wc_AesXtsSetKey(&aes, k1, sizeof(k1), AES_ENCRYPTION,
            HEAP_HINT, devId) != 0)
        return -4046;
    ret = wc_AesXtsEncryptSector(NULL, buf, p1, sizeof(p1), s1);
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &aes.aes.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    if (ret == 0)
        return -4047;

    ret = wc_AesXtsEncryptSector(&aes, NULL, p1, sizeof(p1), s1);
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &aes.aes.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    if (ret == 0)
        return -4048;
    wc_AesXtsFree(&aes);

    /* decryption operations */
    if (wc_AesXtsSetKey(&aes, k1, sizeof(k1), AES_DECRYPTION,
            HEAP_HINT, devId) != 0)
        return -4046;
    ret = wc_AesXtsDecryptSector(NULL, buf, c1, sizeof(c1), s1);
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &aes.aes.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    if (ret == 0)
        return -4049;

    ret = wc_AesXtsDecryptSector(&aes, NULL, c1, sizeof(c1), s1);
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &aes.aes.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    if (ret == 0)
        return -4050;
    wc_AesXtsFree(&aes);

    return 0;
}
#endif /* WOLFSSL_AES_128 */
#endif /* WOLFSSL_AES_XTS */

#if defined(HAVE_AES_CBC) && defined(WOLFSSL_AES_128)
static int aes_cbc_test(void)
{
    byte cipher[AES_BLOCK_SIZE];
    byte plain[AES_BLOCK_SIZE];
    int  ret;
    const byte msg[] = { /* "Now is the time for all " w/o trailing 0 */
        0x6e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
        0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20,
        0x66,0x6f,0x72,0x20,0x61,0x6c,0x6c,0x20
    };
    byte key[] = "0123456789abcdef   ";  /* align */
    byte iv[]  = "1234567890abcdef   ";  /* align */

    /* Parameter Validation testing. */
    ret = wc_AesCbcEncryptWithKey(cipher, msg, AES_BLOCK_SIZE, key, 17, NULL);
    if (ret != BAD_FUNC_ARG)
        return -4100;
#ifdef HAVE_AES_DECRYPT
    ret = wc_AesCbcDecryptWithKey(plain, cipher, AES_BLOCK_SIZE, key, 17, NULL);
    if (ret != BAD_FUNC_ARG)
        return -4101;
#endif

    ret = wc_AesCbcEncryptWithKey(cipher, msg, AES_BLOCK_SIZE, key,
                                  AES_BLOCK_SIZE, iv);
    if (ret != 0)
        return -4102;
#ifdef HAVE_AES_DECRYPT
    ret = wc_AesCbcDecryptWithKey(plain, cipher, AES_BLOCK_SIZE, key,
                                  AES_BLOCK_SIZE, iv);
    if (ret != 0)
        return -4103;
    if (XMEMCMP(plain, msg, AES_BLOCK_SIZE) != 0)
        return -4104;
#endif /* HAVE_AES_DECRYPT */

    (void)plain;
    return 0;
}
#endif

int aes_test(void)
{
#if defined(HAVE_AES_CBC) || defined(WOLFSSL_AES_COUNTER)
    Aes enc;
    byte cipher[AES_BLOCK_SIZE * 4];
#if defined(HAVE_AES_DECRYPT) || defined(WOLFSSL_AES_COUNTER)
    Aes dec;
    byte plain [AES_BLOCK_SIZE * 4];
#endif
#endif /* HAVE_AES_CBC || WOLFSSL_AES_COUNTER */
    int  ret = 0;

#ifdef HAVE_AES_CBC
#ifdef WOLFSSL_AES_128
    const byte msg[] = { /* "Now is the time for all " w/o trailing 0 */
        0x6e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
        0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20,
        0x66,0x6f,0x72,0x20,0x61,0x6c,0x6c,0x20
    };

    const byte verify[] =
    {
        0x95,0x94,0x92,0x57,0x5f,0x42,0x81,0x53,
        0x2c,0xcc,0x9d,0x46,0x77,0xa2,0x33,0xcb
    };

    byte key[] = "0123456789abcdef   ";  /* align */
    byte iv[]  = "1234567890abcdef   ";  /* align */

#ifdef WOLFSSL_ASYNC_CRYPT
    if (wc_AesInit(&enc, HEAP_HINT, devId) != 0)
        return -4200;
    if (wc_AesInit(&dec, HEAP_HINT, devId) != 0)
        return -4201;
#endif

    ret = wc_AesSetKey(&enc, key, AES_BLOCK_SIZE, iv, AES_ENCRYPTION);
    if (ret != 0)
        return -4202;
#ifdef HAVE_AES_DECRYPT
    ret = wc_AesSetKey(&dec, key, AES_BLOCK_SIZE, iv, AES_DECRYPTION);
    if (ret != 0)
        return -4203;
#endif

    ret = wc_AesCbcEncrypt(&enc, cipher, msg, AES_BLOCK_SIZE);
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &enc.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    if (ret != 0)
        return -4204;
#ifdef HAVE_AES_DECRYPT
    ret = wc_AesCbcDecrypt(&dec, plain, cipher, AES_BLOCK_SIZE);
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &dec.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    if (ret != 0)
        return -4205;

    if (XMEMCMP(plain, msg, AES_BLOCK_SIZE))
        return -4206;
#endif /* HAVE_AES_DECRYPT */
    if (XMEMCMP(cipher, verify, AES_BLOCK_SIZE))
        return -4207;
#endif /* WOLFSSL_AES_128 */

#if defined(WOLFSSL_AESNI) && defined(HAVE_AES_DECRYPT)
    {
        const byte bigMsg[] = {
            /* "All work and no play makes Jack a dull boy. " */
            0x41,0x6c,0x6c,0x20,0x77,0x6f,0x72,0x6b,
            0x20,0x61,0x6e,0x64,0x20,0x6e,0x6f,0x20,
            0x70,0x6c,0x61,0x79,0x20,0x6d,0x61,0x6b,
            0x65,0x73,0x20,0x4a,0x61,0x63,0x6b,0x20,
            0x61,0x20,0x64,0x75,0x6c,0x6c,0x20,0x62,
            0x6f,0x79,0x2e,0x20,0x41,0x6c,0x6c,0x20,
            0x77,0x6f,0x72,0x6b,0x20,0x61,0x6e,0x64,
            0x20,0x6e,0x6f,0x20,0x70,0x6c,0x61,0x79,
            0x20,0x6d,0x61,0x6b,0x65,0x73,0x20,0x4a,
            0x61,0x63,0x6b,0x20,0x61,0x20,0x64,0x75,
            0x6c,0x6c,0x20,0x62,0x6f,0x79,0x2e,0x20,
            0x41,0x6c,0x6c,0x20,0x77,0x6f,0x72,0x6b,
            0x20,0x61,0x6e,0x64,0x20,0x6e,0x6f,0x20,
            0x70,0x6c,0x61,0x79,0x20,0x6d,0x61,0x6b,
            0x65,0x73,0x20,0x4a,0x61,0x63,0x6b,0x20,
            0x61,0x20,0x64,0x75,0x6c,0x6c,0x20,0x62,
            0x6f,0x79,0x2e,0x20,0x41,0x6c,0x6c,0x20,
            0x77,0x6f,0x72,0x6b,0x20,0x61,0x6e,0x64,
            0x20,0x6e,0x6f,0x20,0x70,0x6c,0x61,0x79,
            0x20,0x6d,0x61,0x6b,0x65,0x73,0x20,0x4a,
            0x61,0x63,0x6b,0x20,0x61,0x20,0x64,0x75,
            0x6c,0x6c,0x20,0x62,0x6f,0x79,0x2e,0x20,
            0x41,0x6c,0x6c,0x20,0x77,0x6f,0x72,0x6b,
            0x20,0x61,0x6e,0x64,0x20,0x6e,0x6f,0x20,
            0x70,0x6c,0x61,0x79,0x20,0x6d,0x61,0x6b,
            0x65,0x73,0x20,0x4a,0x61,0x63,0x6b,0x20,
            0x61,0x20,0x64,0x75,0x6c,0x6c,0x20,0x62,
            0x6f,0x79,0x2e,0x20,0x41,0x6c,0x6c,0x20,
            0x77,0x6f,0x72,0x6b,0x20,0x61,0x6e,0x64,
            0x20,0x6e,0x6f,0x20,0x70,0x6c,0x61,0x79,
            0x20,0x6d,0x61,0x6b,0x65,0x73,0x20,0x4a,
            0x61,0x63,0x6b,0x20,0x61,0x20,0x64,0x75,
            0x6c,0x6c,0x20,0x62,0x6f,0x79,0x2e,0x20,
            0x41,0x6c,0x6c,0x20,0x77,0x6f,0x72,0x6b,
            0x20,0x61,0x6e,0x64,0x20,0x6e,0x6f,0x20,
            0x70,0x6c,0x61,0x79,0x20,0x6d,0x61,0x6b,
            0x65,0x73,0x20,0x4a,0x61,0x63,0x6b,0x20,
            0x61,0x20,0x64,0x75,0x6c,0x6c,0x20,0x62,
            0x6f,0x79,0x2e,0x20,0x41,0x6c,0x6c,0x20,
            0x77,0x6f,0x72,0x6b,0x20,0x61,0x6e,0x64,
            0x20,0x6e,0x6f,0x20,0x70,0x6c,0x61,0x79,
            0x20,0x6d,0x61,0x6b,0x65,0x73,0x20,0x4a,
            0x61,0x63,0x6b,0x20,0x61,0x20,0x64,0x75,
            0x6c,0x6c,0x20,0x62,0x6f,0x79,0x2e,0x20,
            0x41,0x6c,0x6c,0x20,0x77,0x6f,0x72,0x6b,
            0x20,0x61,0x6e,0x64,0x20,0x6e,0x6f,0x20,
            0x70,0x6c,0x61,0x79,0x20,0x6d,0x61,0x6b,
            0x65,0x73,0x20,0x4a,0x61,0x63,0x6b,0x20
        };
        const byte bigKey[] = "0123456789abcdeffedcba9876543210";
        byte bigCipher[sizeof(bigMsg)];
        byte bigPlain[sizeof(bigMsg)];
        word32 keySz, msgSz;

        /* Iterate from one AES_BLOCK_SIZE of bigMsg through the whole
         * message by AES_BLOCK_SIZE for each size of AES key. */
        for (keySz = 16; keySz <= 32; keySz += 8) {
            for (msgSz = AES_BLOCK_SIZE;
                 msgSz <= sizeof(bigMsg);
                 msgSz += AES_BLOCK_SIZE) {

                XMEMSET(bigCipher, 0, sizeof(bigCipher));
                XMEMSET(bigPlain, 0, sizeof(bigPlain));
                ret = wc_AesSetKey(&enc, bigKey, keySz, iv, AES_ENCRYPTION);
                if (ret != 0)
                    return -4208;
                ret = wc_AesSetKey(&dec, bigKey, keySz, iv, AES_DECRYPTION);
                if (ret != 0)
                    return -4209;

                ret = wc_AesCbcEncrypt(&enc, bigCipher, bigMsg, msgSz);
            #if defined(WOLFSSL_ASYNC_CRYPT)
                ret = wc_AsyncWait(ret, &enc.asyncDev, WC_ASYNC_FLAG_NONE);
            #endif
                if (ret != 0)
                    return -4210;

                ret = wc_AesCbcDecrypt(&dec, bigPlain, bigCipher, msgSz);
            #if defined(WOLFSSL_ASYNC_CRYPT)
                ret = wc_AsyncWait(ret, &dec.asyncDev, WC_ASYNC_FLAG_NONE);
            #endif
                if (ret != 0)
                    return -4211;

                if (XMEMCMP(bigPlain, bigMsg, msgSz))
                    return -4212;
            }
        }
    }
#endif /* WOLFSSL_AESNI HAVE_AES_DECRYPT */

    /* Test of AES IV state with encrypt/decrypt */
#ifdef WOLFSSL_AES_128
    {
        /* Test Vector from "NIST Special Publication 800-38A, 2001 Edition"
         * https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38a.pdf
         */
        const byte msg2[] =
        {
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
            0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51
        };

        const byte verify2[] =
        {
            0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
            0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
            0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee,
            0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2
        };
        byte key2[] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
        };
        byte iv2[]  = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
        };


        ret = wc_AesSetKey(&enc, key2, sizeof(key2), iv2, AES_ENCRYPTION);
        if (ret != 0)
            return -5366;
        XMEMSET(cipher, 0, AES_BLOCK_SIZE * 2);
        ret = wc_AesCbcEncrypt(&enc, cipher, msg2, AES_BLOCK_SIZE);
    #if defined(WOLFSSL_ASYNC_CRYPT)
        ret = wc_AsyncWait(ret, &enc.asyncDev, WC_ASYNC_FLAG_NONE);
    #endif
        if (ret != 0)
            return -5367;
        if (XMEMCMP(cipher, verify2, AES_BLOCK_SIZE))
            return -5368;

        ret = wc_AesCbcEncrypt(&enc, cipher + AES_BLOCK_SIZE,
                msg2 + AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    #if defined(WOLFSSL_ASYNC_CRYPT)
        ret = wc_AsyncWait(ret, &enc.asyncDev, WC_ASYNC_FLAG_NONE);
    #endif
        if (ret != 0)
            return -5369;
        if (XMEMCMP(cipher + AES_BLOCK_SIZE, verify2 + AES_BLOCK_SIZE,
                    AES_BLOCK_SIZE))
            return -5370;

        #if defined(HAVE_AES_DECRYPT)
        ret = wc_AesSetKey(&dec, key2, sizeof(key2), iv2, AES_DECRYPTION);
        if (ret != 0)
            return -5371;
        XMEMSET(plain, 0, AES_BLOCK_SIZE * 2);
        ret = wc_AesCbcDecrypt(&dec, plain, verify2, AES_BLOCK_SIZE);
    #if defined(WOLFSSL_ASYNC_CRYPT)
        ret = wc_AsyncWait(ret, &dec.asyncDev, WC_ASYNC_FLAG_NONE);
    #endif
        if (ret != 0)
            return -5372;
        if (XMEMCMP(plain, msg2, AES_BLOCK_SIZE))
            return -5373;

        ret = wc_AesCbcDecrypt(&dec, plain + AES_BLOCK_SIZE,
                verify2 + AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    #if defined(WOLFSSL_ASYNC_CRYPT)
        ret = wc_AsyncWait(ret, &dec.asyncDev, WC_ASYNC_FLAG_NONE);
    #endif
        if (ret != 0)
            return -5374;
        if (XMEMCMP(plain + AES_BLOCK_SIZE, msg2 + AES_BLOCK_SIZE,
                    AES_BLOCK_SIZE))
            return -5375;

        #endif /* HAVE_AES_DECRYPT */
    }
#endif /* WOLFSSL_AES_128 */
#endif /* HAVE_AES_CBC */

#ifdef WOLFSSL_AES_COUNTER
    {
        /* test vectors from "Recommendation for Block Cipher Modes of
         * Operation" NIST Special Publication 800-38A */

        const byte ctrIv[] =
        {
            0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,
            0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff
        };

        const byte ctrPlain[] =
        {
            0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
            0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
            0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,
            0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
            0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,
            0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,
            0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,
            0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10
        };

#ifdef WOLFSSL_AES_128
        const byte oddCipher[] =
        {
            0xb9,0xd7,0xcb,0x08,0xb0,0xe1,0x7b,0xa0,
            0xc2
        };

        const byte ctr128Key[] =
        {
            0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
            0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
        };

        const byte ctr128Cipher[] =
        {
            0x87,0x4d,0x61,0x91,0xb6,0x20,0xe3,0x26,
            0x1b,0xef,0x68,0x64,0x99,0x0d,0xb6,0xce,
            0x98,0x06,0xf6,0x6b,0x79,0x70,0xfd,0xff,
            0x86,0x17,0x18,0x7b,0xb9,0xff,0xfd,0xff,
            0x5a,0xe4,0xdf,0x3e,0xdb,0xd5,0xd3,0x5e,
            0x5b,0x4f,0x09,0x02,0x0d,0xb0,0x3e,0xab,
            0x1e,0x03,0x1d,0xda,0x2f,0xbe,0x03,0xd1,
            0x79,0x21,0x70,0xa0,0xf3,0x00,0x9c,0xee
        };
#endif /* WOLFSSL_AES_128 */

#ifdef WOLFSSL_AES_192
        const byte ctr192Key[] =
        {
            0x8e,0x73,0xb0,0xf7,0xda,0x0e,0x64,0x52,
            0xc8,0x10,0xf3,0x2b,0x80,0x90,0x79,0xe5,
            0x62,0xf8,0xea,0xd2,0x52,0x2c,0x6b,0x7b
        };

        const byte ctr192Cipher[] =
        {
            0x1a,0xbc,0x93,0x24,0x17,0x52,0x1c,0xa2,
            0x4f,0x2b,0x04,0x59,0xfe,0x7e,0x6e,0x0b,
            0x09,0x03,0x39,0xec,0x0a,0xa6,0xfa,0xef,
            0xd5,0xcc,0xc2,0xc6,0xf4,0xce,0x8e,0x94,
            0x1e,0x36,0xb2,0x6b,0xd1,0xeb,0xc6,0x70,
            0xd1,0xbd,0x1d,0x66,0x56,0x20,0xab,0xf7,
            0x4f,0x78,0xa7,0xf6,0xd2,0x98,0x09,0x58,
            0x5a,0x97,0xda,0xec,0x58,0xc6,0xb0,0x50
        };
#endif
#ifdef WOLFSSL_AES_256
        const byte ctr256Key[] =
        {
            0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
            0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
            0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
            0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
        };

        const byte ctr256Cipher[] =
        {
            0x60,0x1e,0xc3,0x13,0x77,0x57,0x89,0xa5,
            0xb7,0xa7,0xf5,0x04,0xbb,0xf3,0xd2,0x28,
            0xf4,0x43,0xe3,0xca,0x4d,0x62,0xb5,0x9a,
            0xca,0x84,0xe9,0x90,0xca,0xca,0xf5,0xc5,
            0x2b,0x09,0x30,0xda,0xa2,0x3d,0xe9,0x4c,
            0xe8,0x70,0x17,0xba,0x2d,0x84,0x98,0x8d,
            0xdf,0xc9,0xc5,0x8d,0xb6,0x7a,0xad,0xa6,
            0x13,0xc2,0xdd,0x08,0x45,0x79,0x41,0xa6
        };
#endif

#ifdef WOLFSSL_AES_128
        wc_AesSetKeyDirect(&enc, ctr128Key, sizeof(ctr128Key),
                           ctrIv, AES_ENCRYPTION);
        /* Ctr only uses encrypt, even on key setup */
        wc_AesSetKeyDirect(&dec, ctr128Key, sizeof(ctr128Key),
                           ctrIv, AES_ENCRYPTION);

        ret = wc_AesCtrEncrypt(&enc, cipher, ctrPlain, sizeof(ctrPlain));
        if (ret != 0) {
            return -4227;
        }
        ret = wc_AesCtrEncrypt(&dec, plain, cipher, sizeof(ctrPlain));
        if (ret != 0) {
            return -4228;
        }
        if (XMEMCMP(plain, ctrPlain, sizeof(ctrPlain)))
            return -4213;

        if (XMEMCMP(cipher, ctr128Cipher, sizeof(ctr128Cipher)))
            return -4214;

        /* let's try with just 9 bytes, non block size test */
        wc_AesSetKeyDirect(&enc, ctr128Key, AES_BLOCK_SIZE,
                           ctrIv, AES_ENCRYPTION);
        /* Ctr only uses encrypt, even on key setup */
        wc_AesSetKeyDirect(&dec, ctr128Key, AES_BLOCK_SIZE,
                           ctrIv, AES_ENCRYPTION);

        ret = wc_AesCtrEncrypt(&enc, cipher, ctrPlain, sizeof(oddCipher));
        if (ret != 0) {
            return -4229;
        }
        ret = wc_AesCtrEncrypt(&dec, plain, cipher, sizeof(oddCipher));
        if (ret != 0) {
            return -4230;
        }

        if (XMEMCMP(plain, ctrPlain, sizeof(oddCipher)))
            return -4215;

        if (XMEMCMP(cipher, ctr128Cipher, sizeof(oddCipher)))
            return -4216;

        /* and an additional 9 bytes to reuse tmp left buffer */
        ret = wc_AesCtrEncrypt(&enc, cipher, ctrPlain, sizeof(oddCipher));
        if (ret != 0) {
            return -4231;
        }
        ret = wc_AesCtrEncrypt(&dec, plain, cipher, sizeof(oddCipher));
        if (ret != 0) {
            return -4232;
        }

        if (XMEMCMP(plain, ctrPlain, sizeof(oddCipher)))
            return -4217;

        if (XMEMCMP(cipher, oddCipher, sizeof(oddCipher)))
            return -4218;
#endif /* WOLFSSL_AES_128 */

#ifdef WOLFSSL_AES_192
        /* 192 bit key */
        wc_AesSetKeyDirect(&enc, ctr192Key, sizeof(ctr192Key),
                           ctrIv, AES_ENCRYPTION);
        /* Ctr only uses encrypt, even on key setup */
        wc_AesSetKeyDirect(&dec, ctr192Key, sizeof(ctr192Key),
                           ctrIv, AES_ENCRYPTION);

        XMEMSET(plain, 0, sizeof(plain));
        ret = wc_AesCtrEncrypt(&enc, plain, ctr192Cipher, sizeof(ctr192Cipher));
        if (ret != 0) {
            return -4233;
        }

        if (XMEMCMP(plain, ctrPlain, sizeof(ctr192Cipher)))
            return -4219;

        ret = wc_AesCtrEncrypt(&dec, cipher, ctrPlain, sizeof(ctrPlain));
        if (ret != 0) {
            return -4234;
        }
        if (XMEMCMP(ctr192Cipher, cipher, sizeof(ctr192Cipher)))
            return -4220;
#endif /* WOLFSSL_AES_192 */

#ifdef WOLFSSL_AES_256
        /* 256 bit key */
        wc_AesSetKeyDirect(&enc, ctr256Key, sizeof(ctr256Key),
                           ctrIv, AES_ENCRYPTION);
        /* Ctr only uses encrypt, even on key setup */
        wc_AesSetKeyDirect(&dec, ctr256Key, sizeof(ctr256Key),
                           ctrIv, AES_ENCRYPTION);

        XMEMSET(plain, 0, sizeof(plain));
        ret = wc_AesCtrEncrypt(&enc, plain, ctr256Cipher, sizeof(ctr256Cipher));
        if (ret != 0) {
            return -4235;
        }

        if (XMEMCMP(plain, ctrPlain, sizeof(ctrPlain)))
            return -4221;

        ret = wc_AesCtrEncrypt(&dec, cipher, ctrPlain, sizeof(ctrPlain));
        if (ret != 0) {
            return -4236;
        }
        if (XMEMCMP(ctr256Cipher, cipher, sizeof(ctr256Cipher)))
            return -4222;
#endif /* WOLFSSL_AES_256 */
    }
#endif /* WOLFSSL_AES_COUNTER */

#if defined(WOLFSSL_AES_DIRECT) && defined(WOLFSSL_AES_256)
    {
        const byte niPlain[] =
        {
            0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
            0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a
        };

        const byte niCipher[] =
        {
            0xf3,0xee,0xd1,0xbd,0xb5,0xd2,0xa0,0x3c,
            0x06,0x4b,0x5a,0x7e,0x3d,0xb1,0x81,0xf8
        };

        const byte niKey[] =
        {
            0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
            0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
            0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
            0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
        };

        XMEMSET(cipher, 0, AES_BLOCK_SIZE);
        ret = wc_AesSetKey(&enc, niKey, sizeof(niKey), cipher, AES_ENCRYPTION);
        if (ret != 0)
            return -4223;
        wc_AesEncryptDirect(&enc, cipher, niPlain);
        if (XMEMCMP(cipher, niCipher, AES_BLOCK_SIZE) != 0)
            return -4224;

        XMEMSET(plain, 0, AES_BLOCK_SIZE);
        ret = wc_AesSetKey(&dec, niKey, sizeof(niKey), plain, AES_DECRYPTION);
        if (ret != 0)
            return -4225;
        wc_AesDecryptDirect(&dec, plain, niCipher);
        if (XMEMCMP(plain, niPlain, AES_BLOCK_SIZE) != 0)
            return -4226;
    }
#endif /* WOLFSSL_AES_DIRECT && WOLFSSL_AES_256 */

    ret = aes_key_size_test();
    if (ret != 0)
        return ret;

#if defined(HAVE_AES_CBC) && defined(WOLFSSL_AES_128)
    ret = aes_cbc_test();
    if (ret != 0)
        return ret;
#endif

#if defined(WOLFSSL_AES_XTS)
    #ifdef WOLFSSL_AES_128
    ret = aes_xts_128_test();
    if (ret != 0)
        return ret;
    #endif
    #ifdef WOLFSSL_AES_256
    ret = aes_xts_256_test();
    if (ret != 0)
        return ret;
    #endif
    #if defined(WOLFSSL_AES_128) && defined(WOLFSSL_AES_256)
    ret = aes_xts_sector_test();
    if (ret != 0)
        return ret;
    #endif
    #ifdef WOLFSSL_AES_128
    ret = aes_xts_args_test();
    if (ret != 0)
        return ret;
    #endif
#endif

#if defined(WOLFSSL_AES_CFB)
    ret = aescfb_test();
    if (ret != 0)
        return ret;
#endif


    wc_AesFree(&enc);
#ifdef HAVE_AES_DECRYPT
    wc_AesFree(&dec);
    (void)plain;
#endif

    (void)cipher;

    return ret;
}

#ifdef WOLFSSL_AES_192
int aes192_test(void)
{
#ifdef HAVE_AES_CBC
    Aes enc;
    byte cipher[AES_BLOCK_SIZE];
#ifdef HAVE_AES_DECRYPT
    Aes dec;
    byte plain[AES_BLOCK_SIZE];
#endif
#endif /* HAVE_AES_CBC */
    int  ret = 0;

#ifdef HAVE_AES_CBC
    /* Test vectors from NIST Special Publication 800-38A, 2001 Edition
     * Appendix F.2.3  */

    const byte msg[] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
        0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a
    };

    const byte verify[] =
    {
        0x4f,0x02,0x1d,0xb2,0x43,0xbc,0x63,0x3d,
        0x71,0x78,0x18,0x3a,0x9f,0xa0,0x71,0xe8
    };

    byte key[] = {
        0x8e,0x73,0xb0,0xf7,0xda,0x0e,0x64,0x52,
        0xc8,0x10,0xf3,0x2b,0x80,0x90,0x79,0xe5,
        0x62,0xf8,0xea,0xd2,0x52,0x2c,0x6b,0x7b
    };
    byte iv[]  = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F
    };


    if (wc_AesInit(&enc, HEAP_HINT, devId) != 0)
        return -4230;
#ifdef HAVE_AES_DECRYPT
    if (wc_AesInit(&dec, HEAP_HINT, devId) != 0)
        return -4231;
#endif

    ret = wc_AesSetKey(&enc, key, (int) sizeof(key), iv, AES_ENCRYPTION);
    if (ret != 0)
        return -4232;
#ifdef HAVE_AES_DECRYPT
    ret = wc_AesSetKey(&dec, key, (int) sizeof(key), iv, AES_DECRYPTION);
    if (ret != 0)
        return -4233;
#endif

    ret = wc_AesCbcEncrypt(&enc, cipher, msg, (int) sizeof(msg));
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &enc.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    if (ret != 0)
        return -4234;
#ifdef HAVE_AES_DECRYPT
    ret = wc_AesCbcDecrypt(&dec, plain, cipher, (int) sizeof(cipher));
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &dec.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    if (ret != 0)
        return -4235;
    if (XMEMCMP(plain, msg, (int) sizeof(plain))) {
        return -4236;
    }
#endif

    if (XMEMCMP(cipher, verify, (int) sizeof(cipher)))
        return -4237;

    wc_AesFree(&enc);
#ifdef HAVE_AES_DECRYPT
    wc_AesFree(&dec);
#endif

#endif /* HAVE_AES_CBC */

    return ret;
}
#endif /* WOLFSSL_AES_192 */

#ifdef WOLFSSL_AES_256
int aes256_test(void)
{
#ifdef HAVE_AES_CBC
    Aes enc;
    byte cipher[AES_BLOCK_SIZE];
#ifdef HAVE_AES_DECRYPT
    Aes dec;
    byte plain[AES_BLOCK_SIZE];
#endif
#endif /* HAVE_AES_CBC */
    int  ret = 0;

#ifdef HAVE_AES_CBC
    /* Test vectors from NIST Special Publication 800-38A, 2001 Edition,
     * Appendix F.2.5  */
    const byte msg[] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
        0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a
    };

    const byte verify[] =
    {
        0xf5,0x8c,0x4c,0x04,0xd6,0xe5,0xf1,0xba,
        0x77,0x9e,0xab,0xfb,0x5f,0x7b,0xfb,0xd6
    };

    byte key[] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
        0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
        0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
        0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
    };
    byte iv[]  = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F
    };


    if (wc_AesInit(&enc, HEAP_HINT, devId) != 0)
        return -4240;
#ifdef HAVE_AES_DECRYPT
    if (wc_AesInit(&dec, HEAP_HINT, devId) != 0)
        return -4241;
#endif

    ret = wc_AesSetKey(&enc, key, (int) sizeof(key), iv, AES_ENCRYPTION);
    if (ret != 0)
        return -4242;
#ifdef HAVE_AES_DECRYPT
    ret = wc_AesSetKey(&dec, key, (int) sizeof(key), iv, AES_DECRYPTION);
    if (ret != 0)
        return -4243;
#endif

    ret = wc_AesCbcEncrypt(&enc, cipher, msg, (int) sizeof(msg));
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &enc.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    if (ret != 0)
        return -4244;
#ifdef HAVE_AES_DECRYPT
    ret = wc_AesCbcDecrypt(&dec, plain, cipher, (int) sizeof(cipher));
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &dec.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    if (ret != 0)
        return -4245;
    if (XMEMCMP(plain, msg, (int) sizeof(plain))) {
        return -4246;
    }
#endif

    if (XMEMCMP(cipher, verify, (int) sizeof(cipher)))
        return -4247;

    wc_AesFree(&enc);
#ifdef HAVE_AES_DECRYPT
    wc_AesFree(&dec);
#endif

#endif /* HAVE_AES_CBC */

    return ret;
}
#endif /* WOLFSSL_AES_256 */


#ifdef HAVE_AESGCM
int aesgcm_test(void)
{
    Aes enc;

    /*
     * This is Test Case 16 from the document Galois/
     * Counter Mode of Operation (GCM) by McGrew and
     * Viega.
     */
    const byte p[] =
    {
        0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
        0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
        0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
        0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
        0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
        0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
        0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
        0xba, 0x63, 0x7b, 0x39
    };

    const byte a[] =
    {
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xab, 0xad, 0xda, 0xd2
    };

#ifdef WOLFSSL_AES_256
    const byte k1[] =
    {
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
    };

    const byte iv1[] =
    {
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
        0xde, 0xca, 0xf8, 0x88
    };

    const byte c1[] =
    {
        0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07,
        0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d,
        0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9,
        0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa,
        0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d,
        0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38,
        0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a,
        0xbc, 0xc9, 0xf6, 0x62
    };
#endif /* WOLFSSL_AES_256 */

    const byte t1[] =
    {
        0x76, 0xfc, 0x6e, 0xce, 0x0f, 0x4e, 0x17, 0x68,
        0xcd, 0xdf, 0x88, 0x53, 0xbb, 0x2d, 0x55, 0x1b
    };

    /* FIPS, QAT and STM32F2/4 HW Crypto only support 12-byte IV */
#if !defined(HAVE_FIPS) && \
        !defined(STM32_CRYPTO) && !defined(WOLFSSL_PIC32MZ_CRYPT) && \
        !defined(WOLFSSL_XILINX_CRYPT)

    #define ENABLE_NON_12BYTE_IV_TEST
#ifdef WOLFSSL_AES_192
    /* Test Case 12, uses same plaintext and AAD data. */
    const byte k2[] =
    {
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c
    };

    const byte iv2[] =
    {
        0x93, 0x13, 0x22, 0x5d, 0xf8, 0x84, 0x06, 0xe5,
        0x55, 0x90, 0x9c, 0x5a, 0xff, 0x52, 0x69, 0xaa,
        0x6a, 0x7a, 0x95, 0x38, 0x53, 0x4f, 0x7d, 0xa1,
        0xe4, 0xc3, 0x03, 0xd2, 0xa3, 0x18, 0xa7, 0x28,
        0xc3, 0xc0, 0xc9, 0x51, 0x56, 0x80, 0x95, 0x39,
        0xfc, 0xf0, 0xe2, 0x42, 0x9a, 0x6b, 0x52, 0x54,
        0x16, 0xae, 0xdb, 0xf5, 0xa0, 0xde, 0x6a, 0x57,
        0xa6, 0x37, 0xb3, 0x9b
    };

    const byte c2[] =
    {
        0xd2, 0x7e, 0x88, 0x68, 0x1c, 0xe3, 0x24, 0x3c,
        0x48, 0x30, 0x16, 0x5a, 0x8f, 0xdc, 0xf9, 0xff,
        0x1d, 0xe9, 0xa1, 0xd8, 0xe6, 0xb4, 0x47, 0xef,
        0x6e, 0xf7, 0xb7, 0x98, 0x28, 0x66, 0x6e, 0x45,
        0x81, 0xe7, 0x90, 0x12, 0xaf, 0x34, 0xdd, 0xd9,
        0xe2, 0xf0, 0x37, 0x58, 0x9b, 0x29, 0x2d, 0xb3,
        0xe6, 0x7c, 0x03, 0x67, 0x45, 0xfa, 0x22, 0xe7,
        0xe9, 0xb7, 0x37, 0x3b
    };

    const byte t2[] =
    {
        0xdc, 0xf5, 0x66, 0xff, 0x29, 0x1c, 0x25, 0xbb,
        0xb8, 0x56, 0x8f, 0xc3, 0xd3, 0x76, 0xa6, 0xd9
    };
#endif /* WOLFSSL_AES_192 */
#ifdef WOLFSSL_AES_128
    /* The following is an interesting test case from the example
     * FIPS test vectors for AES-GCM. IVlen = 1 byte */
    const byte p3[] =
    {
        0x57, 0xce, 0x45, 0x1f, 0xa5, 0xe2, 0x35, 0xa5,
        0x8e, 0x1a, 0xa2, 0x3b, 0x77, 0xcb, 0xaf, 0xe2
    };

    const byte k3[] =
    {
        0xbb, 0x01, 0xd7, 0x03, 0x81, 0x1c, 0x10, 0x1a,
        0x35, 0xe0, 0xff, 0xd2, 0x91, 0xba, 0xf2, 0x4b
    };

    const byte iv3[] =
    {
        0xca
    };

    const byte c3[] =
    {
        0x6b, 0x5f, 0xb3, 0x9d, 0xc1, 0xc5, 0x7a, 0x4f,
        0xf3, 0x51, 0x4d, 0xc2, 0xd5, 0xf0, 0xd0, 0x07
    };

    const byte a3[] =
    {
        0x40, 0xfc, 0xdc, 0xd7, 0x4a, 0xd7, 0x8b, 0xf1,
        0x3e, 0x7c, 0x60, 0x55, 0x50, 0x51, 0xdd, 0x54
    };

    const byte t3[] =
    {
        0x06, 0x90, 0xed, 0x01, 0x34, 0xdd, 0xc6, 0x95,
        0x31, 0x2e, 0x2a, 0xf9, 0x57, 0x7a, 0x1e, 0xa6
    };
#endif /* WOLFSSL_AES_128 */
#ifdef WOLFSSL_AES_256
    int ivlen;
#endif
#endif

    byte resultT[sizeof(t1)];
    byte resultP[sizeof(p)];
    byte resultC[sizeof(p)];
    int  result;
#ifdef WOLFSSL_AES_256
    int  alen, plen;
#endif

#if !defined(BENCH_EMBEDDED)
    #ifndef BENCH_AESGCM_LARGE
        #define BENCH_AESGCM_LARGE 1024
    #endif
    byte large_input[BENCH_AESGCM_LARGE];
    byte large_output[BENCH_AESGCM_LARGE];
    byte large_outdec[BENCH_AESGCM_LARGE];

    XMEMSET(large_input, 0, sizeof(large_input));
    XMEMSET(large_output, 0, sizeof(large_output));
    XMEMSET(large_outdec, 0, sizeof(large_outdec));
#endif

    XMEMSET(resultT, 0, sizeof(resultT));
    XMEMSET(resultC, 0, sizeof(resultC));
    XMEMSET(resultP, 0, sizeof(resultP));

    if (wc_AesInit(&enc, HEAP_HINT, devId) != 0) {
        return -4300;
    }

#ifdef WOLFSSL_AES_256
    result = wc_AesGcmSetKey(&enc, k1, sizeof(k1));
    if (result != 0)
        return -4301;

    /* AES-GCM encrypt and decrypt both use AES encrypt internally */
    result = wc_AesGcmEncrypt(&enc, resultC, p, sizeof(p), iv1, sizeof(iv1),
                                        resultT, sizeof(resultT), a, sizeof(a));
#if defined(WOLFSSL_ASYNC_CRYPT)
    result = wc_AsyncWait(result, &enc.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    if (result != 0)
        return -4302;
    if (XMEMCMP(c1, resultC, sizeof(resultC)))
        return -4303;
    if (XMEMCMP(t1, resultT, sizeof(resultT)))
        return -4304;

#ifdef HAVE_AES_DECRYPT
    result = wc_AesGcmDecrypt(&enc, resultP, resultC, sizeof(resultC),
                      iv1, sizeof(iv1), resultT, sizeof(resultT), a, sizeof(a));
#if defined(WOLFSSL_ASYNC_CRYPT)
    result = wc_AsyncWait(result, &enc.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    if (result != 0)
        return -4305;
    if (XMEMCMP(p, resultP, sizeof(resultP)))
        return -4306;
#endif /* HAVE_AES_DECRYPT */

    /* Large buffer test */
#ifdef BENCH_AESGCM_LARGE
    /* setup test buffer */
    for (alen=0; alen<BENCH_AESGCM_LARGE; alen++)
        large_input[alen] = (byte)alen;

    /* AES-GCM encrypt and decrypt both use AES encrypt internally */
    result = wc_AesGcmEncrypt(&enc, large_output, large_input,
                              BENCH_AESGCM_LARGE, iv1, sizeof(iv1),
                              resultT, sizeof(resultT), a, sizeof(a));
#if defined(WOLFSSL_ASYNC_CRYPT)
    result = wc_AsyncWait(result, &enc.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    if (result != 0)
        return -4307;

#ifdef HAVE_AES_DECRYPT
    result = wc_AesGcmDecrypt(&enc, large_outdec, large_output,
                              BENCH_AESGCM_LARGE, iv1, sizeof(iv1), resultT,
                              sizeof(resultT), a, sizeof(a));
#if defined(WOLFSSL_ASYNC_CRYPT)
    result = wc_AsyncWait(result, &enc.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    if (result != 0)
        return -4308;
    if (XMEMCMP(large_input, large_outdec, BENCH_AESGCM_LARGE))
        return -4309;
#endif /* HAVE_AES_DECRYPT */
#endif /* BENCH_AESGCM_LARGE */
#ifdef ENABLE_NON_12BYTE_IV_TEST
    /* Variable IV length test */
    for (ivlen=0; ivlen<(int)sizeof(k1); ivlen++) {
         /* AES-GCM encrypt and decrypt both use AES encrypt internally */
         result = wc_AesGcmEncrypt(&enc, resultC, p, sizeof(p), k1,
                         (word32)ivlen, resultT, sizeof(resultT), a, sizeof(a));
#if defined(WOLFSSL_ASYNC_CRYPT)
        result = wc_AsyncWait(result, &enc.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
        if (result != 0)
            return -4310;
#ifdef HAVE_AES_DECRYPT
        result = wc_AesGcmDecrypt(&enc, resultP, resultC, sizeof(resultC), k1,
                         (word32)ivlen, resultT, sizeof(resultT), a, sizeof(a));
#if defined(WOLFSSL_ASYNC_CRYPT)
        result = wc_AsyncWait(result, &enc.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
        if (result != 0)
            return -4311;
#endif /* HAVE_AES_DECRYPT */
    }
#endif

    /* Variable authenticed data length test */
    for (alen=0; alen<(int)sizeof(p); alen++) {
         /* AES-GCM encrypt and decrypt both use AES encrypt internally */
         result = wc_AesGcmEncrypt(&enc, resultC, p, sizeof(p), iv1,
                        sizeof(iv1), resultT, sizeof(resultT), p, (word32)alen);
#if defined(WOLFSSL_ASYNC_CRYPT)
        result = wc_AsyncWait(result, &enc.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
        if (result != 0)
            return -4312;
#ifdef HAVE_AES_DECRYPT
        result = wc_AesGcmDecrypt(&enc, resultP, resultC, sizeof(resultC), iv1,
                        sizeof(iv1), resultT, sizeof(resultT), p, (word32)alen);
#if defined(WOLFSSL_ASYNC_CRYPT)
        result = wc_AsyncWait(result, &enc.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
        if (result != 0)
            return -4313;
#endif /* HAVE_AES_DECRYPT */
    }

#ifdef BENCH_AESGCM_LARGE
    /* Variable plain text length test */
    for (plen=1; plen<BENCH_AESGCM_LARGE; plen++) {
        /* AES-GCM encrypt and decrypt both use AES encrypt internally */
        result = wc_AesGcmEncrypt(&enc, large_output, large_input,
                                  plen, iv1, sizeof(iv1), resultT,
                                  sizeof(resultT), a, sizeof(a));
#if defined(WOLFSSL_ASYNC_CRYPT)
        result = wc_AsyncWait(result, &enc.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
        if (result != 0)
            return -4314;

#ifdef HAVE_AES_DECRYPT
        result = wc_AesGcmDecrypt(&enc, large_outdec, large_output,
                                  plen, iv1, sizeof(iv1), resultT,
                                  sizeof(resultT), a, sizeof(a));
#if defined(WOLFSSL_ASYNC_CRYPT)
        result = wc_AsyncWait(result, &enc.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
        if (result != 0)
            return -4315;
#endif /* HAVE_AES_DECRYPT */
    }
#else
    /* Variable plain text length test */
    for (plen=1; plen<(int)sizeof(p); plen++) {
         /* AES-GCM encrypt and decrypt both use AES encrypt internally */
         result = wc_AesGcmEncrypt(&enc, resultC, p, (word32)plen, iv1,
                           sizeof(iv1), resultT, sizeof(resultT), a, sizeof(a));
#if defined(WOLFSSL_ASYNC_CRYPT)
        result = wc_AsyncWait(result, &enc.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
        if (result != 0)
            return -4314;
#ifdef HAVE_AES_DECRYPT
        result = wc_AesGcmDecrypt(&enc, resultP, resultC, (word32)plen, iv1,
                           sizeof(iv1), resultT, sizeof(resultT), a, sizeof(a));
#if defined(WOLFSSL_ASYNC_CRYPT)
        result = wc_AsyncWait(result, &enc.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
        if (result != 0)
            return -4315;
#endif /* HAVE_AES_DECRYPT */
    }
#endif /* BENCH_AESGCM_LARGE */
#endif /* WOLFSSL_AES_256 */

    /* test with IV != 12 bytes */
#ifdef ENABLE_NON_12BYTE_IV_TEST
    XMEMSET(resultT, 0, sizeof(resultT));
    XMEMSET(resultC, 0, sizeof(resultC));
    XMEMSET(resultP, 0, sizeof(resultP));

#ifdef WOLFSSL_AES_192
    wc_AesGcmSetKey(&enc, k2, sizeof(k2));
    /* AES-GCM encrypt and decrypt both use AES encrypt internally */
    result = wc_AesGcmEncrypt(&enc, resultC, p, sizeof(p), iv2, sizeof(iv2),
                                        resultT, sizeof(resultT), a, sizeof(a));
#if defined(WOLFSSL_ASYNC_CRYPT)
    result = wc_AsyncWait(result, &enc.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    if (result != 0)
        return -4316;
    if (XMEMCMP(c2, resultC, sizeof(resultC)))
        return -4317;
    if (XMEMCMP(t2, resultT, sizeof(resultT)))
        return -4318;

#ifdef HAVE_AES_DECRYPT
    result = wc_AesGcmDecrypt(&enc, resultP, resultC, sizeof(resultC),
                      iv2, sizeof(iv2), resultT, sizeof(resultT), a, sizeof(a));
#if defined(WOLFSSL_ASYNC_CRYPT)
    result = wc_AsyncWait(result, &enc.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    if (result != 0)
        return -4319;
    if (XMEMCMP(p, resultP, sizeof(resultP)))
        return -4320;
#endif /* HAVE_AES_DECRYPT */

    XMEMSET(resultT, 0, sizeof(resultT));
    XMEMSET(resultC, 0, sizeof(resultC));
    XMEMSET(resultP, 0, sizeof(resultP));
#endif /* WOLFSSL_AES_192 */
#ifdef WOLFSSL_AES_128
    wc_AesGcmSetKey(&enc, k3, sizeof(k3));
    /* AES-GCM encrypt and decrypt both use AES encrypt internally */
    result = wc_AesGcmEncrypt(&enc, resultC, p3, sizeof(p3), iv3, sizeof(iv3),
                                        resultT, sizeof(t3), a3, sizeof(a3));
#if defined(WOLFSSL_ASYNC_CRYPT)
    result = wc_AsyncWait(result, &enc.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    if (result != 0)
        return -8209;
    if (XMEMCMP(c3, resultC, sizeof(c3)))
        return -8210;
    if (XMEMCMP(t3, resultT, sizeof(t3)))
        return -8211;

#ifdef HAVE_AES_DECRYPT
    result = wc_AesGcmDecrypt(&enc, resultP, resultC, sizeof(c3),
                      iv3, sizeof(iv3), resultT, sizeof(t3), a3, sizeof(a3));
#if defined(WOLFSSL_ASYNC_CRYPT)
    result = wc_AsyncWait(result, &enc.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    if (result != 0)
        return -8212;
    if (XMEMCMP(p3, resultP, sizeof(p3)))
        return -8213;
#endif /* HAVE_AES_DECRYPT */
#endif /* WOLFSSL_AES_128 */
#endif /* ENABLE_NON_12BYTE_IV_TEST */

#ifdef WOLFSSL_AES_256
    XMEMSET(resultT, 0, sizeof(resultT));
    XMEMSET(resultC, 0, sizeof(resultC));
    XMEMSET(resultP, 0, sizeof(resultP));

    wc_AesGcmSetKey(&enc, k1, sizeof(k1));
    /* AES-GCM encrypt and decrypt both use AES encrypt internally */
    result = wc_AesGcmEncrypt(&enc, resultC, p, sizeof(p), iv1, sizeof(iv1),
                                resultT + 1, sizeof(resultT) - 1, a, sizeof(a));
#if defined(WOLFSSL_ASYNC_CRYPT)
    result = wc_AsyncWait(result, &enc.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    if (result != 0)
        return -4321;
    if (XMEMCMP(c1, resultC, sizeof(resultC)))
        return -4322;
    if (XMEMCMP(t1, resultT + 1, sizeof(resultT) - 1))
        return -4323;

#ifdef HAVE_AES_DECRYPT
    result = wc_AesGcmDecrypt(&enc, resultP, resultC, sizeof(resultC),
              iv1, sizeof(iv1), resultT + 1, sizeof(resultT) - 1, a, sizeof(a));
#if defined(WOLFSSL_ASYNC_CRYPT)
    result = wc_AsyncWait(result, &enc.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    if (result != 0)
        return -4324;
    if (XMEMCMP(p, resultP, sizeof(resultP)))
        return -4325;
#endif /* HAVE_AES_DECRYPT */
#endif /* WOLFSSL_AES_256 */
    wc_AesFree(&enc);

    return 0;
}

#ifdef WOLFSSL_AES_128
int gmac_test(void)
{
    Gmac gmac;

    const byte k1[] =
    {
        0x89, 0xc9, 0x49, 0xe9, 0xc8, 0x04, 0xaf, 0x01,
        0x4d, 0x56, 0x04, 0xb3, 0x94, 0x59, 0xf2, 0xc8
    };
    const byte iv1[] =
    {
        0xd1, 0xb1, 0x04, 0xc8, 0x15, 0xbf, 0x1e, 0x94,
        0xe2, 0x8c, 0x8f, 0x16
    };
    const byte a1[] =
    {
       0x82, 0xad, 0xcd, 0x63, 0x8d, 0x3f, 0xa9, 0xd9,
       0xf3, 0xe8, 0x41, 0x00, 0xd6, 0x1e, 0x07, 0x77
    };
    const byte t1[] =
    {
        0x88, 0xdb, 0x9d, 0x62, 0x17, 0x2e, 0xd0, 0x43,
        0xaa, 0x10, 0xf1, 0x6d, 0x22, 0x7d, 0xc4, 0x1b
    };

    const byte k2[] =
    {
        0x40, 0xf7, 0xec, 0xb2, 0x52, 0x6d, 0xaa, 0xd4,
        0x74, 0x25, 0x1d, 0xf4, 0x88, 0x9e, 0xf6, 0x5b
    };
    const byte iv2[] =
    {
        0xee, 0x9c, 0x6e, 0x06, 0x15, 0x45, 0x45, 0x03,
        0x1a, 0x60, 0x24, 0xa7
    };
    const byte a2[] =
    {
        0x94, 0x81, 0x2c, 0x87, 0x07, 0x4e, 0x15, 0x18,
        0x34, 0xb8, 0x35, 0xaf, 0x1c, 0xa5, 0x7e, 0x56
    };
    const byte t2[] =
    {
        0xc6, 0x81, 0x79, 0x8e, 0x3d, 0xda, 0xb0, 0x9f,
        0x8d, 0x83, 0xb0, 0xbb, 0x14, 0xb6, 0x91
    };

    byte tag[16];

    XMEMSET(&gmac, 0, sizeof(Gmac)); /* clear context */
    XMEMSET(tag, 0, sizeof(tag));
    wc_GmacSetKey(&gmac, k1, sizeof(k1));
    wc_GmacUpdate(&gmac, iv1, sizeof(iv1), a1, sizeof(a1), tag, sizeof(t1));
    if (XMEMCMP(t1, tag, sizeof(t1)) != 0)
        return -4400;

    XMEMSET(tag, 0, sizeof(tag));
    wc_GmacSetKey(&gmac, k2, sizeof(k2));
    wc_GmacUpdate(&gmac, iv2, sizeof(iv2), a2, sizeof(a2), tag, sizeof(t2));
    if (XMEMCMP(t2, tag, sizeof(t2)) != 0)
        return -4401;

    return 0;
}
#endif /* WOLFSSL_AES_128 */
#endif /* HAVE_AESGCM */

#if defined(HAVE_AESCCM) && defined(WOLFSSL_AES_128)
int aesccm_test(void)
{
    Aes enc;

    /* key */
    const byte k[] =
    {
        0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf
    };

    /* nonce */
    const byte iv[] =
    {
        0x00, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00, 0xa0,
        0xa1, 0xa2, 0xa3, 0xa4, 0xa5
    };

    /* plaintext */
    const byte p[] =
    {
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e
    };

    const byte a[] =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
    };

    const byte c[] =
    {
        0x58, 0x8c, 0x97, 0x9a, 0x61, 0xc6, 0x63, 0xd2,
        0xf0, 0x66, 0xd0, 0xc2, 0xc0, 0xf9, 0x89, 0x80,
        0x6d, 0x5f, 0x6b, 0x61, 0xda, 0xc3, 0x84
    };

    const byte t[] =
    {
        0x17, 0xe8, 0xd1, 0x2c, 0xfd, 0xf9, 0x26, 0xe0
    };

    byte t2[sizeof(t)];
    byte p2[sizeof(p)];
    byte c2[sizeof(c)];

    int result;

    XMEMSET(&enc, 0, sizeof(Aes)); /* clear context */
    XMEMSET(t2, 0, sizeof(t2));
    XMEMSET(c2, 0, sizeof(c2));
    XMEMSET(p2, 0, sizeof(p2));

    result = wc_AesCcmSetKey(&enc, k, sizeof(k));
    if (result != 0)
        return -4500;

    /* AES-CCM encrypt and decrypt both use AES encrypt internally */
    result = wc_AesCcmEncrypt(&enc, c2, p, sizeof(c2), iv, sizeof(iv),
                                                 t2, sizeof(t2), a, sizeof(a));
    if (result != 0)
        return -4501;
    if (XMEMCMP(c, c2, sizeof(c2)))
        return -4502;
    if (XMEMCMP(t, t2, sizeof(t2)))
        return -4503;

    result = wc_AesCcmDecrypt(&enc, p2, c2, sizeof(p2), iv, sizeof(iv),
                                                 t2, sizeof(t2), a, sizeof(a));
    if (result != 0)
        return -4504;
    if (XMEMCMP(p, p2, sizeof(p2)))
        return -4505;

    /* Test the authentication failure */
    t2[0]++; /* Corrupt the authentication tag. */
    result = wc_AesCcmDecrypt(&enc, p2, c, sizeof(p2), iv, sizeof(iv),
                                                 t2, sizeof(t2), a, sizeof(a));
    if (result == 0)
        return -4506;

    /* Clear c2 to compare against p2. p2 should be set to zero in case of
     * authentication fail. */
    XMEMSET(c2, 0, sizeof(c2));
    if (XMEMCMP(p2, c2, sizeof(p2)))
        return -4507;

    return 0;
}
#endif /* HAVE_AESCCM WOLFSSL_AES_128 */


#ifdef HAVE_AES_KEYWRAP

#define MAX_KEYWRAP_TEST_OUTLEN 40
#define MAX_KEYWRAP_TEST_PLAINLEN 32

typedef struct keywrapVector {
    const byte* kek;
    const byte* data;
    const byte* verify;
    word32 kekLen;
    word32 dataLen;
    word32 verifyLen;
} keywrapVector;

int aeskeywrap_test(void)
{
    int wrapSz, plainSz, testSz, i;

    /* test vectors from RFC 3394 (kek, data, verify) */

#ifdef WOLFSSL_AES_128
    /* Wrap 128 bits of Key Data with a 128-bit KEK */
    const byte k1[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    const byte d1[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
    };

    const byte v1[] = {
        0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47,
        0xAE, 0xF3, 0x4B, 0xD8, 0xFB, 0x5A, 0x7B, 0x82,
        0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2, 0xCF, 0xE5
    };
#endif /* WOLFSSL_AES_128 */

#ifdef WOLFSSL_AES_192
    /* Wrap 128 bits of Key Data with a 192-bit KEK */
    const byte k2[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
    };

    const byte d2[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
    };

    const byte v2[] = {
        0x96, 0x77, 0x8B, 0x25, 0xAE, 0x6C, 0xA4, 0x35,
        0xF9, 0x2B, 0x5B, 0x97, 0xC0, 0x50, 0xAE, 0xD2,
        0x46, 0x8A, 0xB8, 0xA1, 0x7A, 0xD8, 0x4E, 0x5D
    };
#endif

#ifdef WOLFSSL_AES_256
    /* Wrap 128 bits of Key Data with a 256-bit KEK */
    const byte k3[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };

    const byte d3[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
    };

    const byte v3[] = {
        0x64, 0xE8, 0xC3, 0xF9, 0xCE, 0x0F, 0x5B, 0xA2,
        0x63, 0xE9, 0x77, 0x79, 0x05, 0x81, 0x8A, 0x2A,
        0x93, 0xC8, 0x19, 0x1E, 0x7D, 0x6E, 0x8A, 0xE7
    };
#endif

#ifdef WOLFSSL_AES_192
    /* Wrap 192 bits of Key Data with a 192-bit KEK */
    const byte k4[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
    };

    const byte d4[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
    };

    const byte v4[] = {
        0x03, 0x1D, 0x33, 0x26, 0x4E, 0x15, 0xD3, 0x32,
        0x68, 0xF2, 0x4E, 0xC2, 0x60, 0x74, 0x3E, 0xDC,
        0xE1, 0xC6, 0xC7, 0xDD, 0xEE, 0x72, 0x5A, 0x93,
        0x6B, 0xA8, 0x14, 0x91, 0x5C, 0x67, 0x62, 0xD2
    };
#endif

#ifdef WOLFSSL_AES_256
    /* Wrap 192 bits of Key Data with a 256-bit KEK */
    const byte k5[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };

    const byte d5[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
    };

    const byte v5[] = {
        0xA8, 0xF9, 0xBC, 0x16, 0x12, 0xC6, 0x8B, 0x3F,
        0xF6, 0xE6, 0xF4, 0xFB, 0xE3, 0x0E, 0x71, 0xE4,
        0x76, 0x9C, 0x8B, 0x80, 0xA3, 0x2C, 0xB8, 0x95,
        0x8C, 0xD5, 0xD1, 0x7D, 0x6B, 0x25, 0x4D, 0xA1
    };

    /* Wrap 256 bits of Key Data with a 256-bit KEK */
    const byte k6[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };

    const byte d6[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    const byte v6[] = {
        0x28, 0xC9, 0xF4, 0x04, 0xC4, 0xB8, 0x10, 0xF4,
        0xCB, 0xCC, 0xB3, 0x5C, 0xFB, 0x87, 0xF8, 0x26,
        0x3F, 0x57, 0x86, 0xE2, 0xD8, 0x0E, 0xD3, 0x26,
        0xCB, 0xC7, 0xF0, 0xE7, 0x1A, 0x99, 0xF4, 0x3B,
        0xFB, 0x98, 0x8B, 0x9B, 0x7A, 0x02, 0xDD, 0x21
    };
#endif /* WOLFSSL_AES_256 */

    byte output[MAX_KEYWRAP_TEST_OUTLEN];
    byte plain [MAX_KEYWRAP_TEST_PLAINLEN];

    const keywrapVector test_wrap[] =
    {
    #ifdef WOLFSSL_AES_128
        {k1, d1, v1, sizeof(k1), sizeof(d1), sizeof(v1)},
    #endif
    #ifdef WOLFSSL_AES_192
        {k2, d2, v2, sizeof(k2), sizeof(d2), sizeof(v2)},
    #endif
    #ifdef WOLFSSL_AES_256
        {k3, d3, v3, sizeof(k3), sizeof(d3), sizeof(v3)},
    #endif
    #ifdef WOLFSSL_AES_192
        {k4, d4, v4, sizeof(k4), sizeof(d4), sizeof(v4)},
    #endif
    #ifdef WOLFSSL_AES_256
        {k5, d5, v5, sizeof(k5), sizeof(d5), sizeof(v5)},
        {k6, d6, v6, sizeof(k6), sizeof(d6), sizeof(v6)}
    #endif
    };
    testSz = sizeof(test_wrap) / sizeof(keywrapVector);

    XMEMSET(output, 0, sizeof(output));
    XMEMSET(plain,  0, sizeof(plain));

    for (i = 0; i < testSz; i++) {

        wrapSz = wc_AesKeyWrap(test_wrap[i].kek, test_wrap[i].kekLen,
                               test_wrap[i].data, test_wrap[i].dataLen,
                               output, sizeof(output), NULL);

        if ( (wrapSz < 0) || (wrapSz != (int)test_wrap[i].verifyLen) )
            return -4600;

        if (XMEMCMP(output, test_wrap[i].verify, test_wrap[i].verifyLen) != 0)
            return -4601;

        plainSz = wc_AesKeyUnWrap((byte*)test_wrap[i].kek, test_wrap[i].kekLen,
                                  output, wrapSz,
                                  plain, sizeof(plain), NULL);

        if ( (plainSz < 0) || (plainSz != (int)test_wrap[i].dataLen) )
            return -4602;

        if (XMEMCMP(plain, test_wrap[i].data, test_wrap[i].dataLen) != 0)
            return -4610 - i;
    }

    return 0;
}
#endif /* HAVE_AES_KEYWRAP */
#endif /* NO_AES */

#ifdef HAVE_STACK_SIZE
THREAD_RETURN WOLFSSL_THREAD wolfcrypt_test(void* args)
#else
int wolfcrypt_test(void* args)
#endif
{
    int ret;

#ifdef WOLFSSL_TRACK_MEMORY
    InitMemoryTracker();
#endif

#ifndef NO_AES
    if ( (ret = aes_test()) != 0)
        return err_sys("AES      test failed!\n", ret);
    else
        printf( "AES      test passed!\n");

#ifdef WOLFSSL_AES_192
    if ( (ret = aes192_test()) != 0)
        return err_sys("AES192   test failed!\n", ret);
    else
        printf( "AES192   test passed!\n");
#endif

#ifdef WOLFSSL_AES_256
    if ( (ret = aes256_test()) != 0)
        return err_sys("AES256   test failed!\n", ret);
    else
        printf( "AES256   test passed!\n");
#endif
#ifdef HAVE_AESGCM
    if ( (ret = aesgcm_test()) != 0)
        return err_sys("AES-GCM  test failed!\n", ret);
    else
        printf( "AES-GCM  test passed!\n");
#endif

#if defined(HAVE_AESCCM) && defined(WOLFSSL_AES_128)
    if ( (ret = aesccm_test()) != 0)
        return err_sys("AES-CCM  test failed!\n", ret);
    else
        printf( "AES-CCM  test passed!\n");
#endif
#ifdef HAVE_AES_KEYWRAP
    if ( (ret = aeskeywrap_test()) != 0)
        return err_sys("AES Key Wrap test failed!\n", ret);
    else
        printf( "AES Key Wrap test passed!\n");
#endif
#endif

#ifdef WOLFSSL_TRACK_MEMORY
    ShowMemoryTracker();
#endif

    EXIT_TEST(ret);
}

int main (void)
{
    func_args args;

    #ifdef HAVE_STACK_SIZE
        StackSizeCheck(&args, wolfcrypt_test);
    #else
        wolfcrypt_test(&args);
    #endif

    return 0;
}

