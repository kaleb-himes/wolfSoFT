#include <stdio.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/signature.h>
#include <wolfssl/certs_test.h>
#include <wolfssl/wolfcrypt/mem_track.h>

#define FOURK_BUF 4096
#define HEAP_HINT NULL
/* for async devices */
static int devId = INVALID_DEVID;


#define ERROR_OUT(err, eLabel) { ret = (err); goto eLabel; }

#ifdef HAVE_STACK_SIZE
    #include <wolfssl/ssl.h>
    #define err_sys err_sys_remap /* remap err_sys */
    #include <wolfssl/test.h>
    #undef err_sys

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


#ifndef NO_RSA
static int rsa_flatten_test(RsaKey* key)
{
    int    ret;
    byte   e[256];
    byte   n[256];
    word32 eSz = sizeof(e);
    word32 nSz = sizeof(n);

    /* Parameter Validation testing. */
    ret = wc_RsaFlattenPublicKey(NULL, e, &eSz, n, &nSz);
#ifdef HAVE_USER_RSA
    /* Implementation using IPP Libraries returns:
     *     -101 = USER_CRYPTO_ERROR
     */
    if (ret == 0)
#else
    if (ret != BAD_FUNC_ARG)
#endif
        return -5330;
    ret = wc_RsaFlattenPublicKey(key, NULL, &eSz, n, &nSz);
#ifdef HAVE_USER_RSA
    /* Implementation using IPP Libraries returns:
     *     -101 = USER_CRYPTO_ERROR
     */
    if (ret == 0)
#else
    if (ret != BAD_FUNC_ARG)
#endif
        return -5331;
    ret = wc_RsaFlattenPublicKey(key, e, NULL, n, &nSz);
#ifdef HAVE_USER_RSA
    /* Implementation using IPP Libraries returns:
     *     -101 = USER_CRYPTO_ERROR
     */
    if (ret == 0)
#else
    if (ret != BAD_FUNC_ARG)
#endif
        return -5332;
    ret = wc_RsaFlattenPublicKey(key, e, &eSz, NULL, &nSz);
#ifdef HAVE_USER_RSA
    /* Implementation using IPP Libraries returns:
     *     -101 = USER_CRYPTO_ERROR
     */
    if (ret == 0)
#else
    if (ret != BAD_FUNC_ARG)
#endif
        return -5333;
    ret = wc_RsaFlattenPublicKey(key, e, &eSz, n, NULL);
#ifdef HAVE_USER_RSA
    /* Implementation using IPP Libraries returns:
     *     -101 = USER_CRYPTO_ERROR
     */
    if (ret == 0)
#else
    if (ret != BAD_FUNC_ARG)
#endif
        return -5334;
    ret = wc_RsaFlattenPublicKey(key, e, &eSz, n, &nSz);
    if (ret != 0)
        return -5335;
    eSz = 0;
    ret = wc_RsaFlattenPublicKey(key, e, &eSz, n, &nSz);
#ifdef HAVE_USER_RSA
    /* Implementation using IPP Libraries returns:
     *     -101 = USER_CRYPTO_ERROR
     */
    if (ret == 0)
#elif defined(HAVE_FIPS) && \
      (!defined(HAVE_FIPS_VERSION) || (HAVE_FIPS_VERSION < 2))
    if (ret != 0)
#else
    if (ret != RSA_BUFFER_E)
#endif
        return -5336;
    eSz = sizeof(e);
    nSz = 0;
    ret = wc_RsaFlattenPublicKey(key, e, &eSz, n, &nSz);
#ifdef HAVE_USER_RSA
    /* Implementation using IPP Libraries returns:
     *     -101 = USER_CRYPTO_ERROR
     */
    if (ret == 0)
#else
    if (ret != RSA_BUFFER_E)
#endif
        return -5337;

    return 0;
}

#ifndef NO_SIG_WRAPPER
static int rsa_sig_test(RsaKey* key, word32 keyLen, int modLen, WC_RNG* rng)
{
    int ret;
    word32 sigSz;
    byte   in[] = "Everyone gets Friday off.";
    word32 inLen = (word32)XSTRLEN((char*)in);
    byte   out[256];

    /* Parameter Validation testing. */
    ret = wc_SignatureGetSize(WC_SIGNATURE_TYPE_NONE, key, keyLen);
    if (ret != BAD_FUNC_ARG)
        return -5338;
    ret = wc_SignatureGetSize(WC_SIGNATURE_TYPE_RSA, key, 0);
    if (ret != BAD_FUNC_ARG)
        return -5339;

    sigSz = (word32)modLen;
    ret = wc_SignatureGenerate(WC_HASH_TYPE_SHA256, WC_SIGNATURE_TYPE_RSA, NULL,
                               inLen, out, &sigSz, key, keyLen, rng);
    if (ret != BAD_FUNC_ARG)
        return -5340;
    ret = wc_SignatureGenerate(WC_HASH_TYPE_SHA256, WC_SIGNATURE_TYPE_RSA, in,
                               0, out, &sigSz, key, keyLen, rng);
    if (ret != BAD_FUNC_ARG)
        return -5341;
    ret = wc_SignatureGenerate(WC_HASH_TYPE_SHA256, WC_SIGNATURE_TYPE_RSA, in,
                               inLen, NULL, &sigSz, key, keyLen, rng);
    if (ret != BAD_FUNC_ARG)
        return -5342;
    ret = wc_SignatureGenerate(WC_HASH_TYPE_SHA256, WC_SIGNATURE_TYPE_RSA, in,
                               inLen, out, NULL, key, keyLen, rng);
    if (ret != BAD_FUNC_ARG)
        return -5343;
    ret = wc_SignatureGenerate(WC_HASH_TYPE_SHA256, WC_SIGNATURE_TYPE_RSA, in,
                               inLen, out, &sigSz, NULL, keyLen, rng);
    if (ret != BAD_FUNC_ARG)
        return -5344;
    ret = wc_SignatureGenerate(WC_HASH_TYPE_SHA256, WC_SIGNATURE_TYPE_RSA, in,
                               inLen, out, &sigSz, key, 0, rng);
    if (ret != BAD_FUNC_ARG)
        return -5345;
    ret = wc_SignatureGenerate(WC_HASH_TYPE_SHA256, WC_SIGNATURE_TYPE_RSA, in,
                               inLen, out, &sigSz, key, keyLen, NULL);
#ifdef HAVE_USER_RSA
    /* Implementation using IPP Libraries returns:
     *     -101 = USER_CRYPTO_ERROR
     */
    if (ret == 0)
#elif defined(WOLFSSL_ASYNC_CRYPT)
    /* async may not require RNG */
    if (ret != 0 && ret != MISSING_RNG_E)
#elif defined(HAVE_FIPS) || defined(WOLFSSL_ASYNC_CRYPT) || \
     !defined(WC_RSA_BLINDING)
    /* FIPS140 implementation does not do blinding */
    if (ret != 0)
#else
    if (ret != MISSING_RNG_E)
#endif
        return -5346;
    sigSz = 0;
    ret = wc_SignatureGenerate(WC_HASH_TYPE_SHA256, WC_SIGNATURE_TYPE_RSA, in,
                               inLen, out, &sigSz, key, keyLen, rng);
    if (ret != BAD_FUNC_ARG)
        return -5347;

    ret = wc_SignatureVerify(WC_HASH_TYPE_SHA256, WC_SIGNATURE_TYPE_RSA, NULL,
                             inLen, out, (word32)modLen, key, keyLen);
    if (ret != BAD_FUNC_ARG)
        return -5348;
    ret = wc_SignatureVerify(WC_HASH_TYPE_SHA256, WC_SIGNATURE_TYPE_RSA, in,
                             0, out, (word32)modLen, key, keyLen);
    if (ret != BAD_FUNC_ARG)
        return -5349;
    ret = wc_SignatureVerify(WC_HASH_TYPE_SHA256, WC_SIGNATURE_TYPE_RSA, in,
                             inLen, NULL, (word32)modLen, key, keyLen);
    if (ret != BAD_FUNC_ARG)
        return -5350;
    ret = wc_SignatureVerify(WC_HASH_TYPE_SHA256, WC_SIGNATURE_TYPE_RSA, in,
                             inLen, out, 0, key, keyLen);
    if (ret != BAD_FUNC_ARG)
        return -5351;
    ret = wc_SignatureVerify(WC_HASH_TYPE_SHA256, WC_SIGNATURE_TYPE_RSA, in,
                             inLen, out, (word32)modLen, NULL, keyLen);
    if (ret != BAD_FUNC_ARG)
        return -5352;
    ret = wc_SignatureVerify(WC_HASH_TYPE_SHA256, WC_SIGNATURE_TYPE_RSA, in,
                             inLen, out, (word32)modLen, key, 0);
    if (ret != BAD_FUNC_ARG)
        return -5353;

#ifndef HAVE_ECC
    ret = wc_SignatureGetSize(WC_SIGNATURE_TYPE_ECC, key, keyLen);
    if (ret != SIG_TYPE_E)
        return -5354;
#endif

    /* Use APIs. */
    ret = wc_SignatureGetSize(WC_SIGNATURE_TYPE_RSA, key, keyLen);
    if (ret != modLen)
        return -5355;
    ret = wc_SignatureGetSize(WC_SIGNATURE_TYPE_RSA_W_ENC, key, keyLen);
    if (ret != modLen)
        return -5356;

    sigSz = (word32)ret;
    ret = wc_SignatureGenerate(WC_HASH_TYPE_SHA256, WC_SIGNATURE_TYPE_RSA, in,
                               inLen, out, &sigSz, key, keyLen, rng);
    if (ret != 0)
        return -5357;

    ret = wc_SignatureVerify(WC_HASH_TYPE_SHA256, WC_SIGNATURE_TYPE_RSA, in,
                             inLen, out, (word32)modLen, key, keyLen);
    if (ret != 0)
        return -5358;

    sigSz = sizeof(out);
    ret = wc_SignatureGenerate(WC_HASH_TYPE_SHA256, WC_SIGNATURE_TYPE_RSA_W_ENC,
                               in, inLen, out, &sigSz, key, keyLen, rng);
    if (ret != 0)
        return -5359;

    ret = wc_SignatureVerify(WC_HASH_TYPE_SHA256, WC_SIGNATURE_TYPE_RSA_W_ENC,
                             in, inLen, out, (word32)modLen, key, keyLen);
    if (ret != 0)
        return -5360;

    /* Wrong signature type. */
    ret = wc_SignatureVerify(WC_HASH_TYPE_SHA256, WC_SIGNATURE_TYPE_RSA, in,
                             inLen, out, (word32)modLen, key, keyLen);
    if (ret == 0)
        return -5361;

    return 0;
}
#endif /* !NO_SIG_WRAPPER */

#ifndef HAVE_USER_RSA
static int rsa_decode_test(void)
{
    int        ret;
    word32     inSz;
    word32     inOutIdx;
    RsaKey     keyPub;
    const byte n[2] = { 0x00, 0x23 };
    const byte e[2] = { 0x00, 0x03 };
    const byte good[] = { 0x30, 0x06, 0x02, 0x01, 0x23, 0x02, 0x1, 0x03 };
    const byte goodAlgId[] = { 0x30, 0x0f, 0x30, 0x0d, 0x06, 0x00,
            0x03, 0x09, 0x00, 0x30, 0x06, 0x02, 0x01, 0x23, 0x02, 0x1, 0x03 };
    const byte goodAlgIdNull[] = { 0x30, 0x11, 0x30, 0x0f, 0x06, 0x00,
            0x05, 0x00, 0x03, 0x09, 0x00, 0x30, 0x06, 0x02, 0x01, 0x23,
            0x02, 0x1, 0x03 };
    const byte badAlgIdNull[] = { 0x30, 0x12, 0x30, 0x10, 0x06, 0x00,
            0x05, 0x01, 0x00, 0x03, 0x09, 0x00, 0x30, 0x06, 0x02, 0x01, 0x23,
            0x02, 0x1, 0x03 };
    const byte badNotBitString[] = { 0x30, 0x0f, 0x30, 0x0d, 0x06, 0x00,
            0x04, 0x09, 0x00, 0x30, 0x06, 0x02, 0x01, 0x23, 0x02, 0x1, 0x03 };
    const byte badBitStringLen[] = { 0x30, 0x0f, 0x30, 0x0d, 0x06, 0x00,
            0x03, 0x0a, 0x00, 0x30, 0x06, 0x02, 0x01, 0x23, 0x02, 0x1, 0x03 };
    const byte badNoSeq[] = { 0x30, 0x0d, 0x30, 0x0b, 0x06, 0x00, 0x03, 0x07,
            0x00, 0x02, 0x01, 0x23, 0x02, 0x1, 0x03 };
    const byte badNoObj[] = {
            0x30, 0x0f, 0x30, 0x0d, 0x05, 0x00, 0x03, 0x09, 0x00, 0x30, 0x06,
            0x02, 0x01, 0x23, 0x02, 0x1, 0x03 };
    const byte badIntN[] = { 0x30, 0x06, 0x02, 0x05, 0x23, 0x02, 0x1, 0x03 };
    const byte badNotIntE[] = { 0x30, 0x06, 0x02, 0x01, 0x23, 0x04, 0x1, 0x03 };
    const byte badLength[] = { 0x30, 0x04, 0x02, 0x01, 0x23, 0x02, 0x1, 0x03 };
    const byte badBitStrNoZero[] = { 0x30, 0x0e, 0x30, 0x0c, 0x06, 0x00,
            0x03, 0x08, 0x30, 0x06, 0x02, 0x01, 0x23, 0x02, 0x1, 0x03 };

    ret = wc_InitRsaKey(&keyPub, NULL);
    if (ret != 0)
        return -5400;

    /* Parameter Validation testing. */
    ret = wc_RsaPublicKeyDecodeRaw(NULL, sizeof(n), e, sizeof(e), &keyPub);
    if (ret != BAD_FUNC_ARG) {
        ret = -5401;
        goto done;
    }
    ret = wc_RsaPublicKeyDecodeRaw(n, sizeof(n), NULL, sizeof(e), &keyPub);
    if (ret != BAD_FUNC_ARG) {
        ret = -5402;
        goto done;
    }
    ret = wc_RsaPublicKeyDecodeRaw(n, sizeof(n), e, sizeof(e), NULL);
    if (ret != BAD_FUNC_ARG) {
        ret = -5403;
        goto done;
    }
    /* TODO: probably should fail when length is -1! */
    ret = wc_RsaPublicKeyDecodeRaw(n, (word32)-1, e, sizeof(e), &keyPub);
    if (ret != 0) {
        ret = -5404;
        goto done;
    }
    wc_FreeRsaKey(&keyPub);
    ret = wc_InitRsaKey(&keyPub, NULL);
    if (ret != 0)
        return -5405;
    ret = wc_RsaPublicKeyDecodeRaw(n, sizeof(n), e, (word32)-1, &keyPub);
    if (ret != 0) {
        ret = -5406;
        goto done;
    }
    wc_FreeRsaKey(&keyPub);
    ret = wc_InitRsaKey(&keyPub, NULL);
    if (ret != 0)
        return -5407;

    /* Use API. */
    ret = wc_RsaPublicKeyDecodeRaw(n, sizeof(n), e, sizeof(e), &keyPub);
    if (ret != 0) {
        ret = -5408;
        goto done;
    }
    wc_FreeRsaKey(&keyPub);
    ret = wc_InitRsaKey(&keyPub, NULL);
    if (ret != 0)
        return -5409;

    /* Parameter Validation testing. */
    inSz = sizeof(good);
    ret = wc_RsaPublicKeyDecode(NULL, &inOutIdx, &keyPub, inSz);
    if (ret != BAD_FUNC_ARG) {
        ret = -5410;
        goto done;
    }
    ret = wc_RsaPublicKeyDecode(good, NULL, &keyPub, inSz);
    if (ret != BAD_FUNC_ARG) {
        ret = -5411;
        goto done;
    }
    ret = wc_RsaPublicKeyDecode(good, &inOutIdx, NULL, inSz);
    if (ret != BAD_FUNC_ARG) {
        ret = -5412;
        goto done;
    }

    /* Use good data and offest to bad data. */
    inOutIdx = 2;
    inSz = sizeof(good) - inOutIdx;
    ret = wc_RsaPublicKeyDecode(good, &inOutIdx, &keyPub, inSz);
    if (ret != ASN_PARSE_E) {
        ret = -5413;
        goto done;
    }
    inOutIdx = 2;
    inSz = sizeof(goodAlgId) - inOutIdx;
    ret = wc_RsaPublicKeyDecode(goodAlgId, &inOutIdx, &keyPub, inSz);
    if (ret != ASN_PARSE_E) {
        ret = -5414;
        goto done;
    }
    /* Try different bad data. */
    inSz = sizeof(badAlgIdNull);
    inOutIdx = 0;
    ret = wc_RsaPublicKeyDecode(badAlgIdNull, &inOutIdx, &keyPub, inSz);
    if (ret != ASN_EXPECT_0_E) {
        ret = -5415;
        goto done;
    }
    inSz = sizeof(badNotBitString);
    inOutIdx = 0;
    ret = wc_RsaPublicKeyDecode(badNotBitString, &inOutIdx, &keyPub, inSz);
    if (ret != ASN_BITSTR_E) {
        ret = -5416;
        goto done;
    }
    inSz = sizeof(badBitStringLen);
    inOutIdx = 0;
    ret = wc_RsaPublicKeyDecode(badBitStringLen, &inOutIdx, &keyPub, inSz);
    if (ret != ASN_PARSE_E) {
        ret = -5417;
        goto done;
    }
    inSz = sizeof(badNoSeq);
    inOutIdx = 0;
    ret = wc_RsaPublicKeyDecode(badNoSeq, &inOutIdx, &keyPub, inSz);
    if (ret != ASN_PARSE_E) {
        ret = -5418;
        goto done;
    }
    inSz = sizeof(badNoObj);
    inOutIdx = 0;
    ret = wc_RsaPublicKeyDecode(badNoObj, &inOutIdx, &keyPub, inSz);
    if (ret != ASN_PARSE_E) {
        ret = -5419;
        goto done;
    }
    inSz = sizeof(badIntN);
    inOutIdx = 0;
    ret = wc_RsaPublicKeyDecode(badIntN, &inOutIdx, &keyPub, inSz);
    if (ret != ASN_RSA_KEY_E) {
        ret = -5420;
        goto done;
    }
    inSz = sizeof(badNotIntE);
    inOutIdx = 0;
    ret = wc_RsaPublicKeyDecode(badNotIntE, &inOutIdx, &keyPub, inSz);
    if (ret != ASN_RSA_KEY_E) {
        ret = -5421;
        goto done;
    }
    /* TODO: Shouldn't pass as the sequence length is too small. */
    inSz = sizeof(badLength);
    inOutIdx = 0;
    ret = wc_RsaPublicKeyDecode(badLength, &inOutIdx, &keyPub, inSz);
    if (ret != 0) {
        ret = -5422;
        goto done;
    }
    /* TODO: Shouldn't ignore object id's data. */
    wc_FreeRsaKey(&keyPub);
    ret = wc_InitRsaKey(&keyPub, NULL);
    if (ret != 0)
        return -5423;

    /* Valid data cases. */
    inSz = sizeof(good);
    inOutIdx = 0;
    ret = wc_RsaPublicKeyDecode(good, &inOutIdx, &keyPub, inSz);
    if (ret != 0) {
        ret = -5424;
        goto done;
    }
    if (inOutIdx != inSz) {
        ret = -5425;
        goto done;
    }
    wc_FreeRsaKey(&keyPub);
    ret = wc_InitRsaKey(&keyPub, NULL);
    if (ret != 0)
        return -5426;

    inSz = sizeof(goodAlgId);
    inOutIdx = 0;
    ret = wc_RsaPublicKeyDecode(goodAlgId, &inOutIdx, &keyPub, inSz);
    if (ret != 0) {
        ret = -5427;
        goto done;
    }
    if (inOutIdx != inSz) {
        ret = -5428;
        goto done;
    }
    wc_FreeRsaKey(&keyPub);
    ret = wc_InitRsaKey(&keyPub, NULL);
    if (ret != 0)
        return -5429;

    inSz = sizeof(goodAlgIdNull);
    inOutIdx = 0;
    ret = wc_RsaPublicKeyDecode(goodAlgIdNull, &inOutIdx, &keyPub, inSz);
    if (ret != 0) {
        ret = -5430;
        goto done;
    }
    if (inOutIdx != inSz) {
        ret = -5431;
        goto done;
    }
    wc_FreeRsaKey(&keyPub);
    ret = wc_InitRsaKey(&keyPub, NULL);
    if (ret != 0)
        return -5432;

    inSz = sizeof(badBitStrNoZero);
    inOutIdx = 0;
    ret = wc_RsaPublicKeyDecode(badBitStrNoZero, &inOutIdx, &keyPub, inSz);
    if (ret != ASN_EXPECT_0_E) {
        ret = -5433;
        goto done;
    }
    ret = 0;

done:
    wc_FreeRsaKey(&keyPub);
    return ret;
}
#endif

#define RSA_TEST_BYTES 256

#ifdef WC_RSA_PSS
static int rsa_pss_test(WC_RNG* rng, RsaKey* key)
{
    byte             digest[WC_MAX_DIGEST_SIZE];
    int              ret     = 0;
    const char*      inStr   = "Everyone gets Friday off.";
    word32           inLen   = (word32)XSTRLEN((char*)inStr);
    word32           outSz;
    word32           plainSz;
    word32           digestSz;
    int              i, j;
#ifdef RSA_PSS_TEST_WRONG_PARAMS
    int              k, l;
#endif
    byte*            plain;
    int              mgf[]   = {
#ifndef NO_SHA
                                 WC_MGF1SHA1,
#endif
#ifdef WOLFSSL_SHA224
                                 WC_MGF1SHA224,
#endif
                                 WC_MGF1SHA256,
#ifdef WOLFSSL_SHA384
                                 WC_MGF1SHA384,
#endif
#ifdef WOLFSSL_SHA512
                                 WC_MGF1SHA512
#endif
                               };
    enum wc_HashType hash[]  = {
#ifndef NO_SHA
                                 WC_HASH_TYPE_SHA,
#endif
#ifdef WOLFSSL_SHA224
                                 WC_HASH_TYPE_SHA224,
#endif
                                 WC_HASH_TYPE_SHA256,
#ifdef WOLFSSL_SHA384
                                 WC_HASH_TYPE_SHA384,
#endif
#ifdef WOLFSSL_SHA512
                                 WC_HASH_TYPE_SHA512,
#endif
                               };

    DECLARE_VAR_INIT(in, byte, inLen, inStr, HEAP_HINT);
    DECLARE_VAR(out, byte, RSA_TEST_BYTES, HEAP_HINT);
    DECLARE_VAR(sig, byte, RSA_TEST_BYTES, HEAP_HINT);

    /* Test all combinations of hash and MGF. */
    for (j = 0; j < (int)(sizeof(hash)/sizeof(*hash)); j++) {
        /* Calculate hash of message. */
        ret = wc_Hash(hash[j], in, inLen, digest, sizeof(digest));
        if (ret != 0)
            ERROR_OUT(-5450, exit_rsa_pss);
        digestSz = wc_HashGetDigestSize(hash[j]);

        for (i = 0; i < (int)(sizeof(mgf)/sizeof(*mgf)); i++) {
            outSz = RSA_TEST_BYTES;
            do {
            #if defined(WOLFSSL_ASYNC_CRYPT)
                ret = wc_AsyncWait(ret, &key->asyncDev,
                    WC_ASYNC_FLAG_CALL_AGAIN);
            #endif
                if (ret >= 0) {
                    ret = wc_RsaPSS_Sign_ex(digest, digestSz, out, outSz,
                        hash[j], mgf[i], -1, key, rng);
                }
            } while (ret == WC_PENDING_E);
            if (ret <= 0)
                ERROR_OUT(-5451, exit_rsa_pss);
            outSz = ret;

            XMEMCPY(sig, out, outSz);
            plain = NULL;

            do {
            #if defined(WOLFSSL_ASYNC_CRYPT)
                ret = wc_AsyncWait(ret, &key->asyncDev,
                    WC_ASYNC_FLAG_CALL_AGAIN);
            #endif
                if (ret >= 0) {
                    ret = wc_RsaPSS_VerifyInline_ex(sig, outSz, &plain, hash[j],
                        mgf[i], -1, key);
                }
            } while (ret == WC_PENDING_E);
            if (ret <= 0)
                ERROR_OUT(-5452, exit_rsa_pss);
            plainSz = ret;

            ret = wc_RsaPSS_CheckPadding(digest, digestSz, plain, plainSz,
                                         hash[j]);
            if (ret != 0)
                ERROR_OUT(-5453, exit_rsa_pss);

#ifdef RSA_PSS_TEST_WRONG_PARAMS
            for (k = 0; k < (int)(sizeof(mgf)/sizeof(*mgf)); k++) {
                for (l = 0; l < (int)(sizeof(hash)/sizeof(*hash)); l++) {
                    if (i == k && j == l)
                        continue;

                    XMEMCPY(sig, out, outSz);

                    do {
                    #if defined(WOLFSSL_ASYNC_CRYPT)
                        ret = wc_AsyncWait(ret, &key->asyncDev,
                            WC_ASYNC_FLAG_CALL_AGAIN);
                    #endif
                        if (ret >= 0) {
                            ret = wc_RsaPSS_VerifyInline_ex(sig, outSz,
                                (byte**)&plain, hash[l], mgf[k], -1, key);
                        }
                    } while (ret == WC_PENDING_E);
                    if (ret >= 0)
                        ERROR_OUT(-5454, exit_rsa_pss);
                }
            }
#endif
        }
    }

    /* Test that a salt length of zero works. */
    digestSz = wc_HashGetDigestSize(hash[0]);
    outSz = RSA_TEST_BYTES;
    do {
    #if defined(WOLFSSL_ASYNC_CRYPT)
        ret = wc_AsyncWait(ret, &key->asyncDev,
            WC_ASYNC_FLAG_CALL_AGAIN);
    #endif
        if (ret >= 0) {
            ret = wc_RsaPSS_Sign_ex(digest, digestSz, out, outSz, hash[0],
                mgf[0], 0, key, rng);
        }
    } while (ret == WC_PENDING_E);
    if (ret <= 0)
        ERROR_OUT(-5460, exit_rsa_pss);
    outSz = ret;

    do {
    #if defined(WOLFSSL_ASYNC_CRYPT)
        ret = wc_AsyncWait(ret, &key->asyncDev,
            WC_ASYNC_FLAG_CALL_AGAIN);
    #endif
        if (ret >= 0) {
            ret = wc_RsaPSS_Verify_ex(out, outSz, sig, outSz, hash[0], mgf[0],
                0, key);
        }
    } while (ret == WC_PENDING_E);
    if (ret <= 0)
        ERROR_OUT(-5461, exit_rsa_pss);
    plainSz = ret;

    do {
    #if defined(WOLFSSL_ASYNC_CRYPT)
        ret = wc_AsyncWait(ret, &key->asyncDev,
            WC_ASYNC_FLAG_CALL_AGAIN);
    #endif
        if (ret >= 0) {
            ret = wc_RsaPSS_CheckPadding_ex(digest, digestSz, sig, plainSz,
                hash[0], 0);
        }
    } while (ret == WC_PENDING_E);
    if (ret != 0)
        ERROR_OUT(-5462, exit_rsa_pss);

    XMEMCPY(sig, out, outSz);
    plain = NULL;
    do {
    #if defined(WOLFSSL_ASYNC_CRYPT)
        ret = wc_AsyncWait(ret, &key->asyncDev,
            WC_ASYNC_FLAG_CALL_AGAIN);
    #endif
        if (ret >= 0) {
            ret = wc_RsaPSS_VerifyInline_ex(sig, outSz, &plain, hash[0], mgf[0],
                0, key);
        }
    } while (ret == WC_PENDING_E);
    if (ret <= 0)
        ERROR_OUT(-5463, exit_rsa_pss);
    plainSz = ret;

    ret = wc_RsaPSS_CheckPadding_ex(digest, digestSz, plain, plainSz, hash[0],
                                    0);
    if (ret != 0)
        ERROR_OUT(-5464, exit_rsa_pss);

    /* Test bad salt lengths in various APIs. */
    digestSz = wc_HashGetDigestSize(hash[0]);
    outSz = RSA_TEST_BYTES;
    do {
    #if defined(WOLFSSL_ASYNC_CRYPT)
        ret = wc_AsyncWait(ret, &key->asyncDev,
            WC_ASYNC_FLAG_CALL_AGAIN);
    #endif
        if (ret >= 0) {
            ret = wc_RsaPSS_Sign_ex(digest, digestSz, out, outSz, hash[0],
                mgf[0], -2, key, rng);
        }
    } while (ret == WC_PENDING_E);
    if (ret != PSS_SALTLEN_E)
        ERROR_OUT(-5470, exit_rsa_pss);

    do {
    #if defined(WOLFSSL_ASYNC_CRYPT)
        ret = wc_AsyncWait(ret, &key->asyncDev,
            WC_ASYNC_FLAG_CALL_AGAIN);
    #endif
        if (ret >= 0) {
            ret = wc_RsaPSS_Sign_ex(digest, digestSz, out, outSz, hash[0],
                mgf[0], digestSz + 1, key, rng);
        }
    } while (ret == WC_PENDING_E);
    if (ret != PSS_SALTLEN_E)
        ERROR_OUT(-5471, exit_rsa_pss);

    do {
    #if defined(WOLFSSL_ASYNC_CRYPT)
        ret = wc_AsyncWait(ret, &key->asyncDev,
            WC_ASYNC_FLAG_CALL_AGAIN);
    #endif
        if (ret >= 0) {
            ret = wc_RsaPSS_VerifyInline_ex(sig, outSz, &plain, hash[0],
                mgf[0], -2, key);
        }
    } while (ret == WC_PENDING_E);
    if (ret != PSS_SALTLEN_E)
        ERROR_OUT(-5472, exit_rsa_pss);

    do {
    #if defined(WOLFSSL_ASYNC_CRYPT)
        ret = wc_AsyncWait(ret, &key->asyncDev,
            WC_ASYNC_FLAG_CALL_AGAIN);
    #endif
        if (ret >= 0) {
            ret = wc_RsaPSS_VerifyInline_ex(sig, outSz, &plain, hash[0], mgf[0],
                digestSz + 1, key);
        }
    } while (ret == WC_PENDING_E);
    if (ret != PSS_SALTLEN_E)
        ERROR_OUT(-5473, exit_rsa_pss);

    ret = wc_RsaPSS_CheckPadding_ex(digest, digestSz, plain, plainSz, hash[0],
                                    -2);
    if (ret != PSS_SALTLEN_E)
        ERROR_OUT(-5474, exit_rsa_pss);
    ret = wc_RsaPSS_CheckPadding_ex(digest, digestSz, plain, plainSz, hash[0],
                                    digestSz + 1);
    if (ret != PSS_SALTLEN_E)
        ERROR_OUT(-5475, exit_rsa_pss);

    ret = 0;
exit_rsa_pss:
    FREE_VAR(in, HEAP_HINT);
    FREE_VAR(out, HEAP_HINT);

    return ret;
}
#endif

int rsa_test(void)
{
    int    ret;
    byte*  tmp = NULL;
    byte*  der = NULL;
    byte*  pem = NULL;
    size_t bytes;
    WC_RNG rng;
    RsaKey key;
#ifdef WOLFSSL_CERT_EXT
    RsaKey keypub;
#endif
#ifdef WOLFSSL_KEY_GEN
    RsaKey genKey;
#endif
#if defined(WOLFSSL_CERT_GEN) || defined(HAVE_NTRU)
    RsaKey caKey;
#endif
#ifdef HAVE_ECC
    #ifdef WOLFSSL_CERT_GEN
        ecc_key caEccKey;
        ecc_key caEccKeyPub;
    #endif
#endif /* HAVE_ECC */
    word32 idx = 0;
    byte*  res;
    const char* inStr = "Everyone gets Friday off.";
    word32      inLen = (word32)XSTRLEN((char*)inStr);
    const word32 outSz   = RSA_TEST_BYTES;
    const word32 plainSz = RSA_TEST_BYTES;
#if !defined(USE_CERT_BUFFERS_1024) && !defined(USE_CERT_BUFFERS_2048) \
                                    && !defined(NO_FILESYSTEM)
    FILE    *file, *file2;
#endif
#ifdef WOLFSSL_TEST_CERT
    DecodedCert cert;
#endif

    DECLARE_VAR_INIT(in, byte, inLen, inStr, HEAP_HINT);
    DECLARE_VAR(out, byte, RSA_TEST_BYTES, HEAP_HINT);
    DECLARE_VAR(plain, byte, RSA_TEST_BYTES, HEAP_HINT);

#ifdef WOLFSSL_ASYNC_CRYPT
    if (in == NULL)
        return MEMORY_E;
#endif

    /* initialize stack structures */
    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(&key, 0, sizeof(key));
#ifdef WOLFSSL_CERT_EXT
    XMEMSET(&keypub, 0, sizeof(keypub));
#endif
#ifdef WOLFSSL_KEY_GEN
    XMEMSET(&genKey, 0, sizeof(genKey));
#endif
#if defined(WOLFSSL_CERT_GEN) || defined(HAVE_NTRU)
    XMEMSET(&caKey, 0, sizeof(caKey));
#endif
#ifdef HAVE_ECC
    #ifdef WOLFSSL_CERT_GEN
        XMEMSET(&caEccKey, 0, sizeof(caEccKey));
        XMEMSET(&caEccKeyPub, 0, sizeof(caEccKeyPub));
    #endif
#endif /* HAVE_ECC */

#ifndef HAVE_USER_RSA
    ret = rsa_decode_test();
    if (ret != 0) {
        printf("RSA_DECODE\t\ttest failed!\n");
        return ret;
    } else
        printf( "RSA_DECODE\t\ttest passed!\n");
#endif

#ifdef USE_CERT_BUFFERS_1024
    bytes = (size_t)sizeof_client_key_der_1024;
	if (bytes < (size_t)sizeof_client_cert_der_1024)
		bytes = (size_t)sizeof_client_cert_der_1024;
#elif defined(USE_CERT_BUFFERS_2048)
    bytes = (size_t)sizeof_client_key_der_2048;
	if (bytes < (size_t)sizeof_client_cert_der_2048)
		bytes = (size_t)sizeof_client_cert_der_2048;
#else
	bytes = FOURK_BUF;
#endif

    tmp = (byte*)XMALLOC(bytes, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (tmp == NULL
    #ifdef WOLFSSL_ASYNC_CRYPT
        || out == NULL || plain == NULL
    #endif
    ) {
        return -5500;
    }

#ifdef USE_CERT_BUFFERS_1024
    XMEMCPY(tmp, client_key_der_1024, (size_t)sizeof_client_key_der_1024);
#elif defined(USE_CERT_BUFFERS_2048)
    XMEMCPY(tmp, client_key_der_2048, (size_t)sizeof_client_key_der_2048);
#elif !defined(NO_FILESYSTEM)
    file = fopen(clientKey, "rb");
    if (!file) {
        err_sys("can't open ./certs/client-key.der, "
                "Please run from wolfSSL home dir", -40);
        ERROR_OUT(-5501, exit_rsa);
    }

    bytes = fread(tmp, 1, FOURK_BUF, file);
    fclose(file);
#else
    /* No key to use. */
    ERROR_OUT(-5502, exit_rsa);
#endif /* USE_CERT_BUFFERS */

    ret = wc_InitRsaKey_ex(&key, HEAP_HINT, devId);
    if (ret != 0) {
        ERROR_OUT(-5503, exit_rsa);
    }
    ret = wc_RsaPrivateKeyDecode(tmp, &idx, &key, (word32)bytes);
    if (ret != 0) {
        ERROR_OUT(-5504, exit_rsa);
    }

#ifndef HAVE_FIPS
    ret = wc_InitRng_ex(&rng, HEAP_HINT, devId);
#else
    ret = wc_InitRng(&rng);
#endif
    if (ret != 0) {
        ERROR_OUT(-5505, exit_rsa);
    }

#ifndef NO_SIG_WRAPPER
    ret = rsa_sig_test(&key, sizeof(RsaKey), wc_RsaEncryptSize(&key), &rng);
    if (ret != 0) {
        printf("RSA_SIG_TEST\t\ttest failed!\n");
        return ret;
    } else
        printf( "RSA_SIG_TEST\t\ttest passed!\n");
#endif

    do {
#if defined(WOLFSSL_ASYNC_CRYPT)
        ret = wc_AsyncWait(ret, &key.asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
#endif
        if (ret >= 0) {
            ret = wc_RsaPublicEncrypt(in, inLen, out, outSz, &key, &rng);
        }
    } while (ret == WC_PENDING_E);
    if (ret < 0) {
        ERROR_OUT(-5506, exit_rsa);
    }

#ifdef WC_RSA_BLINDING
    {
        int tmpret = ret;
        ret = wc_RsaSetRNG(&key, &rng);
        if (ret < 0) {
            ERROR_OUT(-5507, exit_rsa);
        }
        ret = tmpret;
    }
#endif

    idx = (word32)ret; /* save off encrypted length */
    do {
#if defined(WOLFSSL_ASYNC_CRYPT)
        ret = wc_AsyncWait(ret, &key.asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
#endif
        if (ret >= 0) {
            ret = wc_RsaPrivateDecrypt(out, idx, plain, plainSz, &key);
        }
    } while (ret == WC_PENDING_E);
    if (ret < 0) {
        ERROR_OUT(-5508, exit_rsa);
    }

    if (XMEMCMP(plain, in, inLen)) {
        ERROR_OUT(-5509, exit_rsa);
    }
    do {
#if defined(WOLFSSL_ASYNC_CRYPT)
        ret = wc_AsyncWait(ret, &key.asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
#endif
        if (ret >= 0) {
            ret = wc_RsaPrivateDecryptInline(out, idx, &res, &key);
        }
    } while (ret == WC_PENDING_E);
    if (ret < 0) {
        ERROR_OUT(-5510, exit_rsa);
    }
    if (ret != (int)inLen) {
        ERROR_OUT(-5511, exit_rsa);
    }
    if (XMEMCMP(res, in, inLen)) {
        ERROR_OUT(-5512, exit_rsa);
    }

    do {
#if defined(WOLFSSL_ASYNC_CRYPT)
        ret = wc_AsyncWait(ret, &key.asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
#endif
        if (ret >= 0) {
            ret = wc_RsaSSL_Sign(in, inLen, out, outSz, &key, &rng);
        }
    } while (ret == WC_PENDING_E);
    if (ret < 0) {
        ERROR_OUT(-5513, exit_rsa);
    }

    idx = (word32)ret;
    XMEMSET(plain, 0, plainSz);
    do {
#if defined(WOLFSSL_ASYNC_CRYPT)
        ret = wc_AsyncWait(ret, &key.asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
#endif
        if (ret >= 0) {
            ret = wc_RsaSSL_Verify(out, idx, plain, plainSz, &key);
        }
    } while (ret == WC_PENDING_E);
    if (ret < 0) {
        ERROR_OUT(-5514, exit_rsa);
    }

    if (XMEMCMP(plain, in, (size_t)ret)) {
        ERROR_OUT(-5515, exit_rsa);
    }

    #ifndef WC_NO_RSA_OAEP
    /* OAEP padding testing */
    #if !defined(HAVE_FAST_RSA) && !defined(HAVE_USER_RSA) && \
        (!defined(HAVE_FIPS) || \
         (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 2)))
    #ifndef NO_SHA
    XMEMSET(plain, 0, plainSz);

    do {
#if defined(WOLFSSL_ASYNC_CRYPT)
        ret = wc_AsyncWait(ret, &key.asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
#endif
        if (ret >= 0) {
            ret = wc_RsaPublicEncrypt_ex(in, inLen, out, outSz, &key, &rng,
                       WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA, WC_MGF1SHA1, NULL, 0);
        }
    } while (ret == WC_PENDING_E);
    if (ret < 0) {
        ERROR_OUT(-5516, exit_rsa);
    }

    idx = (word32)ret;
    do {
#if defined(WOLFSSL_ASYNC_CRYPT)
        ret = wc_AsyncWait(ret, &key.asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
#endif
        if (ret >= 0) {
            ret = wc_RsaPrivateDecrypt_ex(out, idx, plain, plainSz, &key,
                       WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA, WC_MGF1SHA1, NULL, 0);
        }
    } while (ret == WC_PENDING_E);
    if (ret < 0) {
        ERROR_OUT(-5517, exit_rsa);
    }

    if (XMEMCMP(plain, in, inLen)) {
        ERROR_OUT(-5518, exit_rsa);
    }
    #endif /* NO_SHA */

    #ifndef NO_SHA256
    XMEMSET(plain, 0, plainSz);
    do {
#if defined(WOLFSSL_ASYNC_CRYPT)
        ret = wc_AsyncWait(ret, &key.asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
#endif
        if (ret >= 0) {
            ret = wc_RsaPublicEncrypt_ex(in, inLen, out, outSz, &key, &rng,
                  WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA256, WC_MGF1SHA256, NULL, 0);
        }
    } while (ret == WC_PENDING_E);
    if (ret < 0) {
        ERROR_OUT(-5519, exit_rsa);
    }

    idx = (word32)ret;
    do {
#if defined(WOLFSSL_ASYNC_CRYPT)
        ret = wc_AsyncWait(ret, &key.asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
#endif
        if (ret >= 0) {
            ret = wc_RsaPrivateDecrypt_ex(out, idx, plain, plainSz, &key,
                  WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA256, WC_MGF1SHA256, NULL, 0);
        }
    } while (ret == WC_PENDING_E);
    if (ret < 0) {
        ERROR_OUT(-5520, exit_rsa);
    }

    if (XMEMCMP(plain, in, inLen)) {
        ERROR_OUT(-5521, exit_rsa);
    }

    do {
#if defined(WOLFSSL_ASYNC_CRYPT)
        ret = wc_AsyncWait(ret, &key.asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
#endif
        if (ret >= 0) {
            ret = wc_RsaPrivateDecryptInline_ex(out, idx, &res, &key,
                WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA256, WC_MGF1SHA256, NULL, 0);
        }
    } while (ret == WC_PENDING_E);
    if (ret < 0) {
        ERROR_OUT(-5522, exit_rsa);
    }
    if (ret != (int)inLen) {
        ERROR_OUT(-5523, exit_rsa);
    }
    if (XMEMCMP(res, in, inLen)) {
        ERROR_OUT(-5524, exit_rsa);
    }

    /* check fails if not using the same optional label */
    XMEMSET(plain, 0, plainSz);
    do {
#if defined(WOLFSSL_ASYNC_CRYPT)
        ret = wc_AsyncWait(ret, &key.asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
#endif
        if (ret >= 0) {
            ret = wc_RsaPublicEncrypt_ex(in, inLen, out, outSz, &key, &rng,
                  WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA256, WC_MGF1SHA256, NULL, 0);
        }
    } while (ret == WC_PENDING_E);
    if (ret < 0) {
        ERROR_OUT(-5525, exit_rsa);
    }

/* TODO: investigate why Cavium Nitrox doesn't detect decrypt error here */
#ifndef HAVE_CAVIUM
    idx = (word32)ret;
    do {
#if defined(WOLFSSL_ASYNC_CRYPT)
        ret = wc_AsyncWait(ret, &key.asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
#endif
        if (ret >= 0) {
            ret = wc_RsaPrivateDecrypt_ex(out, idx, plain, plainSz, &key,
               WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA256, WC_MGF1SHA256, in, inLen);
        }
    } while (ret == WC_PENDING_E);
    if (ret > 0) { /* in this case decrypt should fail */
        ERROR_OUT(-5526, exit_rsa);
    }
    ret = 0;
#endif /* !HAVE_CAVIUM */

    /* check using optional label with encrypt/decrypt */
    XMEMSET(plain, 0, plainSz);
    do {
#if defined(WOLFSSL_ASYNC_CRYPT)
        ret = wc_AsyncWait(ret, &key.asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
#endif
        if (ret >= 0) {
            ret = wc_RsaPublicEncrypt_ex(in, inLen, out, outSz, &key, &rng,
               WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA256, WC_MGF1SHA256, in, inLen);
        }
    } while (ret == WC_PENDING_E);
    if (ret < 0) {
        ERROR_OUT(-5527, exit_rsa);
    }

    idx = (word32)ret;
    do {
#if defined(WOLFSSL_ASYNC_CRYPT)
        ret = wc_AsyncWait(ret, &key.asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
#endif
        if (ret >= 0) {
            ret = wc_RsaPrivateDecrypt_ex(out, idx, plain, plainSz, &key,
               WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA256, WC_MGF1SHA256, in, inLen);
        }
    } while (ret == WC_PENDING_E);
    if (ret < 0) {
        ERROR_OUT(-5528, exit_rsa);
    }

    if (XMEMCMP(plain, in, inLen)) {
        ERROR_OUT(-5529, exit_rsa);
    }

    #ifndef NO_SHA
        /* check fail using mismatch hash algorithms */
        XMEMSET(plain, 0, plainSz);
        do {
    #if defined(WOLFSSL_ASYNC_CRYPT)
            ret = wc_AsyncWait(ret, &key.asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
    #endif
            if (ret >= 0) {
                ret = wc_RsaPublicEncrypt_ex(in, inLen, out, outSz, &key, &rng,
                    WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA, WC_MGF1SHA1, in, inLen);
            }
        } while (ret == WC_PENDING_E);
        if (ret < 0) {
            ERROR_OUT(-5530, exit_rsa);
        }

/* TODO: investigate why Cavium Nitrox doesn't detect decrypt error here */
#ifndef HAVE_CAVIUM
        idx = (word32)ret;
        do {
    #if defined(WOLFSSL_ASYNC_CRYPT)
            ret = wc_AsyncWait(ret, &key.asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
    #endif
            if (ret >= 0) {
                ret = wc_RsaPrivateDecrypt_ex(out, idx, plain, plainSz, &key,
                    WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA256, WC_MGF1SHA256,
                    in, inLen);
            }
        } while (ret == WC_PENDING_E);
        if (ret > 0) { /* should fail */
            ERROR_OUT(-5531, exit_rsa);
        }
        ret = 0;
#endif /* !HAVE_CAVIUM */
        #endif /* NO_SHA*/
    #endif /* NO_SHA256 */

    #ifdef WOLFSSL_SHA512
    /* Check valid RSA key size is used while using hash length of SHA512
       If key size is less than (hash length * 2) + 2 then is invalid use
       and test, since OAEP padding requires this.
       BAD_FUNC_ARG is returned when this case is not met */
    if (wc_RsaEncryptSize(&key) > ((int)WC_SHA512_DIGEST_SIZE * 2) + 2) {
        XMEMSET(plain, 0, plainSz);
        do {
    #if defined(WOLFSSL_ASYNC_CRYPT)
            ret = wc_AsyncWait(ret, &key.asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
    #endif
            if (ret >= 0) {
                ret = wc_RsaPublicEncrypt_ex(in, inLen, out, outSz, &key, &rng,
                  WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA512, WC_MGF1SHA512, NULL, 0);
            }
        } while (ret == WC_PENDING_E);
        if (ret < 0) {
            ERROR_OUT(-5532, exit_rsa);
        }

        idx = ret;
        do {
    #if defined(WOLFSSL_ASYNC_CRYPT)
            ret = wc_AsyncWait(ret, &key.asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
    #endif
            if (ret >= 0) {
                ret = wc_RsaPrivateDecrypt_ex(out, idx, plain, plainSz, &key,
                  WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA512, WC_MGF1SHA512, NULL, 0);
            }
        } while (ret == WC_PENDING_E);
        if (ret < 0) {
            ERROR_OUT(-5533, exit_rsa);
        }

        if (XMEMCMP(plain, in, inLen)) {
            ERROR_OUT(-5534, exit_rsa);
        }
    }
    #endif /* WOLFSSL_SHA512 */

    /* check using pkcsv15 padding with _ex API */
    XMEMSET(plain, 0, plainSz);
    do {
#if defined(WOLFSSL_ASYNC_CRYPT)
        ret = wc_AsyncWait(ret, &key.asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
#endif
        if (ret >= 0) {
            ret = wc_RsaPublicEncrypt_ex(in, inLen, out, outSz, &key, &rng,
                  WC_RSA_PKCSV15_PAD, WC_HASH_TYPE_NONE, 0, NULL, 0);
        }
    } while (ret == WC_PENDING_E);
    if (ret < 0) {
        ERROR_OUT(-5535, exit_rsa);
    }

    idx = (word32)ret;
    do {
#if defined(WOLFSSL_ASYNC_CRYPT)
        ret = wc_AsyncWait(ret, &key.asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
#endif
        if (ret >= 0) {
            ret = wc_RsaPrivateDecrypt_ex(out, idx, plain, plainSz, &key,
                  WC_RSA_PKCSV15_PAD, WC_HASH_TYPE_NONE, 0, NULL, 0);
        }
    } while (ret == WC_PENDING_E);
    if (ret < 0) {
        ERROR_OUT(-5536, exit_rsa);
    }

    if (XMEMCMP(plain, in, inLen)) {
        ERROR_OUT(-5537, exit_rsa);
    }
    #endif /* !HAVE_FAST_RSA && !HAVE_FIPS */
    #endif /* WC_NO_RSA_OAEP */

    ret = rsa_flatten_test(&key);
    if (ret != 0) {
        printf("RSA_FLATTEN\t\ttest failed!\n");
        return ret;
    } else
        printf( "RSA_FLATTEN\t\ttest passed!\n");

#if defined(WOLFSSL_MDK_ARM)
    #define sizeof(s) XSTRLEN((char *)(s))
#endif

#ifdef USE_CERT_BUFFERS_1024
    XMEMCPY(tmp, client_cert_der_1024, (size_t)sizeof_client_cert_der_1024);
    bytes = (size_t)sizeof_client_cert_der_1024;
#elif defined(USE_CERT_BUFFERS_2048)
    XMEMCPY(tmp, client_cert_der_2048, (size_t)sizeof_client_cert_der_2048);
    bytes = (size_t)sizeof_client_cert_der_2048;
#elif !defined(NO_FILESYSTEM)
    file2 = fopen(clientCert, "rb");
    if (!file2) {
        ERROR_OUT(-5538, exit_rsa);
    }

    bytes = fread(tmp, 1, FOURK_BUF, file2);
    fclose(file2);
#else
    /* No certificate to use. */
    ERROR_OUT(-5539, exit_rsa);
#endif

#ifdef sizeof
        #undef sizeof
#endif

#ifdef WOLFSSL_TEST_CERT
    InitDecodedCert(&cert, tmp, (word32)bytes, 0);

    ret = ParseCert(&cert, CERT_TYPE, NO_VERIFY, 0);
    if (ret != 0) {
        FreeDecodedCert(&cert);
        ERROR_OUT(-5540, exit_rsa);
    }

    FreeDecodedCert(&cert);
#else
    (void)bytes;
#endif

#ifdef WOLFSSL_CERT_EXT

#ifdef USE_CERT_BUFFERS_1024
    XMEMCPY(tmp, client_keypub_der_1024, sizeof_client_keypub_der_1024);
    bytes = sizeof_client_keypub_der_1024;
#elif defined(USE_CERT_BUFFERS_2048)
    XMEMCPY(tmp, client_keypub_der_2048, sizeof_client_keypub_der_2048);
    bytes = sizeof_client_keypub_der_2048;
#else
    file = fopen(clientKeyPub, "rb");
    if (!file) {
        err_sys("can't open ./certs/client-keyPub.der, "
                "Please run from wolfSSL home dir", -40);
        ERROR_OUT(-5541, exit_rsa);
    }

    bytes = fread(tmp, 1, FOURK_BUF, file);
    fclose(file);
#endif /* USE_CERT_BUFFERS */

    ret = wc_InitRsaKey(&keypub, HEAP_HINT);
    if (ret != 0) {
        ERROR_OUT(-5542, exit_rsa);
    }
    idx = 0;

    ret = wc_RsaPublicKeyDecode(tmp, &idx, &keypub, (word32)bytes);
    if (ret != 0) {
        ERROR_OUT(-5543, exit_rsa);
    }
#endif /* WOLFSSL_CERT_EXT */

#ifdef WOLFSSL_KEY_GEN
    {
        int    derSz = 0;
        int    keySz = 1024;

        #ifdef HAVE_FIPS
            keySz = 2048;
        #endif /* HAVE_FIPS */

        ret = wc_InitRsaKey(&genKey, HEAP_HINT);
        if (ret != 0) {
            ERROR_OUT(-5550, exit_rsa);
        }
        ret = wc_MakeRsaKey(&genKey, keySz, WC_RSA_EXPONENT, &rng);
        if (ret != 0) {
            ERROR_OUT(-5551, exit_rsa);
        }

        der = (byte*)XMALLOC(FOURK_BUF, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (der == NULL) {
            ERROR_OUT(-5552, exit_rsa);
        }
        pem = (byte*)XMALLOC(FOURK_BUF, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (pem == NULL) {
            ERROR_OUT(-5553, exit_rsa);
        }

        derSz = wc_RsaKeyToDer(&genKey, der, FOURK_BUF);
        if (derSz < 0) {
            ERROR_OUT(-5554, exit_rsa);
        }

        ret = SaveDerAndPem(der, derSz, pem, FOURK_BUF, keyDerFile, keyPemFile,
            PRIVATEKEY_TYPE, -5555);
        if (ret != 0) {
            goto exit_rsa;
        }

        wc_FreeRsaKey(&genKey);
        ret = wc_InitRsaKey(&genKey, HEAP_HINT);
        if (ret != 0) {
            ERROR_OUT(-5560, exit_rsa);
        }
        idx = 0;
        ret = wc_RsaPrivateKeyDecode(der, &idx, &genKey, derSz);
        if (ret != 0) {
            ERROR_OUT(-5561, exit_rsa);
        }

        wc_FreeRsaKey(&genKey);
        XFREE(pem, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        pem = NULL;
        XFREE(der, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        der = NULL;
    }
#endif /* WOLFSSL_KEY_GEN */

#ifdef WC_RSA_PSS
    ret = rsa_pss_test(&rng, &key);
    if (ret != 0) {
        printf("RSA_PSS\t\t\ttest failed!\n");
        return ret;
    } else
        printf( "RSA_PSS\t\t\ttest passed!\n");

#endif

exit_rsa:
    wc_FreeRsaKey(&key);
#ifdef WOLFSSL_CERT_EXT
    wc_FreeRsaKey(&keypub);
#endif
#ifdef WOLFSSL_KEY_GEN
    wc_FreeRsaKey(&genKey);
#endif
#ifdef WOLFSSL_CERT_GEN
    wc_FreeRsaKey(&caKey);
    #ifdef HAVE_ECC
        wc_ecc_free(&caEccKey);
        #ifdef WOLFSSL_CERT_EXT
            wc_ecc_free(&caEccKeyPub);
        #endif
    #endif
#endif

    XFREE(pem, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(der, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(tmp, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    wc_FreeRng(&rng);

    FREE_VAR(in, HEAP_HINT);
    FREE_VAR(out, HEAP_HINT);
    FREE_VAR(plain, HEAP_HINT);

    /* ret can be greater then 0 with certgen but all negative values should
     * be returned and treated as an error */
    if (ret >= 0) {
        return 0;
    }
    else {
        return ret;
    }
}

#endif


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

#ifndef NO_RSA
    if ( (ret = rsa_test()) != 0) {
        return err_sys("RSA\t\t\ttest failed!\n", ret);
        ;
    } else
        printf( "RSA\t\t\ttest passed!\n");
#endif

#ifdef WOLFSSL_TRACK_MEMORY
    ShowMemoryTracker();
#endif

    EXIT_TEST(ret);

}

int main(void)
{
    func_args args;
    #ifdef HAVE_STACK_SIZE
        StackSizeCheck(&args, wolfcrypt_test);
    #else
        wolfcrypt_test(&args);
    #endif

    return 0;
}


