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

//    ret = rsa_flatten_test(&key);
//    if (ret != 0) {
//        printf("RSA_FLATTEN\t\ttest failed!\n");
//        return ret;
//    } else
//        printf( "RSA_FLATTEN\t\ttest passed!\n");

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


