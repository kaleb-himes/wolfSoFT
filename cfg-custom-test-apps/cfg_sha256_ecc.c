#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/certs_test.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/signature.h>

#define HEAP_HINT NULL
static int devId = INVALID_DEVID;

typedef struct testVector {
    const char*  input;
    const char*  output;
    size_t inLen;
    size_t outLen;
} testVector;

#define ERROR_OUT(err, eLabel) { ret = (err); goto eLabel; }

#ifdef HAVE_STACK_SIZE
static THREAD_RETURN err_sys(const char* msg, int es)
#else
static int err_sys(const char* msg, int es)
#endif
{
    printf("%s error = %d\n", msg, es);

    EXIT_TEST(-1);
}

#define FOURK_BUF 4096

#ifdef HAVE_ECC

#ifdef BENCH_EMBEDDED
    #define ECC_SHARED_SIZE 128
#else
    #define ECC_SHARED_SIZE 1024
#endif
#define ECC_DIGEST_SIZE     MAX_ECC_BYTES
#define ECC_SIG_SIZE        ECC_MAX_SIG_SIZE

#ifndef NO_ECC_VECTOR_TEST
    #if (defined(HAVE_ECC192) || defined(HAVE_ECC224) ||\
         !defined(NO_ECC256) || defined(HAVE_ECC384) ||\
         defined(HAVE_ECC521) || defined(HAVE_ALL_CURVES))
        #define HAVE_ECC_VECTOR_TEST
    #endif
#endif

#ifdef HAVE_ECC_VECTOR_TEST
typedef struct eccVector {
    const char* msg; /* SHA-1 Encoded Message */
    const char* Qx;
    const char* Qy;
    const char* d; /* Private Key */
    const char* R;
    const char* S;
    const char* curveName;
    word32 msgLen;
    word32 keySize;
} eccVector;

static int ecc_test_vector_item(const eccVector* vector)
{
    int ret = 0, verify = 0;
    word32  x;
    ecc_key userA;
    DECLARE_VAR(sig, byte, ECC_SIG_SIZE, HEAP_HINT);

    ret = wc_ecc_init_ex(&userA, HEAP_HINT, devId);
    if (ret != 0) {
        FREE_VAR(sig, HEAP_HINT);
        return ret;
    }

    XMEMSET(sig, 0, ECC_SIG_SIZE);
    x = ECC_SIG_SIZE;

    ret = wc_ecc_import_raw(&userA, vector->Qx, vector->Qy,
                                             vector->d, vector->curveName);
    if (ret != 0)
        goto done;

    ret = wc_ecc_rs_to_sig(vector->R, vector->S, sig, &x);
    if (ret != 0)
        goto done;

    do {
    #if defined(WOLFSSL_ASYNC_CRYPT)
        ret = wc_AsyncWait(ret, &userA.asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
    #endif
        if (ret >= 0) {
            ret = wc_ecc_verify_hash(sig, x, (byte*)vector->msg, vector->msgLen,
                                                               &verify, &userA);
        }
    } while (ret == WC_PENDING_E);

    if (ret != 0)
        goto done;

    if (verify != 1)
        ret = -6508;

done:
    wc_ecc_free(&userA);

    FREE_VAR(sig, HEAP_HINT);

    return ret;
}

static int ecc_test_vector(int keySize)
{
    int     ret;
    eccVector vec;

    XMEMSET(&vec, 0, sizeof(vec));
    vec.keySize = (word32)keySize;

    switch(keySize) {

#if defined(HAVE_ECC112) || defined(HAVE_ALL_CURVES)
    case 14:
        return 0;
#endif /* HAVE_ECC112 */
#if defined(HAVE_ECC128) || defined(HAVE_ALL_CURVES)
    case 16:
        return 0;
#endif /* HAVE_ECC128 */
#if defined(HAVE_ECC160) || defined(HAVE_ALL_CURVES)
    case 20:
        return 0;
#endif /* HAVE_ECC160 */

#if defined(HAVE_ECC192) || defined(HAVE_ALL_CURVES)
    case 24:
        /* first [P-192,SHA-1] vector from FIPS 186-3 NIST vectors */
        #if 1
            vec.msg = "\x60\x80\x79\x42\x3f\x12\x42\x1d\xe6\x16\xb7\x49\x3e\xbe\x55\x1c\xf4\xd6\x5b\x92";
            vec.msgLen = 20;
        #else
            /* This is the raw message prior to SHA-1 */
            vec.msg =
                "\xeb\xf7\x48\xd7\x48\xeb\xbc\xa7\xd2\x9f\xb4\x73\x69\x8a\x6e\x6b"
                "\x4f\xb1\x0c\x86\x5d\x4a\xf0\x24\xcc\x39\xae\x3d\xf3\x46\x4b\xa4"
                "\xf1\xd6\xd4\x0f\x32\xbf\x96\x18\xa9\x1b\xb5\x98\x6f\xa1\xa2\xaf"
                "\x04\x8a\x0e\x14\xdc\x51\xe5\x26\x7e\xb0\x5e\x12\x7d\x68\x9d\x0a"
                "\xc6\xf1\xa7\xf1\x56\xce\x06\x63\x16\xb9\x71\xcc\x7a\x11\xd0\xfd"
                "\x7a\x20\x93\xe2\x7c\xf2\xd0\x87\x27\xa4\xe6\x74\x8c\xc3\x2f\xd5"
                "\x9c\x78\x10\xc5\xb9\x01\x9d\xf2\x1c\xdc\xc0\xbc\xa4\x32\xc0\xa3"
                "\xee\xd0\x78\x53\x87\x50\x88\x77\x11\x43\x59\xce\xe4\xa0\x71\xcf";
            vec.msgLen = 128;
        #endif
        vec.Qx = "07008ea40b08dbe76432096e80a2494c94982d2d5bcf98e6";
        vec.Qy = "76fab681d00b414ea636ba215de26d98c41bd7f2e4d65477";
        vec.d  = "e14f37b3d1374ff8b03f41b9b3fdd2f0ebccf275d660d7f3";
        vec.R  = "6994d962bdd0d793ffddf855ec5bf2f91a9698b46258a63e";
        vec.S  = "02ba6465a234903744ab02bc8521405b73cf5fc00e1a9f41";
        vec.curveName = "SECP192R1";
        break;
#endif /* HAVE_ECC192 */

#if defined(HAVE_ECC224) || defined(HAVE_ALL_CURVES)
    case 28:
        /* first [P-224,SHA-1] vector from FIPS 186-3 NIST vectors */
        #if 1
            vec.msg = "\xb9\xa3\xb8\x6d\xb0\xba\x99\xfd\xc6\xd2\x94\x6b\xfe\xbe\x9c\xe8\x3f\x10\x74\xfc";
            vec.msgLen = 20;
        #else
            /* This is the raw message prior to SHA-1 */
            vec.msg =
                "\x36\xc8\xb2\x29\x86\x48\x7f\x67\x7c\x18\xd0\x97\x2a\x9e\x20\x47"
                "\xb3\xaf\xa5\x9e\xc1\x62\x76\x4e\xc3\x0b\x5b\x69\xe0\x63\x0f\x99"
                "\x0d\x4e\x05\xc2\x73\xb0\xe5\xa9\xd4\x28\x27\xb6\x95\xfc\x2d\x64"
                "\xd9\x13\x8b\x1c\xf4\xc1\x21\x55\x89\x4c\x42\x13\x21\xa7\xbb\x97"
                "\x0b\xdc\xe0\xfb\xf0\xd2\xae\x85\x61\xaa\xd8\x71\x7f\x2e\x46\xdf"
                "\xe3\xff\x8d\xea\xb4\xd7\x93\x23\x56\x03\x2c\x15\x13\x0d\x59\x9e"
                "\x26\xc1\x0f\x2f\xec\x96\x30\x31\xac\x69\x38\xa1\x8d\x66\x45\x38"
                "\xb9\x4d\xac\x55\x34\xef\x7b\x59\x94\x24\xd6\x9b\xe1\xf7\x1c\x20";
            vec.msgLen = 128;
        #endif
        vec.Qx = "8a4dca35136c4b70e588e23554637ae251077d1365a6ba5db9585de7";
        vec.Qy = "ad3dee06de0be8279d4af435d7245f14f3b4f82eb578e519ee0057b1";
        vec.d  = "97c4b796e1639dd1035b708fc00dc7ba1682cec44a1002a1a820619f";
        vec.R  = "147b33758321e722a0360a4719738af848449e2c1d08defebc1671a7";
        vec.S  = "24fc7ed7f1352ca3872aa0916191289e2e04d454935d50fe6af3ad5b";
        vec.curveName = "SECP224R1";
        break;
#endif /* HAVE_ECC224 */

#if defined(HAVE_ECC239) || defined(HAVE_ALL_CURVES)
    case 30:
        return 0;
#endif /* HAVE_ECC239 */

#if !defined(NO_ECC256) || defined(HAVE_ALL_CURVES)
    case 32:
        /* first [P-256,SHA-1] vector from FIPS 186-3 NIST vectors */
        #if 1
            vec.msg = "\xa3\xf9\x1a\xe2\x1b\xa6\xb3\x03\x98\x64\x47\x2f\x18\x41\x44\xc6\xaf\x62\xcd\x0e";
            vec.msgLen = 20;
        #else
            /* This is the raw message prior to SHA-1 */
            vec.msg =
                "\xa2\x4b\x21\x76\x2e\x6e\xdb\x15\x3c\xc1\x14\x38\xdb\x0e\x92\xcd"
                "\xf5\x2b\x86\xb0\x6c\xa9\x70\x16\x06\x27\x59\xc7\x0d\x36\xd1\x56"
                "\x2c\xc9\x63\x0d\x7f\xc7\xc7\x74\xb2\x8b\x54\xe3\x1e\xf5\x58\x72"
                "\xb2\xa6\x5d\xf1\xd7\xec\x26\xde\xbb\x33\xe7\xd9\x27\xef\xcc\xf4"
                "\x6b\x63\xde\x52\xa4\xf4\x31\xea\xca\x59\xb0\x5d\x2e\xde\xc4\x84"
                "\x5f\xff\xc0\xee\x15\x03\x94\xd6\x1f\x3d\xfe\xcb\xcd\xbf\x6f\x5a"
                "\x73\x38\xd0\xbe\x3f\x2a\x77\x34\x51\x98\x3e\xba\xeb\x48\xf6\x73"
                "\x8f\xc8\x95\xdf\x35\x7e\x1a\x48\xa6\x53\xbb\x35\x5a\x31\xa1\xb4"
            vec.msgLen = 128;
        #endif
        vec.Qx = "fa2737fb93488d19caef11ae7faf6b7f4bcd67b286e3fc54e8a65c2b74aeccb0";
        vec.Qy = "d4ccd6dae698208aa8c3a6f39e45510d03be09b2f124bfc067856c324f9b4d09";
        vec.d  = "be34baa8d040a3b991f9075b56ba292f755b90e4b6dc10dad36715c33cfdac25";
        vec.R  = "2b826f5d44e2d0b6de531ad96b51e8f0c56fdfead3c236892e4d84eacfc3b75c";
        vec.S  = "a2248b62c03db35a7cd63e8a120a3521a89d3d2f61ff99035a2148ae32e3a248";
        vec.curveName = "SECP256R1";
        break;
#endif /* !NO_ECC256 */

#if defined(HAVE_ECC320) || defined(HAVE_ALL_CURVES)
    case 40:
        return 0;
#endif /* HAVE_ECC320 */

#if defined(HAVE_ECC384) || defined(HAVE_ALL_CURVES)
    case 48:
        /* first [P-384,SHA-1] vector from FIPS 186-3 NIST vectors */
        #if 1
            vec.msg = "\x9b\x9f\x8c\x95\x35\xa5\xca\x26\x60\x5d\xb7\xf2\xfa\x57\x3b\xdf\xc3\x2e\xab\x8b";
            vec.msgLen = 20;
        #else
            /* This is the raw message prior to SHA-1 */
            vec.msg =
                "\xab\xe1\x0a\xce\x13\xe7\xe1\xd9\x18\x6c\x48\xf7\x88\x9d\x51\x47"
                "\x3d\x3a\x09\x61\x98\x4b\xc8\x72\xdf\x70\x8e\xcc\x3e\xd3\xb8\x16"
                "\x9d\x01\xe3\xd9\x6f\xc4\xf1\xd5\xea\x00\xa0\x36\x92\xbc\xc5\xcf"
                "\xfd\x53\x78\x7c\x88\xb9\x34\xaf\x40\x4c\x03\x9d\x32\x89\xb5\xba"
                "\xc5\xae\x7d\xb1\x49\x68\x75\xb5\xdc\x73\xc3\x09\xf9\x25\xc1\x3d"
                "\x1c\x01\xab\xda\xaf\xeb\xcd\xac\x2c\xee\x43\x39\x39\xce\x8d\x4a"
                "\x0a\x5d\x57\xbb\x70\x5f\x3b\xf6\xec\x08\x47\x95\x11\xd4\xb4\xa3"
                "\x21\x1f\x61\x64\x9a\xd6\x27\x43\x14\xbf\x0d\x43\x8a\x81\xe0\x60"
            vec.msgLen = 128;
        #endif
        vec.Qx = "e55fee6c49d8d523f5ce7bf9c0425ce4ff650708b7de5cfb095901523979a7f042602db30854735369813b5c3f5ef868";
        vec.Qy = "28f59cc5dc509892a988d38a8e2519de3d0c4fd0fbdb0993e38f18506c17606c5e24249246f1ce94983a5361c5be983e";
        vec.d  = "a492ce8fa90084c227e1a32f7974d39e9ff67a7e8705ec3419b35fb607582bebd461e0b1520ac76ec2dd4e9b63ebae71";
        vec.R  = "6820b8585204648aed63bdff47f6d9acebdea62944774a7d14f0e14aa0b9a5b99545b2daee6b3c74ebf606667a3f39b7";
        vec.S  = "491af1d0cccd56ddd520b233775d0bc6b40a6255cc55207d8e9356741f23c96c14714221078dbd5c17f4fdd89b32a907";
        vec.curveName = "SECP384R1";
        break;
#endif /* HAVE_ECC384 */

#if defined(HAVE_ECC512) || defined(HAVE_ALL_CURVES)
    case 64:
        return 0;
#endif /* HAVE_ECC512 */

#if defined(HAVE_ECC521) || defined(HAVE_ALL_CURVES)
    case 66:
        /* first [P-521,SHA-1] vector from FIPS 186-3 NIST vectors */
        #if 1
            vec.msg = "\x1b\xf7\x03\x9c\xca\x23\x94\x27\x3f\x11\xa1\xd4\x8d\xcc\xb4\x46\x6f\x31\x61\xdf";
            vec.msgLen = 20;
        #else
            /* This is the raw message prior to SHA-1 */
            vec.msg =
                "\x50\x3f\x79\x39\x34\x0a\xc7\x23\xcd\x4a\x2f\x4e\x6c\xcc\x27\x33"
                "\x38\x3a\xca\x2f\xba\x90\x02\x19\x9d\x9e\x1f\x94\x8b\xe0\x41\x21"
                "\x07\xa3\xfd\xd5\x14\xd9\x0c\xd4\xf3\x7c\xc3\xac\x62\xef\x00\x3a"
                "\x2d\xb1\xd9\x65\x7a\xb7\x7f\xe7\x55\xbf\x71\xfa\x59\xe4\xd9\x6e"
                "\xa7\x2a\xe7\xbf\x9d\xe8\x7d\x79\x34\x3b\xc1\xa4\xbb\x14\x4d\x16"
                "\x28\xd1\xe9\xe9\xc8\xed\x80\x8b\x96\x2c\x54\xe5\xf9\x6d\x53\xda"
                "\x14\x7a\x96\x38\xf9\x4a\x91\x75\xd8\xed\x61\x05\x5f\x0b\xa5\x73"
                "\xa8\x2b\xb7\xe0\x18\xee\xda\xc4\xea\x7b\x36\x2e\xc8\x9c\x38\x2b"
            vec.msgLen = 128;
        #endif
        vec.Qx = "12fbcaeffa6a51f3ee4d3d2b51c5dec6d7c726ca353fc014ea2bf7cfbb9b910d32cbfa6a00fe39b6cdb8946f22775398b2e233c0cf144d78c8a7742b5c7a3bb5d23";
        vec.Qy = "09cdef823dd7bf9a79e8cceacd2e4527c231d0ae5967af0958e931d7ddccf2805a3e618dc3039fec9febbd33052fe4c0fee98f033106064982d88f4e03549d4a64d";
        vec.d  = "1bd56bd106118eda246155bd43b42b8e13f0a6e25dd3bb376026fab4dc92b6157bc6dfec2d15dd3d0cf2a39aa68494042af48ba9601118da82c6f2108a3a203ad74";
        vec.R  = "0bd117b4807710898f9dd7778056485777668f0e78e6ddf5b000356121eb7a220e9493c7f9a57c077947f89ac45d5acb6661bbcd17abb3faea149ba0aa3bb1521be";
        vec.S  = "019cd2c5c3f9870ecdeb9b323abdf3a98cd5e231d85c6ddc5b71ab190739f7f226e6b134ba1d5889ddeb2751dabd97911dff90c34684cdbe7bb669b6c3d22f2480c";
        vec.curveName = "SECP521R1";
        break;
#endif /* HAVE_ECC521 */
    default:
        return NOT_COMPILED_IN; /* Invalid key size / Not supported */
    }; /* Switch */

    ret = ecc_test_vector_item(&vec);
    if (ret < 0) {
        return ret;
    }

    return 0;
}

#ifdef HAVE_ECC_CDH
static int ecc_test_cdh_vectors(void)
{
    int ret;
    ecc_key pub_key, priv_key;
    byte    sharedA[32] = {0}, sharedB[32] = {0};
    word32  x, z;

    const char* QCAVSx = "700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287";
    const char* QCAVSy = "db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac";
    const char* dIUT =   "7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534";
    const char* QIUTx =  "ead218590119e8876b29146ff89ca61770c4edbbf97d38ce385ed281d8a6b230";
    const char* QIUTy =  "28af61281fd35e2fa7002523acc85a429cb06ee6648325389f59edfce1405141";
    const char* ZIUT =   "46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b";

    /* setup private and public keys */
    ret = wc_ecc_init(&pub_key);
    if (ret != 0)
        return ret;
    ret = wc_ecc_init(&priv_key);
    if (ret != 0) {
        wc_ecc_free(&pub_key);
        goto done;
    }
    wc_ecc_set_flags(&pub_key, WC_ECC_FLAG_COFACTOR);
    wc_ecc_set_flags(&priv_key, WC_ECC_FLAG_COFACTOR);
    ret = wc_ecc_import_raw(&pub_key, QCAVSx, QCAVSy, NULL, "SECP256R1");
    if (ret != 0)
        goto done;
    ret = wc_ecc_import_raw(&priv_key, QIUTx, QIUTy, dIUT, "SECP256R1");
    if (ret != 0)
        goto done;

    /* compute ECC Cofactor shared secret */
    x = sizeof(sharedA);
    ret = wc_ecc_shared_secret(&priv_key, &pub_key, sharedA, &x);
    if (ret != 0) {
        goto done;
    }

    /* read in expected Z */
    z = sizeof(sharedB);
    ret = Base16_Decode((const byte*)ZIUT, (word32)XSTRLEN(ZIUT), sharedB, &z);
    if (ret != 0)
        goto done;

    /* compare results */
    if (x != z || XMEMCMP(sharedA, sharedB, x)) {
        ERROR_OUT(-6509, done);
    }

done:
    wc_ecc_free(&priv_key);
    wc_ecc_free(&pub_key);
    return ret;
}
#endif /* HAVE_ECC_CDH */
#endif /* HAVE_ECC_VECTOR_TEST */

#ifdef HAVE_ECC_KEY_IMPORT
/* returns 0 on success */
static int ecc_test_make_pub(WC_RNG* rng)
{
    ecc_key key;
    unsigned char* exportBuf;
    unsigned char* tmp;
    unsigned char msg[] = "test wolfSSL ECC public gen";
    word32 x, tmpSz;
    int ret = 0;
    ecc_point* pubPoint = NULL;
#if defined(HAVE_ECC_DHE) && defined(HAVE_ECC_KEY_EXPORT)
    ecc_key pub;
#endif
#ifdef HAVE_ECC_VERIFY
    int verify = 0;
#endif
#ifndef USE_CERT_BUFFERS_256
    FILE* file;
#endif

    tmp = (byte*)XMALLOC(FOURK_BUF, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (tmp == NULL) {
        return -6810;
    }
    exportBuf = (byte*)XMALLOC(FOURK_BUF, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (exportBuf == NULL) {
        XFREE(tmp, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        return -6811;
    }

#ifdef USE_CERT_BUFFERS_256
    XMEMCPY(tmp, ecc_key_der_256, (size_t)sizeof_ecc_key_der_256);
    tmpSz = (size_t)sizeof_ecc_key_der_256;
#else
    file = fopen(eccKeyDerFile, "rb");
    if (!file) {
        ERROR_OUT(-6812, done);
    }

    tmpSz = (word32)fread(tmp, 1, FOURK_BUF, file);
    fclose(file);
#endif /* USE_CERT_BUFFERS_256 */

    wc_ecc_init(&key);

    /* import private only then test with */
    ret = wc_ecc_import_private_key(tmp, tmpSz, NULL, 0, NULL);
    if (ret == 0) {
        ERROR_OUT(-6813, done);
    }

    ret = wc_ecc_import_private_key(NULL, tmpSz, NULL, 0, &key);
    if (ret == 0) {
        ERROR_OUT(-6814, done);
    }

    x = 0;
    ret = wc_EccPrivateKeyDecode(tmp, &x, &key, tmpSz);
    if (ret != 0) {
        ERROR_OUT(-6815, done);
    }

#ifdef HAVE_ECC_KEY_EXPORT
    x = FOURK_BUF;
    ret = wc_ecc_export_private_only(&key, exportBuf, &x);
    if (ret != 0) {
        ERROR_OUT(-6816, done);
    }

    /* make private only key */
    wc_ecc_free(&key);
    wc_ecc_init(&key);
    ret = wc_ecc_import_private_key(exportBuf, x, NULL, 0, &key);
    if (ret != 0) {
        ERROR_OUT(-6817, done);
    }

    x = FOURK_BUF;
    ret = wc_ecc_export_x963_ex(&key, exportBuf, &x, 0);
    if (ret == 0) {
        ERROR_OUT(-6818, done);
    }

#endif /* HAVE_ECC_KEY_EXPORT */

    ret = wc_ecc_make_pub(NULL, NULL);
    if (ret == 0) {
        ERROR_OUT(-6819, done);
    }

    pubPoint = wc_ecc_new_point_h(HEAP_HINT);
    if (pubPoint == NULL) {
        ERROR_OUT(-6820, done);
    }

    ret = wc_ecc_make_pub(&key, pubPoint);
    if (ret != 0) {
        ERROR_OUT(-6821, done);
    }

#ifdef HAVE_ECC_KEY_EXPORT
    /* export should still fail, is private only key */
    x = FOURK_BUF;
    ret = wc_ecc_export_x963_ex(&key, exportBuf, &x, 0);
    if (ret == 0) {
        ERROR_OUT(-6822, done);
    }
#endif /* HAVE_ECC_KEY_EXPORT */

#ifdef HAVE_ECC_SIGN
    tmpSz = FOURK_BUF;
    ret = wc_ecc_sign_hash(msg, sizeof(msg), tmp, &tmpSz, rng, &key);
    if (ret != 0) {
        ERROR_OUT(-6823, done);
    }

#ifdef HAVE_ECC_VERIFY
    /* try verify with private only key */
    ret = wc_ecc_verify_hash(tmp, tmpSz, msg, sizeof(msg), &verify, &key);
    if (ret != 0) {
        ERROR_OUT(-6824, done);
    }

    if (verify != 1) {
        ERROR_OUT(-6825, done);
    }
#ifdef HAVE_ECC_KEY_EXPORT
    /* exporting the public part should now work */
    x = FOURK_BUF;
    ret = wc_ecc_export_x963_ex(&key, exportBuf, &x, 0);
    if (ret != 0) {
        ERROR_OUT(-6826, done);
    }
#endif /* HAVE_ECC_KEY_EXPORT */
#endif /* HAVE_ECC_VERIFY */

#endif /* HAVE_ECC_SIGN */

#if defined(HAVE_ECC_DHE) && defined(HAVE_ECC_KEY_EXPORT)
    /* now test private only key with creating a shared secret */
    x = FOURK_BUF;
    ret = wc_ecc_export_private_only(&key, exportBuf, &x);
    if (ret != 0) {
        ERROR_OUT(-6827, done);
    }

    /* make private only key */
    wc_ecc_free(&key);
    wc_ecc_init(&key);
    ret = wc_ecc_import_private_key(exportBuf, x, NULL, 0, &key);
    if (ret != 0) {
        ERROR_OUT(-6828, done);
    }

    /* check that public export fails with private only key */
    x = FOURK_BUF;
    ret = wc_ecc_export_x963_ex(&key, exportBuf, &x, 0);
    if (ret == 0) {
        ERROR_OUT(-6829, done);
    }

    /* make public key for shared secret */
    wc_ecc_init(&pub);
    ret = wc_ecc_make_key(rng, 32, &pub);
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &pub.asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
#endif
    if (ret != 0) {
        ERROR_OUT(-6830, done);
    }

    x = FOURK_BUF;
    ret = wc_ecc_shared_secret(&key, &pub, exportBuf, &x);
    wc_ecc_free(&pub);
    if (ret != 0) {
        ERROR_OUT(-6831, done);
    }
#endif /* HAVE_ECC_DHE && HAVE_ECC_KEY_EXPORT */

    ret = 0;

done:

    XFREE(tmp, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(exportBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

    wc_ecc_del_point_h(pubPoint, HEAP_HINT);
    wc_ecc_free(&key);

    return ret;
}
#endif /* HAVE_ECC_KEY_IMPORT */


#ifdef WOLFSSL_KEY_GEN
static int ecc_test_key_gen(WC_RNG* rng, int keySize)
{
    int    ret = 0;
    int    derSz;
    word32 pkcs8Sz;
    byte*  der;
    byte*  pem;
    ecc_key userA;

    der = (byte*)XMALLOC(FOURK_BUF, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (der == NULL) {
        return -6840;
    }
    pem = (byte*)XMALLOC(FOURK_BUF, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (pem == NULL) {
        XFREE(der, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        return -6840;
    }

    ret = wc_ecc_init_ex(&userA, HEAP_HINT, devId);
    if (ret != 0)
        goto done;

    ret = wc_ecc_make_key(rng, keySize, &userA);
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &userA.asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
#endif
    if (ret != 0)
        goto done;

    ret = wc_ecc_check_key(&userA);
    if (ret != 0)
        goto done;

    derSz = wc_EccKeyToDer(&userA, der, FOURK_BUF);
    if (derSz < 0) {
        ERROR_OUT(derSz, done);
    }

    ret = SaveDerAndPem(der, derSz, pem, FOURK_BUF, eccCaKeyTempFile,
            eccCaKeyPemFile, ECC_PRIVATEKEY_TYPE, -6510);
    if (ret != 0) {
        goto done;
    }

    /* test export of public key */
    derSz = wc_EccPublicKeyToDer(&userA, der, FOURK_BUF, 1);
    if (derSz < 0) {
        ERROR_OUT(derSz, done);
    }
    if (derSz == 0) {
        ERROR_OUT(-6514, done);
    }

    ret = SaveDerAndPem(der, derSz, NULL, 0, eccPubKeyDerFile,
        NULL, 0, -6515);
    if (ret != 0) {
        goto done;
    }

    /* test export of PKCS#8 unecrypted private key */
    pkcs8Sz = FOURK_BUF;
    derSz = wc_EccPrivateKeyToPKCS8(&userA, der, &pkcs8Sz);
    if (derSz < 0) {
        ERROR_OUT(derSz, done);
    }

    if (derSz == 0) {
        ERROR_OUT(-6516, done);
    }

    ret = SaveDerAndPem(der, derSz, NULL, 0, eccPkcs8KeyDerFile,
                        NULL, 0, -6517);
    if (ret != 0) {
        goto done;
    }

done:

    XFREE(der, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(pem, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    wc_ecc_free(&userA);

    return ret;
}
#endif /* WOLFSSL_KEY_GEN */

static int ecc_test_curve_size(WC_RNG* rng, int keySize, int testVerifyCount,
    int curve_id, const ecc_set_type* dp)
{
    DECLARE_VAR(sharedA, byte, ECC_SHARED_SIZE, HEAP_HINT);
    DECLARE_VAR(sharedB, byte, ECC_SHARED_SIZE, HEAP_HINT);
#ifdef HAVE_ECC_KEY_EXPORT
    byte    exportBuf[1024];
#endif
    word32  x, y;
#ifdef HAVE_ECC_SIGN
    DECLARE_VAR(sig, byte, ECC_SIG_SIZE, HEAP_HINT);
    DECLARE_VAR(digest, byte, ECC_DIGEST_SIZE, HEAP_HINT);
    int     i;
#ifdef HAVE_ECC_VERIFY
    int     verify;
#endif /* HAVE_ECC_VERIFY */
#endif /* HAVE_ECC_SIGN */
    int     ret;
    ecc_key userA, userB, pubKey;

    (void)testVerifyCount;
    (void)dp;

    XMEMSET(&userA, 0, sizeof(ecc_key));
    XMEMSET(&userB, 0, sizeof(ecc_key));
    XMEMSET(&pubKey, 0, sizeof(ecc_key));

    ret = wc_ecc_init_ex(&userA, HEAP_HINT, devId);
    if (ret != 0)
        goto done;
    ret = wc_ecc_init_ex(&userB, HEAP_HINT, devId);
    if (ret != 0)
        goto done;
    ret = wc_ecc_init_ex(&pubKey, HEAP_HINT, devId);
    if (ret != 0)
        goto done;

#ifdef WOLFSSL_CUSTOM_CURVES
    if (dp != NULL) {
        ret = wc_ecc_set_custom_curve(&userA, dp);
        if (ret != 0)
            goto done;
        ret = wc_ecc_set_custom_curve(&userB, dp);
        if (ret != 0)
            goto done;
    }
#endif

    ret = wc_ecc_make_key_ex(rng, keySize, &userA, curve_id);
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &userA.asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
#endif
    if (ret != 0)
        goto done;

    ret = wc_ecc_check_key(&userA);
    if (ret != 0)
        goto done;

    ret = wc_ecc_make_key_ex(rng, keySize, &userB, curve_id);
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &userB.asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
#endif
    if (ret != 0)
        goto done;

    /* only perform the below tests if the key size matches */
    if (dp == NULL && keySize > 0 && wc_ecc_size(&userA) != keySize) {
        ret = ECC_CURVE_OID_E;
        goto done;
    }


#ifdef HAVE_ECC_DHE
    x = ECC_SHARED_SIZE;
    do {
    #if defined(WOLFSSL_ASYNC_CRYPT)
        ret = wc_AsyncWait(ret, &userA.asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
    #endif
        if (ret >= 0)
            ret = wc_ecc_shared_secret(&userA, &userB, sharedA, &x);
    } while (ret == WC_PENDING_E);
    if (ret != 0) {
        goto done;
    }

    y = ECC_SHARED_SIZE;
    do {
    #if defined(WOLFSSL_ASYNC_CRYPT)
        ret = wc_AsyncWait(ret, &userB.asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
    #endif
        if (ret >= 0)
            ret = wc_ecc_shared_secret(&userB, &userA, sharedB, &y);
    } while (ret == WC_PENDING_E);
    if (ret != 0)
        goto done;

    if (y != x)
        ERROR_OUT(-6517, done);

    if (XMEMCMP(sharedA, sharedB, x))
        ERROR_OUT(-6518, done);
#endif /* HAVE_ECC_DHE */

#ifdef HAVE_ECC_CDH
    /* add cofactor flag */
    wc_ecc_set_flags(&userA, WC_ECC_FLAG_COFACTOR);
    wc_ecc_set_flags(&userB, WC_ECC_FLAG_COFACTOR);

    x = sizeof(sharedA);
    ret = wc_ecc_shared_secret(&userA, &userB, sharedA, &x);
    if (ret != 0) {
        goto done;
    }

    y = sizeof(sharedB);
    ret = wc_ecc_shared_secret(&userB, &userA, sharedB, &y);
    if (ret != 0)
        goto done;

    if (y != x)
        ERROR_OUT(-6519, done);

    if (XMEMCMP(sharedA, sharedB, x))
        ERROR_OUT(-6520, done);

    /* remove cofactor flag */
    wc_ecc_set_flags(&userA, 0);
    wc_ecc_set_flags(&userB, 0);
#endif /* HAVE_ECC_CDH */

#ifdef HAVE_ECC_KEY_EXPORT
    x = sizeof(exportBuf);
    ret = wc_ecc_export_x963_ex(&userA, exportBuf, &x, 0);
    if (ret != 0)
        goto done;

#ifdef HAVE_ECC_KEY_IMPORT
    #ifdef WOLFSSL_CUSTOM_CURVES
        if (dp != NULL) {
            ret = wc_ecc_set_custom_curve(&pubKey, dp);
            if (ret != 0) goto done;
        }
    #endif
    ret = wc_ecc_import_x963_ex(exportBuf, x, &pubKey, curve_id);
    if (ret != 0)
        goto done;

#ifdef HAVE_ECC_DHE
    y = ECC_SHARED_SIZE;
    do {
    #if defined(WOLFSSL_ASYNC_CRYPT)
        ret = wc_AsyncWait(ret, &userB.asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
    #endif
        if (ret >= 0)
            ret = wc_ecc_shared_secret(&userB, &pubKey, sharedB, &y);
    } while (ret == WC_PENDING_E);
    if (ret != 0)
        goto done;

    if (XMEMCMP(sharedA, sharedB, y))
        ERROR_OUT(-6521, done);
#endif /* HAVE_ECC_DHE */

    #ifdef HAVE_COMP_KEY
        /* try compressed export / import too */
        x = sizeof(exportBuf);
        ret = wc_ecc_export_x963_ex(&userA, exportBuf, &x, 1);
        if (ret != 0)
            goto done;
        wc_ecc_free(&pubKey);

        ret = wc_ecc_init_ex(&pubKey, HEAP_HINT, devId);
        if (ret != 0)
            goto done;
    #ifdef WOLFSSL_CUSTOM_CURVES
        if (dp != NULL) {
            ret = wc_ecc_set_custom_curve(&pubKey, dp);
            if (ret != 0) goto done;
        }
    #endif
        ret = wc_ecc_import_x963_ex(exportBuf, x, &pubKey, curve_id);
        if (ret != 0)
            goto done;

    #ifdef HAVE_ECC_DHE
        y = ECC_SHARED_SIZE;
        do {
        #if defined(WOLFSSL_ASYNC_CRYPT)
            ret = wc_AsyncWait(ret, &userB.asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
        #endif
            if (ret >= 0)
                ret = wc_ecc_shared_secret(&userB, &pubKey, sharedB, &y);
        } while (ret == WC_PENDING_E);
        if (ret != 0)
            goto done;

        if (XMEMCMP(sharedA, sharedB, y))
            ERROR_OUT(-6522, done);
    #endif /* HAVE_ECC_DHE */
    #endif /* HAVE_COMP_KEY */

#endif /* HAVE_ECC_KEY_IMPORT */
#endif /* HAVE_ECC_KEY_EXPORT */

#ifdef HAVE_ECC_SIGN
    /* ECC w/out Shamir has issue with all 0 digest */
    /* WC_BIGINT doesn't have 0 len well on hardware */
#if defined(ECC_SHAMIR) && !defined(WOLFSSL_ASYNC_CRYPT)
    /* test DSA sign hash with zeros */
    for (i = 0; i < (int)ECC_DIGEST_SIZE; i++) {
        digest[i] = 0;
    }

    x = ECC_SIG_SIZE;
    do {
    #if defined(WOLFSSL_ASYNC_CRYPT)
        ret = wc_AsyncWait(ret, &userA.asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
    #endif
        if (ret >= 0)
            ret = wc_ecc_sign_hash(digest, ECC_DIGEST_SIZE, sig, &x, rng,
                                                                        &userA);
    } while (ret == WC_PENDING_E);
    if (ret != 0)
        goto done;

#ifdef HAVE_ECC_VERIFY
    for (i=0; i<testVerifyCount; i++) {
        verify = 0;
        do {
        #if defined(WOLFSSL_ASYNC_CRYPT)
            ret = wc_AsyncWait(ret, &userA.asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
        #endif
            if (ret >= 0)
                ret = wc_ecc_verify_hash(sig, x, digest, ECC_DIGEST_SIZE,
                                                               &verify, &userA);
        } while (ret == WC_PENDING_E);
        if (ret != 0)
            goto done;
        if (verify != 1)
            ERROR_OUT(-6523, done);
    }
#endif /* HAVE_ECC_VERIFY */
#endif /* ECC_SHAMIR && !WOLFSSL_ASYNC_CRYPT */

    /* test DSA sign hash with sequence (0,1,2,3,4,...) */
    for (i = 0; i < (int)ECC_DIGEST_SIZE; i++) {
        digest[i] = (byte)i;
    }

    x = ECC_SIG_SIZE;
    do {
    #if defined(WOLFSSL_ASYNC_CRYPT)
        ret = wc_AsyncWait(ret, &userA.asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
    #endif
        if (ret >= 0)
            ret = wc_ecc_sign_hash(digest, ECC_DIGEST_SIZE, sig, &x, rng,
                                                                        &userA);
    } while (ret == WC_PENDING_E);
    if (ret != 0)
        ERROR_OUT(-6524, done);

#ifdef HAVE_ECC_VERIFY
    for (i=0; i<testVerifyCount; i++) {
        verify = 0;
        do {
        #if defined(WOLFSSL_ASYNC_CRYPT)
            ret = wc_AsyncWait(ret, &userA.asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
        #endif
            if (ret >= 0)
                ret = wc_ecc_verify_hash(sig, x, digest, ECC_DIGEST_SIZE,
                                                               &verify, &userA);
        } while (ret == WC_PENDING_E);
        if (ret != 0)
            goto done;
        if (verify != 1)
            ERROR_OUT(-6525, done);
    }
#endif /* HAVE_ECC_VERIFY */
#endif /* HAVE_ECC_SIGN */

#ifdef HAVE_ECC_KEY_EXPORT
    x = sizeof(exportBuf);
    ret = wc_ecc_export_private_only(&userA, exportBuf, &x);
    if (ret != 0)
        goto done;
#endif /* HAVE_ECC_KEY_EXPORT */

done:
    wc_ecc_free(&pubKey);
    wc_ecc_free(&userB);
    wc_ecc_free(&userA);

    FREE_VAR(sharedA, HEAP_HINT);
    FREE_VAR(sharedB, HEAP_HINT);
#ifdef HAVE_ECC_SIGN
    FREE_VAR(sig, HEAP_HINT);
    FREE_VAR(digest, HEAP_HINT);
#endif

    return ret;
}

#undef  ECC_TEST_VERIFY_COUNT
#define ECC_TEST_VERIFY_COUNT 2
static int ecc_test_curve(WC_RNG* rng, int keySize)
{
    int ret;

    ret = ecc_test_curve_size(rng, keySize, ECC_TEST_VERIFY_COUNT,
        ECC_CURVE_DEF, NULL);
    if (ret < 0) {
        if (ret == ECC_CURVE_OID_E) {
            /* ignore error for curves not found */
            /* some curve sizes are only available with:
                HAVE_ECC_SECPR2, HAVE_ECC_SECPR3, HAVE_ECC_BRAINPOOL
                and HAVE_ECC_KOBLITZ */
        }
        else {
            printf("ecc_test_curve_size %d failed!: %d\n", keySize, ret);
            return ret;
        }
    }

#ifdef HAVE_ECC_VECTOR_TEST
    ret = ecc_test_vector(keySize);
    if (ret < 0) {
        printf("ecc_test_vector %d failed!: %d\n", keySize, ret);
        return ret;
    }
#endif

#ifdef WOLFSSL_KEY_GEN
    ret = ecc_test_key_gen(rng, keySize);
    if (ret < 0) {
        if (ret == ECC_CURVE_OID_E) {
            /* ignore error for curves not found */
        }
        else {
            printf("ecc_test_key_gen %d failed!: %d\n", keySize, ret);
            return ret;
        }
    }
#endif

    return 0;
}

#if !defined(WOLFSSL_ATECC508A) && defined(HAVE_ECC_KEY_IMPORT) && \
     defined(HAVE_ECC_KEY_EXPORT)
static int ecc_point_test(void)
{
    int        ret;
    ecc_point* point;
    ecc_point* point2;
#ifdef HAVE_COMP_KEY
    ecc_point* point3;
    ecc_point* point4;
#endif
    word32     outLen;
    byte       out[65];
    byte       der[] = { 0x04, /* = Uncompressed */
                         0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                         0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                         0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                         0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                         0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                         0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                         0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                         0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
#ifdef HAVE_COMP_KEY
    byte       derComp0[] = { 0x02, /* = Compressed, y even */
                              0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                              0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                              0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                              0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    byte       derComp1[] = { 0x03, /* = Compressed, y odd */
                              0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                              0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                              0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                              0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
#endif
    byte       altDer[] = { 0x04, /* = Uncompressed */
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
    int curve_idx = wc_ecc_get_curve_idx(ECC_SECP256R1);

    /* if curve P256 is not enabled then test should not fail */
    if (curve_idx == ECC_CURVE_INVALID)
        return 0;

    outLen = sizeof(out);
    point = wc_ecc_new_point();
    if (point == NULL)
        return -6600;
    point2 = wc_ecc_new_point();
    if (point2 == NULL) {
        wc_ecc_del_point(point);
        return -6601;
    }
#ifdef HAVE_COMP_KEY
    point3 = wc_ecc_new_point();
    if (point3 == NULL) {
        wc_ecc_del_point(point2);
        wc_ecc_del_point(point);
        return -6602;
    }
    point4 = wc_ecc_new_point();
    if (point4 == NULL) {
        wc_ecc_del_point(point3);
        wc_ecc_del_point(point2);
        wc_ecc_del_point(point);
        return -6603;
    }
#endif

    /* Parameter Validation testing. */
    wc_ecc_del_point(NULL);
    ret = wc_ecc_import_point_der(NULL, sizeof(der), curve_idx, point);
    if (ret != ECC_BAD_ARG_E) {
        ret = -6604;
        goto done;
    }
    ret = wc_ecc_import_point_der(der, sizeof(der), ECC_CURVE_INVALID, point);
    if (ret != ECC_BAD_ARG_E) {
        ret = -6605;
        goto done;
    }
    ret = wc_ecc_import_point_der(der, sizeof(der), curve_idx, NULL);
    if (ret != ECC_BAD_ARG_E) {
        ret = -6606;
        goto done;
    }
    ret = wc_ecc_export_point_der(-1, point, out, &outLen);
    if (ret != ECC_BAD_ARG_E) {
        ret = -6607;
        goto done;
    }
    ret = wc_ecc_export_point_der(curve_idx, NULL, out, &outLen);
    if (ret != ECC_BAD_ARG_E) {
        ret = -6608;
        goto done;
    }
    ret = wc_ecc_export_point_der(curve_idx, point, NULL, &outLen);
    if (ret != LENGTH_ONLY_E || outLen != sizeof(out)) {
        ret = -6609;
        goto done;
    }
    ret = wc_ecc_export_point_der(curve_idx, point, out, NULL);
    if (ret != ECC_BAD_ARG_E) {
        ret = -6610;
        goto done;
    }
    outLen = 0;
    ret = wc_ecc_export_point_der(curve_idx, point, out, &outLen);
    if (ret != BUFFER_E) {
        ret = -6611;
        goto done;
    }
    ret = wc_ecc_copy_point(NULL, NULL);
    if (ret != ECC_BAD_ARG_E) {
        ret = -6612;
        goto done;
    }
    ret = wc_ecc_copy_point(NULL, point2);
    if (ret != ECC_BAD_ARG_E) {
        ret = -6613;
        goto done;
    }
    ret = wc_ecc_copy_point(point, NULL);
    if (ret != ECC_BAD_ARG_E) {
        ret = -6614;
        goto done;
    }
    ret = wc_ecc_cmp_point(NULL, NULL);
    if (ret != BAD_FUNC_ARG) {
        ret = -6615;
        goto done;
    }
    ret = wc_ecc_cmp_point(NULL, point2);
    if (ret != BAD_FUNC_ARG) {
        ret = -6616;
        goto done;
    }
    ret = wc_ecc_cmp_point(point, NULL);
    if (ret != BAD_FUNC_ARG) {
        ret = -6617;
        goto done;
    }

    /* Use API. */
    ret = wc_ecc_import_point_der(der, sizeof(der), curve_idx, point);
    if (ret != 0) {
        ret = -6618;
        goto done;
    }

    outLen = sizeof(out);
    ret = wc_ecc_export_point_der(curve_idx, point, out, &outLen);
    if (ret != 0) {
        ret = -6619;
        goto done;
    }
    if (outLen != sizeof(der)) {
        ret = -6620;
        goto done;
    }
    if (XMEMCMP(out, der, outLen) != 0) {
        ret = -6621;
        goto done;
    }

    ret = wc_ecc_copy_point(point2, point);
    if (ret != MP_OKAY) {
        ret = -6622;
        goto done;
    }
    ret = wc_ecc_cmp_point(point2, point);
    if (ret != MP_EQ) {
        ret = -6623;
        goto done;
    }

    ret = wc_ecc_import_point_der(altDer, sizeof(altDer), curve_idx, point2);
    if (ret != 0) {
        ret = -6624;
        goto done;
    }
    ret = wc_ecc_cmp_point(point2, point);
    if (ret != MP_GT) {
        ret = -6625;
        goto done;
    }

#ifdef HAVE_COMP_KEY
    ret = wc_ecc_import_point_der(derComp0, sizeof(der), curve_idx, point3);
    if (ret != 0) {
        ret = -6626;
        goto done;
    }

    ret = wc_ecc_import_point_der(derComp1, sizeof(der), curve_idx, point4);
    if (ret != 0) {
        ret = -6627;
        goto done;
    }
#endif

done:
#ifdef HAVE_COMP_KEY
    wc_ecc_del_point(point4);
    wc_ecc_del_point(point3);
#endif
    wc_ecc_del_point(point2);
    wc_ecc_del_point(point);

    return ret;
}
#endif /* !WOLFSSL_ATECC508A && HAVE_ECC_KEY_IMPORT && HAVE_ECC_KEY_EXPORT */

#ifndef NO_SIG_WRAPPER
static int ecc_sig_test(WC_RNG* rng, ecc_key* key)
{
    int     ret;
    word32  sigSz;
    int     size;
    byte    out[ECC_MAX_SIG_SIZE];
    byte   in[] = "Everyone gets Friday off.";
    word32 inLen = (word32)XSTRLEN((char*)in);

    size = wc_ecc_sig_size(key);

    ret = wc_SignatureGetSize(WC_SIGNATURE_TYPE_ECC, key, sizeof(*key));
    if (ret != size)
        return -6628;

    sigSz = (word32)ret;
    ret = wc_SignatureGenerate(WC_HASH_TYPE_SHA256, WC_SIGNATURE_TYPE_ECC, in,
                               inLen, out, &sigSz, key, sizeof(*key), rng);
    if (ret != 0)
        return -6629;

    ret = wc_SignatureVerify(WC_HASH_TYPE_SHA256, WC_SIGNATURE_TYPE_ECC, in,
                             inLen, out, sigSz, key, sizeof(*key));
    if (ret != 0)
        return -6630;

    return 0;
}
#endif

#if defined(HAVE_ECC_KEY_IMPORT) && defined(HAVE_ECC_KEY_EXPORT)
static int ecc_exp_imp_test(ecc_key* key)
{
    int        ret;
    int        curve_id;
    ecc_key    keyImp;
    byte       priv[32];
    word32     privLen;
    byte       pub[65];
    word32     pubLen, pubLenX, pubLenY;
    const char qx[] = "7a4e287890a1a47ad3457e52f2f76a83"
                      "ce46cbc947616d0cbaa82323818a793d";
    const char qy[] = "eec4084f5b29ebf29c44cce3b3059610"
                      "922f8b30ea6e8811742ac7238fe87308";
    const char d[]  = "8c14b793cb19137e323a6d2e2a870bca"
                      "2e7a493ec1153b3a95feb8a4873f8d08";

    wc_ecc_init(&keyImp);

    privLen = sizeof(priv);
    ret = wc_ecc_export_private_only(key, priv, &privLen);
    if (ret != 0) {
        ret = -6631;
        goto done;
    }
    pubLen = sizeof(pub);
    ret = wc_ecc_export_point_der(key->idx, &key->pubkey, pub, &pubLen);
    if (ret != 0) {
        ret = -6632;
        goto done;
    }

    ret = wc_ecc_import_private_key(priv, privLen, pub, pubLen, &keyImp);
    if (ret != 0) {
        ret = -6633;
        goto done;
    }

    wc_ecc_free(&keyImp);
    wc_ecc_init(&keyImp);

    ret = wc_ecc_import_raw_ex(&keyImp, qx, qy, d, ECC_SECP256R1);
    if (ret != 0) {
        ret = -6634;
        goto done;
    }

    wc_ecc_free(&keyImp);
    wc_ecc_init(&keyImp);

    curve_id = wc_ecc_get_curve_id(key->idx);
    if (curve_id < 0) {
        ret = -6635;
        goto done;
    }

    /* test import private only */
    ret = wc_ecc_import_private_key_ex(priv, privLen, NULL, 0, &keyImp,
                                       curve_id);
    if (ret != 0) {
        ret = -6636;
        goto done;
    }

    wc_ecc_free(&keyImp);
    wc_ecc_init(&keyImp);

    /* test export public raw */
    pubLenX = pubLenY = 32;
    ret = wc_ecc_export_public_raw(key, pub, &pubLenX, &pub[32], &pubLenY);
    if (ret != 0) {
        ret = -6637;
        goto done;
    }

#ifndef HAVE_SELFTEST
    /* test import of public */
    ret = wc_ecc_import_unsigned(&keyImp, pub, &pub[32], NULL, ECC_SECP256R1);
    if (ret != 0) {
        ret = -6638;
        goto done;
    }
#endif

    wc_ecc_free(&keyImp);
    wc_ecc_init(&keyImp);

    /* test export private and public raw */
    pubLenX = pubLenY = privLen = 32;
    ret = wc_ecc_export_private_raw(key, pub, &pubLenX, &pub[32], &pubLenY,
        priv, &privLen);
    if (ret != 0) {
        ret = -6639;
        goto done;
    }

#ifndef HAVE_SELFTEST
    /* test import of private and public */
    ret = wc_ecc_import_unsigned(&keyImp, pub, &pub[32], priv, ECC_SECP256R1);
    if (ret != 0) {
        ret = -6640;
        goto done;
    }
#endif

done:
    wc_ecc_free(&keyImp);
    return ret;
}
#endif /* HAVE_ECC_KEY_IMPORT && HAVE_ECC_KEY_EXPORT */

#ifndef WOLFSSL_ATECC508A
#if defined(HAVE_ECC_KEY_IMPORT) && !defined(WOLFSSL_VALIDATE_ECC_IMPORT)
static int ecc_mulmod_test(ecc_key* key1)
{
    int ret;
    ecc_key    key2;
    ecc_key    key3;

    wc_ecc_init(&key2);
    wc_ecc_init(&key3);

    /* TODO: Use test data, test with WOLFSSL_VALIDATE_ECC_IMPORT. */
    /* Need base point (Gx,Gy) and parameter A - load them as the public and
     * private key in key2.
     */
    ret = wc_ecc_import_raw_ex(&key2, key1->dp->Gx, key1->dp->Gy, key1->dp->Af,
                               ECC_SECP256R1);
    if (ret != 0)
        goto done;

    /* Need a point (Gx,Gy) and prime - load them as the public and private key
     * in key3.
     */
    ret = wc_ecc_import_raw_ex(&key3, key1->dp->Gx, key1->dp->Gy,
                               key1->dp->prime, ECC_SECP256R1);
    if (ret != 0)
        goto done;

    ret = wc_ecc_mulmod(&key1->k, &key2.pubkey, &key3.pubkey, &key2.k, &key3.k,
                        1);
    if (ret != 0) {
        ret = -6641;
        goto done;
    }

done:
    wc_ecc_free(&key3);
    wc_ecc_free(&key2);
    return ret;
}
#endif

static int ecc_ssh_test(ecc_key* key)
{
    int    ret;
    byte   out[128];
    word32 outLen = sizeof(out);

    /* Parameter Validation testing. */
    ret = wc_ecc_shared_secret_ssh(NULL, &key->pubkey, out, &outLen);
    if (ret != BAD_FUNC_ARG)
        return -6642;
    ret = wc_ecc_shared_secret_ssh(key, NULL, out, &outLen);
    if (ret != BAD_FUNC_ARG)
        return -6643;
    ret = wc_ecc_shared_secret_ssh(key, &key->pubkey, NULL, &outLen);
    if (ret != BAD_FUNC_ARG)
        return -6644;
    ret = wc_ecc_shared_secret_ssh(key, &key->pubkey, out, NULL);
    if (ret != BAD_FUNC_ARG)
        return -6645;

    /* Use API. */
    ret = wc_ecc_shared_secret_ssh(key, &key->pubkey, out, &outLen);
    if (ret != 0)
        return -6646;
    return 0;
}
#endif

static int ecc_def_curve_test(WC_RNG *rng)
{
    int     ret;
    ecc_key key;

    wc_ecc_init(&key);

    ret = wc_ecc_make_key(rng, 32, &key);
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &key.asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
#endif
    if (ret != 0) {
        ret = -6647;
        goto done;
    }

#ifndef NO_SIG_WRAPPER
    ret = ecc_sig_test(rng, &key);
    if (ret < 0)
        goto done;
#endif
#if defined(HAVE_ECC_KEY_IMPORT) && defined(HAVE_ECC_KEY_EXPORT)
    ret = ecc_exp_imp_test(&key);
    if (ret < 0)
        goto done;
#endif
#ifndef WOLFSSL_ATECC508A
#if defined(HAVE_ECC_KEY_IMPORT) && !defined(WOLFSSL_VALIDATE_ECC_IMPORT)
    ret = ecc_mulmod_test(&key);
    if (ret < 0)
        goto done;
#endif
    ret = ecc_ssh_test(&key);
    if (ret < 0)
        goto done;
#endif /* WOLFSSL_ATECC508A */
done:
    wc_ecc_free(&key);
    return ret;
}

#ifdef WOLFSSL_CERT_EXT
static int ecc_decode_test(void)
{
    int        ret;
    word32     inSz;
    word32     inOutIdx;
    ecc_key    key;

    /* SECP256R1 OID: 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 */

    const byte good[] = { 0x30, 0x14, 0x30, 0x0b, 0x06, 0x00,
            0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
            0x03, 0x04, 0x00, 0x04, 0x01, 0x01 };
    const byte badNoObjId[] = { 0x30, 0x08, 0x30, 0x06, 0x03, 0x04,
            0x00, 0x04, 0x01, 0x01 };
    const byte badOneObjId[] = { 0x30, 0x0a, 0x30, 0x08, 0x06, 0x00, 0x03, 0x04,
            0x00, 0x04, 0x01, 0x01 };
    const byte badObjId1Len[] = { 0x30, 0x0c, 0x30, 0x0a, 0x06, 0x09,
            0x06, 0x00, 0x03, 0x04, 0x00, 0x04, 0x01, 0x01 };
    const byte badObj2d1Len[] = { 0x30, 0x0c, 0x30, 0x0a, 0x06, 0x00,
            0x06, 0x07, 0x03, 0x04, 0x00, 0x04, 0x01, 0x01 };
    const byte badNotBitStr[] = { 0x30, 0x14, 0x30, 0x0b, 0x06, 0x00,
            0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
            0x04, 0x04, 0x00, 0x04, 0x01, 0x01 };
    const byte badBitStrLen[] = { 0x30, 0x14, 0x30, 0x0b, 0x06, 0x00,
            0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
            0x03, 0x05, 0x00, 0x04, 0x01, 0x01 };
    const byte badNoBitStrZero[] = { 0x30, 0x13, 0x30, 0x0a, 0x06, 0x00,
            0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
            0x03, 0x03, 0x04, 0x01, 0x01 };
    const byte badPoint[] = { 0x30, 0x12, 0x30, 0x09, 0x06, 0x00,
            0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
            0x03, 0x03, 0x00, 0x04, 0x01 };

    XMEMSET(&key, 0, sizeof(key));
    wc_ecc_init(&key);

    inSz = sizeof(good);
    ret = wc_EccPublicKeyDecode(NULL, &inOutIdx, &key, inSz);
    if (ret != BAD_FUNC_ARG) {
        ret = -6700;
        goto done;
    }
    ret = wc_EccPublicKeyDecode(good, NULL, &key, inSz);
    if (ret != BAD_FUNC_ARG) {
        ret = -6701;
        goto done;
    }
    ret = wc_EccPublicKeyDecode(good, &inOutIdx, NULL, inSz);
    if (ret != BAD_FUNC_ARG) {
        ret = -6702;
        goto done;
    }
    ret = wc_EccPublicKeyDecode(good, &inOutIdx, &key, 0);
    if (ret != BAD_FUNC_ARG) {
        ret = -6703;
        goto done;
    }

    /* Change offset to produce bad input data. */
    inOutIdx = 2;
    inSz = sizeof(good) - inOutIdx;
    ret = wc_EccPublicKeyDecode(good, &inOutIdx, &key, inSz);
    if (ret != ASN_PARSE_E) {
        ret = -6704;
        goto done;
    }
    inOutIdx = 4;
    inSz = sizeof(good) - inOutIdx;
    ret = wc_EccPublicKeyDecode(good, &inOutIdx, &key, inSz);
    if (ret != ASN_PARSE_E) {
        ret = -6705;
        goto done;
    }
    /* Bad data. */
    inSz = sizeof(badNoObjId);
    inOutIdx = 0;
    ret = wc_EccPublicKeyDecode(badNoObjId, &inOutIdx, &key, inSz);
    if (ret != ASN_OBJECT_ID_E) {
        ret = -6706;
        goto done;
    }
    inSz = sizeof(badOneObjId);
    inOutIdx = 0;
    ret = wc_EccPublicKeyDecode(badOneObjId, &inOutIdx, &key, inSz);
    if (ret != ASN_OBJECT_ID_E) {
        ret = -6707;
        goto done;
    }
    inSz = sizeof(badObjId1Len);
    inOutIdx = 0;
    ret = wc_EccPublicKeyDecode(badObjId1Len, &inOutIdx, &key, inSz);
    if (ret != ASN_PARSE_E) {
        ret = -6708;
        goto done;
    }
    inSz = sizeof(badObj2d1Len);
    inOutIdx = 0;
    ret = wc_EccPublicKeyDecode(badObj2d1Len, &inOutIdx, &key, inSz);
    if (ret != ASN_PARSE_E) {
        ret = -6709;
        goto done;
    }
    inSz = sizeof(badNotBitStr);
    inOutIdx = 0;
    ret = wc_EccPublicKeyDecode(badNotBitStr, &inOutIdx, &key, inSz);
    if (ret != ASN_BITSTR_E) {
        ret = -6710;
        goto done;
    }
    inSz = sizeof(badBitStrLen);
    inOutIdx = 0;
    ret = wc_EccPublicKeyDecode(badBitStrLen, &inOutIdx, &key, inSz);
    if (ret != ASN_PARSE_E) {
        ret = -6711;
        goto done;
    }
    inSz = sizeof(badNoBitStrZero);
    inOutIdx = 0;
    ret = wc_EccPublicKeyDecode(badNoBitStrZero, &inOutIdx, &key, inSz);
    if (ret != ASN_EXPECT_0_E) {
        ret = -6712;
        goto done;
    }
    inSz = sizeof(badPoint);
    inOutIdx = 0;
    ret = wc_EccPublicKeyDecode(badPoint, &inOutIdx, &key, inSz);
    if (ret != ASN_ECC_KEY_E) {
        ret = -6713;
        goto done;
    }

    inSz = sizeof(good);
    inOutIdx = 0;
    ret = wc_EccPublicKeyDecode(good, &inOutIdx, &key, inSz);
    if (ret != 0) {
        ret = -6714;
        goto done;
    }

done:
    wc_ecc_free(&key);
    return ret;
}
#endif /* WOLFSSL_CERT_EXT */

#ifdef WOLFSSL_CUSTOM_CURVES
static const byte eccKeyExplicitCurve[] = {
    0x30, 0x81, 0xf5, 0x30, 0x81, 0xae, 0x06, 0x07,
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x30,
    0x81, 0xa2, 0x02, 0x01, 0x01, 0x30, 0x2c, 0x06,
    0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x01, 0x01,
    0x02, 0x21, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff,
    0xff, 0xfc, 0x2f, 0x30, 0x06, 0x04, 0x01, 0x00,
    0x04, 0x01, 0x07, 0x04, 0x41, 0x04, 0x79, 0xbe,
    0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0,
    0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b,
    0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2,
    0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98, 0x48, 0x3a,
    0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d, 0xa4,
    0xfb, 0xfc, 0x0e, 0x11, 0x08, 0xa8, 0xfd, 0x17,
    0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19, 0x9c, 0x47,
    0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8, 0x02, 0x21,
    0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0,
    0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41,
    0x41, 0x02, 0x01, 0x01, 0x03, 0x42, 0x00, 0x04,
    0x3c, 0x4c, 0xc9, 0x5e, 0x2e, 0xa2, 0x3d, 0x49,
    0xcc, 0x5b, 0xff, 0x4f, 0xc9, 0x2e, 0x1d, 0x4a,
    0xc6, 0x21, 0xf6, 0xf3, 0xe6, 0x0b, 0x4f, 0xa9,
    0x9d, 0x74, 0x99, 0xdd, 0x97, 0xc7, 0x6e, 0xbe,
    0x14, 0x2b, 0x39, 0x9d, 0x63, 0xc7, 0x97, 0x0d,
    0x45, 0x25, 0x40, 0x30, 0x77, 0x05, 0x76, 0x88,
    0x38, 0x96, 0x29, 0x7d, 0x9c, 0xe1, 0x50, 0xbe,
    0xac, 0xf0, 0x1d, 0x86, 0xf4, 0x2f, 0x65, 0x0b
};

static int ecc_test_custom_curves(WC_RNG* rng)
{
    int     ret;
    word32  inOutIdx;
    ecc_key key;

    /* test use of custom curve - using BRAINPOOLP256R1 for test */
    const word32 ecc_oid_brainpoolp256r1_sum = 104;
    const ecc_oid_t ecc_oid_brainpoolp256r1[] = {
        0x2B,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x07
    };
    const ecc_set_type ecc_dp_brainpool256r1 = {
        32,                                                                 /* size/bytes */
        ECC_CURVE_CUSTOM,                                                   /* ID         */
        "BRAINPOOLP256R1",                                                  /* curve name */
        "A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377", /* prime      */
        "7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9", /* A          */
        "26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6", /* B          */
        "A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7", /* order      */
        "8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262", /* Gx         */
        "547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997", /* Gy         */
        ecc_oid_brainpoolp256r1,                                            /* oid/oidSz  */
        sizeof(ecc_oid_brainpoolp256r1) / sizeof(ecc_oid_t),
        ecc_oid_brainpoolp256r1_sum,                                        /* oid sum    */
        1,                                                                  /* cofactor   */
    };

    ret = ecc_test_curve_size(rng, 0, ECC_TEST_VERIFY_COUNT, ECC_CURVE_DEF,
        &ecc_dp_brainpool256r1);
    if (ret != 0) {
        printf("ECC test for custom curve failed! %d\n", ret);
        return ret;
    }

    #if defined(HAVE_ECC_BRAINPOOL) || defined(HAVE_ECC_KOBLITZ)
    {
        int curve_id;
        #ifdef HAVE_ECC_BRAINPOOL
            curve_id = ECC_BRAINPOOLP256R1;
        #else
            curve_id = ECC_SECP256K1;
        #endif
        /* Test and demonstrate use of non-SECP curve */
        ret = ecc_test_curve_size(rng, 0, ECC_TEST_VERIFY_COUNT, curve_id, NULL);
        if (ret < 0) {
            printf("ECC test for curve_id %d failed! %d\n", curve_id, ret);
            return ret;
        }
    }
    #endif

    ret = wc_ecc_init_ex(&key, HEAP_HINT, devId);
    if (ret != 0) {
        return -6715;
    }

    inOutIdx = 0;
    ret = wc_EccPublicKeyDecode(eccKeyExplicitCurve, &inOutIdx, &key,
                                                   sizeof(eccKeyExplicitCurve));
    if (ret != 0)
        return -6716;

    wc_ecc_free(&key);

    return ret;
}
#endif /* WOLFSSL_CUSTOM_CURVES */

#ifdef WOLFSSL_CERT_GEN

/* Make Cert / Sign example for ECC cert and ECC CA */
static int ecc_test_cert_gen(WC_RNG* rng)
{
    int ret;
    Cert        myCert;
    int         certSz;
    size_t      bytes;
    word32      idx = 0;
#ifndef USE_CERT_BUFFERS_256
    FILE*       file;
#endif
#ifdef WOLFSSL_TEST_CERT
    DecodedCert decode;
#endif
    byte*  der = NULL;
    byte*  pem = NULL;
    ecc_key caEccKey;
    ecc_key certPubKey;

    XMEMSET(&caEccKey, 0, sizeof(caEccKey));
    XMEMSET(&certPubKey, 0, sizeof(certPubKey));

    der = (byte*)XMALLOC(FOURK_BUF, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (der == NULL) {
        ERROR_OUT(-6720, exit);
    }
    pem = (byte*)XMALLOC(FOURK_BUF, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (pem == NULL) {
        ERROR_OUT(-6721, exit);
    }

    /* Get cert private key */
#ifdef ENABLE_ECC384_CERT_GEN_TEST
    /* Get Cert Key 384 */
#ifdef USE_CERT_BUFFERS_256
    XMEMCPY(der, ca_ecc_key_der_384, sizeof_ca_ecc_key_der_384);
    bytes = sizeof_ca_ecc_key_der_384;
#else
    file = fopen(eccCaKey384File, "rb");
    if (!file) {
        ERROR_OUT(-6722, exit);
    }

    bytes = fread(der, 1, FOURK_BUF, file);
    fclose(file);
    (void)eccCaKeyFile;
#endif /* USE_CERT_BUFFERS_256 */
#else
#ifdef USE_CERT_BUFFERS_256
    XMEMCPY(der, ca_ecc_key_der_256, sizeof_ca_ecc_key_der_256);
    bytes = sizeof_ca_ecc_key_der_256;
#else
    file = fopen(eccCaKeyFile, "rb");
    if (!file) {
        ERROR_OUT(-6722, exit);
    }
    bytes = fread(der, 1, FOURK_BUF, file);
    fclose(file);
#ifdef ENABLE_ECC384_CERT_GEN_TEST
    (void)eccCaKey384File;
#endif
#endif /* USE_CERT_BUFFERS_256 */
#endif /* ENABLE_ECC384_CERT_GEN_TEST */

    /* Get CA Key */
    ret = wc_ecc_init_ex(&caEccKey, HEAP_HINT, devId);
    if (ret != 0) {
        ERROR_OUT(-6723, exit);
    }
    ret = wc_EccPrivateKeyDecode(der, &idx, &caEccKey, (word32)bytes);
    if (ret != 0) {
        ERROR_OUT(-6724, exit);
    }

    /* Make a public key */
    ret = wc_ecc_init_ex(&certPubKey, HEAP_HINT, devId);
    if (ret != 0) {
        ERROR_OUT(-6725, exit);
    }

    ret = wc_ecc_make_key(rng, 32, &certPubKey);
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &certPubKey.asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
#endif
    if (ret != 0) {
        ERROR_OUT(-6726, exit);
    }

    /* Setup Certificate */
    if (wc_InitCert(&myCert)) {
        ERROR_OUT(-6727, exit);
    }

#ifndef NO_SHA256
    myCert.sigType = CTC_SHA256wECDSA;
#else
    myCert.sigType = CTC_SHAwECDSA;
#endif
    XMEMCPY(&myCert.subject, &certDefaultName, sizeof(CertName));

#ifdef WOLFSSL_CERT_EXT
    /* add Policies */
    XSTRNCPY(myCert.certPolicies[0], "2.4.589440.587.101.2.1.9632587.1",
            CTC_MAX_CERTPOL_SZ);
    XSTRNCPY(myCert.certPolicies[1], "1.2.13025.489.1.113549",
            CTC_MAX_CERTPOL_SZ);
    myCert.certPoliciesNb = 2;

    /* add SKID from the Public Key */
    if (wc_SetSubjectKeyIdFromPublicKey(&myCert, NULL, &certPubKey) != 0) {
        ERROR_OUT(-6728, exit);
    }

    /* add AKID from the Public Key */
    if (wc_SetAuthKeyIdFromPublicKey(&myCert, NULL, &caEccKey) != 0) {
        ERROR_OUT(-6729, exit);
    }

    /* add Key Usage */
    if (wc_SetKeyUsage(&myCert, certKeyUsage) != 0) {
        ERROR_OUT(-6730, exit);
    }
#endif /* WOLFSSL_CERT_EXT */

#ifdef ENABLE_ECC384_CERT_GEN_TEST
    #if defined(USE_CERT_BUFFERS_256)
    ret = wc_SetIssuerBuffer(&myCert, ca_ecc_cert_der_384,
                                      sizeof_ca_ecc_cert_der_384);
#else
    ret = wc_SetIssuer(&myCert, eccCaCert384File);
    (void)eccCaCertFile;
#endif
#else
#if defined(USE_CERT_BUFFERS_256)
    ret = wc_SetIssuerBuffer(&myCert, ca_ecc_cert_der_256,
                                      sizeof_ca_ecc_cert_der_256);
#else
    ret = wc_SetIssuer(&myCert, eccCaCertFile);
#ifdef ENABLE_ECC384_CERT_GEN_TEST
    (void)eccCaCert384File;
#endif
#endif
#endif /* ENABLE_ECC384_CERT_GEN_TEST */
    if (ret < 0) {
        ERROR_OUT(-6731, exit);
    }

    certSz = wc_MakeCert(&myCert, der, FOURK_BUF, NULL, &certPubKey, rng);
    if (certSz < 0) {
        ERROR_OUT(-6732, exit);
    }

    ret = 0;
    do {
    #if defined(WOLFSSL_ASYNC_CRYPT)
        ret = wc_AsyncWait(ret, &caEccKey.asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
    #endif
        if (ret >= 0) {
            ret = wc_SignCert(myCert.bodySz, myCert.sigType, der,
                              FOURK_BUF, NULL, &caEccKey, rng);
        }
    } while (ret == WC_PENDING_E);
    if (ret < 0) {
        ERROR_OUT(-6733, exit);
    }
    certSz = ret;

#ifdef WOLFSSL_TEST_CERT
    InitDecodedCert(&decode, der, certSz, 0);
    ret = ParseCert(&decode, CERT_TYPE, NO_VERIFY, 0);
    if (ret != 0) {
        FreeDecodedCert(&decode);
        ERROR_OUT(-6734, exit);

    }
    FreeDecodedCert(&decode);
#endif

    ret = SaveDerAndPem(der, certSz, pem, FOURK_BUF, certEccDerFile,
        certEccPemFile, CERT_TYPE, -6735);
    if (ret != 0) {
        goto exit;
    }

exit:
    wc_ecc_free(&certPubKey);
    wc_ecc_free(&caEccKey);

    XFREE(pem, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(der, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}
#endif /* WOLFSSL_CERT_GEN */

int ecc_test(void)
{
    int ret;
    WC_RNG  rng;

#ifdef WOLFSSL_CERT_EXT
    ret = ecc_decode_test();
    if (ret < 0)
        return ret;
#endif

#ifndef HAVE_FIPS
    ret = wc_InitRng_ex(&rng, HEAP_HINT, devId);
#else
    ret = wc_InitRng(&rng);
#endif
    if (ret != 0)
        return -6800;

#if defined(HAVE_ECC112) || defined(HAVE_ALL_CURVES)
    ret = ecc_test_curve(&rng, 14);
    if (ret < 0) {
        goto done;
    }
#endif /* HAVE_ECC112 */
#if defined(HAVE_ECC128) || defined(HAVE_ALL_CURVES)
    ret = ecc_test_curve(&rng, 16);
    if (ret < 0) {
        goto done;
    }
#endif /* HAVE_ECC128 */
#if defined(HAVE_ECC160) || defined(HAVE_ALL_CURVES)
    ret = ecc_test_curve(&rng, 20);
    if (ret < 0) {
        goto done;
    }
#endif /* HAVE_ECC160 */
#if defined(HAVE_ECC192) || defined(HAVE_ALL_CURVES)
    ret = ecc_test_curve(&rng, 24);
    if (ret < 0) {
        goto done;
    }
#endif /* HAVE_ECC192 */
#if defined(HAVE_ECC224) || defined(HAVE_ALL_CURVES)
    ret = ecc_test_curve(&rng, 28);
    if (ret < 0) {
        goto done;
    }
#endif /* HAVE_ECC224 */
#if defined(HAVE_ECC239) || defined(HAVE_ALL_CURVES)
    ret = ecc_test_curve(&rng, 30);
    if (ret < 0) {
        goto done;
    }
#endif /* HAVE_ECC239 */
#if !defined(NO_ECC256) || defined(HAVE_ALL_CURVES)
    ret = ecc_test_curve(&rng, 32);
    if (ret < 0) {
        goto done;
    }
#if !defined(WOLFSSL_ATECC508A) && defined(HAVE_ECC_KEY_IMPORT) && \
     defined(HAVE_ECC_KEY_EXPORT)
    ret = ecc_point_test();
    if (ret < 0) {
        goto done;
    }
#endif
    ret = ecc_def_curve_test(&rng);
    if (ret < 0) {
        goto done;
    }
#endif /* !NO_ECC256 */
#if defined(HAVE_ECC320) || defined(HAVE_ALL_CURVES)
    ret = ecc_test_curve(&rng, 40);
    if (ret < 0) {
        goto done;
    }
#endif /* HAVE_ECC320 */
#if defined(HAVE_ECC384) || defined(HAVE_ALL_CURVES)
    ret = ecc_test_curve(&rng, 48);
    if (ret < 0) {
        goto done;
    }
#endif /* HAVE_ECC384 */
#if defined(HAVE_ECC512) || defined(HAVE_ALL_CURVES)
    ret = ecc_test_curve(&rng, 64);
    if (ret < 0) {
        goto done;
    }
#endif /* HAVE_ECC512 */
#if defined(HAVE_ECC521) || defined(HAVE_ALL_CURVES)
    ret = ecc_test_curve(&rng, 66);
    if (ret < 0) {
        goto done;
    }
#endif /* HAVE_ECC521 */

#if defined(WOLFSSL_CUSTOM_CURVES)
    ret = ecc_test_custom_curves(&rng);
    if (ret != 0) {
        goto done;
    }
#endif

#ifdef HAVE_ECC_CDH
    ret = ecc_test_cdh_vectors();
    if (ret != 0) {
        printf("ecc_test_cdh_vectors failed! %d\n", ret);
        goto done;
    }
#endif

    ret = ecc_test_make_pub(&rng);
    if (ret != 0) {
        printf("ecc_test_make_pub failed!: %d\n", ret);
        goto done;
    }

#ifdef WOLFSSL_CERT_GEN
    ret = ecc_test_cert_gen(&rng);
    if (ret != 0) {
        printf("ecc_test_cert_gen failed!: %d\n", ret);
        goto done;
    }
#endif

done:
    wc_FreeRng(&rng);

    return ret;
}

#if defined(HAVE_ECC_ENCRYPT) && defined(WOLFSSL_AES_128)

int ecc_encrypt_test(void)
{
    WC_RNG  rng;
    int     ret = 0;
    ecc_key userA, userB;
    byte    msg[48];
    byte    plain[48];
    byte    out[80];
    word32  outSz   = sizeof(out);
    word32  plainSz = sizeof(plain);
    int     i;
    ecEncCtx* cliCtx = NULL;
    ecEncCtx* srvCtx = NULL;
    byte cliSalt[EXCHANGE_SALT_SZ];
    byte srvSalt[EXCHANGE_SALT_SZ];
    const byte* tmpSalt;
    byte    msg2[48];
    byte    plain2[48];
    byte    out2[80];
    word32  outSz2   = sizeof(out2);
    word32  plainSz2 = sizeof(plain2);

#ifndef HAVE_FIPS
    ret = wc_InitRng_ex(&rng, HEAP_HINT, devId);
#else
    ret = wc_InitRng(&rng);
#endif
    if (ret != 0)
        return -6900;

    XMEMSET(&userA, 0, sizeof(userA));
    XMEMSET(&userB, 0, sizeof(userB));

    ret = wc_ecc_init_ex(&userA, HEAP_HINT, devId);
    if (ret != 0)
        goto done;
    ret = wc_ecc_init_ex(&userB, HEAP_HINT, devId);
    if (ret != 0)
        goto done;

    ret  = wc_ecc_make_key(&rng, 32, &userA);
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &userA.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    if (ret != 0){
        ret = -6901; goto done;
    }

    ret = wc_ecc_make_key(&rng, 32, &userB);
#if defined(WOLFSSL_ASYNC_CRYPT)
    ret = wc_AsyncWait(ret, &userB.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    if (ret != 0){
        ret = -6902; goto done;
    }

    /* set message to incrementing 0,1,2,etc... */
    for (i = 0; i < (int)sizeof(msg); i++)
        msg[i] = i;

    /* encrypt msg to B */
    ret = wc_ecc_encrypt(&userA, &userB, msg, sizeof(msg), out, &outSz, NULL);
    if (ret != 0) {
        ret = -6903; goto done;
    }

    /* decrypt msg from A */
    ret = wc_ecc_decrypt(&userB, &userA, out, outSz, plain, &plainSz, NULL);
    if (ret != 0) {
        ret = -6904; goto done;
    }

    if (XMEMCMP(plain, msg, sizeof(msg)) != 0) {
        ret = -6905; goto done;
    }

    /* let's verify message exchange works, A is client, B is server */
    cliCtx = wc_ecc_ctx_new(REQ_RESP_CLIENT, &rng);
    srvCtx = wc_ecc_ctx_new(REQ_RESP_SERVER, &rng);
    if (cliCtx == NULL || srvCtx == NULL) {
        ret = -6906; goto done;
    }

    /* get salt to send to peer */
    tmpSalt = wc_ecc_ctx_get_own_salt(cliCtx);
    if (tmpSalt == NULL) {
        ret = -6907; goto done;
    }
    XMEMCPY(cliSalt, tmpSalt, EXCHANGE_SALT_SZ);

    tmpSalt = wc_ecc_ctx_get_own_salt(srvCtx);
    if (tmpSalt == NULL) {
        ret = -6908; goto done;
    }
    XMEMCPY(srvSalt, tmpSalt, EXCHANGE_SALT_SZ);

    /* in actual use, we'd get the peer's salt over the transport */
    ret = wc_ecc_ctx_set_peer_salt(cliCtx, srvSalt);
    if (ret != 0)
        goto done;
    ret = wc_ecc_ctx_set_peer_salt(srvCtx, cliSalt);
    if (ret != 0)
        goto done;

    ret = wc_ecc_ctx_set_info(cliCtx, (byte*)"wolfSSL MSGE", 11);
    if (ret != 0)
        goto done;
    ret = wc_ecc_ctx_set_info(srvCtx, (byte*)"wolfSSL MSGE", 11);
    if (ret != 0)
        goto done;

    /* get encrypted msg (request) to send to B */
    outSz = sizeof(out);
    ret = wc_ecc_encrypt(&userA, &userB, msg, sizeof(msg), out, &outSz,cliCtx);
    if (ret != 0)
        goto done;

    /* B decrypts msg (request) from A */
    plainSz = sizeof(plain);
    ret = wc_ecc_decrypt(&userB, &userA, out, outSz, plain, &plainSz, srvCtx);
    if (ret != 0)
        goto done;

    if (XMEMCMP(plain, msg, sizeof(msg)) != 0) {
        ret = -6909; goto done;
    }

    /* msg2 (response) from B to A */
    for (i = 0; i < (int)sizeof(msg2); i++)
        msg2[i] = i + sizeof(msg2);

    /* get encrypted msg (response) to send to B */
    ret = wc_ecc_encrypt(&userB, &userA, msg2, sizeof(msg2), out2,
                      &outSz2, srvCtx);
    if (ret != 0)
        goto done;

    /* A decrypts msg (response) from B */
    ret = wc_ecc_decrypt(&userA, &userB, out2, outSz2, plain2, &plainSz2,
                     cliCtx);
    if (ret != 0)
        goto done;

    if (XMEMCMP(plain2, msg2, sizeof(msg2)) != 0) {
        ret = -6910; goto done;
    }

done:

    /* cleanup */
    wc_ecc_ctx_free(srvCtx);
    wc_ecc_ctx_free(cliCtx);

    wc_ecc_free(&userB);
    wc_ecc_free(&userA);
    wc_FreeRng(&rng);

    return ret;
}

#endif /* HAVE_ECC_ENCRYPT */

#ifdef USE_CERT_BUFFERS_256
int ecc_test_buffers(void) {
    size_t bytes;
    ecc_key cliKey;
    ecc_key servKey;
    WC_RNG rng;
    word32 idx = 0;
    int    ret;
    /* pad our test message to 32 bytes so evenly divisible by AES_BLOCK_SZ */
    byte   in[] = "Everyone gets Friday off. ecc p";
    word32 inLen = (word32)XSTRLEN((char*)in);
    byte   out[256];
    byte   plain[256];
    int verify = 0;
    word32 x;

    bytes = (size_t)sizeof_ecc_clikey_der_256;
    /* place client key into ecc_key struct cliKey */
    ret = wc_EccPrivateKeyDecode(ecc_clikey_der_256, &idx, &cliKey,
                                                                (word32)bytes);
    if (ret != 0)
        return -6915;

    idx = 0;
    bytes = (size_t)sizeof_ecc_key_der_256;

    /* place server key into ecc_key struct servKey */
    ret = wc_EccPrivateKeyDecode(ecc_key_der_256, &idx, &servKey,
                                                                (word32)bytes);
    if (ret != 0)
        return -6916;

#ifndef HAVE_FIPS
    ret = wc_InitRng_ex(&rng, HEAP_HINT, devId);
#else
    ret = wc_InitRng(&rng);
#endif
    if (ret != 0)
        return -6917;

#if defined(HAVE_ECC_ENCRYPT) && defined(HAVE_HKDF)
    {
        word32 y;
        /* test encrypt and decrypt if they're available */
        x = sizeof(out);
        ret = wc_ecc_encrypt(&cliKey, &servKey, in, sizeof(in), out, &x, NULL);
        if (ret < 0)
            return -6918;

        y = sizeof(plain);
        ret = wc_ecc_decrypt(&cliKey, &servKey, out, x, plain, &y, NULL);
        if (ret < 0)
            return -6919;

        if (XMEMCMP(plain, in, inLen))
            return -6920;
    }
#endif


    x = sizeof(out);
    ret = wc_ecc_sign_hash(in, inLen, out, &x, &rng, &cliKey);
    if (ret < 0)
        return -6921;

    XMEMSET(plain, 0, sizeof(plain));

    ret = wc_ecc_verify_hash(out, x, plain, sizeof(plain), &verify, &cliKey);
    if (ret < 0)
        return -6922;

    if (XMEMCMP(plain, in, (word32)ret))
        return -6923;

#ifdef WOLFSSL_CERT_EXT
    idx = 0;

    bytes = sizeof_ecc_clikeypub_der_256;

    ret = wc_EccPublicKeyDecode(ecc_clikeypub_der_256, &idx, &cliKey,
                                                               (word32) bytes);
    if (ret != 0)
        return -6924;
#endif

    wc_ecc_free(&cliKey);
    wc_ecc_free(&servKey);
    wc_FreeRng(&rng);

    return 0;
}
#endif /* USE_CERT_BUFFERS_256 */
#endif /* HAVE_ECC */

#ifndef NO_SHA256
int sha256_test(void)
{
    wc_Sha256 sha;
    byte      hash[WC_SHA256_DIGEST_SIZE];
    byte      hashcopy[WC_SHA256_DIGEST_SIZE];
    int       ret = 0;

    testVector a, b, c;
    testVector test_sha[3];
    int times = sizeof(test_sha) / sizeof(struct testVector), i;

    a.input  = "";
    a.output = "\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9"
               "\x24\x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52"
               "\xb8\x55";
    a.inLen  = XSTRLEN(a.input);
    a.outLen = WC_SHA256_DIGEST_SIZE;

    b.input  = "abc";
    b.output = "\xBA\x78\x16\xBF\x8F\x01\xCF\xEA\x41\x41\x40\xDE\x5D\xAE\x22"
               "\x23\xB0\x03\x61\xA3\x96\x17\x7A\x9C\xB4\x10\xFF\x61\xF2\x00"
               "\x15\xAD";
    b.inLen  = XSTRLEN(b.input);
    b.outLen = WC_SHA256_DIGEST_SIZE;

    c.input  = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    c.output = "\x24\x8D\x6A\x61\xD2\x06\x38\xB8\xE5\xC0\x26\x93\x0C\x3E\x60"
               "\x39\xA3\x3C\xE4\x59\x64\xFF\x21\x67\xF6\xEC\xED\xD4\x19\xDB"
               "\x06\xC1";
    c.inLen  = XSTRLEN(c.input);
    c.outLen = WC_SHA256_DIGEST_SIZE;

    test_sha[0] = a;
    test_sha[1] = b;
    test_sha[2] = c;

    ret = wc_InitSha256_ex(&sha, HEAP_HINT, devId);
    if (ret != 0)
        return -2100;

    for (i = 0; i < times; ++i) {
        ret = wc_Sha256Update(&sha, (byte*)test_sha[i].input,
            (word32)test_sha[i].inLen);
        if (ret != 0)
            ERROR_OUT(-2110 - i, exit);
        ret = wc_Sha256GetHash(&sha, hashcopy);
        if (ret != 0)
            ERROR_OUT(-2120 - i, exit);
        ret = wc_Sha256Final(&sha, hash);
        if (ret != 0)
            ERROR_OUT(-2130 - i, exit);

        if (XMEMCMP(hash, test_sha[i].output, WC_SHA256_DIGEST_SIZE) != 0)
            ERROR_OUT(-2140 - i, exit);
        if (XMEMCMP(hash, hashcopy, WC_SHA256_DIGEST_SIZE) != 0)
            ERROR_OUT(-2150 - i, exit);
    }

    /* BEGIN LARGE HASH TEST */ {
    byte large_input[1024];
    const char* large_digest =
        "\x27\x78\x3e\x87\x96\x3a\x4e\xfb\x68\x29\xb5\x31\xc9\xba\x57\xb4"
        "\x4f\x45\x79\x7f\x67\x70\xbd\x63\x7f\xbf\x0d\x80\x7c\xbd\xba\xe0";

    for (i = 0; i < (int)sizeof(large_input); i++) {
        large_input[i] = (byte)(i & 0xFF);
    }
    times = 100;
#ifdef WOLFSSL_PIC32MZ_HASH
    wc_Sha256SizeSet(&sha, times * sizeof(large_input));
#endif
    for (i = 0; i < times; ++i) {
        ret = wc_Sha256Update(&sha, (byte*)large_input,
            (word32)sizeof(large_input));
        if (ret != 0)
            ERROR_OUT(-2160, exit);
    }
    ret = wc_Sha256Final(&sha, hash);
    if (ret != 0)
        ERROR_OUT(-2161, exit);
    if (XMEMCMP(hash, large_digest, WC_SHA256_DIGEST_SIZE) != 0)
        ERROR_OUT(-2162, exit);
    } /* END LARGE HASH TEST */

exit:

    wc_Sha256Free(&sha);

    return ret;
}
#endif

int main(void)
{
    int ret;
#ifdef HAVE_ECC
    if ( (ret = ecc_test()) != 0)
        return err_sys("ECC      test failed!\n", ret);
    else
        printf( "ECC      test passed!\n");
    #if defined(HAVE_ECC_ENCRYPT) && defined(WOLFSSL_AES_128)
        if ( (ret = ecc_encrypt_test()) != 0)
            return err_sys("ECC Enc  test failed!\n", ret);
        else
            printf( "ECC Enc  test passed!\n");
    #endif
    #ifdef USE_CERT_BUFFERS_256
        if ( (ret = ecc_test_buffers()) != 0)
            return err_sys("ECC buffer test failed!\n", ret);
        else
            printf( "ECC buffer test passed!\n");
    #endif
#endif
#ifndef NO_SHA256
    if ( (ret = sha256_test()) != 0)
        return err_sys("SHA-256  test failed!\n", ret);
    else
        printf( "SHA-256  test passed!\n");
#endif

    return ret;
}
