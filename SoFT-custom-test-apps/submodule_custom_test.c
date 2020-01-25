#include <wolfssl/wolfcrypt/settings.h>
/*----------------------------------------------------------------------------*/
/* Place required headers here */
#include <wolfssl/wolfcrypt/sha512.h>
/*----------------------------------------------------------------------------*/
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

#ifndef HAVE_STACK_SIZE
/* func_args from test.h, so don't have to pull in other stuff */
typedef struct func_args {
    int    argc;
    char** argv;
    int    return_code;
} func_args;
#endif /* !HAVE_STACK_SIZE */

/*----------------------------------------------------------------------------*/
/* Copy test cases here! */
/*----------------------------------------------------------------------------*/
typedef struct testVector {
    const char*  input;
    const char*  output;
    size_t inLen;
    size_t outLen;
} testVector;

#ifdef WOLFSSL_SHA512
int sha512_test(void)
{
    wc_Sha512 sha;
    byte      hash[WC_SHA512_DIGEST_SIZE];
    byte      hashcopy[WC_SHA512_DIGEST_SIZE];
    int       ret = 0;

    testVector a, b, c;
    testVector test_sha[3];
    int times = sizeof(test_sha) / sizeof(struct testVector), i;

    a.input  = "";
    a.output = "\xcf\x83\xe1\x35\x7e\xef\xb8\xbd\xf1\x54\x28\x50\xd6\x6d\x80"
               "\x07\xd6\x20\xe4\x05\x0b\x57\x15\xdc\x83\xf4\xa9\x21\xd3\x6c"
               "\xe9\xce\x47\xd0\xd1\x3c\x5d\x85\xf2\xb0\xff\x83\x18\xd2\x87"
               "\x7e\xec\x2f\x63\xb9\x31\xbd\x47\x41\x7a\x81\xa5\x38\x32\x7a"
               "\xf9\x27\xda\x3e";
    a.inLen  = XSTRLEN(a.input);
    a.outLen = WC_SHA512_DIGEST_SIZE;

    b.input  = "abc";
    b.output = "\xdd\xaf\x35\xa1\x93\x61\x7a\xba\xcc\x41\x73\x49\xae\x20\x41"
               "\x31\x12\xe6\xfa\x4e\x89\xa9\x7e\xa2\x0a\x9e\xee\xe6\x4b\x55"
               "\xd3\x9a\x21\x92\x99\x2a\x27\x4f\xc1\xa8\x36\xba\x3c\x23\xa3"
               "\xfe\xeb\xbd\x45\x4d\x44\x23\x64\x3c\xe8\x0e\x2a\x9a\xc9\x4f"
               "\xa5\x4c\xa4\x9f";
    b.inLen  = XSTRLEN(b.input);
    b.outLen = WC_SHA512_DIGEST_SIZE;

    c.input  = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhi"
               "jklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    c.output = "\x8e\x95\x9b\x75\xda\xe3\x13\xda\x8c\xf4\xf7\x28\x14\xfc\x14"
               "\x3f\x8f\x77\x79\xc6\xeb\x9f\x7f\xa1\x72\x99\xae\xad\xb6\x88"
               "\x90\x18\x50\x1d\x28\x9e\x49\x00\xf7\xe4\x33\x1b\x99\xde\xc4"
               "\xb5\x43\x3a\xc7\xd3\x29\xee\xb6\xdd\x26\x54\x5e\x96\xe5\x5b"
               "\x87\x4b\xe9\x09";
    c.inLen  = XSTRLEN(c.input);
    c.outLen = WC_SHA512_DIGEST_SIZE;

    test_sha[0] = a;
    test_sha[1] = b;
    test_sha[2] = c;

    ret = wc_InitSha512_ex(&sha, HEAP_HINT, devId);
    if (ret != 0)
        return -2200;

    for (i = 0; i < times; ++i) {
        ret = wc_Sha512Update(&sha, (byte*)test_sha[i].input,
            (word32)test_sha[i].inLen);
        if (ret != 0)
            ERROR_OUT(-2210 - i, exit);
        ret = wc_Sha512GetHash(&sha, hashcopy);
        if (ret != 0)
            ERROR_OUT(-2220 - i, exit);
        ret = wc_Sha512Final(&sha, hash);
        if (ret != 0)
            ERROR_OUT(-2230 - i, exit);

        if (XMEMCMP(hash, test_sha[i].output, WC_SHA512_DIGEST_SIZE) != 0)
            ERROR_OUT(-2240 - i, exit);
        if (XMEMCMP(hash, hashcopy, WC_SHA512_DIGEST_SIZE) != 0)
            ERROR_OUT(-2250 - i, exit);
    }

    /* BEGIN LARGE HASH TEST */ {
    byte large_input[1024];
    const char* large_digest =
        "\x5a\x1f\x73\x90\xbd\x8c\xe4\x63\x54\xce\xa0\x9b\xef\x32\x78\x2d"
        "\x2e\xe7\x0d\x5e\x2f\x9d\x15\x1b\xdd\x2d\xde\x65\x0c\x7b\xfa\x83"
        "\x5e\x80\x02\x13\x84\xb8\x3f\xff\x71\x62\xb5\x09\x89\x63\xe1\xdc"
        "\xa5\xdc\xfc\xfa\x9d\x1a\x4d\xc0\xfa\x3a\x14\xf6\x01\x51\x90\xa4";

    for (i = 0; i < (int)sizeof(large_input); i++) {
        large_input[i] = (byte)(i & 0xFF);
    }
    times = 100;
    for (i = 0; i < times; ++i) {
        ret = wc_Sha512Update(&sha, (byte*)large_input,
            (word32)sizeof(large_input));
        if (ret != 0)
            ERROR_OUT(-2260, exit);
    }
    ret = wc_Sha512Final(&sha, hash);
    if (ret != 0)
        ERROR_OUT(-2261, exit);
    if (XMEMCMP(hash, large_digest, WC_SHA512_DIGEST_SIZE) != 0)
        ERROR_OUT(-2262, exit);
    } /* END LARGE HASH TEST */

exit:
    wc_Sha512Free(&sha);

    return ret;
}
#endif
/*----------------------------------------------------------------------------*/
/* End of test cases */
/*----------------------------------------------------------------------------*/


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

/*----------------------------------------------------------------------------*/
/* Copy test API calls here! */
/*----------------------------------------------------------------------------*/
#ifdef WOLFSSL_SHA512
    if ( (ret = sha512_test()) != 0)
        return err_sys("SHA-512  test failed!\n", ret);
    else
        printf( "SHA-512  test passed!\n");
#endif
/*----------------------------------------------------------------------------*/
/* End of test cases */
/*----------------------------------------------------------------------------*/

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

