#include <wolfssl/wolfcrypt/settings.h>
/*----------------------------------------------------------------------------*/
/* Place required headers here */
#include ...
#include ... etc.
/*----------------------------------------------------------------------------*/
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/wc_encrypt.h>
#include <wolfssl/wolfcrypt/mem_track.h>

#define HAVE_AES_CBC

#define HEAP_HINT NULL

static int devId = INVALID_DEVID;

#define ERROR_OUT(err, eLabel) { ret = (err); goto eLabel; }

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

/*----------------------------------------------------------------------------*/
/* Copy test cases here! */
/*----------------------------------------------------------------------------*/


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

