/* update-001 - Give your header a name
 * Example: AES_ONLY_H
 *
 * update-002 - unique pre-prended string for lengths
 * Example: AES_ONLY would result in AES_ONLY_C_HNUM, AES_ONLY_C_SNUM ... etc.
 *
 * update-003 - name of the custom test app
 * Example: aes_only would result in cfg_aes_only.c and output dir of aes_only
 *
 * update-004 - unique name prepend for array ID's
 * Example: aesOnly would result in aesOnlyCryptHeaders, aesOnlyCryptSrc... etc.
 *
 * Command that can be copy/pasted for new test case once search/replace and all
 * updates complete:
 * -----------------------------------------------------------------------------

    if (XSTRNCMP(<update-002>_DST, option, (int)XSTRLEN(option)) == 0) {
        printf("Alright! Building %s!\n", <update-002>_DST);

        cfg_build_custom_specific(<update-002>_TEST_FILE,
                                  <update-002>_DST,
                                  <update-004>CryptHeaders, <update-002>_C_HNUM,
                                  <update-004>CryptSrc, <update-002>_C_SNUM,
                                  <update-004>TlsHeaders, <update-002>_T_HNUM,
                                  <update-004>TlsSrc, <update-002>_T_SNUM,
                                  <update-004>Settings);

    }

 * -----------------------------------------------------------------------------
 */

#ifndef <update-001>
#define <update-001>

#include "configurator_common.h"

/* Crypto */
#define <update-002>_C_HNUM 0 /* number of crypto header files */
#define <update-002>_C_SNUM 0 /* number of crypto source files */

/* TLS */
#define <update-002>_T_HNUM 0  /* number of tls header files */
#define <update-002>_T_SNUM 0  /* number of TLS source files */

#define <update-002>_TEST_FILE "cfg_<update-003>.c" //example myCustom.c
#define <update-002>_DST "<update-003>" // example myCustomDir

static char <update-004>CryptHeaders[<update-002>_C_HNUM][LONGEST_H_NAME] = {
};

static char <update-004>CryptSrc[<update-002>_C_SNUM][LONGEST_S_NAME] = {
};

static char <update-004>TlsHeaders[<update-002>_T_HNUM][LONGEST_H_NAME] = {
};

static char <update-004>TlsSrc[<update-002>_T_SNUM][LONGEST_S_NAME] = {
};

static char <update-004>Settings[MOST_SETTINGS][LONGEST_PP_OPT] = {
};


#endif /* <update-001> */
