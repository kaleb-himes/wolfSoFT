#include "SoFT_common.h"
#include "SoFT_builds.h"

void SoFT_do_custom_build(char* option, char* toolChain)
{
    char submoduleTestFile     [SOFT_LONGEST_FILE_NAME] = {0};
    char submoduleCryptHdrs    [SOFT_LARGEST_FILE_LIST][SOFT_LONGEST_FILE_NAME]
                                                                           ={0};
    char submoduleCryptSrcs    [SOFT_LARGEST_FILE_LIST][SOFT_LONGEST_FILE_NAME]
                                                                           ={0};
    char submoduleTlsHdrs      [SOFT_LARGEST_FILE_LIST][SOFT_LONGEST_FILE_NAME]
                                                                           ={0};
    char submoduleTlsSrcs      [SOFT_LARGEST_FILE_LIST][SOFT_LONGEST_FILE_NAME]
                                                                           ={0};
    char submoduleUserSettings [SOFT_LARGEST_FILE_LIST][SOFT_LONGEST_FILE_NAME]
                                                                           ={0};

    SoFT_check_submodule_supported(option);

    SoFT_get_submodule_configuration(option, submoduleTestFile,
                               submoduleCryptHdrs, submoduleCryptSrcs,
                               submoduleTlsHdrs, submoduleTlsSrcs,
                               submoduleUserSettings);

    SoFT_build_custom_specific(submoduleTestFile, option,
                              submoduleCryptHdrs, submoduleCryptSrcs,
                              submoduleTlsHdrs, submoduleTlsSrcs,
                              submoduleUserSettings, toolChain);

    return;

    if (option == NULL || toolChain == NULL) {
        printf("Invalid input\n");
        SoFT_custom_build_usage();
        return;
    }

}

/* Supported Recipes */
//#define AES_ONLY_DST "aes_only"
//#define AES_PWDBASED_DST "aes_pwdbased"
//#define CERT_MNGR_ONLY_DST "cert_manager_only" // example myCustomDir
//#define DSA_ONLY_DST "dsa_only" // example myCustomDir
//#define ECC_ONLY_DST "ecc_only" // example myCustomDir
//#define RSA_PSS_PKCS_DST "rsa_pss_pkcs"
//#define SHA256_ECC_DST "sha256_ecc" // example myCustomDir
//#define SHA256_ECC_NM_DST "sha256_ecc_nm" // example myCustomDir
//#define SHA256_ONLY_DST "sha256_only" // example myCustomDir
//#define SHA512_ONLY_DST "sha512_only" // example myCustomDir

void SoFT_check_submodule_supported(char* option)
{
    const char* supported[25] = {"aes_only","aes_pwdbased", "cert_manager_only",
                                 "dsa_only", "ecc_only", "rsa_pss_pkcs",
                                 "sha256_ecc", "sha256_ecc_nm", "sha256_only",
                                 "sha512_only"};
    int submodules_available = 10;
    int i;
    int is_supported = 0;
    for (i = 0; i < submodules_available; i++) {
       if (XSTRNCMP(option, supported[i], XSTRLEN(option)) == 0) {
            is_supported = 1;
            break;
        }
    }
    if (is_supported == 0) {
        printf("submodule \"%s\" is not yet supported, if you just added a\n"
               "submodule please update the function\n"
               "SoFT_check_submodule_supported() in src/SoFT_builds.c\n"
               "with the new substring of the submodule file and increase the\n"
               "submodules_available to reflect the new count", option);
        SoFT_custom_build_usage();
    }
}

void SoFT_get_submodule_configuration(char* submoduleOption,
                          char* submoduleTestFile,
                          char(* submoduleCryptHdrs)[SOFT_LONGEST_FILE_NAME],
                          char(* submoduleCryptSrcs)[SOFT_LONGEST_FILE_NAME],
                          char(* submoduleTlsHdrs)[SOFT_LONGEST_FILE_NAME],
                          char(* submoduleTlsSrcs)[SOFT_LONGEST_FILE_NAME],
                          char(* submoduleUserSettings)[SOFT_LONGEST_FILE_NAME])
{
    FILE* fStream = NULL;
    char fName[50] = {0};
    char * line = NULL;
    size_t len = 0;
    ssize_t read;
    int fillCryptHdrs = 0, fillCryptSrcs = 0, fillTlsHdrs = 0, fillTlsSrcs = 0,
        fillUserSettings = 0;
    const char* abort1 = "SUBMODULE_CRYPTO_HEADERS:";
    const char* abort2 = "SUBMODULE_CRYPTO_SOURCES:";
    const char* abort3 = "SUBMODULE_TLS_HEADERS:";
    const char* abort4 = "SUBMODULE_TLS_SOURCES:";
    const char* abort5 = "SUBMODULE_USER_SETTINGS:";
    const char* abort6 = "EOF";

    SoFT_build_cmd(fName, "submodule_config_files/submodule_", submoduleOption,
                   ".conf", NULL);
    SoFT_build_cmd(submoduleTestFile, "submodule_", submoduleOption, ".c",NULL);

// Step 1:
    // Open .conf file
    fStream = fopen(fName, "rb");
    SoFT_assrt_ne_null(fStream, "SoFT_get_submodule_configuration .conf");

// Step 2:
    // read in test file name after "SUBMODULE_TEST_FILE"
    while ((read = getline(&line, &len, fStream)) != -1 &&
            fillUserSettings == 0) {
        if (fillCryptHdrs == 0 &&
            XSTRNCMP(line, abort1, XSTRLEN(abort1)) == 0) {
            SoFT_parse_conf(abort2, XSTRLEN(abort2), submoduleCryptHdrs,
                           fStream);
            fillCryptHdrs = 1;
            fseek(fStream, 0, SEEK_SET);
        }
        if (fillCryptSrcs == 0 &&
            XSTRNCMP(line, abort2, XSTRLEN(abort2)) == 0) {
            SoFT_parse_conf(abort3, XSTRLEN(abort3), submoduleCryptSrcs,
                           fStream);
            fillCryptSrcs = 1;
            fseek(fStream, 0, SEEK_SET);
        }
        if (fillTlsHdrs == 0 &&
            XSTRNCMP(line, abort3, XSTRLEN(abort3)) == 0) {
            SoFT_parse_conf(abort4, XSTRLEN(abort4), submoduleTlsHdrs,
                           fStream);
            fillTlsHdrs = 1;
            fseek(fStream, 0, SEEK_SET);
        }
        if (fillTlsSrcs == 0 &&
            XSTRNCMP(line, abort4, XSTRLEN(abort4)) == 0) {
            SoFT_parse_conf(abort5, XSTRLEN(abort5), submoduleTlsSrcs,
                           fStream);
            fillTlsSrcs = 1;
            fseek(fStream, 0, SEEK_SET);
        }
        if (fillUserSettings == 0 &&
            XSTRNCMP(line, abort5, XSTRLEN(abort5)) == 0) {
            SoFT_parse_conf(abort6, XSTRLEN(abort6), submoduleUserSettings,
                           fStream);
            fillUserSettings = 1;
        }
    }
}

void SoFT_parse_conf(const char* abortLine, size_t abortLen,
                    char(* fillBuffer)[SOFT_LONGEST_FILE_NAME], FILE* fStream)
{
    char * line = NULL;
    size_t len = 0;
    ssize_t read;
    int position = 0;

    while ((read = getline(&line, &len, fStream)) != -1 &&
            XSTRNCMP(line, abortLine, abortLen) != 0) {
// TODO: Ignore lines that have # or are blank
        if (read < 2 || XSTRSTR(line, "#") || XSTRNCMP(line, "EMPTY", 5) == 0 ||
            XSTRNCMP(line, "EOF", 3) == 0 || XSTRSTR(line, "//")) {
            continue;
        }
        XSTRNCPY(fillBuffer[position], line, XSTRLEN(line) - 1);
        position++;
    }

    return;
}

void SoFT_build_custom_specific(char* testFile, char* dst,
                          char(* submoduleCryptHdrs)[SOFT_LONGEST_FILE_NAME],
                          char(* submoduleCryptSrcs)[SOFT_LONGEST_FILE_NAME],
                          char(* submoduleTlsHdrs)[SOFT_LONGEST_FILE_NAME],
                          char(* submoduleTlsSrcs)[SOFT_LONGEST_FILE_NAME],
                          char(* submoduleUserSettings)[SOFT_LONGEST_FILE_NAME],
                          char* toolChain)
{
    int i;
    char c_cmd[SOFT_LONGEST_COMMAND];
    SoFT_clear_cmd(c_cmd);
    char src[] = "./wolfssl"; /* assume for now TODO: make src user specified */
    char* customFName = testFile;


    /* setup the directories to reflect traditional */
    SoFT_setup_traditional(dst);

    /* set to a common test app */
    SoFT_build_cmd(c_cmd, "cp SoFT-custom-test-apps/", customFName,
                  " SoFT-custom-test-apps/SoFT_custom_test.c", NULL);
    system(c_cmd);
    SoFT_clear_cmd(c_cmd);

    SoFT_copy_test_app(src, dst);

    /* create the project makefile (generic solution) */

    if (XSTRNCMP(ARM_THUMB, toolChain, (int)XSTRLEN(ARM_THUMB)) == 0)
        SoFT_create_arm_thumb_makefile(dst, toolChain);
    else
        SoFT_create_makefile(dst);

    /* Copy in the crypto headers */
    for (i = 0; i < SOFT_LARGEST_FILE_LIST; i++) {
        if (XSTRLEN(submoduleCryptHdrs[i]) > 0) {
            SoFT_copy_crypto_hdr(src, dst, submoduleCryptHdrs[i]);
        }
    }
    /* Copy in the tls headers */
    for (i = 0; i < SOFT_LARGEST_FILE_LIST; i++) {
        if (XSTRLEN(submoduleCryptSrcs[i]) > 0) {
            SoFT_copy_crypto_src(src, dst, submoduleCryptSrcs[i]);
        }
    }
    /* Copy in the crypto sources */
    for (i = 0; i < SOFT_LARGEST_FILE_LIST; i++) {
        if (XSTRLEN(submoduleTlsHdrs[i]) > 0) {
            SoFT_copy_tls_hdr(src, dst, submoduleTlsHdrs[i]);
        }
    }
    /* Copy in the tls sources */
    for (i = 0; i < SOFT_LARGEST_FILE_LIST; i++) {
        if (XSTRLEN(submoduleTlsSrcs[i]) > 0) {
            SoFT_copy_tls_src(src, dst, submoduleTlsSrcs[i]);
        }
    }

    SoFT_create_user_settings(dst);

    for (i = 0; i < SOFT_MOST_SETTINGS; i++) {
        if (XSTRLEN(submoduleUserSettings[i]) > 0) {
            SoFT_write_user_settings(dst, submoduleUserSettings[i]);
        }
    }

    SoFT_close_user_settings(dst);

    /* Build the project */
    SoFT_build_solution(dst, SOFT_BUILD_CUSTOM);

}


void SoFT_custom_build_usage(void)
{
    printf("No valid options found.\n\n");
    printf("Valid builds are:\n");
    printf("\t\taes_only\n");
    printf("\t\taes_pwdbased\n");
    printf("\t\tcert_manager_only\n");
    printf("\t\tdsa_only\n");
    printf("\t\tecc_only\n");
    printf("\t\trsa_pss_pkcs\n");
    printf("\t\tsha256_ecc\n");
    printf("\t\tsha256_ecc_nm\n");
    printf("\t\tsha256_only\n");
    printf("\t\tsha512_only\n\n");
    printf("Valid toolChain options are:\n");
    printf("\t\tDEFAULT - This will use the default gcc compiler\n");
    printf("\t\tARM-THUMB - This will use the arm thumb compiler\n");
    printf("\t\t            NOTE: Set path with = IE ARM-THUMB=<path>/"
                            "arm-none-eabi-\n\n");
    printf("Examples:\n");
    printf("\t\t\"./run c aes_only DEFAULT\"\n");
    printf("\t\t\"./run c rsa_pss_pkcs ARM-THUMB=/usr/local/gcc_arm/gcc-arm-"
           "none-eabi-7-2017-q4/bin/arm-none-eabi-\"\n");
    printf("\n");
    SoFT_abort();
}

void SoFT_setup_traditional(char* destination)
{
    DIR* target;
    char c_cmd[SOFT_LONGEST_COMMAND];
    int ret;


    target = opendir(destination);

    if (target) {
        printf("Whoops, this custom build dir already exists, let's clean up"
               " before getting started!\n");
        closedir(target);
        SoFT_clear_cmd(c_cmd);
        SoFT_build_cmd(c_cmd, "rm -rf ", destination, NULL, NULL);

        ret = system(c_cmd);
        if (ret != 0) {

            printf("Failed to clean up target directory please check"
                   "permissions are not sudo on %s and try again!\n",
                   destination);

            printf("The return value from system execution was %d\n", ret);

            SoFT_abort();
        } else {
            printf("Successfully cleaned up target directory: %s\n",
                   destination);
        }
    }

    SoFT_clear_cmd(c_cmd);
    SoFT_build_cmd(c_cmd, "mkdir ", destination, NULL, NULL);
    system(c_cmd);
    SoFT_clear_cmd(c_cmd);

    SoFT_build_cmd(c_cmd, "mkdir ", destination, "/wolfssl", NULL);
    system(c_cmd);
    SoFT_clear_cmd(c_cmd);

    SoFT_build_cmd(c_cmd, "mkdir ", destination, "/wolfssl/src", NULL);
    system(c_cmd);
    SoFT_clear_cmd(c_cmd);

    SoFT_build_cmd(c_cmd, "mkdir ", destination, "/wolfssl/wolfssl", NULL);
    system(c_cmd);
    SoFT_clear_cmd(c_cmd);

    SoFT_build_cmd(c_cmd, "mkdir ", destination, "/wolfssl/wolfcrypt", NULL);
    system(c_cmd);
    SoFT_clear_cmd(c_cmd);

    SoFT_build_cmd(c_cmd, "mkdir ", destination, "/wolfssl/wolfcrypt/src",NULL);
    system(c_cmd);
    SoFT_clear_cmd(c_cmd);

    SoFT_build_cmd(c_cmd, "mkdir ", destination, "/wolfssl/wolfcrypt/test",
                                                                    NULL);
    system(c_cmd);
    SoFT_clear_cmd(c_cmd);

    SoFT_build_cmd(c_cmd, "mkdir ", destination, "/wolfssl/wolfssl/wolfcrypt",
                                                                       NULL);
    system(c_cmd);
    SoFT_clear_cmd(c_cmd);

    SoFT_build_cmd(c_cmd, "mkdir ", destination, "/wolfssl/wolfssl/openssl",
                                                                       NULL);
    system(c_cmd);
    SoFT_clear_cmd(c_cmd);


    return;
}

void SoFT_copy_test_app(char* src, char* dst)
{
    char c_cmd[SOFT_LONGEST_COMMAND];

    SoFT_clear_cmd(c_cmd);

    /* We are going to need the test app header by default in all cases */
    SoFT_build_cmd(c_cmd, "cp ", src, "/wolfcrypt/test/test.h ", dst);
    SoFT_build_cmd(c_cmd, "/wolfssl/wolfcrypt/test/test.h", NULL, NULL, NULL);
    system(c_cmd);
    SoFT_clear_cmd(c_cmd);

    /* We are going to need the test app by default in all cases */
    SoFT_build_cmd(c_cmd, "cp ", "SoFT-custom-test-apps/SoFT_custom_test.c ",
                  dst, "/wolfcrypt_test.c");
    system(c_cmd);
    SoFT_clear_cmd(c_cmd);

    return;
}

void SoFT_copy_crypto_hdr(char* src, char* dst, char* cryptoH)
{
    char allTrigger[] = "copyAll";
    char c_cmd[SOFT_LONGEST_COMMAND];
    char srcPath[SOFT_LONGEST_COMMAND];
    char dstPath[SOFT_LONGEST_COMMAND];

    SoFT_clear_cmd(c_cmd);
    SoFT_clear_cmd(srcPath);
    SoFT_clear_cmd(dstPath);

    if (XSTRNCMP(cryptoH, allTrigger, XSTRLEN(allTrigger)) == 0) {
        SoFT_build_cmd(srcPath, src, "/wolfssl/wolfcrypt/* ", NULL, NULL);
        SoFT_build_cmd(dstPath, dst, "/wolfssl/wolfssl/wolfcrypt/", NULL, NULL);
        SoFT_build_cmd(c_cmd, "cp ", srcPath, dstPath, NULL);

    } else {
        SoFT_build_cmd(srcPath, src, "/wolfssl/wolfcrypt/", cryptoH, " ");
        SoFT_build_cmd(dstPath, dst, "/wolfssl/wolfssl/wolfcrypt/", cryptoH,
                      NULL);
        SoFT_build_cmd(c_cmd, "cp ", srcPath, dstPath, NULL);
    }

    system(c_cmd);

    SoFT_clear_cmd(c_cmd);
    SoFT_clear_cmd(srcPath);
    SoFT_clear_cmd(dstPath);

    return;
}

void SoFT_copy_tls_hdr(char* src, char* dst, char* tlsH)
{
    char allTrigger[] = "copyAll";
    char c_cmd[SOFT_LONGEST_COMMAND];
    char srcPath[SOFT_LONGEST_COMMAND];
    char dstPath[SOFT_LONGEST_COMMAND];

    SoFT_clear_cmd(c_cmd);
    SoFT_clear_cmd(srcPath);
    SoFT_clear_cmd(dstPath);

    if (XSTRNCMP(tlsH, allTrigger, XSTRLEN(allTrigger)) == 0) {
        SoFT_build_cmd(srcPath, src, "/wolfssl/* ", NULL, NULL);
        SoFT_build_cmd(dstPath, dst, "/wolfssl/wolfssl/", NULL, NULL);
        SoFT_build_cmd(c_cmd, "cp ", srcPath, dstPath, NULL);

        system(c_cmd);
        SoFT_clear_cmd(c_cmd);
        SoFT_clear_cmd(srcPath);
        SoFT_clear_cmd(dstPath);

        SoFT_build_cmd(srcPath, src, "/wolfssl/openssl/* ", NULL, NULL);
        SoFT_build_cmd(dstPath, dst, "/wolfssl/wolfssl/openssl/", NULL, NULL);
        SoFT_build_cmd(c_cmd, "cp ", srcPath, dstPath, NULL);


    } else {
        SoFT_build_cmd(srcPath, src, "/wolfssl/", tlsH, " ");
        SoFT_build_cmd(dstPath, dst, "/wolfssl/wolfssl/", tlsH, NULL);
        SoFT_build_cmd(c_cmd, "cp ", srcPath, dstPath, NULL);
    }

    system(c_cmd);

    SoFT_clear_cmd(c_cmd);
    SoFT_clear_cmd(srcPath);
    SoFT_clear_cmd(dstPath);

    return;
}


void SoFT_copy_crypto_src(char* src, char* dst, char* cryptoS)
{
    char allTrigger[] = "copyAll";
    char c_cmd[SOFT_LONGEST_COMMAND];
    char srcPath[SOFT_LONGEST_COMMAND];
    char dstPath[SOFT_LONGEST_COMMAND];

    SoFT_clear_cmd(srcPath);
    SoFT_clear_cmd(dstPath);
    SoFT_clear_cmd(c_cmd);


    if (XSTRNCMP(cryptoS, allTrigger, XSTRLEN(allTrigger)) == 0) {
        SoFT_build_cmd(srcPath, src, "/wolfcrypt/src/* ", NULL, NULL);
        SoFT_build_cmd(dstPath, dst, "/wolfssl/wolfcrypt/src/", NULL, NULL);
        SoFT_build_cmd(c_cmd, "cp ", srcPath, dstPath, NULL);
    } else {
        SoFT_build_cmd(srcPath, src, "/wolfcrypt/src/", cryptoS, " ");
        SoFT_build_cmd(dstPath, dst, "/wolfssl/wolfcrypt/src/", cryptoS, NULL);
        SoFT_build_cmd(c_cmd, "cp ", srcPath, dstPath, NULL);
    }

    system(c_cmd);
    SoFT_clear_cmd(c_cmd);
    SoFT_clear_cmd(srcPath);
    SoFT_clear_cmd(dstPath);

    return;
}

void SoFT_copy_tls_src(char* src, char* dst, char* tlsS)
{
    char allTrigger[] = "copyAll";
    char c_cmd[SOFT_LONGEST_COMMAND];
    char srcPath[SOFT_LONGEST_COMMAND];
    char dstPath[SOFT_LONGEST_COMMAND];

    SoFT_clear_cmd(srcPath);
    SoFT_clear_cmd(dstPath);
    SoFT_clear_cmd(c_cmd);


    if (XSTRNCMP(tlsS, allTrigger, XSTRLEN(allTrigger)) == 0) {
        SoFT_build_cmd(srcPath, src, "/src/* ", NULL, NULL);
        SoFT_build_cmd(dstPath, dst, "/wolfssl/src/", NULL, NULL);
        SoFT_build_cmd(c_cmd, "cp ", srcPath, dstPath, NULL);
    } else {
        SoFT_build_cmd(srcPath, src, "/src/", tlsS, " ");
        SoFT_build_cmd(dstPath, dst, "/wolfssl/src/", tlsS, NULL);
        SoFT_build_cmd(c_cmd, "cp ", srcPath, dstPath, NULL);
    }

    system(c_cmd);
    SoFT_clear_cmd(c_cmd);
    SoFT_clear_cmd(srcPath);
    SoFT_clear_cmd(dstPath);

    return;
}


void SoFT_create_makefile(char* dst)
{
    size_t ret = 0;
    size_t bufLen = 0;
    char fName[SOFT_LONGEST_COMMAND];
    FILE* fStream;
    char c_cmd[SOFT_LONGEST_COMMAND];

    printf("Creating a makefile in %s directory.\n", dst);
    SoFT_clear_cmd(c_cmd);
    SoFT_clear_cmd(fName);
    SoFT_build_cmd(fName, "Makefile_", dst, NULL, NULL);
    SoFT_build_cmd(c_cmd, "touch ", fName, NULL, NULL);
    system(c_cmd);
    SoFT_clear_cmd(c_cmd);

    fStream = SoFT_open_file_append_mode(fName);

    bufLen = XSTRLEN(MakefileBuf);
    ret = fwrite(MakefileBuf, 1, bufLen, fStream);
    SoFT_check_fwrite_success(ret, bufLen);

    SoFT_build_cmd(c_cmd, "mv ", fName, " ", dst);
    SoFT_build_cmd(c_cmd, "/Makefile", NULL, NULL, NULL);
    system(c_cmd);
    SoFT_clear_cmd(c_cmd);

    fclose(fStream);

    return;
}

void SoFT_create_arm_thumb_makefile(char* dst, char* toolChain)
{
    char toolChainPath[] = "SoFT-custom-toolchains/ARM-THUMB/";
    char c_cmd[SOFT_LONGEST_COMMAND];
    char outFName[SOFT_LONGEST_COMMAND];
    FILE* fStream;
    FILE* outputStream;
    char* line = NULL;
    size_t len = 0;
    ssize_t read = 0;
    int advancePtr = (int) (XSTRLEN(ARM_THUMB) + 1);
    char* justThePath = toolChain+advancePtr;
    size_t ret;

    SoFT_clear_cmd(c_cmd);
    SoFT_clear_cmd(outFName);

    SoFT_build_cmd(c_cmd, "cp ", toolChainPath, "* ", dst);
    system(c_cmd);
    SoFT_clear_cmd(c_cmd);

    SoFT_build_cmd(c_cmd, dst, "/Makefile.common", NULL, NULL);
    SoFT_build_cmd(outFName, dst, "/Makefile.common.tmp", NULL, NULL);

    fStream = fopen(c_cmd, "rb");
    if (fStream == NULL) {
        printf("Failed to open %s\n", c_cmd);
        SoFT_abort();
    }

    SoFT_clear_cmd(c_cmd);
    SoFT_build_cmd(c_cmd, "touch ", outFName, NULL, NULL);
    system(c_cmd);
    SoFT_clear_cmd(c_cmd);

    outputStream = fopen(outFName, "wb");
    if (outputStream == NULL) {
        printf("Failed to open %s\n", outFName);
        SoFT_abort();
    }

    while ((read = getline(&line, &len, fStream)) != EOF) {
        if (strstr(line, "TOOLCHAIN = ")) {
            int writeLen = 0;
            char* commentIn = "#Custom insertion from wolfCFG\n";

            writeLen = (int) XSTRLEN(commentIn);
            ret = fwrite(commentIn, 1, writeLen, outputStream);
            SoFT_check_fwrite_success(ret, writeLen);

            SoFT_build_cmd(c_cmd, "TOOLCHAIN = ", justThePath, "\n", NULL);
            writeLen = (int) XSTRLEN(c_cmd);
            ret = fwrite(c_cmd, 1, writeLen, outputStream);
            SoFT_check_fwrite_success(ret, writeLen);

            writeLen = (int) XSTRLEN(commentIn);
            ret = fwrite(commentIn, 1, writeLen, outputStream);
            SoFT_check_fwrite_success(ret, writeLen);
        } else {
            ret = fwrite(line, 1, XSTRLEN(line), outputStream);
            SoFT_check_fwrite_success(ret, XSTRLEN(line));
        }
    }

    fclose(outputStream);
    fclose(fStream);
    if (line)
        free(line);

    SoFT_clear_cmd(c_cmd);
    SoFT_build_cmd(c_cmd, "mv ", outFName, " ", dst);
    SoFT_build_cmd(c_cmd, "/Makefile.common", NULL, NULL, NULL);
    system(c_cmd);
    SoFT_clear_cmd(c_cmd);
    SoFT_clear_cmd(outFName);

    return;
}

int SoFT_build_solution(char* dst, int testCase)
{
    int ret;

    char c_cmd[SOFT_LONGEST_COMMAND];

    SoFT_clear_cmd(c_cmd);

    /* copy over the test application */

    SoFT_build_cd_cmd(c_cmd, dst);
    if (testCase == SOFT_BUILD_MULTI) {
        SoFT_build_cmd(c_cmd, " && make clean > /dev/null && make > /dev/null ",
                      NULL, NULL, NULL);
    } else {
        SoFT_build_cmd(c_cmd, " && make clean && make",
                  NULL, NULL, NULL);
    }

    printf("c_cmd reads: %s\n", c_cmd);
    ret = system(c_cmd);
    SoFT_clear_cmd(c_cmd);

    return ret;
}

void SoFT_create_user_settings(char* dst)
{
    size_t ret = 0;
    size_t writeLen = 0;
    FILE* fStream;
    char c_cmd[SOFT_LONGEST_COMMAND];
    char fName[SOFT_LONGEST_COMMAND];

//    printf("Creating custom user_settings.h in %s directory.\n", dst);

    SoFT_clear_cmd(c_cmd);
    SoFT_clear_cmd(fName);

    SoFT_build_cmd(fName, dst, "/user_settings.h", NULL, NULL);
//    SoFT_build_cmd(c_cmd, "rm ", fName, NULL, NULL);
//    system(c_cmd);
    SoFT_clear_cmd(c_cmd);
    SoFT_build_cmd(c_cmd, "touch ", fName, NULL, NULL);
    system(c_cmd);
    SoFT_clear_cmd(c_cmd);

    fStream = SoFT_open_file_append_mode(fName);

    SoFT_build_cmd(c_cmd, "#ifndef USER_SETTINGS_H\n", NULL, NULL, NULL);
    writeLen = XSTRLEN(c_cmd);
    ret = fwrite(c_cmd, 1, writeLen, fStream);
//    SoFT_check_fwrite_success(ret, writeLen);
    SoFT_clear_cmd(c_cmd);

    SoFT_build_cmd(c_cmd, "#define USER_SETTINGS_H\n\n", NULL, NULL, NULL);
    writeLen = XSTRLEN(c_cmd);
    ret = fwrite(c_cmd, 1, writeLen, fStream);
    //SoFT_check_fwrite_success(ret, writeLen);
    SoFT_clear_cmd(c_cmd);

    fclose(fStream);

    return;
}

void SoFT_write_user_settings(char* dst, char* setting)
{
    size_t ret = 0;
    size_t setLen = 0;
    size_t finSetLen = 0;
    FILE* fStream;
    char fName[SOFT_LONGEST_COMMAND];
    char finSet[SOFT_LONGEST_COMMAND];

    SoFT_clear_cmd(fName);
    SoFT_clear_cmd(finSet);

    setLen = XSTRLEN(setting);
    if (setLen == 0)
        return;

    SoFT_build_cmd(fName, dst, "/user_settings.h", NULL, NULL);

    fStream = SoFT_open_file_append_mode(fName);

    SoFT_build_cmd(finSet, "#undef ", setting, "\n", NULL);
    finSetLen = XSTRLEN(finSet);

    ret = fwrite(finSet, 1, finSetLen, fStream);
    //SoFT_check_fwrite_success(ret, finSetLen);
    SoFT_clear_cmd(finSet);

    SoFT_build_cmd(finSet, "#define ", setting, "\n\n", NULL);
    finSetLen = XSTRLEN(finSet);

    ret = fwrite(finSet, 1, finSetLen, fStream);
    //SoFT_check_fwrite_success(ret, finSetLen);
    SoFT_clear_cmd(finSet);

    fclose(fStream);

    return;
}

void SoFT_close_user_settings(char* dst)
{
    size_t ret = 0;
    size_t writeLen = 0;
    FILE* fStream;
    char c_cmd[SOFT_LONGEST_COMMAND];
    char fName[SOFT_LONGEST_COMMAND];

    SoFT_clear_cmd(c_cmd);
    SoFT_clear_cmd(fName);

    SoFT_build_cmd(fName, dst, "/user_settings.h", NULL, NULL);

    fStream = SoFT_open_file_append_mode(fName);

    SoFT_build_cmd(c_cmd, "#endif /* USER_SETTINGS_H */\n", NULL, NULL, NULL);
    writeLen = XSTRLEN(c_cmd);
    ret = fwrite(c_cmd, 1, writeLen, fStream);
    //SoFT_check_fwrite_success(ret, writeLen);
    SoFT_clear_cmd(c_cmd);

    fclose(fStream);

    return;

}

FILE* SoFT_open_file_append_mode(char* fName)
{
    FILE* fStream;

    fStream = fopen(fName, "ab");
    if (fStream == NULL) {
        printf("Failed to open file %s at the specified location, please check"
               "file permissions and try again\n", fName);
        SoFT_abort();
    }

    return fStream;
}

void SoFT_check_fwrite_success(size_t written, size_t expected)
{
    if (written == expected) {
        printf("Successfully wrote %zu bytes to file\n", written);
        return;
    } else {
        printf("Failed to write %zu bytes to file, only wrote %zu bytes\n",
               expected, written);
        SoFT_abort();
    }

    return;
}
