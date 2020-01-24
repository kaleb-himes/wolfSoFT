#include "configurator_common.h"
#include "configurator_builds.h"

void cfg_do_custom_build(char* option, char* toolChain)
{
    char recipeTestFile     [CFG_LONGEST_FILE_NAME] = {0};
    char recipeCryptHdrs    [CFG_LARGEST_FILE_LIST][CFG_LONGEST_FILE_NAME] ={0};
    char recipeCryptSrcs    [CFG_LARGEST_FILE_LIST][CFG_LONGEST_FILE_NAME] ={0};
    char recipeTlsHdrs      [CFG_LARGEST_FILE_LIST][CFG_LONGEST_FILE_NAME] ={0};
    char recipeTlsSrcs      [CFG_LARGEST_FILE_LIST][CFG_LONGEST_FILE_NAME] ={0};
    char recipeUserSettings [CFG_LARGEST_FILE_LIST][CFG_LONGEST_FILE_NAME] ={0};

    cfg_check_recipe_supported(option);

    cfg_get_recipe_ingredients(option, recipeTestFile, recipeCryptHdrs,
                               recipeCryptSrcs, recipeTlsHdrs,
                               recipeTlsSrcs, recipeUserSettings);

    cfg_build_custom_specific(recipeTestFile, option,
                              recipeCryptHdrs, recipeCryptSrcs,
                              recipeTlsHdrs, recipeTlsSrcs,
                              recipeUserSettings, toolChain);

    return;

    if (option == NULL || toolChain == NULL) {
        printf("Invalid input\n");
        cfg_custom_build_usage();
        return;
    }

}

void cfg_check_recipe_supported(char* option)
{
    const char* supported[25] = {"aes_only","aes_pwdbased", "cert_manager_only",
                                 "dsa_only", "ecc_only", "rsa_pss_pkcs",
                                 "sha256_ecc", "sha256_ecc_nm", "sha256_only",
                                 "sha512_only"};
    int recipes_available = 10;
    int i;
    int is_supported = 0;
    for (i = 0; i < recipes_available; i++) {
       if (XSTRNCMP(option, supported[i], XSTRLEN(option)) == 0) {
            is_supported = 1;
            break;
        }
    }
    if (is_supported == 0) {
        printf("recipe \"%s\" is not yet supported, if you just added a\n"
               "recipe please update the function\n"
               "cfg_check_recipe_supported() in src/configurator_builds.c\n"
               "with the new substring of the recipe file and increase the \n"
               "recipes_available to reflect the new count", option);
        cfg_custom_build_usage();
    }
}

void cfg_get_recipe_ingredients(char* recipeOption,
                                char* recipeTestFile,
                                char(* recipeCryptHdrs)[CFG_LONGEST_FILE_NAME],
                                char(* recipeCryptSrcs)[CFG_LONGEST_FILE_NAME],
                                char(* recipeTlsHdrs)[CFG_LONGEST_FILE_NAME],
                                char(* recipeTlsSrcs)[CFG_LONGEST_FILE_NAME],
                              char(* recipeUserSettings)[CFG_LONGEST_FILE_NAME])
{
    FILE* fStream = NULL;
    char fName[50] = {0};
    char * line = NULL;
    size_t len = 0;
    ssize_t read;
    int fillCryptHdrs = 0, fillCryptSrcs = 0, fillTlsHdrs = 0, fillTlsSrcs = 0,
        fillUserSettings = 0;
    const char* abort1 = "RECIPE_CRYPTO_HEADERS:";
    const char* abort2 = "RECIPE_CRYPTO_SOURCES:";
    const char* abort3 = "RECIPE_TLS_HEADERS:";
    const char* abort4 = "RECIPE_TLS_SOURCES:";
    const char* abort5 = "RECIPE_USER_SETTINGS:";
    const char* abort6 = "EOF";

    cfg_build_cmd(fName, "recipe-files/configurator_", recipeOption, ".conf",
                  NULL);
    cfg_build_cmd(recipeTestFile, "cfg_", recipeOption, ".c", NULL);

// Step 1:
    // Open .conf file
    fStream = fopen(fName, "rb");
    cfg_assrt_ne_null(fStream, "cfg_get_recipe_ingredients opening .conf");

// Step 2:
    // read in test file name after "RECIPE_TEST_FILE"
    while ((read = getline(&line, &len, fStream)) != -1 &&
            fillUserSettings == 0) {
        if (fillCryptHdrs == 0 &&
            XSTRNCMP(line, abort1, XSTRLEN(abort1)) == 0) {
            cfg_parse_conf(abort2, XSTRLEN(abort2), recipeCryptHdrs,
                           fStream);
            fillCryptHdrs = 1;
            fseek(fStream, 0, SEEK_SET);
        }
        if (fillCryptSrcs == 0 &&
            XSTRNCMP(line, abort2, XSTRLEN(abort2)) == 0) {
            cfg_parse_conf(abort3, XSTRLEN(abort3), recipeCryptSrcs,
                           fStream);
            fillCryptSrcs = 1;
            fseek(fStream, 0, SEEK_SET);
        }
        if (fillTlsHdrs == 0 &&
            XSTRNCMP(line, abort3, XSTRLEN(abort3)) == 0) {
            cfg_parse_conf(abort4, XSTRLEN(abort4), recipeTlsHdrs,
                           fStream);
            fillTlsHdrs = 1;
            fseek(fStream, 0, SEEK_SET);
        }
        if (fillTlsSrcs == 0 &&
            XSTRNCMP(line, abort4, XSTRLEN(abort4)) == 0) {
            cfg_parse_conf(abort5, XSTRLEN(abort5), recipeTlsSrcs,
                           fStream);
            fillTlsSrcs = 1;
            fseek(fStream, 0, SEEK_SET);
        }
        if (fillUserSettings == 0 &&
            XSTRNCMP(line, abort5, XSTRLEN(abort5)) == 0) {
            cfg_parse_conf(abort6, XSTRLEN(abort6), recipeUserSettings,
                           fStream);
            fillUserSettings = 1;
        }
    }
// Step 3:
//    cfg_parse_conf("RECIPE_CRYPTO_SOURCES", "RECIPE_TLS_HEADERS",
//                   recipeCryptSrcs, fStream);
//    cfg_parse_conf("RECIPE_TLS_HEADERS", "RECIPE_TLS_SOURCES",
//                   recipeTlsHdrs, fStream);
//    cfg_parse_conf("RECIPE_TLS_SOURCES", "RECIPE_SETTINGS",
//                   recipeTlsSrcs, fStream);
//    cfg_parse_conf("RECIPE_SETTINGS", "EOF",
//                   recipeUserSettings, fStream);
}

void cfg_parse_conf(const char* abortLine, size_t abortLen,
                    char(* fillBuffer)[CFG_LONGEST_FILE_NAME], FILE* fStream)
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

void cfg_build_custom_specific(char* testFile, char* dst,
                               char(* recipeCryptHdrs)[CFG_LONGEST_FILE_NAME],
                               char(* recipeCryptSrcs)[CFG_LONGEST_FILE_NAME],
                               char(* recipeTlsHdrs)[CFG_LONGEST_FILE_NAME],
                               char(* recipeTlsSrcs)[CFG_LONGEST_FILE_NAME],
                              char(* recipeUserSettings)[CFG_LONGEST_FILE_NAME],
                               char* toolChain)
{
    int i;
    char c_cmd[CFG_LONGEST_COMMAND];
    cfg_clear_cmd(c_cmd);
    char src[] = "./wolfssl"; /* assume for now TODO: make src user specified */
    char* customFName = testFile;


    /* setup the directories to reflect traditional */
    cfg_setup_traditional(dst);

    /* set to a common test app */
    cfg_build_cmd(c_cmd, "cp cfg-custom-test-apps/", customFName,
                  " cfg-custom-test-apps/cfg_custom_test.c", NULL);
    system(c_cmd);
    cfg_clear_cmd(c_cmd);

    cfg_copy_test_app(src, dst);

    /* create the project makefile (generic solution) */

    if (XSTRNCMP(ARM_THUMB, toolChain, (int)XSTRLEN(ARM_THUMB)) == 0)
        cfg_create_arm_thumb_makefile(dst, toolChain);
    else
        cfg_create_makefile(dst);

    /* Copy in the crypto headers */
    for (i = 0; i < CFG_LARGEST_FILE_LIST; i++) {
        if (XSTRLEN(recipeCryptHdrs[i]) > 0) {
            cfg_copy_crypto_hdr(src, dst, recipeCryptHdrs[i]);
        }
    }
    /* Copy in the tls headers */
    for (i = 0; i < CFG_LARGEST_FILE_LIST; i++) {
        if (XSTRLEN(recipeCryptSrcs[i]) > 0) {
            cfg_copy_crypto_src(src, dst, recipeCryptSrcs[i]);
        }
    }
    /* Copy in the crypto sources */
    for (i = 0; i < CFG_LARGEST_FILE_LIST; i++) {
        if (XSTRLEN(recipeTlsHdrs[i]) > 0) {
            cfg_copy_tls_hdr(src, dst, recipeTlsHdrs[i]);
        }
    }
    /* Copy in the tls sources */
    for (i = 0; i < CFG_LARGEST_FILE_LIST; i++) {
        if (XSTRLEN(recipeTlsSrcs[i]) > 0) {
            cfg_copy_tls_src(src, dst, recipeTlsSrcs[i]);
        }
    }

    cfg_create_user_settings(dst);

    for (i = 0; i < CFG_MOST_SETTINGS; i++) {
        if (XSTRLEN(recipeUserSettings[i]) > 0) {
            cfg_write_user_settings(dst, recipeUserSettings[i]);
        }
    }

    cfg_close_user_settings(dst);

    /* Build the project */
    cfg_build_solution(dst, CFG_BUILD_CUSTOM);

}


void cfg_custom_build_usage(void)
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
    cfg_abort();
}

void cfg_setup_traditional(char* destination)
{
    DIR* target;
    char c_cmd[CFG_LONGEST_COMMAND];
    int ret;


    target = opendir(destination);

    if (target) {
        printf("Whoops, this custom build dir already exists, let's clean up"
               " before getting started!\n");
        closedir(target);
        cfg_clear_cmd(c_cmd);
        cfg_build_cmd(c_cmd, "rm -rf ", destination, NULL, NULL);

        ret = system(c_cmd);
        if (ret != 0) {

            printf("Failed to clean up target directory please check"
                   "permissions are not sudo on %s and try again!\n",
                   destination);

            printf("The return value from system execution was %d\n", ret);

            cfg_abort();
        } else {
            printf("Successfully cleaned up target directory: %s\n",
                   destination);
        }
    }

    cfg_clear_cmd(c_cmd);
    cfg_build_cmd(c_cmd, "mkdir ", destination, NULL, NULL);
    system(c_cmd);
    cfg_clear_cmd(c_cmd);

    cfg_build_cmd(c_cmd, "mkdir ", destination, "/wolfssl", NULL);
    system(c_cmd);
    cfg_clear_cmd(c_cmd);

    cfg_build_cmd(c_cmd, "mkdir ", destination, "/wolfssl/src", NULL);
    system(c_cmd);
    cfg_clear_cmd(c_cmd);

    cfg_build_cmd(c_cmd, "mkdir ", destination, "/wolfssl/wolfssl", NULL);
    system(c_cmd);
    cfg_clear_cmd(c_cmd);

    cfg_build_cmd(c_cmd, "mkdir ", destination, "/wolfssl/wolfcrypt", NULL);
    system(c_cmd);
    cfg_clear_cmd(c_cmd);

    cfg_build_cmd(c_cmd, "mkdir ", destination, "/wolfssl/wolfcrypt/src", NULL);
    system(c_cmd);
    cfg_clear_cmd(c_cmd);

    cfg_build_cmd(c_cmd, "mkdir ", destination, "/wolfssl/wolfcrypt/test",
                                                                    NULL);
    system(c_cmd);
    cfg_clear_cmd(c_cmd);

    cfg_build_cmd(c_cmd, "mkdir ", destination, "/wolfssl/wolfssl/wolfcrypt",
                                                                       NULL);
    system(c_cmd);
    cfg_clear_cmd(c_cmd);

    cfg_build_cmd(c_cmd, "mkdir ", destination, "/wolfssl/wolfssl/openssl",
                                                                       NULL);
    system(c_cmd);
    cfg_clear_cmd(c_cmd);


    return;
}

void cfg_copy_test_app(char* src, char* dst)
{
    char c_cmd[CFG_LONGEST_COMMAND];

    cfg_clear_cmd(c_cmd);

    /* We are going to need the test app header by default in all cases */
    cfg_build_cmd(c_cmd, "cp ", src, "/wolfcrypt/test/test.h ", dst);
    cfg_build_cmd(c_cmd, "/wolfssl/wolfcrypt/test/test.h", NULL, NULL, NULL);
    system(c_cmd);
    cfg_clear_cmd(c_cmd);

    /* We are going to need the test app by default in all cases */
    cfg_build_cmd(c_cmd, "cp ", "cfg-custom-test-apps/cfg_custom_test.c ",
                  dst, "/wolfcrypt_test.c");
    system(c_cmd);
    cfg_clear_cmd(c_cmd);

    return;
}

void cfg_copy_crypto_hdr(char* src, char* dst, char* cryptoH)
{
    char allTrigger[] = "copyAll";
    char c_cmd[CFG_LONGEST_COMMAND];
    char srcPath[CFG_LONGEST_COMMAND];
    char dstPath[CFG_LONGEST_COMMAND];

    cfg_clear_cmd(c_cmd);
    cfg_clear_cmd(srcPath);
    cfg_clear_cmd(dstPath);

    if (XSTRNCMP(cryptoH, allTrigger, XSTRLEN(allTrigger)) == 0) {
        cfg_build_cmd(srcPath, src, "/wolfssl/wolfcrypt/* ", NULL, NULL);
        cfg_build_cmd(dstPath, dst, "/wolfssl/wolfssl/wolfcrypt/", NULL, NULL);
        cfg_build_cmd(c_cmd, "cp ", srcPath, dstPath, NULL);

    } else {
        cfg_build_cmd(srcPath, src, "/wolfssl/wolfcrypt/", cryptoH, " ");
        cfg_build_cmd(dstPath, dst, "/wolfssl/wolfssl/wolfcrypt/", cryptoH,
                      NULL);
        cfg_build_cmd(c_cmd, "cp ", srcPath, dstPath, NULL);
    }

    system(c_cmd);

    cfg_clear_cmd(c_cmd);
    cfg_clear_cmd(srcPath);
    cfg_clear_cmd(dstPath);

    return;
}

void cfg_copy_tls_hdr(char* src, char* dst, char* tlsH)
{
    char allTrigger[] = "copyAll";
    char c_cmd[CFG_LONGEST_COMMAND];
    char srcPath[CFG_LONGEST_COMMAND];
    char dstPath[CFG_LONGEST_COMMAND];

    cfg_clear_cmd(c_cmd);
    cfg_clear_cmd(srcPath);
    cfg_clear_cmd(dstPath);

    if (XSTRNCMP(tlsH, allTrigger, XSTRLEN(allTrigger)) == 0) {
        cfg_build_cmd(srcPath, src, "/wolfssl/* ", NULL, NULL);
        cfg_build_cmd(dstPath, dst, "/wolfssl/wolfssl/", NULL, NULL);
        cfg_build_cmd(c_cmd, "cp ", srcPath, dstPath, NULL);

        system(c_cmd);
        cfg_clear_cmd(c_cmd);
        cfg_clear_cmd(srcPath);
        cfg_clear_cmd(dstPath);

        cfg_build_cmd(srcPath, src, "/wolfssl/openssl/* ", NULL, NULL);
        cfg_build_cmd(dstPath, dst, "/wolfssl/wolfssl/openssl/", NULL, NULL);
        cfg_build_cmd(c_cmd, "cp ", srcPath, dstPath, NULL);


    } else {
        cfg_build_cmd(srcPath, src, "/wolfssl/", tlsH, " ");
        cfg_build_cmd(dstPath, dst, "/wolfssl/wolfssl/", tlsH, NULL);
        cfg_build_cmd(c_cmd, "cp ", srcPath, dstPath, NULL);
    }

    system(c_cmd);

    cfg_clear_cmd(c_cmd);
    cfg_clear_cmd(srcPath);
    cfg_clear_cmd(dstPath);

    return;
}


void cfg_copy_crypto_src(char* src, char* dst, char* cryptoS)
{
    char allTrigger[] = "copyAll";
    char c_cmd[CFG_LONGEST_COMMAND];
    char srcPath[CFG_LONGEST_COMMAND];
    char dstPath[CFG_LONGEST_COMMAND];

    cfg_clear_cmd(srcPath);
    cfg_clear_cmd(dstPath);
    cfg_clear_cmd(c_cmd);


    if (XSTRNCMP(cryptoS, allTrigger, XSTRLEN(allTrigger)) == 0) {
        cfg_build_cmd(srcPath, src, "/wolfcrypt/src/* ", NULL, NULL);
        cfg_build_cmd(dstPath, dst, "/wolfssl/wolfcrypt/src/", NULL, NULL);
        cfg_build_cmd(c_cmd, "cp ", srcPath, dstPath, NULL);
    } else {
        cfg_build_cmd(srcPath, src, "/wolfcrypt/src/", cryptoS, " ");
        cfg_build_cmd(dstPath, dst, "/wolfssl/wolfcrypt/src/", cryptoS, NULL);
        cfg_build_cmd(c_cmd, "cp ", srcPath, dstPath, NULL);
    }

    system(c_cmd);
    cfg_clear_cmd(c_cmd);
    cfg_clear_cmd(srcPath);
    cfg_clear_cmd(dstPath);

    return;
}

void cfg_copy_tls_src(char* src, char* dst, char* tlsS)
{
    char allTrigger[] = "copyAll";
    char c_cmd[CFG_LONGEST_COMMAND];
    char srcPath[CFG_LONGEST_COMMAND];
    char dstPath[CFG_LONGEST_COMMAND];

    cfg_clear_cmd(srcPath);
    cfg_clear_cmd(dstPath);
    cfg_clear_cmd(c_cmd);


    if (XSTRNCMP(tlsS, allTrigger, XSTRLEN(allTrigger)) == 0) {
        cfg_build_cmd(srcPath, src, "/src/* ", NULL, NULL);
        cfg_build_cmd(dstPath, dst, "/wolfssl/src/", NULL, NULL);
        cfg_build_cmd(c_cmd, "cp ", srcPath, dstPath, NULL);
    } else {
        cfg_build_cmd(srcPath, src, "/src/", tlsS, " ");
        cfg_build_cmd(dstPath, dst, "/wolfssl/src/", tlsS, NULL);
        cfg_build_cmd(c_cmd, "cp ", srcPath, dstPath, NULL);
    }

    system(c_cmd);
    cfg_clear_cmd(c_cmd);
    cfg_clear_cmd(srcPath);
    cfg_clear_cmd(dstPath);

    return;
}


void cfg_create_makefile(char* dst)
{
    size_t ret = 0;
    size_t bufLen = 0;
    char fName[CFG_LONGEST_COMMAND];
    FILE* fStream;
    char c_cmd[CFG_LONGEST_COMMAND];

    printf("Creating a makefile in %s directory.\n", dst);
    cfg_clear_cmd(c_cmd);
    cfg_clear_cmd(fName);
    cfg_build_cmd(fName, "Makefile_", dst, NULL, NULL);
    cfg_build_cmd(c_cmd, "touch ", fName, NULL, NULL);
    system(c_cmd);
    cfg_clear_cmd(c_cmd);

    fStream = cfg_open_file_append_mode(fName);

    bufLen = XSTRLEN(MakefileBuf);
    ret = fwrite(MakefileBuf, 1, bufLen, fStream);
    cfg_check_fwrite_success(ret, bufLen);

    cfg_build_cmd(c_cmd, "mv ", fName, " ", dst);
    cfg_build_cmd(c_cmd, "/Makefile", NULL, NULL, NULL);
    system(c_cmd);
    cfg_clear_cmd(c_cmd);

    fclose(fStream);

    return;
}

void cfg_create_arm_thumb_makefile(char* dst, char* toolChain)
{
    char toolChainPath[] = "cfg-custom-toolchains/ARM-THUMB/";
    char c_cmd[CFG_LONGEST_COMMAND];
    char outFName[CFG_LONGEST_COMMAND];
    FILE* fStream;
    FILE* outputStream;
    char* line = NULL;
    size_t len = 0;
    ssize_t read = 0;
    int advancePtr = (int) (XSTRLEN(ARM_THUMB) + 1);
    char* justThePath = toolChain+advancePtr;
    size_t ret;

    cfg_clear_cmd(c_cmd);
    cfg_clear_cmd(outFName);

    cfg_build_cmd(c_cmd, "cp ", toolChainPath, "* ", dst);
    system(c_cmd);
    cfg_clear_cmd(c_cmd);

    cfg_build_cmd(c_cmd, dst, "/Makefile.common", NULL, NULL);
    cfg_build_cmd(outFName, dst, "/Makefile.common.tmp", NULL, NULL);

    fStream = fopen(c_cmd, "rb");
    if (fStream == NULL) {
        printf("Failed to open %s\n", c_cmd);
        cfg_abort();
    }

    cfg_clear_cmd(c_cmd);
    cfg_build_cmd(c_cmd, "touch ", outFName, NULL, NULL);
    system(c_cmd);
    cfg_clear_cmd(c_cmd);

    outputStream = fopen(outFName, "wb");
    if (outputStream == NULL) {
        printf("Failed to open %s\n", outFName);
        cfg_abort();
    }

    while ((read = getline(&line, &len, fStream)) != EOF) {
        if (strstr(line, "TOOLCHAIN = ")) {
            int writeLen = 0;
            char* commentIn = "#Custom insertion from wolfCFG\n";

            writeLen = (int) XSTRLEN(commentIn);
            ret = fwrite(commentIn, 1, writeLen, outputStream);
            cfg_check_fwrite_success(ret, writeLen);

            cfg_build_cmd(c_cmd, "TOOLCHAIN = ", justThePath, "\n", NULL);
            writeLen = (int) XSTRLEN(c_cmd);
            ret = fwrite(c_cmd, 1, writeLen, outputStream);
            cfg_check_fwrite_success(ret, writeLen);

            writeLen = (int) XSTRLEN(commentIn);
            ret = fwrite(commentIn, 1, writeLen, outputStream);
            cfg_check_fwrite_success(ret, writeLen);
        } else {
            ret = fwrite(line, 1, XSTRLEN(line), outputStream);
            cfg_check_fwrite_success(ret, XSTRLEN(line));
        }
    }

    fclose(outputStream);
    fclose(fStream);
    if (line)
        free(line);

    cfg_clear_cmd(c_cmd);
    cfg_build_cmd(c_cmd, "mv ", outFName, " ", dst);
    cfg_build_cmd(c_cmd, "/Makefile.common", NULL, NULL, NULL);
    system(c_cmd);
    cfg_clear_cmd(c_cmd);
    cfg_clear_cmd(outFName);

    return;
}

int cfg_build_solution(char* dst, int testCase)
{
    int ret;

    char c_cmd[CFG_LONGEST_COMMAND];

    cfg_clear_cmd(c_cmd);

    /* copy over the test application */

    cfg_build_cd_cmd(c_cmd, dst);
    if (testCase == CFG_BUILD_MULTI) {
        cfg_build_cmd(c_cmd, " && make clean > /dev/null && make > /dev/null ",
                      NULL, NULL, NULL);
    } else {
        cfg_build_cmd(c_cmd, " && make clean && make",
                  NULL, NULL, NULL);
    }

    printf("c_cmd reads: %s\n", c_cmd);
    ret = system(c_cmd);
    cfg_clear_cmd(c_cmd);

    return ret;
}

void cfg_create_user_settings(char* dst)
{
    size_t ret = 0;
    size_t writeLen = 0;
    FILE* fStream;
    char c_cmd[CFG_LONGEST_COMMAND];
    char fName[CFG_LONGEST_COMMAND];

//    printf("Creating custom user_settings.h in %s directory.\n", dst);

    cfg_clear_cmd(c_cmd);
    cfg_clear_cmd(fName);

    cfg_build_cmd(fName, dst, "/user_settings.h", NULL, NULL);
//    cfg_build_cmd(c_cmd, "rm ", fName, NULL, NULL);
//    system(c_cmd);
    cfg_clear_cmd(c_cmd);
    cfg_build_cmd(c_cmd, "touch ", fName, NULL, NULL);
    system(c_cmd);
    cfg_clear_cmd(c_cmd);

    fStream = cfg_open_file_append_mode(fName);

    cfg_build_cmd(c_cmd, "#ifndef USER_SETTINGS_H\n", NULL, NULL, NULL);
    writeLen = XSTRLEN(c_cmd);
    ret = fwrite(c_cmd, 1, writeLen, fStream);
//    cfg_check_fwrite_success(ret, writeLen);
    cfg_clear_cmd(c_cmd);

    cfg_build_cmd(c_cmd, "#define USER_SETTINGS_H\n\n", NULL, NULL, NULL);
    writeLen = XSTRLEN(c_cmd);
    ret = fwrite(c_cmd, 1, writeLen, fStream);
    //cfg_check_fwrite_success(ret, writeLen);
    cfg_clear_cmd(c_cmd);

    fclose(fStream);

    return;
}

void cfg_write_user_settings(char* dst, char* setting)
{
    size_t ret = 0;
    size_t setLen = 0;
    size_t finSetLen = 0;
    FILE* fStream;
    char fName[CFG_LONGEST_COMMAND];
    char finSet[CFG_LONGEST_COMMAND];

    cfg_clear_cmd(fName);
    cfg_clear_cmd(finSet);

    setLen = XSTRLEN(setting);
    if (setLen == 0)
        return;

    cfg_build_cmd(fName, dst, "/user_settings.h", NULL, NULL);

    fStream = cfg_open_file_append_mode(fName);

    cfg_build_cmd(finSet, "#undef ", setting, "\n", NULL);
    finSetLen = XSTRLEN(finSet);

    ret = fwrite(finSet, 1, finSetLen, fStream);
    //cfg_check_fwrite_success(ret, finSetLen);
    cfg_clear_cmd(finSet);

    cfg_build_cmd(finSet, "#define ", setting, "\n\n", NULL);
    finSetLen = XSTRLEN(finSet);

    ret = fwrite(finSet, 1, finSetLen, fStream);
    //cfg_check_fwrite_success(ret, finSetLen);
    cfg_clear_cmd(finSet);

    fclose(fStream);

    return;
}

void cfg_close_user_settings(char* dst)
{
    size_t ret = 0;
    size_t writeLen = 0;
    FILE* fStream;
    char c_cmd[CFG_LONGEST_COMMAND];
    char fName[CFG_LONGEST_COMMAND];

    cfg_clear_cmd(c_cmd);
    cfg_clear_cmd(fName);

    cfg_build_cmd(fName, dst, "/user_settings.h", NULL, NULL);

    fStream = cfg_open_file_append_mode(fName);

    cfg_build_cmd(c_cmd, "#endif /* USER_SETTINGS_H */\n", NULL, NULL, NULL);
    writeLen = XSTRLEN(c_cmd);
    ret = fwrite(c_cmd, 1, writeLen, fStream);
    //cfg_check_fwrite_success(ret, writeLen);
    cfg_clear_cmd(c_cmd);

    fclose(fStream);

    return;

}

FILE* cfg_open_file_append_mode(char* fName)
{
    FILE* fStream;

    fStream = fopen(fName, "ab");
    if (fStream == NULL) {
        printf("Failed to open file %s at the specified location, please check"
               "file permissions and try again\n", fName);
        cfg_abort();
    }

    return fStream;
}

void cfg_check_fwrite_success(size_t written, size_t expected)
{
    if (written == expected)
        printf("Successfully wrote %zu bytes to file\n", written);
    else {
        printf("Failed to write %zu bytes to file, only wrote %zu bytes\n",
               expected, written);
        cfg_abort();
    }

    return;
}
