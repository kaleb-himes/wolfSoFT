#include "configurator_common.h"
#include "configurator_builds.h"
#include "custom_builds/configurator_aes_only.h"
#include "custom_builds/configurator_rsa_pss_pkcs.h"
#include "custom_builds/configurator_sha256_ecc.h"
#include "custom_builds/configurator_sha512_only.h"
#include "custom_builds/configurator_ecc_only.h"
#include "custom_builds/configurator_sha256_only.h"

void cfg_do_custom_build(char* option, char* toolChain)
{

    if (option == NULL || toolChain == NULL) {
        printf("Invalid input\n");
        cfg_custom_build_usage();
    }

/*----------------------------------------------------------------------------*/
/* Aes Only please */
/*----------------------------------------------------------------------------*/
    if (XSTRNCMP(AES_ONLY_DST, option, (int)XSTRLEN(option)) == 0) {
        printf("Alright! Building %s!\n", AES_ONLY_DST);

        cfg_build_custom_specific(AES_ONLY_TEST_FILE, AES_ONLY_DST,
                                  aesOnlyCryptHeaders, AES_ONLY_C_HNUM,
                                  aesOnlyCryptSrc, AES_ONLY_C_SNUM,
                                  aesOnlyTlsHeaders, AES_ONLY_T_HNUM,
                                  aesOnlyTlsSrc, AES_ONLY_T_SNUM,
                                  aesOnlySettings, toolChain);
    }
/*----------------------------------------------------------------------------*/
/* RSA PSS PKCS */
/*----------------------------------------------------------------------------*/
    else if (XSTRNCMP(RSA_PSS_PKCS_DST, option, (int) XSTRLEN(option)) == 0) {
        printf("Alright! Building %s!\n", RSA_PSS_PKCS_DST);

        cfg_build_custom_specific(RSA_PSS_PKCS_TEST_FILE, RSA_PSS_PKCS_DST,
                                  rsaPssPkcsCryptHeaders, RSA_PSS_PKCS_C_HNUM,
                                  rsaPssPkcsCryptSrc, RSA_PSS_PKCS_C_SNUM,
                                  rsaPssPkcsTlsHeaders, RSA_PSS_PKCS_T_HNUM,
                                  rsaPssPkcsTlsSrc, RSA_PSS_PKCS_T_SNUM,
                                  rsaPssPkcsSettings, toolChain);
    }
/*----------------------------------------------------------------------------*/
/* RSA PSS PKCS "Sign/Verify" (sv) but "No Encrypt/Decrypt" (ned) */
/*----------------------------------------------------------------------------*/
    else if (XSTRNCMP(RSA_PSS_PKCS_SV_NED_DST, option, (int) XSTRLEN(option))
                                                                         == 0) {
        printf("Alright! Building %s!\n", RSA_PSS_PKCS_SV_NED_DST);

        cfg_build_custom_specific(RSA_PSS_PKCS_SV_NED_TEST_FILE,
                                  RSA_PSS_PKCS_SV_NED_DST,
                                  rsaPssPkcsCryptHeaders, RSA_PSS_PKCS_C_HNUM,
                                  rsaPssPkcsCryptSrc, RSA_PSS_PKCS_C_SNUM,
                                  rsaPssPkcsTlsHeaders, RSA_PSS_PKCS_T_HNUM,
                                  rsaPssPkcsTlsSrc, RSA_PSS_PKCS_T_SNUM,
                                  rsaPssPkcsSettings, toolChain);

    }
/*----------------------------------------------------------------------------*/
/* SHA256 ECC */
/*----------------------------------------------------------------------------*/
    else if (XSTRNCMP(SHA256_ECC_DST, option, (int) XSTRLEN(option)) == 0) {
        printf("Alright! Building %s!\n", SHA256_ECC_DST);

        cfg_build_custom_specific(SHA256_ECC_TEST_FILE,
                                  SHA256_ECC_DST,
                                  sha256EccCryptHeaders, SHA256_ECC_C_HNUM,
                                  sha256EccCryptSrc, SHA256_ECC_C_SNUM,
                                  sha256EccTlsHeaders, SHA256_ECC_T_HNUM,
                                  sha256EccTlsSrc, SHA256_ECC_T_SNUM,
                                  sha256EccSettings, toolChain);
    }
/*----------------------------------------------------------------------------*/
/* SHA512 Only */
/*----------------------------------------------------------------------------*/
    else if (XSTRNCMP(SHA512_ONLY_DST, option, (int)XSTRLEN(option)) == 0) {
        printf("Alright! Building %s!\n", SHA512_ONLY_DST);

        cfg_build_custom_specific(SHA512_ONLY_TEST_FILE,
                                  SHA512_ONLY_DST,
                                  sha512OnlyCryptHeaders, SHA512_ONLY_C_HNUM,
                                  sha512OnlyCryptSrc, SHA512_ONLY_C_SNUM,
                                  sha512OnlyTlsHeaders, SHA512_ONLY_T_HNUM,
                                  sha512OnlyTlsSrc, SHA512_ONLY_T_SNUM,
                                  sha512OnlySettings, toolChain);

    }
/*----------------------------------------------------------------------------*/
/* ECC Only */
/*----------------------------------------------------------------------------*/
    else if (XSTRNCMP(ECC_ONLY_DST, option, (int)XSTRLEN(option)) == 0) {
        printf("Alright! Building %s!\n", ECC_ONLY_DST);

        cfg_build_custom_specific(ECC_ONLY_TEST_FILE,
                                  ECC_ONLY_DST,
                                  eccOnlyCryptHeaders, ECC_ONLY_C_HNUM,
                                  eccOnlyCryptSrc, ECC_ONLY_C_SNUM,
                                  eccOnlyTlsHeaders, ECC_ONLY_T_HNUM,
                                  eccOnlyTlsSrc, ECC_ONLY_T_SNUM,
                                  eccOnlySettings, toolChain);

    }
/*----------------------------------------------------------------------------*/
/* SHA256 Only */
/*----------------------------------------------------------------------------*/
    else if (XSTRNCMP(SHA256_ONLY_DST, option, (int)XSTRLEN(option)) == 0) {
        printf("Alright! Building %s!\n", SHA256_ONLY_DST);

        cfg_build_custom_specific(SHA256_ONLY_TEST_FILE,
                                  SHA256_ONLY_DST,
                                  sha256OnlyCryptHeaders, SHA256_ONLY_C_HNUM,
                                  sha256OnlyCryptSrc, SHA256_ONLY_C_SNUM,
                                  sha256OnlyTlsHeaders, SHA256_ONLY_T_HNUM,
                                  sha256OnlyTlsSrc, SHA256_ONLY_T_SNUM,
                                  sha256OnlySettings, toolChain);

    }
/*----------------------------------------------------------------------------*/
/* No builds found */
/*----------------------------------------------------------------------------*/
    else {
        cfg_custom_build_usage();
    }
}

void cfg_build_custom_specific(char* testFile, char* dst,
                               char(* cryptHdrArr)[LONGEST_H_NAME],
                               int cryptHdrALen,
                               char(* cryptSrcArr)[LONGEST_S_NAME],
                               int cryptSrcALen,
                               char(* tlsHdrArr)[LONGEST_H_NAME],
                               int tlsHdrALen,
                               char(* tlsSrcArr)[LONGEST_S_NAME],
                               int tlsSrcALen,
                               char(* buildSettings)[LONGEST_PP_OPT],
                               char* toolChain)
{
    int i;
    char c_cmd[LONGEST_COMMAND];
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
    for (i = 0; i < cryptHdrALen; i++) {
        cfg_copy_crypto_hdr(src, dst, cryptHdrArr[i]);
    }
    /* Copy in the tls headers */
    for (i = 0; i < tlsHdrALen; i++) {
        cfg_copy_tls_hdr(src, dst, tlsHdrArr[i]);
    }
    /* Copy in the crypto sources */
    for (i = 0; i < cryptSrcALen; i++) {
        cfg_copy_crypto_src(src, dst, cryptSrcArr[i]);
    }
    /* Copy in the tls sources */
    for (i = 0; i < tlsSrcALen; i++) {
        cfg_copy_crypto_src(src, dst, tlsSrcArr[i]);
    }

    cfg_create_user_settings(dst);

    for (i = 0; i < MOST_SETTINGS; i++) {
        cfg_write_user_settings(dst, buildSettings[i]);
    }

    cfg_close_user_settings(dst);

    /* Build the project */
    cfg_build_solution(dst);

}


void cfg_custom_build_usage(void)
{
    printf("No valid options found.\n\n");
    printf("Valid builds are:\n");
    printf("\t\taes_only\n");
    printf("\t\trsa_pss_pkcs\n");
    printf("\t\trsa_pss_pkcs_sv_ned\n");
    printf("\t\tsha256_ecc\n");
    printf("\t\tsha512_only\n\n");
    printf("Valid toolChain options are:\n");
    printf("\t\tDEFAULT - This will use the default gcc compiler\n");
    printf("\t\tARM-THUMB - This will use the arm thumb compiler\n");
    printf("\t\t            NOTE: Set path with = IE ARM-THUMB=<path>/"
                            "arm-none-eabi-\n\n");
    printf("Examples:\n");
    printf("\t\t\"./run c aes_only DEFAULT\"\n");
    printf("\t\t\"./run c rsa_pss_pkcs ARM-THUMB=/usr/local/gcc_arm/gcc-arm-none-eabi-7-2017-q4/bin/arm-none-eabi-\"\n");
    printf("\n");
    cfg_abort();
}

void cfg_setup_traditional(char* destination)
{
    DIR* target;
    char c_cmd[LONGEST_COMMAND];
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

    return;
}

void cfg_copy_test_app(char* src, char* dst)
{
    char c_cmd[LONGEST_COMMAND];

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
    char c_cmd[LONGEST_COMMAND];
    char srcPath[LONGEST_COMMAND];
    char dstPath[LONGEST_COMMAND];

    cfg_clear_cmd(c_cmd);
    cfg_clear_cmd(srcPath);
    cfg_clear_cmd(dstPath);

    cfg_build_cmd(srcPath, src, "/wolfssl/wolfcrypt/", cryptoH, " ");
    cfg_build_cmd(dstPath, dst, "/wolfssl/wolfssl/wolfcrypt/", cryptoH, NULL);
    cfg_build_cmd(c_cmd, "cp ", srcPath, dstPath, NULL);

    system(c_cmd);

    cfg_clear_cmd(c_cmd);
    cfg_clear_cmd(srcPath);
    cfg_clear_cmd(dstPath);

    return;
}

void cfg_copy_tls_hdr(char* src, char* dst, char* tlsH)
{
    char c_cmd[LONGEST_COMMAND];
    char srcPath[LONGEST_COMMAND];
    char dstPath[LONGEST_COMMAND];

    cfg_clear_cmd(c_cmd);
    cfg_clear_cmd(srcPath);
    cfg_clear_cmd(dstPath);

    cfg_build_cmd(srcPath, src, "/wolfssl/", tlsH, " ");
    cfg_build_cmd(dstPath, dst, "/wolfssl/wolfssl/", tlsH, NULL);
    cfg_build_cmd(c_cmd, "cp ", srcPath, dstPath, NULL);

    system(c_cmd);

    cfg_clear_cmd(c_cmd);
    cfg_clear_cmd(srcPath);
    cfg_clear_cmd(dstPath);

    return;
}


void cfg_copy_crypto_src(char* src, char* dst, char* cryptoS)
{
    char c_cmd[LONGEST_COMMAND];
    char srcPath[LONGEST_COMMAND];
    char dstPath[LONGEST_COMMAND];

    cfg_clear_cmd(srcPath);
    cfg_clear_cmd(dstPath);
    cfg_clear_cmd(c_cmd);


    cfg_build_cmd(srcPath, src, "/wolfcrypt/src/", cryptoS, " ");
    cfg_build_cmd(dstPath, dst, "/wolfssl/wolfcrypt/src/", cryptoS, NULL);
    cfg_build_cmd(c_cmd, "cp ", srcPath, dstPath, NULL);
    system(c_cmd);
    cfg_clear_cmd(c_cmd);
    cfg_clear_cmd(srcPath);
    cfg_clear_cmd(dstPath);

    return;
}

void cfg_copy_tls_src(char* src, char* dst, char* tlsS)
{
    char c_cmd[LONGEST_COMMAND];
    char srcPath[LONGEST_COMMAND];
    char dstPath[LONGEST_COMMAND];

    cfg_clear_cmd(srcPath);
    cfg_clear_cmd(dstPath);
    cfg_clear_cmd(c_cmd);


    cfg_build_cmd(srcPath, src, "/src/", tlsS, " ");
    cfg_build_cmd(dstPath, dst, "/wolfssl/src/", tlsS, NULL);
    cfg_build_cmd(c_cmd, "cp ", srcPath, dstPath, NULL);
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
    char fName[LONGEST_COMMAND];
    FILE* fStream;
    char c_cmd[LONGEST_COMMAND];

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
    char c_cmd[LONGEST_COMMAND];
    char outFName[LONGEST_COMMAND];
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

            cfg_build_cmd(c_cmd, "TOOLCHAIN = ", justThePath, NULL, NULL);
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

void cfg_build_solution(char* dst)
{
    char c_cmd[LONGEST_COMMAND];

    cfg_clear_cmd(c_cmd);

    /* copy over the test application */

    cfg_build_cd_cmd(c_cmd, dst);
    cfg_build_cmd(c_cmd, " && make clean && make", NULL, NULL, NULL);
    printf("c_cmd reads: %s\n", c_cmd);
    system(c_cmd);
    cfg_clear_cmd(c_cmd);

    return;
}

void cfg_create_user_settings(char* dst)
{
    size_t ret = 0;
    size_t writeLen = 0;
    FILE* fStream;
    char c_cmd[LONGEST_COMMAND];
    char fName[LONGEST_COMMAND];

    printf("Creating custom user_settings.h in %s directory.\n", dst);

    cfg_clear_cmd(c_cmd);
    cfg_clear_cmd(fName);

    cfg_build_cmd(fName, dst, "/user_settings.h", NULL, NULL);
    cfg_build_cmd(c_cmd, "touch ", fName, NULL, NULL);
    system(c_cmd);
    cfg_clear_cmd(c_cmd);

    fStream = cfg_open_file_append_mode(fName);

    cfg_build_cmd(c_cmd, "#ifndef USER_SETTINGS_H\n", NULL, NULL, NULL);
    writeLen = XSTRLEN(c_cmd);
    ret = fwrite(c_cmd, 1, writeLen, fStream);
    cfg_check_fwrite_success(ret, writeLen);
    cfg_clear_cmd(c_cmd);

    cfg_build_cmd(c_cmd, "#define USER_SETTINGS_H\n\n", NULL, NULL, NULL);
    writeLen = XSTRLEN(c_cmd);
    ret = fwrite(c_cmd, 1, writeLen, fStream);
    cfg_check_fwrite_success(ret, writeLen);
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
    char fName[LONGEST_COMMAND];
    char finSet[LONGEST_COMMAND];

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
    cfg_check_fwrite_success(ret, finSetLen);
    cfg_clear_cmd(finSet);

    cfg_build_cmd(finSet, "#define ", setting, "\n\n", NULL);
    finSetLen = XSTRLEN(finSet);

    ret = fwrite(finSet, 1, finSetLen, fStream);
    cfg_check_fwrite_success(ret, finSetLen);
    cfg_clear_cmd(finSet);

    fclose(fStream);

    return;
}

void cfg_close_user_settings(char* dst)
{
    size_t ret = 0;
    size_t writeLen = 0;
    FILE* fStream;
    char c_cmd[LONGEST_COMMAND];
    char fName[LONGEST_COMMAND];

    cfg_clear_cmd(c_cmd);
    cfg_clear_cmd(fName);

    cfg_build_cmd(fName, dst, "/user_settings.h", NULL, NULL);

    fStream = cfg_open_file_append_mode(fName);

    cfg_build_cmd(c_cmd, "#endif /* USER_SETTINGS_H */\n", NULL, NULL, NULL);
    writeLen = XSTRLEN(c_cmd);
    ret = fwrite(c_cmd, 1, writeLen, fStream);
    cfg_check_fwrite_success(ret, writeLen);
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
