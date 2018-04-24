#include "configurator_common.h"
#include "configurator_builds.h"
#include "custom_builds/configurator_aes_only.h"
#include "custom_builds/configurator_rsa_pss_pkcs.h"
#include "custom_builds/configurator_sha256_ecc.h"

void cfg_do_custom_build(char* option)
{
/*----------------------------------------------------------------------------*/
/* Aes Only please */
/*----------------------------------------------------------------------------*/
    if (XSTRNCMP(AES_ONLY_DST, option, (int)XSTRLEN(option)) == 0) {
        printf("Alright! Building AES Only!\n");

        cfg_build_custom_specific(AES_ONLY_TEST_FILE, AES_ONLY_DST,
                                  aesOnlyCryptHeaders, AES_ONLY_C_HNUM,
                                  aesOnlyCryptSrc, AES_ONLY_C_SNUM,
                                  aesOnlyTlsHeaders, AES_ONLY_T_HNUM,
                                  aesOnlyTlsSrc, AES_ONLY_T_SNUM,
                                  aesOnlySettings);
    }
/*----------------------------------------------------------------------------*/
/* SHA512 Only please  */
/*----------------------------------------------------------------------------*/
    else if (XSTRNCMP("sha512_only", option, (int)XSTRLEN(option)) == 0) {
        printf("Alright! Building SHA512 Only!\n");
    }
/*----------------------------------------------------------------------------*/
/* RSA PSS PKCS */
/*----------------------------------------------------------------------------*/
    else if (XSTRNCMP(RSA_PSS_PKCS_DST, option, (int) XSTRLEN(option)) == 0) {
        printf("Alright! Build RSA PSS and RSA PKCS!\n");

        cfg_build_custom_specific(RSA_PSS_PKCS_TEST_FILE, RSA_PSS_PKCS_DST,
                                  rsaPssPkcsCryptHeaders, RSA_PSS_PKCS_C_HNUM,
                                  rsaPssPkcsCryptSrc, RSA_PSS_PKCS_C_SNUM,
                                  rsaPssPkcsTlsHeaders, RSA_PSS_PKCS_T_HNUM,
                                  rsaPssPkcsTlsSrc, RSA_PSS_PKCS_T_SNUM,
                                  rsaPssPkcsSettings);
    }
/*----------------------------------------------------------------------------*/
/* RSA PSS PKCS "Sign/Verify" (sv) but "No Encrypt/Decrypt" (ned) */
/*----------------------------------------------------------------------------*/
    else if (XSTRNCMP(RSA_PSS_PKCS_SV_NED_DST, option, (int) XSTRLEN(option))
                                                                         == 0) {
        printf("Alright! Build RSA PSS and RSA PKCS!\n");

        cfg_build_custom_specific(RSA_PSS_PKCS_SV_NED_TEST_FILE,
                                  RSA_PSS_PKCS_SV_NED_DST,
                                  rsaPssPkcsCryptHeaders, RSA_PSS_PKCS_C_HNUM,
                                  rsaPssPkcsCryptSrc, RSA_PSS_PKCS_C_SNUM,
                                  rsaPssPkcsTlsHeaders, RSA_PSS_PKCS_T_HNUM,
                                  rsaPssPkcsTlsSrc, RSA_PSS_PKCS_T_SNUM,
                                  rsaPssPkcsSettings);

    }
/*----------------------------------------------------------------------------*/
/* SHA256 ECC */
/*----------------------------------------------------------------------------*/
    else if (XSTRNCMP(SHA256_ECC_DST, option, (int) XSTRLEN(option)) == 0) {
        printf("Alright! Build SHA256 and ECC!\n");

        cfg_build_custom_specific(SHA256_ECC_TEST_FILE,
                                  SHA256_ECC_DST,
                                  sha256EccCryptHeaders, SHA256_ECC_C_HNUM,
                                  sha256EccCryptSrc, SHA256_ECC_C_SNUM,
                                  sha256EccTlsHeaders, SHA256_ECC_T_HNUM,
                                  sha256EccTlsSrc, SHA256_ECC_T_SNUM,
                                  sha256EccSettings);
    }
/*----------------------------------------------------------------------------*/
/* No builds found */
/*----------------------------------------------------------------------------*/
    else {
        printf("No valid options found.\n\n");
        printf("Valid options are:\n");
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
                               char(* buildSettings)[LONGEST_PP_OPT])
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
    printf("\t\taes_only\n");

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
