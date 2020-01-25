#include <SoFT_common.h>

int SoFT_run_config_opts(char* c_pwd, char* config_opts)
{
    int ret;
    char c_cmd[SOFT_LONGEST_COMMAND];

    /* On a mac */
    char* c_fNm1 = "/wolfssl/src/.libs/libwolfssl.dylib";
    /* Linux */
    char* c_fNm2 = "/wolfssl/src/.libs/libwolfssl.so";
    int c_fSz1, c_fSz2;

    int c_sumSz;
    int mallocFlag = 0;

    if (c_pwd == NULL) {
        c_pwd = (char*) malloc(sizeof(char) * SOFT_LONGEST_PATH);
        if (c_pwd == NULL)
            SoFT_abort();
        else
            mallocFlag = 1;
        /* get path to working directory */
        if (getcwd(c_pwd, SOFT_LONGEST_PATH) == NULL)
            SoFT_abort();
    }

    XMEMSET(c_cmd, 0, SOFT_LONGEST_COMMAND);

    /* build the change to directory, configure and make command */
    SoFT_build_cd_cmd(c_cmd, c_pwd);
    SoFT_build_cmd(c_cmd, "/wolfssl && ./configure ", config_opts,
              " > /dev/null", NULL);
    ret = system(c_cmd);
    if (ret != SOFT_CONFIG_NOT_SUPPORTED) /* skip those not supported */
        SoFT_check_ret(ret, 0, "configure library");
    if (ret == SOFT_CONFIG_NOT_SUPPORTED) {
        if (mallocFlag == 1)
            free(c_pwd);
        return ret;
    }

    SoFT_clear_cmd(c_cmd);
    SoFT_build_cd_cmd(c_cmd, c_pwd);
    SoFT_build_cmd(c_cmd, "/wolfssl && make > /dev/null", NULL, NULL, NULL);
    ret = system(c_cmd);
    if (ret != 0 && mallocFlag == 1) {
        free(c_pwd);
        return ret;
    }
    SoFT_check_ret(ret, 0, "make library");

    SoFT_clear_cmd(c_cmd);
    SoFT_build_cd_cmd(c_cmd, c_pwd);
    ret = system(c_cmd);
    if (ret != 0 && mallocFlag == 1) {
        free(c_pwd);
        return ret;
    }
    SoFT_check_ret(ret, 0, "change directory");

    SoFT_build_fname_cmd(c_cmd, c_fNm1, c_pwd);
    c_fSz1 = SoFT_get_file_size(c_cmd);

    SoFT_build_fname_cmd(c_cmd, c_fNm2, c_pwd);
    c_fSz2 = SoFT_get_file_size(c_cmd);

    #ifdef DEBUG_SOFT
      printf("size of %s was %d\n", c_fNm1, c_fSz1);
      printf("size of %s was %d\n", c_fNm2, c_fSz2);
    #endif

    c_sumSz = c_fSz1 + c_fSz2;

    if (mallocFlag)
        free(c_pwd);

    return c_sumSz;
}

void SoFT_check_increase(int baseLine, char* configPart)
{
    int ret;
    char c_config[SOFT_LONGEST_COMMAND];
    float original = (float) baseLine;
    float newNum;

    SoFT_clear_cmd(c_config);
    SoFT_build_cmd(c_config, SOFT_DEFAULT_OPTS, " --enable-", configPart, NULL);

    ret = SoFT_run_config_opts(NULL, c_config);

    if (ret == SOFT_CONFIG_NOT_SUPPORTED) {
        printf("--enable-%s !~ NS ~!\n", configPart);
        return;
    }

    if (ret > baseLine) {
        float increase, tmp;
        newNum = (float) ret;

        increase = newNum - original;
        tmp = increase / original;
        increase = tmp * 100;

        printf("[--enable-%s]\t\tFootprint Increase: [+"
               "%04f] (Percent)\n", configPart, (double) increase);
    } else {
        printf("--enable-%s had no impact\n", configPart);
    }
    return;
}

void SoFT_check_decrease(int baseLine, char* configPart)
{
    int ret;
    char c_config[SOFT_LONGEST_COMMAND];
    float original = (float) baseLine;
    float newNum;

    SoFT_clear_cmd(c_config);
    SoFT_build_cmd(c_config, SOFT_DEFAULT_OPTS, " --disable-", configPart,NULL);

    ret = SoFT_run_config_opts(NULL, c_config);

    if (ret == SOFT_CONFIG_NOT_SUPPORTED) {
        printf("--disable-%s !~ NS ~!\n", configPart);
        return;
    }

    if (ret < baseLine) {
        float decrease, tmp;
        newNum = (float) ret;

        decrease = original - newNum;
        tmp = decrease / original;
        decrease = tmp * 100;

        printf("[--disable-%s]\t\tFootprint Decrease: [-"
               "%04f] (Percent)\n", configPart,
               ((double)(-1) * (double) decrease));
    } else {
        printf("--disable-%s had no impact\n", configPart);
    }

}
