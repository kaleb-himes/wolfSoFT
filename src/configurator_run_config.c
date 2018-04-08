
#include <configurator_common.h>

int cfg_run_config_opts(char* c_pwd, char* config_opts)
{
    int ret;
    char c_cmd[LONGEST_COMMAND];

    /* On a mac */
    char* c_fNm1 = "/wolfssl/src/.libs/libwolfssl.dylib";
    /* Linux */
    char* c_fNm2 = "/wolfssl/src/.libs/libwolfssl.so";
    int c_fSz1, c_fSz2;

    int c_sumSz;
    int mallocFlag = 0;

    if (c_pwd == NULL) {
        c_pwd = (char*) malloc(sizeof(char) * LONGEST_PATH);
        if (c_pwd == NULL)
            cfg_abort();
        else
            mallocFlag = 1;
        /* get path to working directory */
        if (getcwd(c_pwd, LONGEST_PATH) == NULL)
            cfg_abort();
    }

    XMEMSET(c_cmd, 0, LONGEST_COMMAND);

    /* build the change to directory, configure and make command */
    cfg_build_cd_cmd(c_cmd, c_pwd);
    cfg_build_cmd(c_cmd, "/wolfssl && ./configure ", config_opts,
              " > /dev/null", NULL);
    ret = system(c_cmd);
    if (ret != CONFIG_NOT_SUPPORTED) /* skip the ones that aren't supported */
        cfg_check_ret(ret, 0, "configure library");
    if (ret == CONFIG_NOT_SUPPORTED) {
        if (mallocFlag == 1)
            free(c_pwd);
        return ret;
    }

    cfg_clear_cmd(c_cmd);
    cfg_build_cd_cmd(c_cmd, c_pwd);
    cfg_build_cmd(c_cmd, "/wolfssl && make > /dev/null", NULL, NULL, NULL);
    ret = system(c_cmd);
    if (ret != 0 && mallocFlag == 1) {
        free(c_pwd);
        return ret;
    }
    cfg_check_ret(ret, 0, "make library");

    cfg_clear_cmd(c_cmd);
    cfg_build_cd_cmd(c_cmd, c_pwd);
    ret = system(c_cmd);
    if (ret != 0 && mallocFlag == 1) {
        free(c_pwd);
        return ret;
    }
    cfg_check_ret(ret, 0, "change directory");

    cfg_build_fname_cmd(c_cmd, c_fNm1, c_pwd);
    c_fSz1 = cfg_get_file_size(c_cmd);

    cfg_build_fname_cmd(c_cmd, c_fNm2, c_pwd);
    c_fSz2 = cfg_get_file_size(c_cmd);

    printf("size of %s was %d\n", c_fNm1, c_fSz1);
    printf("size of %s was %d\n", c_fNm2, c_fSz2);

    c_sumSz = c_fSz1 + c_fSz2;

    if (mallocFlag)
        free(c_pwd);

    return c_sumSz;
}

void cfg_check_increase(int baseLine, char* configPart)
{
    int ret;
    char c_config[LONGEST_COMMAND];
    float original = (float) baseLine;
    float newNum;

    cfg_clear_cmd(c_config);
    cfg_build_cmd(c_config, DEFAULT_OPTS, " --enable-", configPart, NULL);

    ret = cfg_run_config_opts(NULL, c_config);

    if (ret == CONFIG_NOT_SUPPORTED) {
        printf("--enable-%s !~ NS ~!\n", configPart);
        return;
    }

    if (ret > baseLine) {
        float increase, tmp;
        newNum = (float) ret;

        increase = newNum - original;
        tmp = increase / original;
        increase = tmp * 100;

        printf("--enable-%s increases the build by ---> "
               " %04f percent\n", configPart, (double) increase);
    } else {
        printf("--enable-%s had no impact\n", configPart);
    }
    return;
}

void cfg_check_decrease(int baseLine, char* configPart)
{
    int ret;
    char c_config[LONGEST_COMMAND];
    float original = (float) baseLine;
    float newNum;

    cfg_clear_cmd(c_config);
    cfg_build_cmd(c_config, DEFAULT_OPTS, " --enable-", configPart, NULL);

    ret = cfg_run_config_opts(NULL, c_config);

    if (ret == CONFIG_NOT_SUPPORTED) {
        printf("--disable-%s !~ NS ~!\n", configPart);
        return;
    }

    if (ret < baseLine) {
        float decrease, tmp;
        newNum = (float) ret;

        decrease = original - newNum;
        tmp = decrease / original;
        decrease = tmp * 100;

        printf("--disable-%s decreases the build by --->"
               " %04f percent\n", configPart, (double) decrease);
    } else {
        printf("--disable-%s had no impact\n", configPart);
    }

}
