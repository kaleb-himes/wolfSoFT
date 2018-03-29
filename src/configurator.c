#include <configurator_common.h>

#define FULL_BUILD

int main(void)
{
    char c_pwd[LONGEST_PATH];
    char c_cmd[LONGEST_COMMAND];
    char* gitCmd = "git clone https://github.com/wolfssl/wolfssl.git";
    char* configOutFname = "config-out.txt";
    int ret;
    int default_baseline = 0;
    int difference;
    char allConfigSingles[MOST_CONFIGS][LONGEST_CONFIG];
    int i, j;

    clear_command(c_pwd);
    clear_command(c_cmd);

#ifdef FULL_BUILD
    (void) default_baseline;
    build_cmd(c_cmd, gitCmd, NULL, NULL, NULL);
    system(c_cmd);
    clear_command(c_cmd);

    /* get path to working directory */
    if (getcwd(c_pwd, LONGEST_PATH) == NULL)
        configurator_abort();

    /* cd to wolfssl root dir and run autogen.sh */
    build_cd_cmd(c_cmd, c_pwd);
    build_cmd(c_cmd, "/wolfssl", " && ./autogen.sh", " > /dev/null", " 2&>1");
    system(c_cmd);
    clear_command(c_cmd);

    build_cd_cmd(c_cmd, c_pwd);
    system(c_cmd);
    clear_command(c_cmd);

    /* get a baseline for comparison */
    default_baseline = run_config_opts(c_pwd, DEFAULT_CONFIG);
#endif

    /* run configure to output the help menu */
    /* echo the result to file */
    clear_command(c_cmd);
    build_cd_cmd(c_cmd, c_pwd);
    build_cmd(c_cmd, "/wolfssl && ./configure -h > ../",
              configOutFname, NULL, NULL);
    system(c_cmd);
    clear_command(c_cmd);

    /* scrub the file for configure options */
    /* store configure options in a char[][] */
    for (i = 0; i < MOST_CONFIGS; i++) {
        XMEMSET(allConfigSingles[i], 0, LONGEST_CONFIG);
    }

    scrub_config_out(configOutFname, allConfigSingles);
    /* read out the options one at a time and compare to baseline */
    for (i = 0; i < MOST_CONFIGS; i++) {
        if (XSTRNCMP(allConfigSingles[i], "LAST_LINE", 9) == 0) {
            printf("aborting at %d\n", i);
            break;
        }
        /* TODO: if default on don't run */
        check_increase(default_baseline, allConfigSingles[i]);
        /* TODO: if default off don't run */
        check_decrease(default_baseline, allConfigSingles[i]);
    }

    return 0;
}


