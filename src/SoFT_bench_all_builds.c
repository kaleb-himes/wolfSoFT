#include <SoFT_common.h>

void SoFT_bench_all_configs()
{
    char c_pwd[SOFT_LONGEST_PATH];
    char c_cmd[SOFT_LONGEST_COMMAND];
    char* configOutFname = "config-out.txt";
    int default_baseline = 0;
    char allConfigEnables[SOFT_MOST_CONFIGS][SOFT_LONGEST_CONFIG];
    char allConfigDisables[SOFT_MOST_CONFIGS][SOFT_LONGEST_CONFIG];
    int i;

    SoFT_clear_cmd(c_pwd);
    SoFT_clear_cmd(c_cmd);

    /* get path to working directory */
    if (getcwd(c_pwd, SOFT_LONGEST_PATH) == NULL)
        SoFT_abort();

    /* cd to wolfssl root dir and run autogen.sh */
    printf("Getting the library ready for testing...\n");
    SoFT_build_cd_cmd(c_cmd, c_pwd);
    SoFT_build_cmd(c_cmd, "/wolfssl", " && ./autogen.sh", NULL, NULL);
    system(c_cmd);
    SoFT_clear_cmd(c_cmd);

    SoFT_build_cd_cmd(c_cmd, c_pwd);
    system(c_cmd);
    SoFT_clear_cmd(c_cmd);

    /* get a baseline for comparison */
    printf("Configuring for baseline comparison...\n");
    default_baseline = SoFT_run_config_opts(c_pwd, SOFT_DEFAULT_OPTS);

    /* run configure to output the help menu */
    /* echo the result to file */
    SoFT_clear_cmd(c_cmd);
    SoFT_build_cd_cmd(c_cmd, c_pwd);
    SoFT_build_cmd(c_cmd, "/wolfssl && ./configure -h > ../",
              configOutFname, NULL, NULL);
    system(c_cmd);
    SoFT_clear_cmd(c_cmd);

    /* scrub the file for configure options */
    /* store configure options in a char[][] */
    for (i = 0; i < SOFT_MOST_CONFIGS; i++) {
        XMEMSET(allConfigEnables[i], 0, SOFT_LONGEST_CONFIG);
        XMEMSET(allConfigDisables[i], 0, SOFT_LONGEST_CONFIG);
    }

    SoFT_scrub_config_out(configOutFname, allConfigEnables, allConfigDisables);

    /* read out the options one at a time and compare to baseline */
    for (i = 0; i < SOFT_MOST_CONFIGS; i++) {
        if (XSTRNCMP(allConfigEnables[i], "LAST_LINE", 9) == 0) {
            printf("Tested a total of %d enable options\n", i);
            break;
        }
        SoFT_check_increase(default_baseline, allConfigEnables[i]);
    }

    for (i = 0; i < SOFT_MOST_CONFIGS; i++) {
        if (XSTRNCMP(allConfigDisables[i], "LAST_LINE", 9) == 0) {
            printf("Tested a total of %d disable options\n", i);
            break;
        }
        SoFT_check_decrease(default_baseline, allConfigDisables[i]);
    }

}


