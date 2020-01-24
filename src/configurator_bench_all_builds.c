#include <configurator_common.h>

void cfg_bench_all_configs()
{
    char c_pwd[CFG_LONGEST_PATH];
    char c_cmd[CFG_LONGEST_COMMAND];
    char* configOutFname = "config-out.txt";
    int default_baseline = 0;
    char allConfigEnables[CFG_MOST_CONFIGS][CFG_LONGEST_CONFIG];
    char allConfigDisables[CFG_MOST_CONFIGS][CFG_LONGEST_CONFIG];
    int i;

    cfg_clear_cmd(c_pwd);
    cfg_clear_cmd(c_cmd);

    /* get path to working directory */
    if (getcwd(c_pwd, CFG_LONGEST_PATH) == NULL)
        cfg_abort();

    /* cd to wolfssl root dir and run autogen.sh */
    printf("Getting the library ready for testing...\n");
    cfg_build_cd_cmd(c_cmd, c_pwd);
    cfg_build_cmd(c_cmd, "/wolfssl", " && ./autogen.sh", NULL, NULL);
    system(c_cmd);
    cfg_clear_cmd(c_cmd);

    cfg_build_cd_cmd(c_cmd, c_pwd);
    system(c_cmd);
    cfg_clear_cmd(c_cmd);

    /* get a baseline for comparison */
    printf("Configuring for baseline comparison...\n");
    default_baseline = cfg_run_config_opts(c_pwd, CFG_DEFAULT_OPTS);

    /* run configure to output the help menu */
    /* echo the result to file */
    cfg_clear_cmd(c_cmd);
    cfg_build_cd_cmd(c_cmd, c_pwd);
    cfg_build_cmd(c_cmd, "/wolfssl && ./configure -h > ../",
              configOutFname, NULL, NULL);
    system(c_cmd);
    cfg_clear_cmd(c_cmd);

    /* scrub the file for configure options */
    /* store configure options in a char[][] */
    for (i = 0; i < CFG_MOST_CONFIGS; i++) {
        XMEMSET(allConfigEnables[i], 0, CFG_LONGEST_CONFIG);
        XMEMSET(allConfigDisables[i], 0, CFG_LONGEST_CONFIG);
    }

    cfg_scrub_config_out(configOutFname, allConfigEnables, allConfigDisables);

    /* read out the options one at a time and compare to baseline */
    for (i = 0; i < CFG_MOST_CONFIGS; i++) {
        if (XSTRNCMP(allConfigEnables[i], "LAST_LINE", 9) == 0) {
            printf("Tested a total of %d enable options\n", i);
            break;
        }
        cfg_check_increase(default_baseline, allConfigEnables[i]);
    }

    for (i = 0; i < CFG_MOST_CONFIGS; i++) {
        if (XSTRNCMP(allConfigDisables[i], "LAST_LINE", 9) == 0) {
            printf("Tested a total of %d disable options\n", i);
            break;
        }
        cfg_check_decrease(default_baseline, allConfigDisables[i]);
    }

}


