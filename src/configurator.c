#include <configurator_common.h>

//#define DEBUG_CFG
//#define DEBUG_CFG_CHECK_ITERATE

int main(int argc, char** argv)
{
    int doClone = 1;

    if (argc >= 2) {
        switch (argv[SECOND_INPUT][FIRST_POSITION]) {
            case 'b':

                doClone = cfg_are_we_cloning();
                if (doClone)
                    cfg_clone_target_repo("wolfssl/wolfssl");

                cfg_bench_all_configs();

                break;
            case 'e':
                if (XSTRLEN(argv[THIRD_INPUT]) <= 0) {
                    printf("Invalid user input\n");
                    return INPUT_ERR;
                }

                doClone = cfg_are_we_cloning();
                if (doClone)
                    cfg_clone_target_repo("wolfssl/wolfssl");

                cfg_pp_extract_from_multi_dirs(argv[THIRD_INPUT],
                                               NULL, NULL, NULL);
                break;
            case 'm':
                {
                    char* tD1 = NULL;
                    char* tD2 = NULL;
                    char* tD3 = NULL;
                    char* tD4 = NULL;
                    if (argv[THIRD_INPUT])
                        tD1 = argv[THIRD_INPUT];
                    if (argv[FOURTH_INPUT])
                        tD2 = argv[FOURTH_INPUT];
                    if (argv[FIFTH_INPUT])
                        tD3 = argv[FIFTH_INPUT];
                    if (argv[SIXTH_INPUT])
                        tD4 = argv[SIXTH_INPUT];

                    doClone = cfg_are_we_cloning();
                    if (doClone)
                        cfg_clone_target_repo("wolfssl/wolfssl");

                    cfg_pp_extract_from_multi_dirs(tD1, tD2, tD3, tD4);
                }
                break;
            case 'c':
                printf("OK! Doing a custom build, let's do it!\n");
                doClone = cfg_are_we_cloning();
                if (doClone)
                    cfg_clone_target_repo("wolfssl/wolfssl");

                cfg_do_custom_build(argv[THIRD_INPUT], argv[FOURTH_INPUT]);
                break;
            default:
                printf("TODO: Add Usage\n");
                printf("Invalid option\n");
                break;
        }
    }


    return 0;
}

int cfg_are_we_cloning(void)
{
    char cloneWolf = 'y';

    printf("Do you want to clone wolfSSL first or do you already"
           "\nhave a working copy?\nDefault is: [Y]\n"
           "Please input either [Y/N] >");
    cloneWolf = getchar();
    if (cloneWolf == UPPER_Y || cloneWolf == UPPER_N)
        cloneWolf += 32;
    if (cloneWolf != LOWER_Y && cloneWolf != LOWER_N) {
        printf("Invalid option: %c\n", cloneWolf);
        cfg_abort();
    }

    if (cloneWolf == LOWER_Y)
        return 1;
    else
        return 0;
}
