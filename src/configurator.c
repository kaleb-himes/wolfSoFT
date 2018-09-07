#include <configurator_common.h>

//#define DEBUG_CFG
//#define DEBUG_CFG_CHECK_ITERATE

int main(int argc, char** argv)
{
    int doClone = 1;
    int runBuilder = 0;

    /* USED: b, e, m, c, s, h */

    if (argc >= 2) {

        if (argv[SECOND_INPUT][FIRST_POSITION] != 'h') {
            doClone = cfg_are_we_cloning();
            if (doClone)
                cfg_clone_target_repo("wolfssl/wolfssl");
        }

        switch (argv[SECOND_INPUT][FIRST_POSITION]) {
            case 'a':
                if (argv[THIRD_INPUT] == NULL) {
                    printf("Invalid input, no file name provided\n");
                    return INPUT_ERR;
                }
                cfg_auto_build_from_file(argv[THIRD_INPUT]);
                break;
            case 'b':
                cfg_bench_all_configs();
                break;
            case 'e':
                if (argv[THIRD_INPUT] == NULL) {
                    printf("Invalid user input\n");
                    return INPUT_ERR;
                }
                if (argv[FOURTH_INPUT] == NULL || argv[FOURTH_INPUT] == 0)
                    runBuilder = 0;
                else
                    runBuilder = 1;

                cfg_pp_extract_from_multi_dirs(argv[THIRD_INPUT],
                                               NULL, NULL, NULL, 1, runBuilder);
                break;
            case 'm':
                {
                    char *tD1, *tD2, *tD3, *tD4;
                    int numDirs;

                    if (argc < 7)
                        usage_m();

                    tD1 = argv[THIRD_INPUT];
                    tD2 = argv[FOURTH_INPUT];
                    tD3 = argv[FIFTH_INPUT];
                    tD4 = argv[SIXTH_INPUT];
                    if (XSTRNCMP("1", argv[SEVENTH_INPUT], 1) == 0)
                        numDirs = 1;
                    else if (XSTRNCMP("2", argv[SEVENTH_INPUT], 1) == 0)
                        numDirs = 2;
                    else if (XSTRNCMP("3", argv[SEVENTH_INPUT], 1) == 0)
                        numDirs = 3;
                    else if (XSTRNCMP("4", argv[SEVENTH_INPUT], 1) == 0)
                        numDirs = 4;
                    else
                        usage_m();

                    if (XSTRNCMP("0", argv[EIGHTH_INPUT], 1) == 0)
                        runBuilder = 0;
                    else
                        runBuilder = 1;

                    cfg_pp_extract_from_multi_dirs(tD1, tD2, tD3, tD4,
                                                   numDirs, runBuilder);
                }
                break;
            case 'c':
                printf("OK! Doing a custom build, let's do it!\n");
                cfg_do_custom_build(argv[THIRD_INPUT], argv[FOURTH_INPUT]);
                break;
            case 's':
                printf("Testing single option: %s\n", argv[THIRD_INPUT]);
                cfg_pp_build_test_single(argv[THIRD_INPUT]);
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

void usage_m()
{
    printf("Invalid user input\n");
    printf("ARG1 -> m\n");
    printf("ARG2 -> valid directory to scrub for pre-processor macros\n");
    printf("ARG3 -> valid directory or NULL\n");
    printf("ARG4 -> valid directory or NULL\n");
    printf("ARG5 -> valid directory or NULL\n");
    printf("ARG6 -> number of valid directories from ARGS 2-5\n");
    printf("ARG7 -> flag, 0 = dump pp macros, 1 = use pp macros to run builds");
    printf("Example usages:\n\n");
    printf("\t./run m wolfssl/wolfssl NULL NULL NULL 1 0\n");
    printf("\t./run m wolfssl/wolfssl wolfssl/wolfcrypt/src NULL NULL"
           " 2 0\n");
    printf("\t./run m wolfssl/wolfssl wolfssl/wolfcrypt/src"
           "wolfssl/src wolfssl/wolfssl/wolfcrypt 4 1\n\n\n");
    cfg_abort();
}
