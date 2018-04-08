#include <configurator_common.h>

//#define DEBUG_CFG
//#define DEBUG_CFG_CHECK_ITERATE

int main(int argc, char** argv)
{
    if (argc >= 2) {
        switch (argv[SECOND_INPUT][FIRST_POSITION]) {
            case 'b':
                cfg_bench_all_configs();
                break;
            case 'e':
                if (XSTRLEN(argv[THIRD_INPUT]) <= 0) {
                    printf("Invalid user input\n");
                    return INPUT_ERR;
                }
//                cfg_pp_extract_from_multi_dirs(argv[THIRD_INPUT],
//                                               NULL, NULL, NULL);
                cfg_pp_extract_from_multi_dirs(NULL, NULL, argv[THIRD_INPUT],
                                               NULL);
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
                    cfg_pp_extract_from_multi_dirs(tD1, tD2, tD3, tD4);
                }
                break;
            default:
                printf("TODO: Add Usage\n");
                printf("Invalid option\n");
                break;
        }
    }
    return 0;
}


