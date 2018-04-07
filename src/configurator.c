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
                cfg_pp_extract_from_dir(argv[THIRD_INPUT]);
            default:
                printf("TODO: Add Usage\n");
                printf("Invalid option\n");
                break;
        }
    }
    return 0;
}


