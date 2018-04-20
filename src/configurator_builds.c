#include "configurator_common.h"
#include "configurator_builds.h"

void cfg_do_custom_build(char* option)
{
    if (XSTRNCMP("aes_only", option, 8) == 0) {
        printf("Alright! Building just AES\n");
    } else {
        printf("No valid options found.\n\n");
        printf("Valid options are:\n");
        cfg_custom_build_usage();
    }
}

void cfg_custom_build_usage(void)
{
    printf("\t\taes_only\n");

    printf("\n");
    cfg_abort();
}
