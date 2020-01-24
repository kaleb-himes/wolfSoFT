#include <configurator_common.h>

int cfg_auto_build_from_file(char* configOpsFile)
{
    FILE* fStream;
    char c_cmd[CFG_LONGEST_COMMAND] = {0};
    char* line = NULL;
    size_t lengthOfLine = 0;
    ssize_t read        = 0;
    int ret = 0;
    char* tmpLine = NULL;

    (void) ret;

    cfg_build_cmd(c_cmd, "Opening ", configOpsFile, " file", NULL);
    fStream = fopen(configOpsFile, "r");
    cfg_assrt_ne_null(fStream, c_cmd);

    while ((read = getline(&line, &lengthOfLine, fStream)) != EOF) {
        if (strstr(line, "#")) {
            printf("Ignoring line: %s", line);
        } else if (read == 1) {
            printf("single character line, ignoring as blank line\n");
        } else {
            cfg_clear_cmd(c_cmd);
            tmpLine = (char*) malloc(sizeof(char) * read);
            cfg_assrt_ne_null(tmpLine, "tmpLine malloc");
            XMEMSET(tmpLine, 0, read);
            XMEMCPY(tmpLine, line, read-1);

            printf("Testing configuration:\n./configure %s\n", tmpLine);

            cfg_build_cmd(c_cmd, "cd ./wolfssl && ./configure ", tmpLine,
                          " > /dev/null 2> /dev/null", NULL);
            printf("Configuring wolfSSL...\n");
            ret = system(c_cmd);
            free(tmpLine);

            if (ret != 0) {
                printf("Configuration Failed!\n\n");
                cfg_abort();
            }

            cfg_clear_cmd(c_cmd);
            cfg_build_cmd(c_cmd, "cd ./wolfssl && make check > /dev/null",
                          " 2> /dev/null", NULL, NULL);
            printf("Running \"make check\"...\n");
            ret = system(c_cmd);
            if (ret != 0) {
                printf("Make check Failed!\n\n");
                cfg_clear_cmd(c_cmd);
                cfg_build_cmd(c_cmd, "cd ./wolfssl && cat test-suite.log",
                              NULL, NULL, NULL);
                system(c_cmd);
                cfg_clear_cmd(c_cmd);
                cfg_abort();
            } else {
                printf("Make check Passed!\n\n");
            }
        }
    }

    return 0;
}
