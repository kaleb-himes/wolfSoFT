#include <SoFT_common.h>

int SoFT_auto_build_from_file(char* configOpsFile)
{
    FILE* fStream;
    char c_cmd[SOFT_LONGEST_COMMAND] = {0};
    char* line = NULL;
    size_t lengthOfLine = 0;
    ssize_t read        = 0;
    int ret = 0;
    char* tmpLine = NULL;

    (void) ret;

    SoFT_build_cmd(c_cmd, "Opening ", configOpsFile, " file", NULL);
    fStream = fopen(configOpsFile, "r");
    SoFT_assrt_ne_null(fStream, c_cmd);

    while ((read = getline(&line, &lengthOfLine, fStream)) != EOF) {
        if (strstr(line, "#")) {
            printf("Ignoring line: %s", line);
        } else if (read == 1) {
            printf("single character line, ignoring as blank line\n");
        } else {
            SoFT_clear_cmd(c_cmd);
            tmpLine = (char*) malloc(sizeof(char) * read);
            SoFT_assrt_ne_null(tmpLine, "tmpLine malloc");
            XMEMSET(tmpLine, 0, read);
            XMEMCPY(tmpLine, line, read-1);

            printf("Testing configuration:\n./configure %s\n", tmpLine);

            SoFT_build_cmd(c_cmd, "cd ./wolfssl && ./configure ", tmpLine,
                          " > /dev/null 2> /dev/null", NULL);
            printf("Configuring wolfSSL...\n");
            ret = system(c_cmd);
            free(tmpLine);

            if (ret != 0) {
                printf("Configuration Failed!\n\n");
                SoFT_abort();
            }

            SoFT_clear_cmd(c_cmd);
            SoFT_build_cmd(c_cmd, "cd ./wolfssl && make check > /dev/null",
                          " 2> /dev/null", NULL, NULL);
            printf("Running \"make check\"...\n");
            ret = system(c_cmd);
            if (ret != 0) {
                printf("Make check Failed!\n\n");
                SoFT_clear_cmd(c_cmd);
                SoFT_build_cmd(c_cmd, "cd ./wolfssl && cat test-suite.log",
                              NULL, NULL, NULL);
                system(c_cmd);
                SoFT_clear_cmd(c_cmd);
                SoFT_abort();
            } else {
                printf("Make check Passed!\n\n");
            }
        }
    }

    return 0;
}
