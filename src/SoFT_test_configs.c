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

            printf("Testing configuration:\n./configure --enable-jobserver=4 %s\n", tmpLine);

            SoFT_build_cmd(c_cmd, "export CFLAGS=\"-fdebug-types-section -g1\"",
                           NULL, NULL, NULL);
            ret = system(c_cmd);
            if (ret != 0) {
                printf("ret from exporting CFLAGS = %d\n", ret);
                SoFT_abort();
            }

            SoFT_clear_cmd(c_cmd);
            SoFT_build_cmd(c_cmd, "./configure --enable-jobserver=4 ", tmpLine,
                          " > ./config-output-log.txt ",
                          "2> ./config-output-log.txt");
            printf("Configuring wolfSSL...\n");
            ret = system(c_cmd);
            free(tmpLine);

            if (ret != 0) {
                SoFT_clear_cmd(c_cmd);
                SoFT_build_cmd(c_cmd, "cat config-output-log.txt",
                               NULL, NULL, NULL);
                ret = system(c_cmd);
                (void) ret;
                printf("Configuration Failed!\n\n");
                SoFT_clear_cmd(c_cmd);
                SoFT_abort();
            }

            SoFT_clear_cmd(c_cmd);
            SoFT_build_cmd(c_cmd, "make check > ./make-output-log.txt",
                          " 2> ./make-output-log.txt", NULL, NULL);
            printf("Running \"make check\"...\n");
            ret = system(c_cmd);
            if (ret != 0) {
                /* In the event the "make" failed this should have the output */
                SoFT_clear_cmd(c_cmd);
                SoFT_build_cmd(c_cmd, "make-output-log.txt",
                               NULL, NULL, NULL);
                ret = system(c_cmd);
                (void) ret;
                printf("End of Make Output <-------------------------------\n");

                /* In the event the "test" failed this should have the output */
                SoFT_clear_cmd(c_cmd);
                SoFT_build_cmd(c_cmd, "cat test-suite.log",
                               NULL, NULL, NULL);
                ret = system(c_cmd);
                (void) ret;
                SoFT_clear_cmd(c_cmd);
                printf("End of test-suite.log <----------------------------\n");

                printf("Make check Failed!\n\n");
                SoFT_abort();
            } else {
                printf("Make check Passed!\n\n");
            }
        }
    }

    return 0;
}
