#include <SoFT_common.h>


int SoFT_run_config(char* config, int extra); /* local to file only */
void SoFT_printf(const char* format, ...);

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
            SoFT_printf("Ignoring line: %s", line);
        } else if (read == 1) {
            SoFT_printf("single character line, ignoring as blank line\n");
        } else {
            SoFT_clear_cmd(c_cmd);
            tmpLine = (char*) malloc(sizeof(char) * read);
            SoFT_assrt_ne_null(tmpLine, "tmpLine malloc");
            memset(tmpLine, 0, read);
            memcpy(tmpLine, line, read-1);

/* Config without opensslextra */
            ret = SoFT_run_config(tmpLine, 0);
/* Config with opensslextra */
            ret = SoFT_run_config(tmpLine, 1);
/* Done */
            free(tmpLine);
        }
    }

    return 0;
}

int SoFT_run_config(char* config, int extra)
{
    int ret = 0;
    char c_cmd[SOFT_LONGEST_COMMAND] = {0};

    (void) ret;

#if 0
    SoFT_build_cmd(c_cmd, "export C_EXTRA_FLAGS=\"-fdebug-types-section -g1\"",
                   NULL, NULL, NULL);
    ret = system(c_cmd);
    (void) ret;
    SoFT_clear_cmd(c_cmd);
#endif

    /* Exceptions */
    if (strstr(config, "enable-opensslextra") &&
        strstr(config, "enable-dtls") &&
        strstr(config, "disable-asn") &&
        strstr(config, "disable-ecc") &&
        strstr(config, "disable-rsa") &&
        strstr(config, "enable-psk")) {
        SoFT_printf("openssl-extra + disable-asn, disable-ecc, disable-rsa,"
                    "  enable-psk is currently broken. Needs addressed at a"
                    " later date... skip this test for now\n");
        return 0;
    }

    if (extra == 0) {
        SoFT_printf("Testing configuration:\n./configure --enable-jobserver=16 "
                    "%s\n", config);
        SoFT_build_cmd(c_cmd, "./configure --enable-jobserver=16 ", config,
                       " > ./config-output-log.txt 2> ./config-output-log.txt",
                       NULL);
    } else {

        /* Exception unique to the openssl extra build */
        if (strstr(config, "opensslextra") || strstr(config, "opensslall") ||
            strstr(config, "enable-all")) {
            SoFT_printf("config already contains the extra test so skipping\n");
            return 0;
        }

        if (strstr(config, "sp-math")) {
            SoFT_printf("opensslextra + sp-math do not play nicely... skip this"
                        " test for now\n");
            return 0;
        }

        SoFT_printf("Testing configuration:\n./configure --enable-jobserver=16 "
                    "--enable-opensslextra %s\n", config);
        SoFT_build_cmd(c_cmd,
                       "./configure --enable-jobserver=16 --enable-opensslextra ",
                       config,
                       " > ./config-output-log.txt 2> ./config-output-log.txt",
                       NULL);
    }

    SoFT_printf("Configuring wolfSSL...\n");
    ret = system(c_cmd);

    if (ret != 0) {
        SoFT_clear_cmd(c_cmd);
        SoFT_build_cmd(c_cmd, "cat config-output-log.txt",
                       NULL, NULL, NULL);
        ret = system(c_cmd);
        (void) ret;
        SoFT_printf("Configuration Failed!\n\n");
        SoFT_clear_cmd(c_cmd);
        SoFT_abort();
    }

    SoFT_clear_cmd(c_cmd);
    SoFT_build_cmd(c_cmd, "make check > ./make-output-log.txt",
                  " 2> ./make-output-log.txt", NULL, NULL);
    SoFT_printf("Running \"make check\"...\n");
    ret = system(c_cmd);
    if (ret != 0) {
        /* In the event the "make" failed this should have the output */
        SoFT_clear_cmd(c_cmd);
        SoFT_build_cmd(c_cmd, "make-output-log.txt",
                       NULL, NULL, NULL);
        ret = system(c_cmd);
        (void) ret;
        SoFT_printf("End of Make Output <-------------------------------\n");

        /* In the event the "test" failed this should have the output */
        SoFT_clear_cmd(c_cmd);
        SoFT_build_cmd(c_cmd, "cat test-suite.log",
                       NULL, NULL, NULL);
        ret = system(c_cmd);
        (void) ret;
        SoFT_clear_cmd(c_cmd);
        SoFT_printf("End of test-suite.log <----------------------------\n");

        SoFT_printf("Make check Failed!\n\n");
        SoFT_abort();
    } else {
        SoFT_printf("Make check Passed!\n\n");
    }

    return ret;
}


void SoFT_printf(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    vfprintf(stdout, format, args);
    va_end(args);
    fflush(stdout);
}
