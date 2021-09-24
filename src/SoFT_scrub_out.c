#include <SoFT_common.h>
#include <SoFT_scrub_out.h>

void SoFT_scrub_config_out(char* configOutFname,
                          char(*allConfigEnables)[SOFT_LONGEST_CONFIG],
                          char(*allConfigDisables)[SOFT_LONGEST_CONFIG])
{
    FILE* fStream;
    char* line = NULL;
    char truncLine[SOFT_LONGEST_CONFIG];
    int i = 0, j, k = 0;
    int addOpE = 0;
    int addOpD = 0;

    char* eOp = "--enable-";
    char* dOp = "--disable-";
    char* defaultOn = "enabled)";
    char* defaultOff = "disabled)";
    char* lastLine = "LAST_LINE";

    size_t len = 0;
    ssize_t read;

    memset(truncLine, 0, SOFT_LONGEST_CONFIG);


    fStream = fopen(configOutFname, "rb");
    if (fStream == NULL)
        SoFT_abort();

    while ((read = getline(&line, &len, fStream)) != -1) {

        if (strstr(line, eOp) || strstr(line, dOp)) {

            if (!strstr(line, defaultOn)) {
                addOpE = 1;
            } else if ( strstr(line, defaultOn) || strstr(line, defaultOff)) {
                addOpD = 1;
            } else {
                printf("--------------------------------------------------\n");
                printf("This line failed to meet the conditions specified:\n");
                printf("%s\n", line);
                printf("--------------------------------------------------\n");
            }
        }

        if (addOpE || addOpD) {

            SoFT_truncate_trim_line(line, truncLine);

            for (j = 0; j < SOFT_MOST_IGNORES; j++) {
                if (strncmp(truncLine, ignore_opts[j],
                    strlen(truncLine)) == 0) {
                    if (addOpE)
                        addOpE = 0;
                    if (addOpD)
                        addOpD = 0;
                    break;
                }
            }

            if (addOpE == 1) {
                strncat(allConfigEnables[i], truncLine, strlen(truncLine));
                i++;
                addOpE = 0;
            } else if (addOpD) {
                strncat(allConfigDisables[k], truncLine, strlen(truncLine));
                k++;
                addOpD = 0;
            }

            memset(truncLine, 0, SOFT_LONGEST_CONFIG);
        }
    }
    strncat(allConfigEnables[i], lastLine, strlen(lastLine));
    strncat(allConfigDisables[k], lastLine, strlen(lastLine));

    fclose(fStream);
    if (line)
        free(line);


    return;
}

void SoFT_truncate_trim_line(char* line, char* truncatedLine)
{
    char* a = line;
    char* b = line + 1;
    char* c = truncatedLine;
    int foundIt = 0;

    /* We have a long string like: "--enable-static     <description"
     * Since the goal here is to build all enable/disable options and
     * check the impact on build size we're going to strip the beginning
     * --enable-<keep this part> and remove all chars at the end of the line
     * that describe that feature */
    while(*b != 0) {
        /* account for white space prior to -- sequence */
        if (*a == SOFT_DASH && *b == SOFT_DASH) {
            foundIt = 1;
            b++; /* advance past second dash */
            while (*b != SOFT_DASH) /* skip the <keep this part> */
                b++;
            b++; /* advance past first single dash */
            break; /* exit top level loop */
        }
        a++; /* only increment while look for first -- sequence */
        b++;
    }

    if (foundIt) {
        /* SPACE = ' ', SOFT_NLRET = '\n', SOFT_CRET = '\r', SOFT_L_BRACKET = '['
         */
        while (*b != SOFT_SPACE && *b != SOFT_NLRET && *b != SOFT_CRET &&
               *b != SOFT_L_BRACKET) {
            *c = *b;
            c++;
            b++;
        }
        return;
    }
    /* failure */
    memset(truncatedLine, 0, SOFT_LONGEST_CONFIG);
    return;
}

