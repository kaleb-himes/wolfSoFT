#include <configurator_common.h>
#include <configurator_scrub_out.h>

void cfg_scrub_config_out(char* configOutFname,
                          char(*allConfigEnables)[LONGEST_CONFIG],
                          char(*allConfigDisables)[LONGEST_CONFIG])
{
    FILE* fStream;
    char* line = NULL;
    char truncLine[LONGEST_CONFIG];
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

    XMEMSET(truncLine, 0, LONGEST_CONFIG);


    fStream = fopen(configOutFname, "rb");
    if (fStream == NULL)
        cfg_abort();

    while ((read = getline(&line, &len, fStream)) != -1) {

        if (  (strstr(line, eOp) || strstr(line, dOp))
              &&
              (!strstr(line, defaultOn)) ) {
            addOpE = 1;
        } else if ( strstr(line, eOp) || strstr(line, dOp)) {
            addOpD = 1;
        } else {
            printf("--------------------------------------------------\n");
            printf("This line failed to meet the conditions specified:\n");
            printf("%s\n", line);
            printf("--------------------------------------------------\n");
        }

        if (addOpE || addOpD) {

            cfg_truncate_trim_line(line, truncLine);

            for (j = 0; j < MOST_IGNORES; j++) {
                if (XSTRNCMP(truncLine, ignore_opts[j],
                    XSTRLEN(truncLine)) == 0) {
                    if (addOpE)
                        addOpE = 0;
                    if (addOpD)
                        addOpD = 0;
                    break;
                }
            }

            if (addOpE == 1) {
                XSTRNCAT(allConfigEnables[i], truncLine, XSTRLEN(truncLine));
                i++;
                addOpE = 0;
            } else if (addOpD) {
                XSTRNCAT(allConfigDisables[k], truncLine, XSTRLEN(truncLine));
                k++;
                addOpD = 0;
            }

            XMEMSET(truncLine, 0, LONGEST_CONFIG);
        }
    }
    XSTRNCAT(allConfigEnables[i], lastLine, XSTRLEN(lastLine));
    XSTRNCAT(allConfigDisables[k], lastLine, XSTRLEN(lastLine));

    fclose(fStream);
    if (line)
        free(line);


    return;
}

void cfg_truncate_trim_line(char* line, char* truncatedLine)
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
        if (*a == DASH && *b == DASH) {
            foundIt = 1;
            b++; /* advance past second dash */
            while (*b != DASH) /* skip the <keep this part> */
                b++;
            b++; /* advance past first single dash */
            break; /* exit top level loop */
        }
        a++; /* only increment while look for first -- sequence */
        b++;
    }

    if (foundIt) {
        /* SPACE = ' ', NLRET = '\n', CRET = '\r', L_BRACKET = '[' */
        while (*b != SPACE && *b != NLRET && *b != CRET && *b != L_BRACKET) {
            *c = *b;
            c++;
            b++;
        }
        return;
    }
    /* failure */
    XMEMSET(truncatedLine, 0, LONGEST_CONFIG);
    return;
}

