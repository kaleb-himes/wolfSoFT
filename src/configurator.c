#include <configurator_common.h>
#include <dirent.h>

int main(int argc, char** argv)
{
    int i, j;

    if (argc >= 2) {
        switch (argv[SECOND_WORD][FIRST_POSITION]) {
            case 'b':
                cfg_bench_all_configs();
                break;
            default:
                printf("Invalid option %c\n", argv[SECOND_WORD][FIRST_POSITION]);
                break;
        }
    }

/* --------- next stuff to get working, port to own API after solved -------- */
    DIR* dStream;
    char* targetDir = "wolfssl/src";
    struct dirent* currF;
    FILE* currFStream;
    char cmdArray[LONGEST_COMMAND];
    char* line = NULL;
    ssize_t read;
    size_t lengthOfLine;
    PP_OPT* head = NULL;

    cfg_clear_cmd(cmdArray);
    cfg_clone_target_repo("wolfssl/wolfssl");

    dStream = opendir(targetDir);
    cfg_assrt_ne_null(dStream, "Opening wolfssl/src/ directory");

    while ( (currF = readdir(dStream)) ) {
        if (XSTRNCMP(currF->d_name, ".", 1) == 0)
            continue;
        if (XSTRNCMP(currF->d_name, "..", 2) == 0)
            continue;

        if (getcwd(cmdArray, LONGEST_PATH) == NULL)
            cfg_abort();

        cfg_build_cmd(cmdArray, "/", targetDir, "/", currF->d_name);
        currFStream = fopen(cmdArray, "rb");
        printf("fileName + path = %s\n", cmdArray);

        cfg_clear_cmd(cmdArray);
        cfg_build_cmd(cmdArray, "Opening ", currF->d_name, " file", NULL);
        cfg_assrt_ne_null(currFStream, cmdArray);
        cfg_clear_cmd(cmdArray);
        printf("Successfully opened %s\n", currF->d_name);

        /* read file line by line and check for ifdef, ifndef, defined */
        /* found ifdef, look for first capitol letter between A - Z or _  */
        /* if not found on line move on, same for ifndef */
        /* found defined, look for first ( then look for first capitol A - Z or
         * _ if not found move on, check line for more than one "define" keyword
          */
        while ( (read = getline(&line, &lengthOfLine, currFStream)) != -1 ) {
            if (strstr(line, "#ifdef")) {
                printf("Found \"ifdef\" in \"%s\"\n", line);
                head = cfg_init_pp_opt(head);
                cfg_get_pp_macro_single(head, line, (int)lengthOfLine);
            }

            if (strstr(line, "#ifndef"))
                printf("Found \"ifndef\" in \"%s\"\n", line);
            if (strstr(line, "defined") && strstr(line, "#if"))
                printf("Found \"defined\" in \"%s\"\n", line);
            
        }

        fclose(currFStream);
        //temp break for testing
        break;
    }

    return 0;
}

void cfg_get_pp_macro_single(PP_OPT* curr, char* line, int lSz)
{
    PP_OPT* next;
    int i, j;
    int lFlag = 0;

    printf("DEBUG: we're working with line: \"%s\"", line);
    printf("DEBUG: length of line is: %d\n", lSz);
    cfg_assrt_ne_null(curr, "Called get_pp_macro_single with null argument");

    next = curr->next;

    if (next != NULL) {
        printf("Called get_pp_macro_single with a node that has a next\n");
        cfg_abort();
    }

    next = (PP_OPT*) malloc(sizeof(PP_OPT));
    cfg_assrt_ne_null(next, "creating next in get_pp_macro_single");

    /* Start at the front of line and inter till space */
    j = 0;
    for (i = 0; i < lSz; i++) {
        if ( (line[i] >= UPPER_A && line[i] <= UPPER_Z)  /* regex = [A-Z]+ */
             || (line[i] == UNDERSCORE)                  /* regex = TODO:  */
           ) {
            printf("%c", line[i]);
            curr->pp_opt[j] = line[i];
            j++;
        }
    }
}

PP_OPT* cfg_init_pp_opt(PP_OPT* in)
{
    if (in == NULL) {
        in = (PP_OPT*) malloc(sizeof(PP_OPT));
        cfg_assrt_ne_null(in, "cfg_init_pp_opt");
    }

    in->previous = NULL;
    in->next = NULL;
    XMEMSET(in, 0, LONGEST_PP_OPT);

    return in;
}
