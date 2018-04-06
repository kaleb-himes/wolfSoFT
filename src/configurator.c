#include <configurator_common.h>
#include <dirent.h>

//#define DEBUG_CFG

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
    PP_OPT* curr = NULL;
    int counter = 0;
    char multiOpts[OPTS_IN_A_LINE][LONGEST_PP_OPT];
    int optsFound = 0;

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

//tmp for testing
        if (XSTRNCMP(currF->d_name, "ssl.c", 5) != 0)
            continue;
//end tmp for testing
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
        curr = cfg_pp_node_init(curr);
        while ( (read = getline(&line, &lengthOfLine, currFStream)) != -1 ) {
            if (strstr(line, "#ifdef")) {
                printf("DEBUG: Found \"#ifdef\" in %s\n", line);
                curr = cfg_pp_node_fill_single(curr, line, (int)lengthOfLine);
            }

            if (strstr(line, "#ifndef")) {
                printf("DEBUG: Found \"ifndef\" in \"%s\"\n", line);
                curr = cfg_pp_node_fill_single(curr, line, (int) lengthOfLine);
            }
            if (strstr(line, "defined") && strstr(line, "#if")) {
                printf("DEBUG: Found \"defined\" in \"%s\"\n", line);
                /* call fill single with each string in array */
                cfg_pp_string_extract_multi(multiOpts, line, (int) lengthOfLine,
                                                                    &optsFound);
                for (i = 0; i < optsFound; i++) {
                    curr = cfg_pp_node_fill_single(curr, multiOpts[i],
                                                   (int) XSTRLEN(multiOpts[i]));
                }
                /* clear out the arrays */
                for (i = 0; i < optsFound; i++) {
                    XMEMSET(multiOpts[i], 0, LONGEST_PP_OPT);
                }
            }
        }

        fclose(currFStream);
        //temp break for testing
//        break;
    }
    if (line)
        free(line);
    closedir(dStream);

#ifdef DEBUG_CFG
    printf("DEBUG: Checking the list\n");
#endif
    cfg_pp_list_iterate(curr);
    cfg_pp_list_free(curr);
    return 0;
}

PP_OPT* cfg_pp_node_fill_single(PP_OPT* curr, char* line, int lSz)
{
    PP_OPT* next;
    int i, j;
    int startPoint = 0;
    int lFlag = 0;
    int duplicateCheck = -1;
    char c_tmp[LONGEST_PP_OPT];
    int breakCheck = KEEP_GOING;

    XMEMSET(c_tmp, 0, LONGEST_PP_OPT);

    cfg_assrt_ne_null(curr, "Called get_pp_macro_single with null argument");

    next = curr->next;

    if (next != NULL) {
        printf("Called get_pp_macro_single with a node that has a next\n");
        cfg_abort();
    }


    next = cfg_pp_node_init(next);;
    cfg_assrt_ne_null(next, "creating next in get_pp_macro_single");

    if (strstr(line, "#ifndef")) {
        while (breakCheck == KEEP_GOING) {
            if (line[startPoint] == HASHTAG) {
                startPoint+=6;
                breakCheck = STOP_GOING;
            }
            startPoint++;
        }
    }

    if (strstr(line, "#ifdef")) {
        while (breakCheck == KEEP_GOING) {
            if (line[startPoint] == HASHTAG) {
                startPoint+=5;
                breakCheck = STOP_GOING;
            }
            startPoint++;
        }
    }

    j = 0;
    for (i = startPoint; i < lSz; i++) {
        if (
             (line[i] >= UPPER_A && line[i] <= UPPER_Z)   /* regex= [A-Z]+ */
            ||
             (line[i] == UNDERSCORE)                      /* regex= TODO:  */
            ||
             (line[i] >= NUM_ZERO && line[i] <= NUM_NINE) /* regex= [0-9]+ */
            ||
             (line[i] >= LOWER_A && line[i] <= LOWER_Z)   /* regex= [a-z]+ */
           ) {

            /* store in temp at first for duplicate check */
            c_tmp[j] = line[i];
            j++;
        }

        if ( (line[i] == NLRET || line[i] == CRET ) ) {
            c_tmp[j] = '\0';
            break;
        }
    }

#ifdef IGNORE_DUPLICATES
    /* get all pre_processor macros regardless of duplicates */
    duplicateCheck = NO_DUP;
#else
    duplicateCheck = cfg_pp_list_check_for_dup(curr, c_tmp);
#endif

    if (duplicateCheck == NO_DUP) {
        for (i = 0; i < XSTRLEN(c_tmp); i++) {
            curr->pp_opt[i] = c_tmp[i];
        }
    } else {
        free(next);
        return curr;
    }

    curr->next = next;
    next->previous = curr;
    return next;
}

void cfg_pp_string_extract_multi(char(*out)[LONGEST_PP_OPT],
                                 char* line, int lSz, int* optsFound)
{
    int i;
    int j = 0;
    int k = 0;
    int breakCheck = KEEP_GOING;

    for (i = 0; i < lSz; i++) {
        if (line[i] == BACKSLASH && (line[i+1] == NLRET || line[i+1] == CRET))
            break;
        if (line[i] == LPARAN) {
            /* special case for "#if (defined(THIS) && !defined(THAT))
             * due to the leading LPARAN */
            if (line[i + 1] == 'd' && line[i+2] == 'e' && line[i+3] == 'f')
                breakCheck = KEEP_GOING;
            else
                breakCheck = STOP_GOING;
        }
        if (breakCheck == KEEP_GOING)
            continue;
        if (
             (line[i] >= UPPER_A && line[i] <= UPPER_Z)   /* regex= [A-Z]+ */
            ||
             (line[i] == UNDERSCORE)                      /* regex= TODO:  */
            ||
             (line[i] >= NUM_ZERO && line[i] <= NUM_NINE) /* regex= [0-9]+ */
            ||
             (line[i] >= LOWER_A && line[i] <= LOWER_Z)   /* regex= [a-z]+ */
           ) {

            /* store in temp at first for duplicate check */
            out[j][k] = line[i];
            k++;
        }

        if (line[i] == RPARAN) {
            *optsFound += 1;
            out[j][k] = '\0';
            k = 0;
            printf("DEBUG: ----> In Multi, found this PP MACRO: %s\n", out[j]);
            breakCheck = KEEP_GOING;
            j++;
        }

        if ( (line[i] == NLRET || line[i] == CRET ) ) {
            break;
        }
    }
}

PP_OPT* cfg_pp_node_init(PP_OPT* in)
{
    if (in == NULL) {
        in = (PP_OPT*) malloc(sizeof(PP_OPT));
        cfg_assrt_ne_null(in, "cfg_pp_node_init");
    }

    in->previous = NULL;
    in->next = NULL;
    XMEMSET(in, 0, LONGEST_PP_OPT);

    return in;
}

/* return the one passed in to keep your place in the list when this
 * is called */
PP_OPT* cfg_pp_list_iterate(PP_OPT* in)
{
    PP_OPT* storeRet = in;
    PP_OPT* curr;
    int nodeC = 0;

    cfg_assrt_ne_null(in->pp_opt, "cfg_pp_list_iterate called with"
                                  " node that has no value\n");

    curr = cfg_pp_list_get_head(in);

    printf("-------------------- LIST -------------------------------------\n");
    while(curr->next != NULL) {
        printf("DEBUG: node %d has value %s\n", nodeC, curr->pp_opt);
        curr = curr->next;
        nodeC++;
    }
    printf("---------------------------------------------------------------\n");

    return storeRet;
}

PP_OPT* cfg_pp_list_get_head(PP_OPT* in)
{
    int counter = 0;

    while (in->previous != NULL) {
        in = in->previous;
        counter++;
#ifdef DEBUG_CFG
        printf("DEBUG: Backed up %d\n", counter);
#endif
    }
    return in;
}

void cfg_pp_list_free(PP_OPT* in)
{
    PP_OPT* curr;
    PP_OPT* tmp;

    curr = cfg_pp_list_get_head(in);
    while (curr != NULL) {
        tmp = curr->next;
        free(curr);
        curr = tmp;
    }
    return;
}

int cfg_pp_list_check_for_dup(PP_OPT* in, char* target)
{
    PP_OPT* curr;

    curr = cfg_pp_list_get_head(in);
    while (curr != NULL) {
        if (XSTRNCMP(curr->pp_opt, target, XSTRLEN(target)) == 0) {
#ifdef DEBUG_CFG
            printf("DEBUG: Found duplicate %s\n", target);
#endif
            return FOUND_DUP;
        }
        curr = curr->next;
    }
    return NO_DUP;
}
