#include <configurator_common.h>
#include <configurator_pp_extractor.h>

/* allow up to four dirs for now, switch to more dynamic solution at a later
 * time if necessary or required */
void cfg_pp_extract_from_multi_dirs(char* tD1, char* tD2, char* tD3, char* tD4,
                                    int numDirs, int runBuilder)
{
    #ifdef DEBUG_CFG
      int     lineCount     = 0;
    #endif

    int     i, dCounter;
    int     optsFound     = 0;
    int     shouldAdd     = 0;
    ssize_t read          = 0;
    size_t  lengthOfLine  = 0;
    char*   targetDir     = NULL;
    char*   line          = NULL;
    DIR*    dStream       = NULL;
    FILE*   currFStream   = NULL;
    struct  PP_OPT* curr  = NULL;
    struct  dirent* currF = NULL;
    char    cmdArray[LONGEST_COMMAND] = {0};
    char    multiOpts[OPTS_IN_A_LINE][LONGEST_PP_OPT] = {0};

    cfg_check_ret_nlte(numDirs, 0, "no valid directory strings");

    cfg_clear_cmd(cmdArray);

    curr = cfg_pp_node_init(curr);

    printf("numDirs = %d\n", numDirs);
    for (dCounter = 0; dCounter < numDirs; dCounter++) {

        if (dCounter == 0)
            targetDir = tD1;
        else if (dCounter == 1)
            targetDir = tD2;
        else if (dCounter == 2)
            targetDir = tD3;
        else
            targetDir = tD4;

        dStream = opendir(targetDir);
        if (dStream == NULL) {
            printf("Failed to open %s directory\n", targetDir);
            cfg_abort();
        }

        while ( (currF = readdir(dStream)) ) {
            if (XSTRNCMP(currF->d_name, ".", 1) == 0)
                continue;
            if (XSTRNCMP(currF->d_name, "..", 2) == 0)
                continue;

            if (getcwd(cmdArray, LONGEST_PATH) == NULL)
                cfg_abort();

            cfg_build_cmd(cmdArray, "/", targetDir, "/", currF->d_name);
            currFStream = fopen(cmdArray, "rb");
    #ifdef DEBUG_CFG
            printf("fileName + path = %s\n", cmdArray);
    #endif
            cfg_clear_cmd(cmdArray);
            cfg_build_cmd(cmdArray, "Opening ", currF->d_name, " file", NULL);
            cfg_assrt_ne_null(currFStream, cmdArray);
            cfg_clear_cmd(cmdArray);
    #ifdef DEBUG_CFG
            printf("Successfully opened %s\n", currF->d_name);
    #endif
            while ((read = getline(&line, &lengthOfLine, currFStream)) != -1 ) {

                #ifdef DEBUG_CFG
                  lineCount++;
                #endif

                if (strstr(line, "#ifdef")) {
                    #ifdef DEBUG_CFG
                      printf("lineCount = %d\n", lineCount);
                      printf("DEBUG: Found \"#ifdef\" in %s\n", line);
                    #endif

                    cfg_pp_string_extract_single(multiOpts, line,
                                                 (int) lengthOfLine);

                    shouldAdd = cfg_pp_check_ig(multiOpts[0]);

                    if (shouldAdd == 0) {
                        curr = cfg_pp_node_fill_single(curr, multiOpts[0],
                                                   (int) XSTRLEN(multiOpts[0]));
                    } else {
                        shouldAdd = 0;
                    }

                    #ifdef DEBUG_CFG_CHECK_ITERATE
                      cfg_pp_list_iterate(curr);
                    #endif
                }

                if (strstr(line, "#ifndef")) {

                    #ifdef DEBUG_CFG
                      printf("lineCount = %d\n", lineCount);
                      printf("DEBUG: Found \"ifndef\" in \"%s\"\n", line);
                    #endif

                    cfg_pp_string_extract_single(multiOpts, line,
                                                 (int) lengthOfLine);

                    shouldAdd = cfg_pp_check_ig(multiOpts[0]);

                    if (shouldAdd == 0) {
                        curr = cfg_pp_node_fill_single(curr, multiOpts[0],
                                                   (int) XSTRLEN(multiOpts[0]));
                    } else {
                        shouldAdd = 0;
                    }

                    #ifdef DEBUG_CFG_CHECK_ITERATE
                      cfg_pp_list_iterate(curr);
                    #endif

                }

                /* if (strstr(line, "defined") && strstr(line, "#if")) { */
                /* previously using the above check missed lines such as:
                 * "#if defined(THIS) \
                 *     && !defined(THAT)"
                 * The second line was being skipped.
                 */
                if (strstr(line, "defined")) {

                    #ifdef DEBUG_CFG
                      printf("DEBUG: Found \"defined\" in \"%s\"\n", line);
                    #endif

                    /* call fill single with each string in array */
                    for (i = 0; i < OPTS_IN_A_LINE; i++) {
                        XMEMSET(multiOpts[i], 0, sizeof(multiOpts[i]));
                    }

                    cfg_pp_string_extract_multi(multiOpts, line,
                                                (int) lengthOfLine, &optsFound);
                    for (i = 0; i < optsFound; i++) {
                        shouldAdd = cfg_pp_check_ig(multiOpts[i]);
                        if (shouldAdd == 0) {
                            curr = cfg_pp_node_fill_single(curr, multiOpts[i],
                                                   (int) XSTRLEN(multiOpts[i]));
                        } else {
                            shouldAdd = 0;
                        }
                    }
                    /* clear out the arrays */
                    for (i = 0; i < OPTS_IN_A_LINE; i++) {
                        XMEMSET(multiOpts[i], 0, sizeof(multiOpts[i]));
                    }
                    /* reset optsFound */
                    optsFound = 0;

                    #ifdef DEBUG_CFG_CHECK_ITERATE
                      cfg_pp_list_iterate(curr);
                    #endif

                }
            } /* end file read while loop */

            #ifdef DEBUG_CFG
              lineCount = 0;
            #endif

            fclose(currFStream);
        } /* end directory read while loop */

        closedir(dStream);

    } /* end dCounter for loop */

    if (line)
        free(line);

    #ifdef DEBUG_CFG
      printf("DEBUG: Checking the list\n");
    #endif



    if (curr != NULL) {
        if (runBuilder == 1) {
            cfg_pp_builder(curr);
        } else {
            cfg_pp_list_iterate(curr);
        }
    }

    cfg_pp_list_free(curr);
    return;
}

PP_OPT* cfg_pp_node_fill_single(PP_OPT* curr, char* line, int lSz)
{
    struct PP_OPT* next;
    int i;
    int duplicateCheck = -1;
    char c_tmp[LONGEST_PP_OPT];

    XMEMSET(c_tmp, 0, sizeof(c_tmp));

    cfg_assrt_ne_null(curr, "Called get_pp_macro_single with null argument");

    next = curr->next;

    if (next != NULL) {
        printf("Called get_pp_macro_single with a node that has a next\n");
        cfg_abort();
    }

    next = cfg_pp_node_init(next);;
    cfg_assrt_ne_null(next, "creating next in get_pp_macro_single");

    #ifdef IGNORE_DUPLICATES
      /* get all pre_processor macros regardless of duplicates */
      duplicateCheck = NO_DUP;
    #else
      duplicateCheck = cfg_pp_list_check_for_dup(curr, line);
    #endif

    if (duplicateCheck == NO_DUP) {
        for (i = 0; i < lSz; i++) {
            curr->pp_opt[i] = line[i];
        }
    } else {
        free(next);
        return curr;
    }

    curr->next = next;
    next->previous = curr;
    return next;
}

void cfg_pp_string_extract_single(char(*out)[LONGEST_PP_OPT], char* line,
                                  int lSz)
{
    int i;
    int j = 0;
    int checkForSpaceAfter = 0;


    for (i = 0; i < lSz; i++) {

        if (line[i] == NLRET || line[i] == CRET) {
            out[0][j] = '\0';
            break;
        }

        if (line[i] == SPACE) {
            if (checkForSpaceAfter == 1) {
                out[0][j] = '\0';
                break;
            } else {
                continue;
            }
        }

        if (line[i] == HASHTAG && line[i+1] == 'i' && line[i+2] == 'f') {
            XMEMSET(out[0], 0, sizeof(out[0]));
            checkForSpaceAfter = 1;
            if (strstr(line, "#ifdef"))
                i+=6;
            else if (strstr(line, "#ifndef"))
                i+=7;
            continue;
        }

        out[0][j] = line[i];
        j++;
    }

    #ifdef DEBUG_CFG
      printf("DEBUG: extract single got %s\n", out[0]);
      printf("We were processing line: \"%s\"\n", line);
    #endif
}

void cfg_pp_string_extract_multi(char(*out)[LONGEST_PP_OPT],
                                 char* line, int lSz, int* optsFound)
{
    int i;
    int j = 0;
    int k = 0;
    int breakCheck = KEEP_GOING;

    for (i = 0; i < lSz; i++) {

        if (line[i] == BACKSLASH || line[i] == NLRET || line[i] == CRET) {
            break;
        }

        if (line[i] == LPARAN) {
            /* special case for "#if (defined(THIS) && !defined(THAT))
             * due to the leading LPARAN */
            if (line[i+1] == 'd' && line[i+2] == 'e' && line[i+3] == 'f' &&
                line[i+4] == 'i')
                breakCheck = KEEP_GOING;
            else if (line[i+1] == '!' && line[i+2] == 'd' && line[i+3] == 'e'
                     && line[i+4] == 'f' && line[i+5] == 'i')
                breakCheck = KEEP_GOING;
            else
                breakCheck = STOP_GOING;
        }

        /* special case for "WOLFSSL_MSG(" blah ... not defined .... blah"); */
        if (line[i] == 'd' && line[i+1] == 'e' && line[i+2] == 'f' &&
            line[i+3] == 'i' && ( line[i+7] != '(' && line[i+8] != '(' ) ) {
            breakCheck = KEEP_GOING;
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

            out[j][k] = line[i];
            k++;
        }

        if (line[i] == RPARAN) {
            *optsFound += 1;
            out[j][k] = '\0';

            #ifdef DEBUG_CFG
              printf("DEBUG: ----> In Multi, found this PP MACRO: %s\n", out[j]);
              printf("DEBUG: ----> ");
            #endif

            #ifdef DEBUG_CFG_LVL2
              for (k = 0; k < (int) sizeof(out[j]); k++)
                  printf("%c", out[j][k]);
              printf("\n");
            #endif

            k = 0;
            breakCheck = KEEP_GOING;
            j++;
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
    XMEMSET(in->pp_opt, 0, sizeof(in->pp_opt));
    in->isGood = 0;

    return in;
}

/* return the one passed in to keep your place in the list when this
 * is called */
PP_OPT* cfg_pp_list_iterate(PP_OPT* in)
{
    int nodeC = 0;
    struct PP_OPT* curr = NULL;
    struct PP_OPT* storeRet = in;

    cfg_assrt_ne_null(in, "cfg_pp_list_iterate called with null PP_OPT");

    curr = cfg_pp_list_get_head(in);

    printf("-------------------- LIST -------------------------------------\n");

    while(curr->next != NULL) {

        #ifdef DEBUG_CFG_CHECK_ITERATE
            {
                int i;
                printf("--> %p\n", curr);
                if (curr->previous != NULL)
                    printf("\t\t|-->%p\n", curr->previous);
                else
                    printf("\t\t|-->(null)\n");
                if (curr->next != NULL)
                    printf("\t\t|-->%p\n", curr->next);
                else
                    printf("\t\t|-->(null)\n");

                printf("\t\t|-->");
                for (i = 0; i < sizeof(curr->pp_opt); i++)
                    printf("%c", curr->pp_opt[i]);
                printf("\n");
            }
        #endif

        printf("%s\n", curr->pp_opt);

        curr = curr->next;

        if (curr == NULL)
            break;

        nodeC++;
    }

    printf("Total C Pre Processor Macros Identified was: %d\n", nodeC);
    printf("---------------------------------------------------------------\n");

    return storeRet;
}

PP_OPT* cfg_pp_list_get_head(PP_OPT* in)
{
    int counter = 0;

    cfg_assrt_ne_null(in, "cfg_pp_list_get_head called with null PP_OPT");

    if (in->previous == NULL)
        return in;

    while (in->previous != NULL) {

        in = in->previous;
        counter++;
        #ifdef DEBUG_CFG_LVL2
          printf("DEBUG: Backed up %d\n", counter);
        #endif

        if (in == NULL)
            break;
    }

    return in;
}

PP_OPT* cfg_pp_list_get_next(PP_OPT* in) {
    if (in != NULL)
        return in->next;

    return NULL; /* Default if in is NULL */
}

PP_OPT* cfg_pp_list_get_prev(PP_OPT* in) {
    if (in != NULL)
        return in->previous;

    return NULL; /* Default if in is NULL */
}


void cfg_pp_list_free(PP_OPT* in)
{
    struct PP_OPT* curr = NULL;
    struct PP_OPT* tmp = NULL;

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
    struct PP_OPT* curr = NULL;


    curr = cfg_pp_list_get_head(in);

    while (curr != NULL) {

        if (XSTRNCMP(curr->pp_opt, target, XSTRLEN(target)) == 0) {
            return FOUND_DUP;
        }

        curr = curr->next;
    }

    return NO_DUP;
}

int cfg_pp_check_ig(char* pp_to_check)
{
    int i = 0;
    int lenIn, lenChk, lenCmp;

    lenIn = (int) XSTRLEN(pp_to_check);

    while (XSTRNCMP(END_ALERT, ignore_pp_opts[i], XSTRLEN(END_ALERT)) != 0) {
        lenChk = (int) XSTRLEN(ignore_pp_opts[i]);

        lenCmp = (lenIn < lenChk) ? lenIn : lenChk;

        if (XSTRNCMP(pp_to_check, ignore_pp_opts[i], (size_t) lenCmp) == 0) {
#ifdef DEBUG_CFG
            printf("DEBUG: Return 1, %s and %s match\n", pp_to_check, ignore_pp_opts[i]);
#endif
            return 1;
        }

        i++;
    }

    i = 0;

    while (XSTRNCMP(END_ALERT, ignore_pp_opts_partial[i],
                    XSTRLEN(END_ALERT)) != 0) {
        lenChk = (int) XSTRLEN(ignore_pp_opts_partial[i]);
        lenCmp = (lenIn < lenChk) ? lenIn : lenChk;

        if (XSTRNCMP(pp_to_check, ignore_pp_opts_partial[i],
                     (size_t) lenCmp) == 0) {
            printf("DEBUG: Return 1, %s and %s match\n", pp_to_check,
                    ignore_pp_opts_partial[i]);
            return 1;
        }
        i++;
    }

    return 0;
}

void cfg_pp_builder(PP_OPT* in)
{
    struct PP_OPT* curr = NULL;
    struct PP_OPT* temp = NULL;

    int i = 0, ret = 0;
    int lenIn, lenChk, lenCmp;
    int skipCheck = 0;
    char c_cmd[LONGEST_COMMAND];
    char src[] = "./wolfssl"; /* assume for now TODO: make src user specified */
    char dst[] = "pp_build_dir";
    char* pp_to_check;

    cfg_clear_cmd(c_cmd);

    cfg_pp_builder_setup_buildDir(dst, src);

    curr = cfg_pp_list_get_head(in);

    /* case 0, single options, test each individually with defaults */
    while (curr->next != NULL && ret != USER_INTERRUPT) {

        /* Single setting to test */
        pp_to_check = curr->pp_opt;
        lenIn = (int) XSTRLEN(pp_to_check);

        while (XSTRNCMP(END_ALERT, ignore_pp_opts_single_testing[i],
                        XSTRLEN(END_ALERT)) != 0) {
            lenChk = (int) XSTRLEN(ignore_pp_opts_single_testing[i]);
            lenCmp = (lenIn < lenChk) ? lenIn : lenChk;

            if (XSTRNCMP(pp_to_check, ignore_pp_opts_single_testing[i],
                         (size_t) lenCmp) == 0) {
                printf("DEBUG: %s not supported without other options\n"
                       "SKIP!!!\n", pp_to_check);
                skipCheck = 1;
                curr->isGood = 2;
            }
            i++;
        }

        /* reset counter for next check */
        i = 0;

        if (!skipCheck) {
            cfg_pp_builder_setup_reqOpts(dst);
            cfg_write_user_settings(dst, curr->pp_opt);
            fprintf(stderr, "Testing %s\n", curr->pp_opt);

/* This is going to repeat, place in a function - Functionize-2 */
            cfg_close_user_settings(dst);

            /* Build the project */
            ret = cfg_build_solution(dst);
            if (ret == 0)
                curr->isGood = 1;
            else {
                fprintf(stderr, "%s caused a failure\n", curr->pp_opt);
                curr->isGood = 0;
            }

            if (curr->isGood == 1) {
                cfg_build_cmd(c_cmd, "./", dst, "/run ", NULL);

                ret = system(c_cmd);
                if (ret == 0)
                    curr->isGood = 1;
                else {
                    fprintf(stderr, "%s caused a failure\n", curr->pp_opt);
                    curr->isGood = 0;
                }
            }
        }
        skipCheck = 0;
        curr = cfg_pp_list_get_next(curr);
    }

    /* case 1, brute force */
    /* iterate through the list, add one build option at a time */
    /* NEEDS WORK, DISABLED FOR NOW let's just get the singles going at least */

//    while (curr->next != NULL && ret != USER_INTERRUPT) {
//
//        cfg_create_user_settings(dst);
//        cfg_write_user_settings(dst, "WC_RSA_BLINDING");
//        cfg_write_user_settings(dst, "TFM_TIMING_RESISTANT");
//        cfg_write_user_settings(dst, "ECC_TIMING_RESISTANT");
//        cfg_write_user_settings(dst, "USE_CERT_BUFFERS_2048");
//        cfg_write_user_settings(dst, "USE_CERT_BUFFERS_256");
//
//        if (curr != NULL) {
//            temp = cfg_pp_list_get_head(in);
//            while (XSTRNCMP(temp->pp_opt, curr->pp_opt, XSTRLEN(temp->pp_opt))
//                   != 0) {
//
//                if (temp->isGood == 1)
//                    cfg_write_user_settings(dst, temp->pp_opt);
//
//                temp = temp->next;
//            }
//
//            cfg_write_user_settings(dst, curr->pp_opt);
//            fprintf(stderr, "Adding %s to the build settings\n", curr->pp_opt);
//        }
//
//        cfg_close_user_settings(dst);
//
//        /* Build the project */
//        ret = cfg_build_solution(dst);
//        if (ret == 0)
//            curr->isGood = 1;
//        else {
//            fprintf(stderr, "%s caused a failure\n", curr->pp_opt);
//            curr->isGood = 0;
//        }
//
//        if (curr->isGood == 1) {
//            cfg_build_cmd(c_cmd, "./", dst, "/run ", NULL);
//
//            ret = system(c_cmd);
//            if (ret == 0)
//                curr->isGood = 1;
//            else {
//                fprintf(stderr, "%s caused a failure\n", curr->pp_opt);
//                curr->isGood = 0;
//            }
//        }
//
//        curr = cfg_pp_list_get_next(curr);
//    } // End of brute force while loop

    cfg_pp_print_results(curr, "The following build options were skipped",
                         SKIP_CHK);
    cfg_pp_print_results(curr, "The following build options failed", FAIL_CHK);
    cfg_pp_print_results(curr, "The following build options succeeded",
                         SUCC_CHK);
}

void cfg_pp_build_test_single(char* testOption)
{
    PP_OPT* testOp;
    int ret;
    char src[] = "./wolfssl";
    char dst[] = "pp_build_dir";
    char c_cmd[LONGEST_COMMAND];

    testOp = cfg_pp_node_init(testOp);
    cfg_assrt_ne_null(testOp, "testOp is NULL");

    strncpy(testOp->pp_opt, testOption, strlen(testOption));
    printf("Copied: \"%s\" into testOp->pp_opt\n", testOp->pp_opt);


    cfg_pp_builder_setup_buildDir(dst, src);
    cfg_pp_builder_setup_reqOpts(dst);
    cfg_write_user_settings(dst, testOp->pp_opt);
    cfg_close_user_settings(dst);

    /* Build the project */
    ret = cfg_build_solution(dst);
    if (ret == 0)
        testOp->isGood = 1;
    else {
        fprintf(stderr, "%s caused a failure\n", testOp->pp_opt);
        testOp->isGood = 0;
    }

    if (testOp->isGood == 1) {
        cfg_build_cmd(c_cmd, "./", dst, "/run ", NULL);

        ret = system(c_cmd);
        if (ret == 0)
            testOp->isGood = 1;
        else {
            fprintf(stderr, "%s caused a failure\n", testOp->pp_opt);
            testOp->isGood = 0;
        }
    }

    return;
}

void cfg_pp_builder_setup_buildDir(char* dst, char* src)
{
    char c_cmd[LONGEST_COMMAND];
    cfg_clear_cmd(c_cmd);


    /* setup the directories to reflect traditional */
    cfg_setup_traditional(dst);

    /* set to a common test app */
    cfg_build_cmd(c_cmd, "cp ./wolfssl/wolfcrypt/test/test.c", NULL,
                  " cfg-custom-test-apps/cfg_custom_test.c", NULL);
    system(c_cmd);
    cfg_clear_cmd(c_cmd);

    cfg_copy_test_app(src, dst);

    /* create the project makefile (generic solution) */

    cfg_create_makefile(dst);

    /* Copy in the crypto headers */
    cfg_copy_crypto_hdr(src, dst, "copyAll");

    /* Copy in the tls headers */
    cfg_copy_tls_hdr(src, dst, "copyAll");

    /* Copy in the crypto sources */
    cfg_copy_crypto_src(src, dst, "copyAll");

    /* Copy in the tls sources */
    cfg_copy_tls_src(src, dst, "copyAll");

    return;
}

void cfg_pp_builder_setup_reqOpts(char* dst)
{
    cfg_create_user_settings(dst);
    /* default settings always on to prevent failure */
    cfg_write_user_settings(dst, "WC_RSA_BLINDING");
    cfg_write_user_settings(dst, "TFM_TIMING_RESISTANT");
    cfg_write_user_settings(dst, "ECC_TIMING_RESISTANT");
    cfg_write_user_settings(dst, "USE_CERT_BUFFERS_2048");
    cfg_write_user_settings(dst, "USE_CERT_BUFFERS_256");

    return;
}

void cfg_pp_print_results(PP_OPT* curr, char* msg, int value)
{
    PP_OPT* temp;
    int foundOne = 0;

    temp = cfg_pp_list_get_head(curr);
    fprintf(stderr, "-----------------------------------\n");
    fprintf(stderr, "%s\n", msg);
    while (temp->next != NULL) {
        if (temp->isGood == value) {
            fprintf(stderr, "%s\n", temp->pp_opt);
            foundOne++;
        }
        temp = temp->next;
    }
    if (foundOne == 0)
        fprintf(stderr, "** NONE **\n");
    return;
}
