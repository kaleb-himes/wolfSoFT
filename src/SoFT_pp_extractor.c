#include <SoFT_common.h>
#include <SoFT_pp_extractor.h>

/* allow up to four dirs for now, switch to more dynamic solution at a later
 * time if necessary or required */
void SoFT_pp_extract_from_multi_dirs(char* tD1, char* tD2, char* tD3, char* tD4,
                                    int numDirs, int runBuilder)
{
    #ifdef DEBUG_SOFT_LINE_COUNT
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
    struct  D_LINKED_LIST_NODE* curr  = NULL;
    struct  dirent* currF = NULL;
    char    cmdArray[SOFT_LONGEST_COMMAND] = {0};
    char    multiOpts[SOFT_OPTS_IN_A_LINE][SOFT_LONGEST_PP_OPT] = {0};

    SoFT_check_ret_nlte(numDirs, 0, "no valid directory strings");

    SoFT_clear_cmd(cmdArray);

    curr = SoFT_d_lnkd_list_node_init(curr);

    fprintf(stderr, "numDirs = %d\n", numDirs);
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
            fprintf(stderr, "Failed to open %s directory\n", targetDir);
            SoFT_abort();
        }

        while ( (currF = readdir(dStream)) ) {
            if (XSTRNCMP(currF->d_name, ".", 1) == 0)
                continue;
            if (XSTRNCMP(currF->d_name, "..", 2) == 0)
                continue;

            if (getcwd(cmdArray, SOFT_LONGEST_PATH) == NULL)
                SoFT_abort();

            SoFT_build_cmd(cmdArray, "/", targetDir, "/", currF->d_name);
            currFStream = fopen(cmdArray, "rb");
    #ifdef DEBUG_SOFT_LINE_COUNT
            fprintf(stderr, "fileName + path = %s\n", cmdArray);
    #endif
            SoFT_clear_cmd(cmdArray);
            SoFT_build_cmd(cmdArray, "Opening ", currF->d_name, " file", NULL);
            SoFT_assrt_ne_null(currFStream, cmdArray);
            SoFT_clear_cmd(cmdArray);
    #ifdef DEBUG_SOFT
            fprintf(stderr, "Successfully opened %s\n", currF->d_name);
    #endif
            while ((read = getline(&line, &lengthOfLine, currFStream)) != -1 ) {

                #ifdef DEBUG_SOFT_LINE_COUNT
                  lineCount++;
                #endif

                if (strstr(line, "#ifdef")) {
                    #ifdef DEBUG_SOFT_LINE_COUNT
                      fprintf(stderr, "lineCount = %d\n", lineCount);
                    #endif

                    SoFT_pp_string_extract_single(multiOpts, line,
                                                 (int) lengthOfLine);

                    shouldAdd = SoFT_pp_check_ignore(multiOpts[0]);

                    if (shouldAdd == 0) {
                #ifdef DEBUG_SOFT_LINE_COUNT
                        fprintf(stderr, "DEBUG: Found \"ifdef\" in \"%s\"\n",
                                line);
                        fprintf(stderr, "Adding %s\n", multiOpts[0]);
                #endif

                        curr = SoFT_d_lnkd_list_node_fill_single(curr, multiOpts[0],
                                                   (int) XSTRLEN(multiOpts[0]));
                    }

                    #ifdef DEBUG_SOFT_CHECK_ITERATE
                      SoFT_d_lnkd_list_iterate(curr);
                    #endif
                }

                if (strstr(line, "#ifndef")) {

                    #ifdef DEBUG_SOFT_LINE_COUNT
                      fprintf(stderr, "lineCount = %d\n", lineCount);
                    #endif

                    SoFT_pp_string_extract_single(multiOpts, line,
                                                 (int) lengthOfLine);

                    shouldAdd = SoFT_pp_check_ignore(multiOpts[0]);

                    if (shouldAdd == 0) {
                #ifdef DEBUG_SOFT_LINE_COUNT
                        fprintf(stderr, "DEBUG: Found \"ifndef\" in \"%s\"\n",
                                line);
                        fprintf(stderr, "Adding %s\n", multiOpts[0]);
                #endif
                        curr = SoFT_d_lnkd_list_node_fill_single(curr, multiOpts[0],
                                                   (int) XSTRLEN(multiOpts[0]));
                    }

                    #ifdef DEBUG_SOFT_CHECK_ITERATE
                      SoFT_d_lnkd_list_iterate(curr);
                    #endif

                }

                /* if (strstr(line, "defined") && strstr(line, "#if")) { */
                /* previously using the above check missed lines such as:
                 * "#if defined(THIS) \
                 *     && !defined(THAT)"
                 * The second line was being skipped.
                 */
                if (strstr(line, "defined")) {

                    #ifdef DEBUG_SOFT_LINE_COUNT
                      fprintf(stderr, "lineCount = %d\n", lineCount);
                    #endif

                    /* call fill single with each string in array */
                    for (i = 0; i < SOFT_OPTS_IN_A_LINE; i++) {
                        XMEMSET(multiOpts[i], 0, sizeof(multiOpts[i]));
                    }

                    SoFT_pp_string_extract_multi(multiOpts, line,
                                                (int) lengthOfLine, &optsFound);
                    for (i = 0; i < optsFound; i++) {
                        shouldAdd = SoFT_pp_check_ignore(multiOpts[i]);
                        if (shouldAdd == 0) {
                    #ifdef DEBUG_SOFT_LINE_COUNT
                            fprintf(stderr, "DEBUG: Found \"defined\" in"
                                    " \"%s\"\n", line);
                            fprintf(stderr, "Adding %s\n", multiOpts[i]);
                    #endif
                            curr = SoFT_d_lnkd_list_node_fill_single(curr, multiOpts[i],
                                                   (int) XSTRLEN(multiOpts[i]));
                        }
                    }
                    /* clear out the arrays */
                    for (i = 0; i < SOFT_OPTS_IN_A_LINE; i++) {
                        XMEMSET(multiOpts[i], 0, sizeof(multiOpts[i]));
                    }
                    /* reset optsFound */
                    optsFound = 0;

                    #ifdef DEBUG_SOFT_CHECK_ITERATE
                      SoFT_d_lnkd_list_iterate(curr);
                    #endif

                }
            } /* end file read while loop */

            #ifdef DEBUG_SOFT_LINE_COUNT
              lineCount = 0;
            #endif

            fclose(currFStream);
        } /* end directory read while loop */

        closedir(dStream);

    } /* end dCounter for loop */

    if (line)
        free(line);

    #ifdef DEBUG_SOFT
      fprintf(stderr, "DEBUG: Checking the list\n");
    #endif



    if (curr != NULL) {
        if (runBuilder == 1) {
            SoFT_pp_builder(curr);
        } else {
            SoFT_d_lnkd_list_iterate(curr);
        }
    }

    SoFT_d_lnkd_list_free(curr);
    return;
}

void SoFT_pp_string_extract_single(char(*out)[SOFT_LONGEST_PP_OPT], char* line,
                                  int lSz)
{
    int i;
    int j = 0;
    int checkForSpaceAfter = 0;


    for (i = 0; i < lSz; i++) {

        if (line[i] == SOFT_NLRET || line[i] == SOFT_CRET) {
            out[0][j] = '\0';
            break;
        }

        if (line[i] == SOFT_SPACE) {
            if (checkForSpaceAfter == 1) {
                out[0][j] = '\0';
                break;
            } else {
                continue;
            }
        }

        if (line[i] == SOFT_HASHTAG && line[i+1] == 'i' && line[i+2] == 'f') {
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

    #ifdef DEBUG_SOFT
      fprintf(stderr, "DEBUG: extract single got %s\n", out[0]);
      fprintf(stderr, "We were processing line: \"%s\"\n", line);
    #endif
}

void SoFT_pp_string_extract_multi(char(*out)[SOFT_LONGEST_PP_OPT],
                                 char* line, int lSz, int* optsFound)
{
    int i;
    int j = 0;
    int k = 0;
    int breakCheck = SOFT_KEEP_GOING;
    int inside_comment = 0;

    for (i = 0; i < lSz; i++) {

        if (line[i] == SOFT_BACKSLASH || line[i] == SOFT_NLRET ||
            line[i] == SOFT_CRET) {
            break;
        }

        if (line[i] == '/' && line[i+1] == '*' && inside_comment == 0)
            inside_comment = 1;
        if (line[i] == '*' && line[i+1] == '/' && inside_comment == 1)
            inside_comment = 0;

        if (line[i] == SOFT_LPARAN) {
            /* special case for "#if (defined(THIS) && !defined(THAT))
             * due to the leading SOFT_LPARAN */
            if (line[i+1] == 'd' && line[i+2] == 'e' && line[i+3] == 'f' &&
                line[i+4] == 'i')
                breakCheck = SOFT_KEEP_GOING;
            /* special case for "( defined(THIS)" where space between leading
             * SOFT_LPARAN and word defined */
            else if (line[i+2] == 'd' && line[i+3] == 'e' && line[i+4] == 'f' &&
                     line[i+5] == 'i')
                breakCheck = SOFT_KEEP_GOING;
            else if (line[i+1] == '!' && line[i+2] == 'd' && line[i+3] == 'e'
                     && line[i+4] == 'f' && line[i+5] == 'i')
                breakCheck = SOFT_KEEP_GOING;
            /* special case to ignore void casts in lines with word defined */
            else if (line[i+1] == 'v' && line[i+2] == 'o' && line[i+3] == 'i' &&
                     line[i+4] == 'd')
                breakCheck = SOFT_KEEP_GOING;
            /* special case for keyword defined inside of comment brackets */
            else if (inside_comment == 1)
                breakCheck = SOFT_KEEP_GOING;
            else
                breakCheck = SOFT_STOP_GOING;
        }

        /* special case for "WOLFSSL_MSG(" blah ... not defined .... blah"); */
        if (line[i] == 'd' && line[i+1] == 'e' && line[i+2] == 'f' &&
            line[i+3] == 'i' && ( line[i+7] != '(' && line[i+8] != '(' ) ) {
            breakCheck = SOFT_KEEP_GOING;
        }

        if (breakCheck == SOFT_KEEP_GOING)
            continue;

        if (
             (line[i] >= SOFT_UPPER_A && line[i] <= SOFT_UPPER_Z)   /* regex= [A-Z]+ */
            ||
             (line[i] == SOFT_UNDERSCORE)                      /* regex= TODO:  */
            ||
             (line[i] >= SOFT_NUM_ZERO &&
              line[i] <= SOFT_NUM_NINE) /* regex= [0-9]+ */
            ||
             (line[i] >= SOFT_LOWER_A && line[i] <= SOFT_LOWER_Z)   /* regex= [a-z]+ */
           ) {

            out[j][k] = line[i];
            k++;
        }

        if (line[i] == SOFT_RPARAN) {
            *optsFound += 1;
            out[j][k] = '\0';

            #ifdef DEBUG_SOFT
              fprintf(stderr, "DEBUG: ----> In Multi, found this PP MACRO: %s"
                      "\n", out[j]);
              fprintf(stderr, "DEBUG: ----> ");
            #endif

            #ifdef DEBUG_SOFT_LVL2
              for (k = 0; k < (int) sizeof(out[j]); k++)
                  fprintf(stderr, "%c", out[j][k]);
              fprintf(stderr, "\n");
            #endif

            k = 0;
            breakCheck = SOFT_KEEP_GOING;
            j++;
        }
    }
}

int SoFT_pp_check_ignore(char* pp_to_check)
{
    int i = 0;
    int lenIn, lenChk, lenCmp;

    lenIn = (int) XSTRLEN(pp_to_check);

    while (XSTRNCMP(END_ALERT, ignore_pp_opts[i], XSTRLEN(END_ALERT)) != 0) {
        lenChk = (int) XSTRLEN(ignore_pp_opts[i]);

        lenCmp = (lenIn < lenChk) ? lenIn : lenChk;

        if (XSTRNCMP(pp_to_check, ignore_pp_opts[i], (size_t) lenCmp) == 0) {
#ifdef DEBUG_SOFT
            fprintf(stderr, "DEBUG: Return 1, %s and %s match\n",
                    pp_to_check, ignore_pp_opts[i]);
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
            fprintf(stderr, "DEBUG: Return 1, %s and %s match\n", pp_to_check,
                    ignore_pp_opts_partial[i]);
            return 1;
        }
        i++;
    }

    return 0;
}

void SoFT_pp_builder(D_LINKED_LIST_NODE* in)
{
    struct D_LINKED_LIST_NODE* curr = NULL;
    struct D_LINKED_LIST_NODE* temp = NULL;

    int i = 0, ret = 0;
    int lenIn, lenChk, lenCmp;
    int skipCheck = 0;
    char c_cmd[SOFT_LONGEST_COMMAND];
    char src[] = "./wolfssl"; /* assume for now TODO: make src user specified */
    char dst[] = "pp_build_dir";
    char* pp_to_check;

    SoFT_clear_cmd(c_cmd);

    SoFT_pp_builder_setup_buildDir(dst, src);

    curr = SoFT_d_lnkd_list_get_head(in);

    /* case 0, single options, test each individually with defaults */
    while (curr->next != NULL && ret != SOFT_USER_INTERRUPT) {

        /* Single setting to test */
        pp_to_check = curr->pp_opt;
        lenIn = (int) XSTRLEN(pp_to_check);

        while (XSTRNCMP(END_ALERT, ignore_pp_opts_single_testing[i],
                        XSTRLEN(END_ALERT)) != 0) {
            lenChk = (int) XSTRLEN(ignore_pp_opts_single_testing[i]);
            lenCmp = (lenIn < lenChk) ? lenIn : lenChk;

            if (XSTRNCMP(pp_to_check, ignore_pp_opts_single_testing[i],
                         (size_t) lenCmp) == 0) {
                fprintf(stderr, "SKIPPING PP MACRO:\"%s\" Logging it for later"
                        " review\n", pp_to_check);
                skipCheck = 1;
                curr->isGood = 2;
                break;
            }
            i++;
        }

        /* reset counter for next check */
        i = 0;

        if (!skipCheck) {
            SoFT_pp_builder_setup_reqOpts(dst);
            SoFT_write_user_settings(dst, curr->pp_opt);
            fprintf(stderr, "Testing %s\n", curr->pp_opt);

/* This is going to repeat, place in a function - Functionize-2 */
            SoFT_close_user_settings(dst);

            /* Build the project */
            ret = SoFT_build_solution(dst, SOFT_BUILD_MULTI);
            if (ret == 0) {
                curr->isGood = 1;
                fprintf(stderr, "%s BUILD PASSED! ... ", curr->pp_opt);
            } else {
                fprintf(stderr, "%s BUILD FAILED!\n", curr->pp_opt);
                curr->isGood = 0;
            }

            if (curr->isGood == 1) {
                SoFT_clear_cmd(c_cmd);
                SoFT_build_cmd(c_cmd, "./", dst, "/run > /dev/null", NULL);

                ret = system(c_cmd);
                if (ret == 0) {
                    fprintf(stderr, "TEST PASSED!\n");
                    curr->isGood = 1;
                } else {
                    fprintf(stderr, "TEST FAILED!\n");
                    curr->isGood = 0;
                }
            }
        }
        skipCheck = 0;
        curr = SoFT_d_lnkd_list_get_next(curr);
    }

    SoFT_pp_print_results(curr, "The following build options were skipped",
                         SKIP_CHK);
    SoFT_pp_print_results(curr, "The following build options failed", FAIL_CHK);
    SoFT_pp_print_results(curr, "The following build options succeeded",
                         SUCC_CHK);

    return;
}

void SoFT_pp_build_test_single(char* testOption)
{
    D_LINKED_LIST_NODE* testOp = NULL;
    int ret;
    char src[] = "./wolfssl";
    char dst[] = "pp_build_dir";
    char c_cmd[SOFT_LONGEST_COMMAND];

    testOp = SoFT_d_lnkd_list_node_init(testOp);
    SoFT_assrt_ne_null(testOp, "testOp is NULL");

    strncpy(testOp->pp_opt, testOption, strlen(testOption));
    fprintf(stderr, "Copied: \"%s\" into testOp->pp_opt\n", testOp->pp_opt);


    SoFT_pp_builder_setup_buildDir(dst, src);
    SoFT_pp_builder_setup_reqOpts(dst);
    SoFT_write_user_settings(dst, testOp->pp_opt);
    SoFT_close_user_settings(dst);

    /* Build the project */
    ret = SoFT_build_solution(dst, SOFT_BUILD_SINGLE);
    if (ret == 0)
        testOp->isGood = 1;
    else {
        fprintf(stderr, "%s caused a failure\n", testOp->pp_opt);
        fprintf(stderr, "Ret val: %d\n", ret);
        testOp->isGood = 0;
    }

    SoFT_clear_cmd(c_cmd);
    if (testOp->isGood == 1) {
        SoFT_build_cmd(c_cmd, "./", dst, "/run ", NULL);

        ret = system(c_cmd);
        if (ret == 0)
            testOp->isGood = 1;
        else {
            fprintf(stderr, "%s caused a failure\n", testOp->pp_opt);
            testOp->isGood = 0;
        }
    }

    SoFT_d_lnkd_list_free(testOp);
    return;
}

void SoFT_pp_builder_setup_buildDir(char* dst, char* src)
{
    char c_cmd[SOFT_LONGEST_COMMAND];
    SoFT_clear_cmd(c_cmd);


    /* setup the directories to reflect traditional */
    SoFT_setup_traditional(dst);

    /* set to a common test app */
    SoFT_build_cmd(c_cmd, "cp ./wolfssl/wolfcrypt/test/test.c", NULL,
                  " SoFT-custom-test-apps/SoFT_custom_test.c", NULL);
    system(c_cmd);
    SoFT_clear_cmd(c_cmd);

    SoFT_copy_test_app(src, dst);

    /* create the project makefile (generic solution) */

    SoFT_create_makefile(dst);

    /* Copy in the crypto headers */
    SoFT_copy_crypto_hdr(src, dst, "copyAll");

    /* Copy in the tls headers */
    SoFT_copy_tls_hdr(src, dst, "copyAll");

    /* Copy in the crypto sources */
    SoFT_copy_crypto_src(src, dst, "copyAll");

    /* Copy in the tls sources */
    SoFT_copy_tls_src(src, dst, "copyAll");

    return;
}

void SoFT_pp_builder_setup_reqOpts(char* dst)
{
    SoFT_create_user_settings(dst);
    /* default settings always on to prevent failure */
    SoFT_write_user_settings(dst, "WC_RSA_BLINDING");
    SoFT_write_user_settings(dst, "TFM_TIMING_RESISTANT");
    SoFT_write_user_settings(dst, "ECC_TIMING_RESISTANT");
    SoFT_write_user_settings(dst, "USE_CERT_BUFFERS_2048");
    SoFT_write_user_settings(dst, "USE_CERT_BUFFERS_256");

    return;
}

void SoFT_pp_print_results(D_LINKED_LIST_NODE* curr, char* msg, int value)
{
    D_LINKED_LIST_NODE* temp;
    int foundOne = 0;

    temp = SoFT_d_lnkd_list_get_head(curr);
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
