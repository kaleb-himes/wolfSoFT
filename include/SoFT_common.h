#ifndef SOFT_COMMON_HDR
#define SOFT_COMMON_HDR

#include <stdio.h>
#include <stdlib.h> /* For system calls */
#include <unistd.h> /* path to working directory */
#include <dirent.h>
#include <stdarg.h> /* to use va_start */
#include <string.h>
#include <SoFT_configs.h>

/*----------------------------------------------------------------------------*/
/* DEFINES */
/*----------------------------------------------------------------------------*/
/* known ascii char hex values for comparison purposes */
#define SOFT_SPACE 0x20      /* self explanitory = ' '  */
#define SOFT_DASH 0x2D       /* self explanitory = '-'  */
#define SOFT_L_BRACKET 0x5B  /* self explanitory = '['  */
#define SOFT_CRET 0xD        /* Carriage Return  = '\r' */
#define SOFT_NLRET 0xA       /* New Line Return  = '\n' */
#define SOFT_UPPER_A 0x41    /* uppercase A      = 'A'  */
#define SOFT_UPPER_Z 0x5A    /* uppercase Z      = 'Z'  */
#define SOFT_LPARAN 0X28     /* Left Parna       = '('  */
#define SOFT_RPARAN 0x29     /* Right Paran      = ')'  */
#define SOFT_UNDERSCORE 0x5F /* Underscore       = '_'  */
#define SOFT_NUM_ZERO   0x30 /* number zero      = '0'  */
#define SOFT_NUM_NINE   0x39 /* number nine      = '9'  */
#define SOFT_LOWER_A    0x61 /* lowercase a      = 'a'  */
#define SOFT_LOWER_Z    0x7A /* lowercase z      = 'z'  */
#define SOFT_HASHTAG    0x23 /* the hashtag      = '#'  */
#define SOFT_BACKSLASH  0x5C /* the escape char  = '\'  */
#define SOFT_UPPER_Y    0x59 /* uppercase Y      = 'Y'  */
#define SOFT_UPPER_N    0x4E /* uppercase N      = 'N'  */
#define SOFT_LOWER_Y    0x79 /* lowercase y      = 'y'  */
#define SOFT_LOWER_N    0x6E /* lowercase n      = 'n'  */

#define SOFT_NO_DUP                  0
#define SOFT_FOUND_DUP               1
#define SOFT_STOP_GOING              1
#define SOFT_KEEP_GOING              0
#define SOFT_SINGLE_CHAR             1
#define SOFT_LONGEST_PATH            4096
#define SOFT_MOST_CONFIGS            200
#define SOFT_MOST_IGNORES            22
#define SOFT_NUM_BINARIES            3
#define SOFT_OPTS_IN_A_LINE          5
#define SOFT_LONGEST_CONFIG          80
#define SOFT_FIRST_POSITION          0
#define SOFT_LONGEST_PP_OPT          100*sizeof(char)
#define SOFT_LONGEST_PP_OPT          100*sizeof(char)
#define SOFT_LONGEST_COMMAND         4096
#define SOFT_CONFIG_NOT_SUPPORTED    256
#define SOFT_LONGEST_LINE            100*sizeof(char)
#define SOFT_MOST_SETTINGS           80
#define SOFT_LARGEST_FILE_LIST       70
#define SOFT_LONGEST_FILE_NAME       150
#define SOFT_USER_INTERRUPT          2
/*----------------------------------------------------------------------------*/
/* ENUMS */
/*----------------------------------------------------------------------------*/
/* errors */
enum {
    FILE_ERR,
    INPUT_ERR
};

/* For use in command line args processing */
enum {
    SOFT_FIRST_INPUT   = 0,
    SOFT_SECOND_INPUT  = 1,
    SOFT_THIRD_INPUT   = 2,
    SOFT_FOURTH_INPUT  = 3,
    SOFT_FIFTH_INPUT   = 4,
    SOFT_SIXTH_INPUT   = 5,
    SOFT_SEVENTH_INPUT = 6,
    SOFT_EIGHTH_INPUT  = 7,
};

/* test cases */
enum {
    SOFT_BUILD_MULTI = 2,
    SOFT_BUILD_SINGLE = 3,
    SOFT_BUILD_CUSTOM = 4
};

/*----------------------------------------------------------------------------*/
/* STRUCTS */
/*----------------------------------------------------------------------------*/

typedef struct D_LINKED_LIST_NODE
{
    struct D_LINKED_LIST_NODE* previous;
    struct D_LINKED_LIST_NODE* next;
    char value[SOFT_LONGEST_PP_OPT];
    int isGood;
} D_LINKED_LIST_NODE;

/*----------------------------------------------------------------------------*/
/* Static strings */
/*----------------------------------------------------------------------------*/


/* a fixed array of options to ignore if found when scrubbing the output
 * of configure help menu
 */
static char ignore_opts[SOFT_MOST_CONFIGS][SOFT_LONGEST_CONFIG] = {
{"jobserver"},              /* 1 */
{"options-checking"},       /* 2 */
{"option-checking"},        /* 3 */
{"FEATURE"},                /* 4 */
{"silent-rules"},           /* 5 */
{"static"},                 /* 6 */
{"shared"},                 /* 7 */
{"fast-install"},           /* 8 */
{"dependency-tracking"},    /* 9 */
{"libtool-lock"},           /* 10 */
{"32bit"},                  /* 11 */
{"leanpsk"},                /* 12 */
{"armasm"},                 /* 13 */
{"xilinx"},                 /* 14 */
{"fips"},                   /* 15 */
{"hashdrbg"},               /* 16 */
{"qsh"},                    /* 17 */
{"fast-rsa"},               /* 18 */
{"mcapi"},                  /* 19 */
{"asynccrypt"},             /* 20 */
{"asyncthreads"},           /* 21 */
};

/*----------------------------------------------------------------------------*/
/* FUNCTIONS */
/*----------------------------------------------------------------------------*/

/*
 * quick one-liner to check a return value
 * @p1 - value returned from function call
 * @p2 - target value to compare against
 * @p3 - msg to print on failure (debug indicator)
 * example: check_ret(value, 0, "my_api_name");
 *          this call will compare value to 0 and if not equal will abort the
 *          program and print the msg: "my_api_name".
 */
void SoFT_check_ret(int, int, char*);
/*
 * @p1 - value returned from function call
 * @p2 - target value to compare against
 * @p3 - msg to print on failure (debug indicator)
 * See notes for check_ret, does same except checks to make sure that
 * p1 is not less than or equal to p2
 */
void SoFT_check_ret_nlte(int, int, char*);

/* assert not null */
void SoFT_assrt_ne_null(void*, char*);

/*
 * aborts the SoFT early
 */
void SoFT_abort(void);

/*
 * A function to zero out a buffer.
 *
 * @p1 - a buffer to zero-out
 * uses XMEMSET to zero a command of SOFT_LONGEST_COMMAND length
 * TODO: needs some sanity checks, could behave badly if called with shorter
 *       buffers.
 */
void SoFT_clear_cmd(char*);
/*
 * A function to build up ANY command with optional parameters
 *
 * @p1 - buffer to store concatenated strings in.
 * @p2 - string to concatenate to end of whatever is in p1. If p1 is empty this
 *       will be the first string in p1.
 *       if p2 is NULL it will be skipped.
 * @p3 - same as p2
 * @p4 - same as p2
 * @p5 - same as p2
 */
void SoFT_build_cmd(char*, char*, char*, char*, char*);
/*
 * A useful way to build up a change to directory command
 *
 * @p1 - buffer to store concatenated strings.
 * @p2 - concat to the string "cd "
 * example: calling build_cd_cmd(buffer, "/Users/uname/wolfssl");
 *          will result in a buffer containing the string:
 *          "cd /Users/uname/wolfssl"
 */
void SoFT_build_cd_cmd(char*, char*);

/*
 * A function to build the name of file + some path to that file.
 *
 * @p1 - buffer to store concatenated strings
 * @p2 - the name of the file without a path
 * @p3 - the path to where the file lives IE path-to-working dir of that file
 *
 * NOTE: This function will zero out p1 unlike build_cmd and build_cd_cmd.
 *
 * example: calling build_fname_cmd(buffer, "/tests/unit.test", $PWD"/wolfssl");
 *          will result in a buffer containing the string:
 *          $PWD"/wolfssl/tests/unit.test"
 */
void SoFT_build_fname_cmd(char*, char*, char*);

/*
 * @p1 - the name of the file to be opened
 * opens the file and uses fseek to get the length. Closes the file and returns
 * the file length.
 *
 * NOTE: include the  path+fname if not in current dir.
 * See also: build_fname_cmd
 */
int SoFT_get_file_size(char*);

/*
 * @p1 - path to cd to before executing the command. If NULL will default to the
 *       directory where this program is executing from and add on "/wolfssl/"
 *       to the end of that current working directory.
 * @p2 - The set of configure options to run, no assumptions are made for the
 *       configure options passed in and there are no sanity checks at this time
 */
int SoFT_run_config_opts(char*, char*);
/*
 * A function for checking the increase footprint size of wolfSSL when
 * configured with p1
 *
 * @p1 - a default baseline to compare against.
 * @p2 - the configure part to test.
 *
 * NOTE: Assumptions are being made about configure options in this function.
 *       Assumption1: configPart contains no leading `-` and no preceeding
 *       enable IE to test --enable-tls13 just pass in the string "tls13".
 */
void SoFT_check_increase(int, char*);
/* same as SoFT_check_increase but for --disable-option */
void SoFT_check_decrease(int, char*);

/*
 * @p1 - a file name to dump the output of "./configure -h"
 * @p2 - a 2D array to hold the configure options identified when reading the
 *       file line by line (p1) to be tested with enable
 * @p3 - same as p2 but to be tested with disable
 *
 * Scrubs the output of "./configure -h" help menu for configure options
 * to test, will pick up new configure options added to wolfSSL
 */
void SoFT_scrub_config_out(char*, char(*)[SOFT_LONGEST_CONFIG],
                          char(*)[SOFT_LONGEST_CONFIG]);

/*
 * Runs the configure options returned by SoFT_scrub_config_out
 */
void SoFT_bench_all_configs(void);

/*
 * @p1 - a String identifying the repo to clone
 *
 * Clones the repository, there are assumptions being made that the repo
 * resides at https://github.com/, will not work against repos hosted on
 * other servers.
 *
 * EXAMPLE: SoFT_clone_target_repo("wolfssl/wolfssl");
 * will clone "https://github.com/wolfssl/wolfssl.git"
 */
void SoFT_clone_target_repo(char*);

/*
 * @p1 - The node to fill in the C Pre Processor macro
 * @p2 - The pre-processor macro to put in the node (p1)
 * @p3 - The length fo the pre-processor macro (p2)
 *
 * A function to populate a single node in a doubly linked list. Each node
 * contains two parts, a pointer to the next node, a pointer to the previous
 * node, and an array to hold the C Pre Processor macro extracted by either
 * SoFT_pp_string_extract_multi or SoFT_pp_string_extract_single
 */
D_LINKED_LIST_NODE* SoFT_d_lnkd_list_node_fill_single(D_LINKED_LIST_NODE*,
                                                      char*, int);

/*
 * PRELUDE to the below API's
 *----------------------------
 * In the C Programming Language there are two constructs for checking if a Pre
 * Processor macro is defined, the first construct is:
 * "#ifdef OPT" or "#ifndef OPT".
 * The above  construct only supports one following pre-processor macro.
 * The other construct is:
 * "#if defined(OPT) [ && / || ] !defined(OPT2)... etc. That construct supports
 * multiple pre-processor macros per line and sometime across multiple lines.
 *----------------------------
 */

/*
 * @p1 - A 2D array for holding the C Pre-Processors extracted from (p2)
 * @p2 - The line to extract Pre Processor Macros from
 * @p3 - The length of p2
 * @p4 - a variable to be updated letting the calling function know how many
 *       Pre Processor Macros were found in p2
 *
 * SoFT_pp_string_extract_multi is for handling lines that contain the key words
 * "defined". It can handle a line with only a single pre-processor
 * macro but it can also handle cases such as:
 * #if defined(THIS) && defined (THAT) \
 *     && !defined(OTHER)
 */
void SoFT_pp_string_extract_multi(char(*)[SOFT_LONGEST_PP_OPT], char*, int,
                                  int*);

/*
 * @p1 - A 2D array for holding the C Pre-Processor extracted from (p2)
 * @p2 - The line to extract the single Pre Processor Macro from
 * @p3 - The length of p2
 *
 * SoFT_pp_string_extract_single is for handling lines that contain the key words
 * "#ifdef" or "#ifndef". It can handle a line with only a single pre-processor
 * macro.
  */
void SoFT_pp_string_extract_single(char(*)[SOFT_LONGEST_PP_OPT], char*, int);

/*
 * @p1 - a node from the doubly linked list to be initialized. Will set the
 * previous to NULL, the next to NULL and zeroize the C Pre-Processor macro
 * array.
 *
 * Will malloc the node if it has not already been malloced.
 *
 * RETURN: a pointer to the newly initialized node.
 *
 * EXAMPLE:
 *          struct D_LINKED_LIST_NODE* myNode = NULL;
 *          myNode = SoFT_pp_init(myNode);
 */
D_LINKED_LIST_NODE* SoFT_d_lnkd_list_node_init(D_LINKED_LIST_NODE*);

/*
 * @p1 - Any node in the doubly linked list
 *
 * This function will use SoFT_d_lnkd_list_get_head to return to the head of the
 * list once at the head this function will then traverse the entirety of the
 * list printing out each pre-processor macro in every node. At the end will
 * also print the number of pre-processor macros contained in the list.
 *
 * RETURN: a pointer to the original node passed in
 *
 * EXAMPLE:
 *          currentNode = SoFT_d_lnkd_list_iterate(currentNode);
 *
 * NOTE: All operations IE backing up to head and iterating over the list are
 *       done with a COPY of the passed in node so the original node never gets
 *       changed. You will retain your place in the list when calling this
 *       function and not getting the return also IE:
 *       SoFT_d_lnkd_list_iterate(currentNode);
 *                                         // no return assignment also retains
 *                                         // your place in the list.
 */
D_LINKED_LIST_NODE* SoFT_d_lnkd_list_iterate(D_LINKED_LIST_NODE*);

/*
 * @p1 - Any node in the doubly linked list
 *
 * As described will back up until the head of the list is found.
 *
 * RETURN: returns a pointer to the head of the list.
 */
D_LINKED_LIST_NODE* SoFT_d_lnkd_list_get_head(D_LINKED_LIST_NODE*);
D_LINKED_LIST_NODE* SoFT_d_lnkd_list_get_next(D_LINKED_LIST_NODE*);
D_LINKED_LIST_NODE* SoFT_d_lnkd_list_get_prev(D_LINKED_LIST_NODE*);

/*
 * @p1 - Any node in the doubly linked list
 *
 * This function will first back up to the head of the list and the traverse
 * the entire list freeing each node it encounters until the tail of the list is
 * free'd
 */
void SoFT_d_lnkd_list_free(D_LINKED_LIST_NODE*);

/*
 * @p1 - Any node in the doubly linked list
 * @p2 - a string containing the C Pre-Processor macro that is being considered
 *       for addition to the list.
 *
 * This function will first back up to the head of the list and traverse the
 * list one node at a time checking if p2 already exists in the list.
 * If a node is found that has the same value as p2 then FOUND_DUP is returned.
 * Otherwise if no node is identified containing the same string the NO_DUP
 * is returned.
 *
 * RETURN: An integer indicating if a duplicate was found or not.
 */
int SoFT_d_lnkd_list_check_for_dup(D_LINKED_LIST_NODE*, char*);

/*
 * @p1 - a string containing the name of a directory or the value NULL
 * @p2 - a string containing the name of a directory or the value NULL
 * @p3 - a string containing the name of a directory or the value NULL
 * @p4 - a string containing the name of a directory or the value NULL
 *
 * This function assumes that the user will NOT call it in an
 * invalid manner. The following are not supported where the word "valid"
 * indicates a valid directory path:
 *
 * SoFT_pp_extract_from_multi_dirs(NULL, valid, NULL, NULL);     // INVALID
 * SoFT_pp_extract_from_multi_dirs(NULL, NULL, valid, NULL);     // INVALID
 * SoFT_pp_extract_from_multi_dirs(NULL, NULL, NULL, valid);     // INVALID
 * SoFT_pp_extract_from_multi_dirs(NULL, valid, valid2, NULL);   // INVALID
 * SoFT_pp_extract_from_multi_dirs(NULL, NULL, valid, valid2);   // INVALID
 * SoFT_pp_extract_from_multi_dirs(NULL, valid, valid2, valid3); // INVALID
 *
 * If called in one of the above ways the NULL directory will fail to open
 * and the SoFT will detect it and abort the program exiting cleanly.
 *
 * The following ARE SUPPORTED and will run as expected:
 *
 * SoFT_pp_extract_from_multi_dirs(valid, NULL, NULL, NULL);       // VALID
 * SoFT_pp_extract_from_multi_dirs(valid, valid2, NULL, NULL);     // VALID
 * SoFT_pp_extract_from_multi_dirs(valid, valid2, valid3, NULL);   // VALID
 * SoFT_pp_extract_from_multi_dirs(valid, valid2, valid3, valid4); // VALID
 */
void SoFT_pp_extract_from_multi_dirs(char*, char*, char*, char*, int, int);
int SoFT_pp_check_ignore(char*);
void SoFT_pp_builder(D_LINKED_LIST_NODE*);
void SoFT_pp_build_test_single(char*);
void SoFT_pp_builder_setup_buildDir(char*, char*);
void SoFT_pp_builder_setup_reqOpts(char*);
void SoFT_pp_print_results(D_LINKED_LIST_NODE*, char*, int);

int SoFT_auto_build_from_file(char*);

void SoFT_do_custom_build(char*, char*);
void SoFT_custom_build_usage(void);
int SoFT_are_we_cloning(void);
void SoFT_setup_traditional(char*);
void SoFT_copy_crypto_hdr(char*, char*, char*);
void SoFT_copy_crypto_src(char*, char*, char*);
void SoFT_copy_tls_hdr(char*, char*, char*);
void SoFT_copy_tls_src(char*, char*, char*);
void SoFT_create_makefile(char*);
void SoFT_create_arm_thumb_makefile(char*, char*);
int SoFT_build_solution(char*, int);
void SoFT_copy_test_app(char*, char*);
void SoFT_create_user_settings(char*);
void SoFT_write_user_settings(char*, char*);
void SoFT_close_user_settings(char*);
FILE* SoFT_open_file_append_mode(char*);
void SoFT_check_fwrite_success(size_t, size_t);
void SoFT_build_aes_only(void);
void SoFT_build_rsa_pss_pkcs(char*, char*);
void SoFT_check_submodule_supported(char* option);
void SoFT_get_submodule_configuration(char*,
                                char*,
                                D_LINKED_LIST_NODE*,
                                D_LINKED_LIST_NODE*,
                                D_LINKED_LIST_NODE*,
                                D_LINKED_LIST_NODE*,
                                D_LINKED_LIST_NODE*);

void SoFT_parse_conf(const char* abortLine, size_t abortLen,
                     D_LINKED_LIST_NODE* fillNode, FILE* fStream);

void SoFT_build_custom_specific(char*, char*,
                               D_LINKED_LIST_NODE*,
                               D_LINKED_LIST_NODE*,
                               D_LINKED_LIST_NODE*,
                               D_LINKED_LIST_NODE*,
                               D_LINKED_LIST_NODE*, char*);

void SoFT_parse_dynamic_conf();
void usage_m(void);
#endif /* SOFT_COMMON_HDR */
