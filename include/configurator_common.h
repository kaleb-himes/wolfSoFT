#ifndef C_CONF_COMMN
#define C_CONF_COMMN

#include <stdio.h>
#include <stdlib.h> /* For system calls */
#include <unistd.h> /* path to working directory */
#include <dirent.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include <configurator_configs.h>

/*----------------------------------------------------------------------------*/
/* DEFINES */
/*----------------------------------------------------------------------------*/
/* known ascii char hex values for comparison purposes */
#define SPACE 0x20      /* self explanitory = ' '  */
#define DASH 0x2D       /* self explanitory = '-'  */
#define L_BRACKET 0x5B  /* self explanitory = '['  */
#define CRET 0xD        /* Carriage Return  = '\r' */
#define NLRET 0xA       /* New Line Return  = '\n' */
#define UPPER_A 0x41    /* uppercase A      = 'A'  */
#define UPPER_Z 0x5A    /* uppercase Z      = 'Z'  */
#define LPARAN 0X28     /* Left Parna       = '('  */
#define RPARAN 0x29     /* Right Paran      = ')'  */
#define UNDERSCORE 0x5F /* Underscore       = '_'  */
#define NUM_ZERO   0x30 /* number zero      = '0'  */
#define NUM_NINE   0x39 /* number nine      = '9'  */
#define LOWER_A    0x61 /* lowercase a      = 'a'  */
#define LOWER_Z    0x7A /* lowercase z      = 'z'  */
#define HASHTAG    0x23 /* the hashtag      = '#'  */
#define BACKSLASH  0x5C /* the escape char  = '\'  */
#define UPPER_Y    0x59 /* uppercase Y      = 'Y'  */
#define UPPER_N    0x4E /* uppercase N      = 'N'  */
#define LOWER_Y    0x79 /* lowercase y      = 'y'  */
#define LOWER_N    0x6E /* lowercase n      = 'n'  */

#define NO_DUP                  0
#define FOUND_DUP               1
#define STOP_GOING              1
#define KEEP_GOING              0
#define SINGLE_CHAR             1
#define LONGEST_PATH            4096
#define MOST_CONFIGS            200
#define NUM_BINARIES            3
#define OPTS_IN_A_LINE          5
#define LONGEST_CONFIG          80
#define FIRST_POSITION          0
#define LONGEST_PP_OPT          80*sizeof(char)
#define LONGEST_COMMAND         4096
#define CONFIG_NOT_SUPPORTED    256
#define LONGEST_LINE            80
/*----------------------------------------------------------------------------*/
/* ENUMS */
/*----------------------------------------------------------------------------*/
/* errors */
enum {
    FILE_ERR,
    INPUT_ERR
};

enum {
    FIRST_INPUT  = 0,
    SECOND_INPUT = 1,
    THIRD_INPUT  = 2,
    FOURTH_INPUT = 3,
    FIFTH_INPUT  = 4,
    SIXTH_INPUT  = 5,
};
/*----------------------------------------------------------------------------*/
/* STRUCTS */
/*----------------------------------------------------------------------------*/

typedef struct PP_OPT
{
    struct PP_OPT* previous;
    struct PP_OPT* next;
    char pp_opt[LONGEST_PP_OPT];
} PP_OPT;

/*----------------------------------------------------------------------------*/
/* Static strings */
/*----------------------------------------------------------------------------*/


/* a fixed array of options to ignore if found when scrubbing the output
 * of configure help menu
 */
#define MOST_IGNORES 22
static char ignore_opts[MOST_CONFIGS][LONGEST_CONFIG] = {
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
void cfg_check_ret(int, int, char*);
/*
 * @p1 - value returned from function call
 * @p2 - target value to compare against
 * @p3 - msg to print on failure (debug indicator)
 * See notes for check_ret, does same except checks to make sure that
 * p1 is not less than or equal to p2
 */
void cfg_check_ret_nlte(int, int, char*);

/* assert not null */
void cfg_assrt_ne_null(void*, char*);

/*
 * aborts the configurator early
 */
void cfg_abort(void);

/*
 * A function to zero out a buffer.
 *
 * @p1 - a buffer to zero-out
 * uses XMEMSET to zero a command of LONGEST_COMMAND length
 * TODO: needs some sanity checks, could behave badly if called with shorter
 *       buffers.
 */
void cfg_clear_cmd(char*);
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
void cfg_build_cmd(char*, char*, char*, char*, char*);
/*
 * A useful way to build up a change to directory command
 *
 * @p1 - buffer to store concatenated strings.
 * @p2 - concat to the string "cd "
 * example: calling build_cd_cmd(buffer, "/Users/uname/wolfssl");
 *          will result in a buffer containing the string:
 *          "cd /Users/uname/wolfssl"
 */
void cfg_build_cd_cmd(char*, char*);

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
void cfg_build_fname_cmd(char*, char*, char*);

/*
 * @p1 - the name of the file to be opened
 * opens the file and uses fseek to get the length. Closes the file and returns
 * the file length.
 *
 * NOTE: include the  path+fname if not in current dir.
 * See also: build_fname_cmd
 */
int cfg_get_file_size(char*);

/*
 * @p1 - path to cd to before executing the command. If NULL will default to the
 *       directory where this program is executing from and add on "/wolfssl/"
 *       to the end of that current working directory.
 * @p2 - The set of configure options to run, no assumptions are made for the
 *       configure options passed in and there are no sanity checks at this time
 */
int cfg_run_config_opts(char*, char*);
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
void cfg_check_increase(int, char*);
/* same as cfg_check_increase but for --disable-option */
void cfg_check_decrease(int, char*);

/*
 * @p1 - a file name to dump the output of "./configure -h"
 * @p2 - a 2D array to hold the configure options identified when reading the
 *       file line by line (p1) to be tested with enable
 * @p3 - same as p2 but to be tested with disable
 *
 * Scrubs the output of "./configure -h" help menu for configure options
 * to test, will pick up new configure options added to wolfSSL
 */
void cfg_scrub_config_out(char*, char(*)[LONGEST_CONFIG],
                          char(*)[LONGEST_CONFIG]);

/*
 * Runs the configure options returned by cfg_scrub_config_out
 */
void cfg_bench_all_configs(void);

/*
 * @p1 - a String identifying the repo to clone
 *
 * Clones the repository, there are assumptions being made that the repo
 * resides at https://github.com/, will not work against repos hosted on
 * other servers.
 *
 * EXAMPLE: cfg_clone_target_repo("wolfssl/wolfssl");
 * will clone "https://github.com/wolfssl/wolfssl.git"
 */
void cfg_clone_target_repo(char*);

/*
 * @p1 - The node to fill in the C Pre Processor macro
 * @p2 - The pre-processor macro to put in the node (p1)
 * @p3 - The length fo the pre-processor macro (p2)
 *
 * A function to populate a single node in a doubly linked list. Each node
 * contains two parts, a pointer to the next node, a pointer to the previous
 * node, and an array to hold the C Pre Processor macro extracted by either
 * cfg_pp_string_extract_multi or cfg_pp_string_extract_single
 */
PP_OPT* cfg_pp_node_fill_single(PP_OPT*, char*, int);

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
 * cfg_pp_string_extract_multi is for handling lines that contain the key words
 * "defined". It can handle a line with only a single pre-processor
 * macro but it can also handle cases such as:
 * #if defined(THIS) && defined (THAT) \
 *     && !defined(OTHER)
 */
void cfg_pp_string_extract_multi(char(*)[LONGEST_PP_OPT], char*, int, int*);

/*
 * @p1 - A 2D array for holding the C Pre-Processor extracted from (p2)
 * @p2 - The line to extract the single Pre Processor Macro from
 * @p3 - The length of p2
 *
 * cfg_pp_string_extract_single is for handling lines that contain the key words
 * "#ifdef" or "#ifndef". It can handle a line with only a single pre-processor
 * macro.
  */
void cfg_pp_string_extract_single(char(*)[LONGEST_PP_OPT], char*, int);

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
 *          struct PP_OPT* myNode = NULL;
 *          myNode = cfg_pp_init(myNode);
 */
PP_OPT* cfg_pp_node_init(PP_OPT*);

/*
 * @p1 - Any node in the doubly linked list
 *
 * This function will use cfg_pp_list_get_head to return to the head of the list
 * once at the head this function will then traverse the entirety of the list
 * printing out each pre-processor macro in every node. At the end will also
 * print the number of pre-processor macros contained in the list.
 *
 * RETURN: a pointer to the original node passed in
 *
 * EXAMPLE:
 *          currentNode = cfg_pp_list_iterate(currentNode);
 *
 * NOTE: All operations IE backing up to head and iterating over the list are
 *       done with a COPY of the passed in node so the original node never gets
 *       changed. You will retain your place in the list when calling this
 *       function and not getting the return also IE:
 *       cfg_pp_list_iterate(currentNode); // no return assignment also retains
 *                                         // your place in the list.
 */
PP_OPT* cfg_pp_list_iterate(PP_OPT*);

/*
 * @p1 - Any node in the doubly linked list
 *
 * As described will back up until the head of the list is found.
 *
 * RETURN: returns a pointer to the head of the list.
 */
PP_OPT* cfg_pp_list_get_head(PP_OPT*);

/*
 * @p1 - Any node in the doubly linked list
 *
 * This function will first back up to the head of the list and the traverse
 * the entire list freeing each node it encounters until the tail of the list is
 * free'd
 */
void cfg_pp_list_free(PP_OPT*);

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
int cfg_pp_list_check_for_dup(PP_OPT*, char*);

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
 * cfg_pp_extract_from_multi_dirs(NULL, valid, NULL, NULL);     // INVALID
 * cfg_pp_extract_from_multi_dirs(NULL, NULL, valid, NULL);     // INVALID
 * cfg_pp_extract_from_multi_dirs(NULL, NULL, NULL, valid);     // INVALID
 * cfg_pp_extract_from_multi_dirs(NULL, valid, valid2, NULL);   // INVALID
 * cfg_pp_extract_from_multi_dirs(NULL, NULL, valid, valid2);   // INVALID
 * cfg_pp_extract_from_multi_dirs(NULL, valid, valid2, valid3); // INVALID
 *
 * If called in one of the above ways the NULL directory will fail to open
 * and the configurator will detect it and abort the program exiting cleanly.
 *
 * The following ARE SUPPORTED and will run as expected:
 *
 * cfg_pp_extract_from_multi_dirs(valid, NULL, NULL, NULL);       // VALID
 * cfg_pp_extract_from_multi_dirs(valid, valid2, NULL, NULL);     // VALID
 * cfg_pp_extract_from_multi_dirs(valid, valid2, valid3, NULL);   // VALID
 * cfg_pp_extract_from_multi_dirs(valid, valid2, valid3, valid4); // VALID
 */
void cfg_pp_extract_from_multi_dirs(char*, char*, char*, char*);


int cfg_pp_check_ig(char*);
void cfg_do_custom_build(char*);
void cfg_custom_build_usage(void);
int cfg_are_we_cloning(void);

#endif /* C_CONF_COMMN */
