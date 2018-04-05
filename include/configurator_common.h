#ifndef C_CONF_COMMN
#define C_CONF_COMMN

#include <stdio.h>
#include <stdlib.h> /* For system calls */
#include <unistd.h> /* path to working directory */
#include <regex.h>

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
/*----------------------------------------------------------------------------*/
/* ENUMS */
/*----------------------------------------------------------------------------*/
enum {
    SECOND_WORD          = 1,
    SINGLE_CHAR          = 1,
    LONGEST_PATH         = 4096,
    MOST_CONFIGS         = 200,
    NUM_BINARIES         = 3,
    LONGEST_CONFIG       = 75,
    FIRST_POSITION       = 0,
    LONGEST_COMMAND      = 4096,
    CONFIG_NOT_SUPPORTED = 256,
    LONGEST_PP_OPT       = 50,
};

/* errors */
enum {
    FILE_ERR
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
 * @p1 - a default average size IE baseline to compare against.
 * @p2 - the configure part to test.
 *
 * NOTE: Assumptions are being made about configure options in this function.
 *       Assumption1: configPart contains no leading - and no preceeding enable
 */
void cfg_check_increase(int, char*);
void cfg_check_decrease(int, char*);

void cfg_scrub_config_out(char*, char(*)[LONGEST_CONFIG]);
void cfg_bench_all_configs(void);
void cfg_clone_target_repo(char*);
PP_OPT* cfg_get_pp_macro_single(PP_OPT* curr, char* line, int lSz);
PP_OPT* cfg_init_pp_opt(PP_OPT*);
PP_OPT* cfg_iterate_over_pp_list(PP_OPT* in);
PP_OPT* cfg_backup_to_head(PP_OPT* in);

#endif /* C_CONF_COMMN */
