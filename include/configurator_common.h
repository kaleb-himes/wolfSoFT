#ifndef C_CONF_COMMN
#define C_CONF_COMMN

#include <stdio.h>
#include <stdlib.h> /* For system calls */
#include <unistd.h> /* path to working directory */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include <configurator_configs.h>

/* known ascii char hex values for comparison purposes */
#define SPACE 0x20      /* self explanitory = ' '  */
#define DASH 0x2D       /* self explanitory = '-'  */
#define L_BRACKET 0x5B  /* self explanitory = '['  */
#define CRET 0xD        /* Carriage Return  = '\r' */
#define NLRET 0xA       /* New Line Return  = '\n' */

/* useful enums to avoid magic numbers */
enum {
    LONGEST_PATH = 4096,
    LONGEST_COMMAND = 4096,
    NUM_BINARIES = 3,
    MOST_CONFIGS = 200,
    LONGEST_CONFIG = 75,
    CONFIG_NOT_SUPPORTED = 256,
};

/* errors */
enum {
    FILE_ERR
};

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

void check_ret(int, int, char*);
void check_ret_nlte(int, int, char*);
void configurator_abort(void);

void clear_command(char*);
void build_cmd(char*, char*, char*, char*, char*);
void build_cd_cmd(char*, char*);
void build_fname_cmd(char*, char*, char*);

int get_file_size(char*);

int run_config_opts(char*, char*);
void scrub_config_out(char*, char(*)[LONGEST_CONFIG]);

void check_increase(int, char*);
void check_decrease(int, char*);


#endif /* C_CONF_COMMN */
