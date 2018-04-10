#ifndef C_CONF_PP_SPCFC
#define C_CONF_PP_SPCFC

/* a fixed array of C Pre Processor Macros to be ignore if found when scrubbing
 * files for pre-processor macros
 */

#define MOST_PP_IG 50           /* increase as needed */
#define MOST_PP_IG_PARTIALS 50  /* increase as needed */

#define MOST_IGNORES 22
static char ignore_pp_opts[MOST_PP_IG][LONGEST_CONFIG] = {
{"HAVE_CONFIG_H"},      /* 1 */
{"__MACH__"},           /* 2 */
{"__FreeBSD__"},        /* 3 */
{"__linux__"},          /* 4 */
{"max"},                /* 5 */
{"min"},                /* 6 */
{"HAVE_ERRNO_H"},       /* 7 */
{"_WIN32"},             /* 8 */
{"_MSC_VER"},           /* 9 */
{"__sun"},              /* 10 */
{"TRUE"},               /* 11 */
{"FALSE"},              /* 12 */
{"_WIN32_WCE"},         /* 13 */
{"__x86_64__"},         /* 14 */
{"_M_X64"},             /* 15 */
{"__ILP32__"},          /* 16 */
{"__ILP32__1"},         /* 17 */
{"__GNUC__"},           /* 18 */
{"__GNUC__4"},          /* 19 */
{"__clang__"},          /* 20 */
{"__clang_major__3"},   /* 21 */
{"__ELF__"},            /* 22 */
{"__cplusplus"},        /* 23 */
{"__ICCARM__"},         /* 24 */
{"__GNUC_PREREQ"},      /* 25 */
{"43"},                 /* 26 */
{"__thumb__"},          /* 27 */
{"__hpux__"},           /* 28 */
{"__MINGW32__"},        /* 29 */
{"__INTEGRITY"},        /* 30 */
{"__PPU"},              /* 31 */
{"END_OF_IGNORE_PP_OPTS"} /* ALWAYS LAST */
};

static char ignore_pp_opts_partial[MOST_PP_IG_PARTIALS][LONGEST_PP_OPT] = {
{"BUILD_TLS_"},
{"BUILD_WDM_"},
{"END_OF_IGNORE_PP_OPTS"} /* ALWAYS LAST */
};

#endif /* c_CONF_PP_SPCFC */

