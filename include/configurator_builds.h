#ifndef CFG_BUILDS_H
#define CFG_BUILDS_H

/*----------------------------------------------------------------------------*/
/* Aes Only please */
/*----------------------------------------------------------------------------*/
#define AESO_HNUM 9 /* number of header files */
#define AESO_HLEN 14 /* length to hold the longest of header names + '\0' */
#define AESO_SNUM 2
#define AESO_SLEN 7
static char CFG_AES_ONLY_HEADERS[AESO_HNUM][AESO_HLEN] = {
  {"aes.h"},
  {"error-crypt.h"},
  {"logging.h"},
  {"memory.h"},
  {"misc.h"},
  {"settings.h"},
  {"types.h"},
  {"visibility.h"},
  {"wc_port.h"}
};

static char CFG_AES_ONLY_SRC[AESO_SNUM][AESO_SLEN] = {
  {"aes.c"},
  {"misc.c"}
};


#endif /* CFG_BUILDS_H */
