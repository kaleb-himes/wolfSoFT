#ifndef SOFT_BUILDS_H
#define SOFT_BUILDS_H

#include <SoFT_common.h>

#define ARM_THUMB "ARM-THUMB"


static char MakefileBuf[] = "# wolfSSL-custom-makefile-project\n\
#\n\
# Copyright (C) 2006-2018 wolfSSL Inc.\n\
#\n\
# This file is part of wolfSSL.\n\
#\n\
# wolfSSL is free software; you can redistribute it and/or modify\n\
# it under the terms of the GNU General Public License as published by\n\
# the Free Software Foundation; either version 2 of the License, or\n\
# (at your option) any later version.\n\
#\n\
# wolfSSL is distributed in the hope that it will be useful,\n\
# but WITHOUT ANY WARRANTY; without even the implied warranty of\n\
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n\
# GNU General Public License for more details.\n\
#\n\
# You should have received a copy of the GNU General Public License\n\
# along with this program; if not, write to the Free Software\n\
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA\n\
\n\
program_NAME := run\n\
\n\
#                                    wolfssl/src/*.c\n\
#                                     |\n\
#                                     |      wolfssl/wolfcrypt/src/*.c\n\
#                                     |      |\n\
program_C_SRCS_TMP := $(wildcard *.c */*/*.c */*/*/*.c)\n\
#remove misc.c from the buid objects\n\
program_C_SRCS := $(filter-out $(wildcard */*/*/misc.c\\\n\
                    */*/*/asm.c */*/bio.c */*/*/evp.c */*/conf.c\\\n\
                    */*/x509.c),\\\n\
                    $(program_C_SRCS_TMP))\n\
program_C_OBJS := ${program_C_SRCS:.c=.o}\n\
\n\
program_CXX_SRCS := $(wildcard *.cpp)\n\
program_CXX_OBJS := ${program_CXX_SRCS:.cpp=.o}\n\
program_OBJS := $(program_C_OBJS) $(program_CXX_OBJS)\n\
program_INCLUDE_DIRS :=\n\
program_LIBRARY_DIRS :=\n\
program_LIBRARIES :=\n\
\n\
program_INCLUDE_DIRS += ./\n\
program_INCLUDE_DIRS += ./wolfssl/\n\
program_LIBRARIES += pthread\n\
\n\
CPPFLAGS += $(foreach includedir,$(program_INCLUDE_DIRS),-I$(includedir))\n\
CPPFLAGS += -Werror\n\
CPPFLAGS += -Os\n\
CPPFLAGS += -DWOLFSSL_USER_SETTINGS\n\
#CPPFLAGS += -Weverything\n\
#CPPFLAGS += -m32\n\
LDFLAGS += $(foreach librarydir,$(program_LIBRARY_DIRS),-L$(librarydir))\n\
LDFLAGS += $(foreach library,$(program_LIBRARIES),-l$(library))\n\
\n\
.PHONY: all clean distclean\n\
\n\
all: $(program_NAME)\n\
\n\
$(program_NAME): $(program_OBJS)\n\
\t$(LINK.cc) -pthread $(program_OBJS) -o $(program_NAME)\n\
\n\
clean:\n\
\t@- $(RM) $(program_NAME)\n\
\t@- $(RM) $(program_OBJS)\n\
\n\
distclean: clean\n";

#define SOFT_CH  D_LINKED_LIST_NODE** CHdrs
#define SOFT_CS  D_LINKED_LIST_NODE** CSrcs
#define SOFT_TH  D_LINKED_LIST_NODE** THdrs
#define SOFT_TS  D_LINKED_LIST_NODE** TSrcs
#define SOFT_US D_LINKED_LIST_NODE** USettings

void SoFT_add_defaults(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);

/*------------------------------------------------------------------------*/
/* major features */
/*------------------------------------------------------------------------*/

/* DEFAULT RNG */
void SoFT_add_feature_DEFAULT_RNG(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);
void SoFT_remove_feature_DEFAULT_RNG(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);

/* RSA */
void SoFT_add_feature_RSA(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);
void SoFT_remove_feature_RSA(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);

/* ECC */
void SoFT_add_feature_ECC(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);
void SoFT_remove_feature_ECC(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);

/* DH */
void SoFT_add_feature_DH(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);
void SoFT_remove_feature_DH(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);

/* DSA */
void SoFT_add_feature_DSA(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);
void SoFT_remove_feature_DSA(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);

/* PWDBASED */
void SoFT_add_feature_PWDBASED(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);
void SoFT_remove_feature_PWDBASED(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);

/* AES */
void SoFT_add_feature_AES(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);

/* ASN */
void SoFT_add_feature_ASN(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);
void SoFT_remove_feature_ASN(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);

/* DES3 */
void SoFT_add_feature_DES3(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);
void SoFT_remove_feature_DES3(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);

/* RABBIT */
void SoFT_add_feature_RABBIT(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);
void SoFT_remove_feature_RABBIT(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);

/* CHACHA */
void SoFT_add_feature_CHACHA(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);

/* ARC4 / RC4 */
void SoFT_add_feature_ARC4(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);
void SoFT_remove_feature_ARC4(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);

/* MD2 */
void SoFT_add_feature_MD2(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);

/* MD4 */
void SoFT_add_feature_MD4(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);
void SoFT_remove_feature_MD4(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);

/* MD5 */
void SoFT_add_feature_MD5(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);
void SoFT_remove_feature_MD5(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);

/* SHA / SHA1 */
void SoFT_add_feature_SHA1(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);
void SoFT_remove_feature_SHA1(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);

/* HMAC */
void SoFT_add_feature_HMAC(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);
void SoFT_remove_feature_HMAC(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);

/* SHA256 */
void SoFT_add_feature_SHA256(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);
void SoFT_remove_feature_SHA256(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);

/* SHA384 */
void SoFT_add_feature_SHA384(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);

/* SHA512 */
void SoFT_add_feature_SHA512(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);

/* MATHS */
void SoFT_add_feature_FAST_MATH(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);
void SoFT_add_feature_NORMAL_MATH(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);
void SoFT_add_feature_SP_MATH(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);
void SoFT_remove_feature_MATH(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);

/* OLD_TLS */
void SoFT_add_feature_OLD_TLS(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);
void SoFT_remove_feature_OLD_TLS(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);

/* TLS */
void SoFT_add_feature_TLS(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);
void SoFT_remove_feature_TLS(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);

/* SIG WRAPPER */
void SoFT_add_feature_SIG_WRAP(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);
void SoFT_remove_feature_SIG_WRAP(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);

/*------------------------------------------------------------------------*/
/* minor features */
/*------------------------------------------------------------------------*/

/* RSA PSS */
void SoFT_add_feature_RSA_PSS(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);

/* HASH:
 *      NOTE:Non Configurable, default when using a hash algo that requires it
 */
void SoFT_add_feature_HASH(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);
void SoFT_remove_feature_HASH(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);

/* RSA 3072 */
void SoFT_add_feature_RSA_3072(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);

/* RSA 4096 */
void SoFT_add_feature_RSA_4096(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);

/* RSA 8192 */
void SoFT_add_feature_RSA_8192(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);

/* Cert Buffers 2048 */
void SoFT_add_feature_CB2048(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);

/* Cert Buffers 3072 */
void SoFT_add_feature_CB3072(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);

/* Cert Buffers 4096 */
void SoFT_add_feature_CB4096(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);

/* Cert Buffers 256 */
void SoFT_add_feature_CB256(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);

/* CODING */
void SoFT_add_feature_CODING(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);
void SoFT_remove_feature_CODING(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);


void SoFT_add_feature_AES_128(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);
void SoFT_add_feature_AES_192(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);
void SoFT_add_feature_AES_256(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);
void SoFT_add_feature_SP_ASM(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);

/*------------------------------------------------------------------------*/
/* Accelerators */
/*------------------------------------------------------------------------*/

void SoFT_add_feature_AESNI(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US);

/*------------------------------------------------------------------------*/
/* Helpers */
/*------------------------------------------------------------------------*/

int SoFT_check_conf_for_opt(char* checkForOption);
void SoFT_add_crypto_src(SOFT_CS, const char* src);
void SoFT_add_crypto_hdr(SOFT_CH, const char* hdr);
void SoFT_add_tls_src(SOFT_TS, const char* src);
void SoFT_add_tls_hdr(SOFT_TH, const char* hdr);
void SoFT_add_setting(SOFT_US, const char* setting);

#endif /* SOFT_BUILDS_H */
