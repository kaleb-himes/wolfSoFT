#ifndef CFG_BUILDS_H
#define CFG_BUILDS_H

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
                    */*/*/asm.c),\\\n\
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
CPPFLAGS += -m32\n\
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


#endif /* CFG_BUILDS_H */
