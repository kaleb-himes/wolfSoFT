program_NAME := run
program_C_SRCS := $(wildcard src/*.c)
program_CXX_SRCS := $(wildcard src/*.cpp)
program_C_OBJS := ${program_C_SRCS:.c=.o}
program_CXX_OBJS := ${program_CXX_SRCS:.cpp=.o}
program_OBJS := $(program_C_OBJS) $(program_CXX_OBJS)
program_LIBRARIES :=

#program_INCLUDE_DIRS += /usr/local/include
#program_LIBRARY_DIRS += /usr/local/lib
program_INCLUDE_DIRS += ./include
#program_INCLUDE_DIRS += /Users/kalebhimes/work/testDir/wolf-install-dir-for-testing/include
#program_LIBRARY_DIRS += /Users/kalebhimes/work/testDir/wolf-install-dir-for-testing/lib
#program_LIBRARIES += wolfssl

CPPFLAGS += $(foreach includedir,$(program_INCLUDE_DIRS),-I$(includedir))
CPPFLAGS += -Werror
#CPPFLAGS += -Weverything
#CPPFLAGS += -Wsign-conversion
CPPFLAGS += -g
CPPFLAGS += -DEBUG_SOFT
LDFLAGS += $(foreach librarydir,$(program_LIBRARY_DIRS),-L$(librarydir))
LDFLAGS += $(foreach library,$(program_LIBRARIES),-l$(library))

.PHONY: all clean distclean

all: $(program_NAME)

$(program_NAME): $(program_OBJS)
	$(LINK.cc) $(program_OBJS) -o $(program_NAME)
#	$(LINK.cc) -fsanitize=address $(program_OBJS) -o $(program_NAME)

clean:
	@- $(RM) $(program_NAME)
	@- $(RM) $(program_OBJS)

check:
	./run-tests.sh

distclean: clean
