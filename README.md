Alpha version 0.1

Use provided makefile to build sources.
Execute program with ./run <args>

USAGE:

```
./run m <path-to>/<dir1> <path-to>/<dir2> <path-to>/<dir3> <path-to>/<dir4>
```

NOTE: No trailing slash ```wolfssl/src``` instead of ```wolfssl/src/```

The ```m``` option indicates desire to process "Multiple" directories for C
Pre Processor macros while taking into account duplicates across directories.

DISCLAIMER: There are still some edge cases to smooth out and the regex needs
some work but will get the job done with little manual scrubbing required
afterwards.

EXAMPLE:

```
./run m wolfssl/src wolfssl/wolfcrypt/src wolfssl/wolfssl \
wolfssl/wolfssl/wolfcrypt > pp-out.txt
```

The above would give you all the pre-processor macros found in the directories:

wolfCFG/wolfssl/src

wolfCFG/wolfssl/wolfcrypt/src

wolfCFG/wolfssl/wolfssl/

wolfCFG/wolfssl/wolfssl/wolfcrypt

In addition to just listing the pre-processors found the above also accounts for
duplicates across directories unlike the ```e``` option covered below.

--------------------------------------------------------------------------------

```
./run e <path>/<to>/<dir>
```

NOTE: No trailing slash ```wolfssl/src``` instead of ```wolfssl/src/```

The ```e``` option will extract all the C Pre Processor Macros from all files
found in the directory provided.

DISCLAIMER: There are still some edge cases to work out and the regex
functionality needs improvements but it will get the job done with little manual
scrubbing required afterwards.

EXAMPLE:

```
./run e wolfssl/src > pp-out.txt
./run e wolfssl/wolfcrypt/src >> pp-out.txt
```

The above would give you all the pre-processor macros found in wolfssl/src and
wolfssl/wolfcrypt/src directories.

--------------------------------------------------------------------------------

```
./run b
```
Running with the ```b``` option will will clone, autogen, and configure the
wolfSSL library, use the default configuration as a baseline and compare the
results of various other configurations to try and determine if enabling or
disabling a feature increases or decreases the overall size of the library.
Last it will print the stats found.

More Granular on the configuration benchmark feature:

The benchmark feature  will use the output of the wolfSSL ```./configure -h```
help menu to determine the available configure options. This design is to allow
for future configure options that are added to wolfSSL to be detected
automatically without developer interaction with the wolfCFG code source. There
are some basic rules written for options that are to be ignored, see the static
array ```ignore_opts``` found in wolfCFG/include/configurator_common.h for the
current list of options being ignored, this list unfortunately will require
developer interaction to update.

Program uses a shared library the idea being that as little code gets optimized
out as possible, giving an accurate build impact on footprint.

Intended use: Support gets many questions about how a configuration will impact
footprint. This program will allow Jenkins to crank out some numbers each night
and a support engineer can check the output log to answer customer questions of
this nature.

--------------------------------------------------------------------------------

