wolfSoFT - wolf Suite of Frameworks and Tools

Alpha version 0.5

Use provided makefile to build sources.
Execute program with ./run <args>

EVERY option will offer to clone the wolfSSL repository, input Y to clone or N
to avoid clone if a local clone is available for testing. Expected path if local
clone is available is: ```wolfSoFT/wolfssl```

FRAMEWORKS:

\-------------------------------------------------------------------------------
FRAMEWORK 1: Pre Processor Extraction and Testing Tool
\-------------------------------------------------------------------------------


```
./run m ARG2 ARG3 ARG4 ARG5 ARG6 ARG7
```

ARG1 -> m
ARG2 -> valid directory to scrub for pre-processor macros
ARG3 -> valid directory or NULL
ARG4 -> valid directory or NULL
ARG5 -> valid directory or NULL
ARG6 -> number of valid directories from ARGS 2-5
ARG7 -> flag, 0 = dump pp macros, 1 = use pp macros to run buildsExample usages:


NOTE: No trailing slash ```wolfssl/src``` instead of ```wolfssl/src/```

The ```m``` option indicates desire to process "Multiple" directories for C
Pre Processor macros while taking into account duplicates across directories.

DISCLAIMER: There are still some edge cases to smooth out and the regex needs
some work but will get the job done with little manual scrubbing required
afterwards.

EXAMPLE(S):

```
./run m wolfssl/wolfssl NULL NULL NULL 1 0
./run m wolfssl/wolfssl wolfssl/wolfcrypt/src NULL NULL 2 0
./run m wolfssl/wolfssl wolfssl/wolfcrypt/srcwolfssl/src wolfssl/wolfssl/wolfcrypt 4 1
./run m wolfssl/src wolfssl/wolfcrypt/src wolfssl/wolfssl wolfssl/wolfssl/wolfcrypt 4 0 > pp-out.txt
```

The last example above would give you all the pre-processor macros found in the
directories:

wolfSoFT/wolfssl/src

wolfSoFT/wolfssl/wolfcrypt/src

wolfSoFT/wolfssl/wolfssl/

wolfSoFT/wolfssl/wolfssl/wolfcrypt

In addition to just listing the pre-processors found the ```m``` option also
accounts for duplicates across directories unlike the ```e``` option below.

\-------------------------------------------------------------------------------

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

\-------------------------------------------------------------------------------

```
./run s <PP_MACRO>
```

If the ```m``` option reports a failing list of pre-processor (pp)  macros you
can re-test just a single pp macro with the ```s``` option.

EXAMPLE:

```
./run s HAVE_POLY1305
```

\-------------------------------------------------------------------------------
FRAMEWORK 2: Footprint Benchmarking
\-------------------------------------------------------------------------------

```
./run b
```
Running with the ```b``` option will autogen and configure the
wolfSSL library, use the default configuration as a baseline and compare the
results of various other configurations to try and determine if enabling or
disabling a feature increases or decreases the overall size of the library.
Last it will print the stats found.

More Granular on the SoFT benchmark feature:

The benchmark feature  will use the output of the wolfSSL ```./configure -h```
help menu to determine the available configure options. This design is to allow
for future configure options that are added to wolfSSL to be detected
automatically without developer interaction with the wolfSoFT code source. There
are some basic rules written for options that are to be ignored, see the static
array ```ignore_opts``` found in wolfSoFT/include/SoFT_common.h for the
current list of options being ignored, this list unfortunately will require
developer interaction to update.

Program uses a shared library the idea being that as little code gets optimized
out as possible, giving an accurate build impact on footprint.

Intended use: Support gets many questions about how a configuration will impact
footprint. This program will allow Jenkins to crank out some numbers each night
and a support engineer can check the output log to answer customer questions of
this nature.

\-------------------------------------------------------------------------------
FRAMEWORK 3: Building Custom SubModules (of the wolfSSL and wolfCrypt libraries)
\-------------------------------------------------------------------------------

```
./run c <custom build name>
```

The ```c``` option will invoke the custom build api with the <custom build name>
specified. For example if you wish to ONLY build the necessary source files to
get an application that just provides access to the wolfCrypt aes API's and
nothing else you can do: ```./run c aes_only```.

Currently supported custom builds are:

```
aes_only - aes only functionality 128, 192, 256
rsa_pss_pkcs - rsa only with dependencies and pss padding
rsa_pss_pkcs_sv_ned - same as above with sign/verify but no encrypt/decrypt
sha256_ecc - sha256 and ecc functionality w/ fastmath
sha256_ecc_nm - as above with normal math
sha512_only - sha512 only functionality
ecc_only - ecc only with dependencies
sha256_only - sha256 only
cert_manager_only - cert manager functionality and dependencies
```

More builds will be added over time, check back often!

--------------------------------------------------------------------------------
FRAMEWORK 4: Automated testing using Jenkins .txt input files
--------------------------------------------------------------------------------

```
./run a <file name>
```

The ```a``` option is to utilize wolfSSL's auto-tools functionality for testing
purposes. The file provided should contain a list of configurations to be tested
Example provided in wolfSoFT/test-config-input.txt
