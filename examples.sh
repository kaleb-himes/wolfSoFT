#!/bin/sh

# get c Pre Processor Macros for all four dirs, both source dirs, and both
# header dirs while accounting for duplicates across all four
#---- Uncomment to run #

#./run m wolfssl/src wolfssl/wolfcrypt/src wolfssl/wolfssl wolfssl/wolfssl/wolfcrypt > wolfssl-pp-all.txt

#----#



# do the same as above but ignore duplicates across directories
#---- Uncomment to run #

#./run e wolfssl/src > wolfssl-pp.txt
#./run e wolfssl/wolfcrypt/src >> wolfssl-pp.txt
#./run e wolfssl/wolfssl >> wolfssl-pp.txt
#./run e wolfssl/wolfssl/wolfcrypt >> wolfssl-pp.txt

#----#


# run the benchmarks for all configure options found in ./configure -h output
# with the exception of those in the ignore_opts array found in the header
# "<wolfCFG-root>/include/configurator_common.h"
#---- Uncomment to run #

#./run b

#----#


# create a custom build that only includes a subset of wolfSSL functionality
#
# current custom supported builds are:
# aes_only
#
#---- Uncomment to run #

#./run c aes_only DEFAULT
#./run c rsa_pss_pkcs DEFAULT
#./run c rsa_pss_pkcs_sv_ned DEFAULT
#./run c sha256_ecc DEFAULT
#./run c sha512_only DEFAULT
#./run c ecc_only DEFAULT

#----#
