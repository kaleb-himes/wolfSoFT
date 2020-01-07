#!/bin/sh

./run c rsa_pss_pkcs ARM-THUMB=/usr/local/gcc_arm/gcc-arm-none-eabi-7-2017-q4/bin/arm-none-eabi-
./run c rsa_pss_pkcs_sv_ned ARM-THUMB=/usr/local/gcc_arm/gcc-arm-none-eabi-7-2017-q4/bin/arm-none-eabi-
./run c aes_only ARM-THUMB=/usr/local/gcc_arm/gcc-arm-none-eabi-7-2017-q4/bin/arm-none-eabi-
./run c sha256_only ARM-THUMB=/usr/local/gcc_arm/gcc-arm-none-eabi-7-2017-q4/bin/arm-none-eabi-
./run c sha256_ecc ARM-THUMB=/usr/local/gcc_arm/gcc-arm-none-eabi-7-2017-q4/bin/arm-none-eabi-
./run c sha256_ecc_nm ARM-THUMB=/usr/local/gcc_arm/gcc-arm-none-eabi-7-2017-q4/bin/arm-none-eabi-
./run c sha512_only ARM-THUMB=/usr/local/gcc_arm/gcc-arm-none-eabi-7-2017-q4/bin/arm-none-eabi-
./run c ecc_only ARM-THUMB=/usr/local/gcc_arm/gcc-arm-none-eabi-7-2017-q4/bin/arm-none-eabi-
./run c cert_mngr_only ARM-THUMB=/usr/local/gcc_arm/gcc-arm-none-eabi-7-2017-q4/bin/arm-none-eabi-

