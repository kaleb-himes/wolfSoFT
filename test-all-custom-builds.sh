#!/bin/sh

echo 'n' | ./run c aes_only
echo 'n' | ./run c rsa_pss_pkcs
echo 'n' | ./run c rsa_pss_pkcs_sv_ned
echo 'n' | ./run c sha256_ecc
echo 'n' | ./run c sha512_only
echo 'n' | ./run c ecc_only

printf '%s\n' "test aes_only"
./aes_only/run
printf '\n%s\n' "test rsa_pss_pkcs"
./rsa_pss_pkcs/run
printf '\n%s\n' "test rsa_pss_pkcs_sv_ned"
./rsa_pss_pkcs_sv_ned/run
printf '\n%s\n' "test sha256_ecc"
./sha256_ecc/run
printf '\n%s\n' "test sha512_only"
./sha512_only/run
printf '\n%s\n' "test ecc_only"
./ecc_only/run

