#!/bin/sh

#make clean && clear && make && echo 'n' | ./run c aes_only DEFAULT
#make clean && clear && make && echo 'n' | ./run c rsa_pss_pkcs DEFAULT
#echo 'n' | ./run c rsa_pss_pkcs_sv_ned DEFAULT
#make clean && clear && make && echo 'n' | ./run c rsa_pss_pkcs_sv_ned DEFAULT
#make clean && clear && make && echo 'n' | ./run c sha256_ecc DEFAULT
#make clean && clear && make && echo 'n' | ./run c sha512_only DEFAULT
#make clean && clear && make && echo 'n' | ./run c ecc_only DEFAULT
#make clean && clear && make && echo 'n' | ./run c sha256_ecc DEFAULT
#make clean && clear && make && echo 'y' | ./run c sha256_only DEFAULT
#make clean && clear && make && echo 'n' | ./run c cert_mngr_only DEFAULT
make clean && clear && make && echo 'n' | ./run c aes_pwdbased DEFAULT
