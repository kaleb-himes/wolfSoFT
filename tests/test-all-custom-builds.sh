#!/bin/sh
ROOT_DIR=$(eval "pwd")

test_result(){
    if [ $1 -eq 0 ]; then
        printf '\e[32m%s\e[0m\n' "$2 Test Passed"
    else
        printf '\e[31m%s\e[0m\n' "$2 Test Failed"
    fi
    if [ -d $2 ]; then
        rm -rf $2/
    fi
}

run_build(){
    echo "n" | ./run c "$1" "$2" > /dev/null
    cd $1 || exit 5
    ./run
    RESULT=$?
    cd $ROOT_DIR || exit 6
    test_result $RESULT $1
}

run_build aes_only DEFAULT
run_build aes_pwdbased DEFAULT
run_build cert_manager_only DEFAULT
run_build dsa_only DEFAULT
run_build ecc_only DEFAULT
run_build sha256_ecc DEFAULT
run_build sha256_ecc_nm DEFAULT
run_build sha256_only DEFAULT
run_build sha512_only DEFAULT
run_build rsa_pss_pkcs ARM-THUMB=/usr/local/gcc_arm/gcc-arm-none-eabi-7-2017-q4/bin/arm-none-eabi-


