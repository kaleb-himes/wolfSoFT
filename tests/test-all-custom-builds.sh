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
    echo "n" | ./run c $1 DEFAULT > /dev/null
    cd $1 || exit 5
    ./run
    RESULT=$?
    cd $ROOT_DIR || exit 6
    test_result $RESULT $1
}

run_build aes_only
run_build aes_pwdbased
run_build cert_manager_only
run_build dsa_only
run_build ecc_only
run_build rsa_pss_pkcs
run_build sha256_ecc
run_build sha256_ecc_nm
run_build sha256_only
run_build sha512_only

