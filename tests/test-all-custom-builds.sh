#!/bin/sh

# Must run from wolfSoFT root directory ./tests/test-all-custom-builds.sh
ROOT_DIR=$(eval "pwd")

test_result(){
    if [ $1 -eq 0 ]; then
        printf '\e[32m%s\e[0m\n' "$2 Test Passed"
    else
        printf '\e[31m%s\e[0m\n' "$2 Test Failed"
        exit 1
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

run_custom_toolchain_build(){
    echo "n" | ./run c "$1" "$2"
    cd $1 || exit 5
    if [ -f ./Build/wolfcrypt_test.elf ]; then
        RESULT=0
    else
        RESULT=1
    fi
    cd $ROOT_DIR || exit 6
    test_result $RESULT $1

}

run_dynamic_build(){
    cp ./tested-dynamic-builds/"$1" ./submodule_config_files/dynamic_submodule.conf || exit 1
    ./run d > /dev/null
    cd $ROOT_DIR/dynamic_submodule || exit 5
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
#run_build rsa_pss_pkcs DEFAULT #broken right now


run_custom_toolchain_build rsa_pss_pkcs ARM-THUMB=/usr/local/gcc_arm/gcc-arm-none-eabi-7-2017-q4/bin/arm-none-eabi-


run_dynamic_build FM_ECC_AES_SHA256.conf
run_dynamic_build FM_RSA_AES_SHA256.conf
run_dynamic_build SP_ECC_AES_SHA256.conf
