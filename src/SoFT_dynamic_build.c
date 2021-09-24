#include <SoFT_common.h>
#include <SoFT_builds.h>


void SoFT_parse_dynamic_conf()
{
    char option[] = "dynamic_submodule";

    char submoduleTestFile [SOFT_LONGEST_FILE_NAME] = "DYNAMIC_TEST";
    char* toolChain = NULL;

    D_LINKED_LIST_NODE* CHdrs       = NULL;
    D_LINKED_LIST_NODE* CSrcs       = NULL;
    D_LINKED_LIST_NODE* THdrs       = NULL;
    D_LINKED_LIST_NODE* TSrcs       = NULL;
    D_LINKED_LIST_NODE* USettings   = NULL;

    CHdrs       = SoFT_d_lnkd_list_node_init(CHdrs);
    CSrcs       = SoFT_d_lnkd_list_node_init(CSrcs);
    THdrs       = SoFT_d_lnkd_list_node_init(THdrs);
    TSrcs       = SoFT_d_lnkd_list_node_init(TSrcs);
    USettings   = SoFT_d_lnkd_list_node_init(USettings);

    /* ToolChain */
    // TODO: Make user configurable
    char tc[] = "DEFAULT";
    toolChain = (char*) malloc(sizeof(char) * 50);
    SoFT_assrt_ne_null(toolChain, "toolChain in SoFT_parse_dynamic_conf");
    memcpy(toolChain, tc, strlen(tc));

    SoFT_add_defaults(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);

/*------------------------------------------------------------------------*/
/* major features */
/*------------------------------------------------------------------------*/
    /* DEFAULT RNG */
    if (SoFT_check_conf_for_opt("ADD_RNG") == 1)
        SoFT_add_feature_DEFAULT_RNG(&CHdrs, &CSrcs, &THdrs, &TSrcs,
                                     &USettings);
    else
        SoFT_remove_feature_DEFAULT_RNG(&CHdrs, &CSrcs, &THdrs, &TSrcs,
                                        &USettings);

    /* RSA */
    if (SoFT_check_conf_for_opt("ADD_RSA") == 1)
        SoFT_add_feature_RSA(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);
    else
        SoFT_remove_feature_RSA(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);

    /* ECC */
    if (SoFT_check_conf_for_opt("ADD_ECC") == 1)
        SoFT_add_feature_ECC(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);
    else
        SoFT_remove_feature_ECC(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);

    /* DH */
    if (SoFT_check_conf_for_opt("ADD_DH") == 1)
        SoFT_add_feature_DH(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);
    else
        SoFT_remove_feature_DH(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);

    /* DSA */
    if (SoFT_check_conf_for_opt("ADD_DSA") == 1)
        SoFT_add_feature_DSA(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);
    else
        SoFT_remove_feature_DSA(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);

    /* PWD_BASED */
    if (SoFT_check_conf_for_opt("ADD_PWDBASED") == 1)
        SoFT_add_feature_PWDBASED(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);
    else
        SoFT_remove_feature_PWDBASED(&CHdrs, &CSrcs, &THdrs, &TSrcs,
                                     &USettings);

    /* AES */
    if (SoFT_check_conf_for_opt("ADD_AES") == 1)
        SoFT_add_feature_AES(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);

    /* DES3 */
    if (SoFT_check_conf_for_opt("ADD_DES3") == 1)
        SoFT_add_feature_DES3(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);
    else
        SoFT_remove_feature_DES3(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);

    /* RABBIT */
    if (SoFT_check_conf_for_opt("ADD_DES3") == 1)
        SoFT_add_feature_RABBIT(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);
    else
        SoFT_remove_feature_RABBIT(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);

    /* CHACHA */
    if (SoFT_check_conf_for_opt("ADD_CHACHA") == 1)
        SoFT_add_feature_CHACHA(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);

    /* ARC4 / RC4 */
    if (SoFT_check_conf_for_opt("ADD_ARC4") == 1 ||
        SoFT_check_conf_for_opt("ADD_RC4") == 1)
        SoFT_add_feature_ARC4(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);
    else
        SoFT_remove_feature_ARC4(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);

    /* MD2 */
    if (SoFT_check_conf_for_opt("ADD_MD2") == 1)
        SoFT_add_feature_MD2(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);

    /* MD4 */
    if (SoFT_check_conf_for_opt("ADD_MD4") == 1)
        SoFT_add_feature_MD4(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);
    else
        SoFT_remove_feature_MD4(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);

    /* MD5 */
    if (SoFT_check_conf_for_opt("ADD_MD5") == 1)
        SoFT_add_feature_MD5(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);
    else
        SoFT_remove_feature_MD5(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);

    /* SHA */
    if (SoFT_check_conf_for_opt("ADD_HASH") == 1)
        SoFT_add_feature_HASH(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);
    else
        SoFT_remove_feature_HASH(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);

    if (SoFT_check_conf_for_opt("ADD_SHA1") == 1 ||
        SoFT_check_conf_for_opt("ADD_SHA") == 1)
        SoFT_add_feature_SHA1(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);
    else
        SoFT_remove_feature_SHA1(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);

    /* HMAC */
    if (SoFT_check_conf_for_opt("ADD_HMAC") == 1)
        SoFT_add_feature_HMAC(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);
    else
        SoFT_remove_feature_HMAC(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);

    /* SHA256 */
    if (SoFT_check_conf_for_opt("ADD_SHA256") == 1)
        SoFT_add_feature_SHA256(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);
    else
        SoFT_remove_feature_SHA256(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);

    if (SoFT_check_conf_for_opt("ADD_SHA384") == 1)
        SoFT_add_feature_SHA384(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);

    if (SoFT_check_conf_for_opt("ADD_SHA512") == 1)
        SoFT_add_feature_SHA512(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);

    /* Maths */
    if (SoFT_check_conf_for_opt("ADD_NORMAL_MATH") == 1)
        SoFT_add_feature_NORMAL_MATH(&CHdrs, &CSrcs, &THdrs, &TSrcs,&USettings);
    else if (SoFT_check_conf_for_opt("ADD_FAST_MATH") == 1)
        SoFT_add_feature_FAST_MATH(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);
    else if (SoFT_check_conf_for_opt("ADD_SP_MATH") == 1)
        SoFT_add_feature_SP_MATH(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);
    else
        SoFT_remove_feature_MATH(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);

    /* TLS */
    if (SoFT_check_conf_for_opt("ADD_OLD_TLS") == 1)
        SoFT_add_feature_OLD_TLS(&CHdrs, &CSrcs, &THdrs, &TSrcs,
                                 &USettings);
    else
        SoFT_remove_feature_OLD_TLS(&CHdrs, &CSrcs, &THdrs, &TSrcs,
                                    &USettings);

    if (SoFT_check_conf_for_opt("ADD_TLS") == 1)
        SoFT_add_feature_TLS(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);
    else
        SoFT_remove_feature_TLS(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);

    /* Signatures */
    if (SoFT_check_conf_for_opt("ADD_SIG_WRAP") == 1)
        SoFT_add_feature_SIG_WRAP(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);
    else
        SoFT_remove_feature_SIG_WRAP(&CHdrs, &CSrcs, &THdrs, &TSrcs,&USettings);

    /* ASN */
    if (SoFT_check_conf_for_opt("ADD_ASN") == 1)
        SoFT_add_feature_ASN(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);
    else
        SoFT_remove_feature_ASN(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);

/*------------------------------------------------------------------------*/
/* minor features */
/*------------------------------------------------------------------------*/
    if (SoFT_check_conf_for_opt("ADD_RSA_PSS") == 1)
        SoFT_add_feature_RSA_PSS(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);
    if (SoFT_check_conf_for_opt("RSA_3072") == 1)
        SoFT_add_feature_RSA_3072(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);
    if (SoFT_check_conf_for_opt("RSA_4096") == 1)
        SoFT_add_feature_RSA_4096(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);
    if (SoFT_check_conf_for_opt("RSA_8192") == 1)
        SoFT_add_feature_RSA_8192(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);
    if (SoFT_check_conf_for_opt("AES_128") == 1)
        SoFT_add_feature_AES_128(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);
    if (SoFT_check_conf_for_opt("AES_192") == 1)
        SoFT_add_feature_AES_192(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);
    if (SoFT_check_conf_for_opt("AES_256") == 1)
        SoFT_add_feature_AES_256(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);
    if (SoFT_check_conf_for_opt("SP_ASM") == 1)
        SoFT_add_feature_SP_ASM(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);
    /* cert buffer sizes */

    if (SoFT_check_conf_for_opt("CB256") == 1)
        SoFT_add_feature_CB256(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);

    if (SoFT_check_conf_for_opt("CB2048") == 1)
        SoFT_add_feature_CB2048(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);

    if (SoFT_check_conf_for_opt("CB3072") == 1)
        SoFT_add_feature_SP_ASM(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);

    if (SoFT_check_conf_for_opt("CB4096") == 1)
        SoFT_add_feature_CB4096(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);

    if (SoFT_check_conf_for_opt("ADD_CODING") == 1)
        SoFT_add_feature_CODING(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);
    else
        SoFT_remove_feature_CODING(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);

/*------------------------------------------------------------------------*/
/* Accelerators */
/*------------------------------------------------------------------------*/

    /* AESNI */
    if (SoFT_check_conf_for_opt("ADD_ASN") == 1)
        SoFT_add_feature_AESNI(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);

/*------------------------------------------------------------------------*/
/* Build the dynamically composed submodule */
/*------------------------------------------------------------------------*/

    SoFT_build_custom_specific(submoduleTestFile, option,
                              CHdrs, CSrcs,
                              THdrs, TSrcs,
                              USettings, toolChain);

    SoFT_d_lnkd_list_free(CHdrs);
    SoFT_d_lnkd_list_free(CSrcs);
    SoFT_d_lnkd_list_free(THdrs);
    SoFT_d_lnkd_list_free(TSrcs);
    SoFT_d_lnkd_list_free(USettings);
    if (toolChain != NULL) {
        free(toolChain);
        toolChain = NULL;
    }

    return;
}

void SoFT_add_defaults(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    SoFT_add_crypto_hdr(CHdrs, "settings.h");
    SoFT_add_crypto_hdr(CHdrs, "visibility.h");
    SoFT_add_crypto_hdr(CHdrs, "wc_port.h");
    SoFT_add_crypto_hdr(CHdrs, "memory.h");
    SoFT_add_crypto_hdr(CHdrs, "types.h");
    SoFT_add_crypto_hdr(CHdrs, "logging.h");
    SoFT_add_crypto_hdr(CHdrs, "error-crypt.h");
    SoFT_add_crypto_hdr(CHdrs, "misc.h");
    /*
     * Begin unnecessary header includes, no sanity checks so have to copy
     * them over 100% of the time anyway :-(
     */
    SoFT_add_crypto_hdr(CHdrs, "asn.h");
    SoFT_add_crypto_hdr(CHdrs, "asn_public.h");
    SoFT_add_crypto_hdr(CHdrs, "arc4.h");
    SoFT_add_crypto_hdr(CHdrs, "md2.h");
    SoFT_add_crypto_hdr(CHdrs, "md4.h");
    SoFT_add_crypto_hdr(CHdrs, "md5.h");
    SoFT_add_crypto_hdr(CHdrs, "sha.h");
    SoFT_add_crypto_hdr(CHdrs, "sha256.h");
    SoFT_add_crypto_hdr(CHdrs, "sha512.h");
    SoFT_add_crypto_hdr(CHdrs, "integer.h");
    SoFT_add_crypto_hdr(CHdrs, "random.h");
    SoFT_add_crypto_hdr(CHdrs, "mpi_class.h");
    SoFT_add_crypto_hdr(CHdrs, "mpi_superclass.h");
    SoFT_add_crypto_hdr(CHdrs, "wolfmath.h");
    SoFT_add_crypto_hdr(CHdrs, "coding.h");
    SoFT_add_crypto_hdr(CHdrs, "signature.h");
    SoFT_add_crypto_hdr(CHdrs, "hash.h");
    SoFT_add_crypto_hdr(CHdrs, "rsa.h");
    SoFT_add_crypto_hdr(CHdrs, "des3.h");
    SoFT_add_crypto_hdr(CHdrs, "chacha.h");
    SoFT_add_crypto_hdr(CHdrs, "chacha20_poly1305.h");
    SoFT_add_crypto_hdr(CHdrs, "poly1305.h");
    SoFT_add_crypto_hdr(CHdrs, "cmac.h");
    SoFT_add_crypto_hdr(CHdrs, "camellia.h");
    SoFT_add_crypto_hdr(CHdrs, "hmac.h");
    SoFT_add_crypto_hdr(CHdrs, "dh.h");
    SoFT_add_crypto_hdr(CHdrs, "dsa.h");
    SoFT_add_crypto_hdr(CHdrs, "srp.h");
    SoFT_add_crypto_hdr(CHdrs, "idea.h");
    SoFT_add_crypto_hdr(CHdrs, "hc128.h");
    SoFT_add_crypto_hdr(CHdrs, "rabbit.h");
    SoFT_add_crypto_hdr(CHdrs, "pwdbased.h");
    SoFT_add_crypto_hdr(CHdrs, "ripemd.h");
    SoFT_add_crypto_hdr(CHdrs, "cpuid.h");

    SoFT_add_crypto_src(CSrcs, "misc.c");
    SoFT_add_crypto_src(CSrcs, "memory.c");
    SoFT_add_crypto_src(CSrcs, "error.c");
    SoFT_add_crypto_src(CSrcs, "logging.c");
    SoFT_add_crypto_src(CSrcs, "wc_port.c");

    SoFT_add_tls_hdr(THdrs, "certs_test.h");
    SoFT_add_tls_hdr(THdrs, "version.h");

    return;
}

/* DEFAULT RNG */
void SoFT_add_feature_DEFAULT_RNG(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    SoFT_add_crypto_hdr(CHdrs, "random.h");
    SoFT_add_crypto_hdr(CHdrs, "sha256.h");
    SoFT_add_crypto_hdr(CHdrs, "hmac.h");

    SoFT_add_crypto_src(CSrcs, "random.c");
    SoFT_add_crypto_src(CSrcs, "sha256.c");
    SoFT_add_crypto_src(CSrcs, "hmac.c");
}

void SoFT_remove_feature_DEFAULT_RNG(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS,
                                     SOFT_US)
{
    SoFT_add_setting(USettings, "WC_NO_RNG");
}

/* RSA */
void SoFT_add_feature_RSA(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    SoFT_add_crypto_hdr(CHdrs, "rsa.h");
    SoFT_add_crypto_src(CSrcs, "rsa.c");
}

void SoFT_remove_feature_RSA(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    SoFT_add_setting(USettings, "NO_RSA");
}

/* ECC */
void SoFT_add_feature_ECC(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    SoFT_add_crypto_hdr(CHdrs, "ecc.h");
    SoFT_add_crypto_src(CSrcs, "ecc.c");
    SoFT_add_setting(USettings, "HAVE_ECC");
}

void SoFT_remove_feature_ECC(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
}

/* DH */
void SoFT_add_feature_DH(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
}

void SoFT_remove_feature_DH(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    SoFT_add_setting(USettings, "NO_DH");
}

/* DSA */
void SoFT_add_feature_DSA(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
}

void SoFT_remove_feature_DSA(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    SoFT_add_setting(USettings, "NO_DSA");
}

/* PWDBASED */
void SoFT_add_feature_PWDBASED(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
}

void SoFT_remove_feature_PWDBASED(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    SoFT_add_setting(USettings, "NO_PWDBASED");
}

/* ASN */
void SoFT_add_feature_ASN(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    SoFT_add_crypto_hdr(CHdrs, "asn.h");
    SoFT_add_crypto_hdr(CHdrs, "asn_public.h");

    SoFT_add_crypto_src(CSrcs, "asn.c");
}

void SoFT_remove_feature_ASN(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    SoFT_add_setting(USettings, "NO_ASN");
}

/* AES */
void SoFT_add_feature_AES(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    SoFT_add_crypto_hdr(CHdrs, "aes.h");
    SoFT_add_crypto_hdr(CHdrs, "wc_encrypt.h");

    SoFT_add_crypto_src(CSrcs, "aes.c");
    SoFT_add_crypto_src(CSrcs, "wc_encrypt.c");
}

/* DES3 */
void SoFT_add_feature_DES3(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{

}
void SoFT_remove_feature_DES3(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    SoFT_add_setting(USettings, "NO_DES3");
}

/* RABBIT */
void SoFT_add_feature_RABBIT(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{

}
void SoFT_remove_feature_RABBIT(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    SoFT_add_setting(USettings, "NO_RABBIT");
}

/* CHACHA */
void SoFT_add_feature_CHACHA(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    SoFT_add_setting(USettings, "HAVE_CHACHA");
}

/* ARC4 / RC4 */
void SoFT_add_feature_ARC4(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
}
void SoFT_remove_feature_ARC4(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    SoFT_add_setting(USettings, "NO_RC4");
}

/* MD2 */
void SoFT_add_feature_MD2(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    SoFT_add_setting(USettings, "WOLFSSL_MD2");
}

/* MD4 */
void SoFT_add_feature_MD4(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{

}
void SoFT_remove_feature_MD4(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    SoFT_add_setting(USettings, "NO_MD4");
}

/* MD5 */
void SoFT_add_feature_MD5(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{

}
void SoFT_remove_feature_MD5(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    SoFT_add_setting(USettings, "NO_MD5");
}

/* SHA / SHA1 */
void SoFT_add_feature_SHA1(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    SoFT_add_crypto_hdr(CHdrs, "sha.h");
}

void SoFT_remove_feature_SHA1(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    SoFT_add_setting(USettings, "NO_SHA");
}

/* HMAC */
void SoFT_add_feature_HMAC(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    SoFT_add_crypto_hdr(CHdrs, "hmac.h");
}

void SoFT_remove_feature_HMAC(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    SoFT_add_setting(USettings, "NO_HMAC");
}

/* SHA256 */
void SoFT_add_feature_SHA256(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    SoFT_add_crypto_hdr(CHdrs, "sha256.h");
}

void SoFT_remove_feature_SHA256(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    SoFT_add_setting(USettings, "NO_SHA256");
}

void SoFT_add_feature_SHA384(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    SoFT_add_crypto_hdr(CHdrs, "sha512.h");
}

void SoFT_add_feature_SHA512(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    SoFT_add_crypto_hdr(CHdrs, "sha512.h");
}

/* FAST MATH */
void SoFT_add_feature_FAST_MATH(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    SoFT_add_crypto_hdr(CHdrs, "tfm.h");
    SoFT_add_crypto_hdr(CHdrs, "wolfmath.h");

    SoFT_add_crypto_src(CSrcs, "tfm.c");
    SoFT_add_crypto_src(CSrcs, "asm.c");
    SoFT_add_crypto_src(CSrcs, "wolfmath.c");

    SoFT_add_setting(USettings, "USE_FAST_MATH");
    SoFT_add_setting(USettings, "WC_RSA_BLINDING");
    SoFT_add_setting(USettings, "TFM_TIMING_RESISTANT");
    SoFT_add_setting(USettings, "ECC_TIMING_RESISTANT");
}

void SoFT_add_feature_NORMAL_MATH(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{

}

void SoFT_add_feature_SP_MATH(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    SoFT_add_crypto_hdr(CHdrs, "sp_int.h");
    SoFT_add_crypto_hdr(CHdrs, "sp.h");
    SoFT_add_crypto_hdr(CHdrs, "integer.h");
    SoFT_add_crypto_hdr(CHdrs, "mpi_class.h");
    SoFT_add_crypto_hdr(CHdrs, "mpi_superclass.h");
    SoFT_add_crypto_hdr(CHdrs, "wolfmath.h");

    SoFT_add_crypto_src(CSrcs, "sp_int.c");
    SoFT_add_crypto_src(CSrcs, "asm.c");
    SoFT_add_crypto_src(CSrcs, "wolfmath.c");
    SoFT_add_crypto_src(CSrcs, "tfm.c");
    SoFT_add_crypto_src(CSrcs, "sp_arm32.c");
    SoFT_add_crypto_src(CSrcs, "sp_arm64.c");
    SoFT_add_crypto_src(CSrcs, "sp_armthumb.c");
    SoFT_add_crypto_src(CSrcs, "sp_c32.c");
    SoFT_add_crypto_src(CSrcs, "sp_c64.c");
    SoFT_add_crypto_src(CSrcs, "sp_cortexm.c");
    SoFT_add_crypto_src(CSrcs, "sp_dsp32.c");
    SoFT_add_crypto_src(CSrcs, "sp_int.c");
    SoFT_add_crypto_src(CSrcs, "sp_x86_64.c");
    SoFT_add_crypto_src(CSrcs, "sp_x86_64_asm.S");

    SoFT_add_setting(USettings, "WOLFSSL_SP");
    SoFT_add_setting(USettings, "WC_RSA_BLINDING");
    SoFT_add_setting(USettings, "TFM_TIMING_RESISTANT");
    SoFT_add_setting(USettings, "ECC_TIMING_RESISTANT");
    SoFT_add_setting(USettings, "WOLFSSL_SP_MATH");
    SoFT_add_setting(USettings, "WOLFSSL_HAVE_SP_RSA");
    SoFT_add_setting(USettings, "WOLFSSL_HAVE_SP_ECC");
    SoFT_add_setting(USettings, "WOLFSSL_HAVE_SP_DH");
}

/* ANY MATH */
void SoFT_remove_feature_MATH(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    SoFT_add_setting(USettings, "NO_BIG_INT");
}

/* OLD_TLS */
void SoFT_add_feature_OLD_TLS(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{

}

void SoFT_remove_feature_OLD_TLS(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    SoFT_add_setting(USettings, "NO_OLD_TLS");
}

/* TLS */
void SoFT_add_feature_TLS(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{

}

void SoFT_remove_feature_TLS(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    SoFT_add_setting(USettings, "WOLFCRYPT_ONLY");
}

/* SIG WRAPPER */
void SoFT_add_feature_SIG_WRAP(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    SoFT_add_crypto_hdr(CHdrs, "signature.h");

    SoFT_add_crypto_src(CSrcs, "signature.c");
}

void SoFT_remove_feature_SIG_WRAP(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    SoFT_add_setting(USettings, "NO_SIG_WRAPPER");
}

/*------------------------------------------------------------------------*/
/* minor features */
/*------------------------------------------------------------------------*/

/* RSA PSS */
void SoFT_add_feature_RSA_PSS(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{

}

/* HASH:
 *      NOTE:Non Configurable, default when using a hash algo that requires it
 */
void SoFT_add_feature_HASH(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    SoFT_add_crypto_hdr(CHdrs, "hash.h");

    SoFT_add_crypto_src(CSrcs, "hash.c");
}

void SoFT_remove_feature_HASH(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    SoFT_add_setting(USettings, "WOLFSSL_NO_HASH");
}

void SoFT_add_feature_RSA_3072(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    // FP_MAX_BITS
}

void SoFT_add_feature_RSA_4096(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    // FP_MAX_BITS
}

void SoFT_add_feature_RSA_8192(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    // FP_MAX_BITS
}

/* Cert buffers 2048 */
void SoFT_add_feature_CB2048(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    SoFT_add_setting(USettings, "USE_CERT_BUFFERS_2048");
}

/* Cert buffers 3072 */
void SoFT_add_feature_CB3072(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    SoFT_add_setting(USettings, "USE_CERT_BUFFERS_3072");
}

/* Cert buffers 4096 */
void SoFT_add_feature_CB4096(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    SoFT_add_setting(USettings, "USE_CERT_BUFFERS_4096");
}

/* Cert buffers 256 */
void SoFT_add_feature_CB256(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    SoFT_add_setting(USettings, "USE_CERT_BUFFERS_256");
}

/* CODING */
void SoFT_add_feature_CODING(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    SoFT_add_crypto_hdr(CHdrs, "coding.h");

    SoFT_add_crypto_src(CSrcs, "coding.c");
}

void SoFT_remove_feature_CODING(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    SoFT_add_setting(USettings, "NO_CODING");
    SoFT_add_setting(USettings, "NO_BIG_INT");
}

/* AES-128 */
void SoFT_add_feature_AES_128(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{

}

void SoFT_add_feature_AES_192(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{

}

void SoFT_add_feature_AES_256(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{

}

void SoFT_add_feature_SP_ASM(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{

}

/* AESNI */
void SoFT_add_feature_AESNI(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    SoFT_add_crypto_hdr(CHdrs, "cpuid.h");

    SoFT_add_crypto_src(CSrcs, "aes_asm.S");
    SoFT_add_crypto_src(CSrcs, "aes_asm.asm");
    SoFT_add_crypto_src(CSrcs, "aes_gcm_asm.S");
}

void SoFT_add_crypto_src(SOFT_CS, const char* src)
{
    int len = (int) strlen(src);
    *CSrcs = SoFT_d_lnkd_list_node_fill_single(*CSrcs, (char*) src, len);
}

void SoFT_add_crypto_hdr(SOFT_CH, const char* hdr)
{
    int len = (int) strlen(hdr);
    *CHdrs = SoFT_d_lnkd_list_node_fill_single(*CHdrs, (char*) hdr, len);
}

void SoFT_add_tls_src(SOFT_TS, const char* src)
{
    int len = (int) strlen(src);
    *TSrcs = SoFT_d_lnkd_list_node_fill_single(*TSrcs, (char*) src, len);
}

void SoFT_add_tls_hdr(SOFT_TH, const char* hdr)
{
    int len = (int) strlen(hdr);
    *THdrs = SoFT_d_lnkd_list_node_fill_single(*THdrs, (char*) hdr, len);
}

void SoFT_add_setting(SOFT_US, const char* setting)
{
    int len = (int) strlen(setting);
    *USettings = SoFT_d_lnkd_list_node_fill_single(*USettings, (char*) setting,
                                                   len);
}


int SoFT_check_conf_for_opt(char* checkForOption)
{
    FILE* fStream = NULL;
    char* fName = "./submodule_config_files/dynamic_submodule.conf";
    char* line = NULL;
    size_t len = 0;
    ssize_t read;
    int i, j;

    fStream = fopen(fName, "rb");
    SoFT_assrt_ne_null(fStream, "SoFT_check_conf_for_opt opening: "
                       "dynamic_submodule.conf");
    while ((read = getline(&line, &len, fStream)) != -1) {

        for (i = 0; i < (int) len; i++) {
            if (line[i] == '\r' || line[i] == '\n')
                line[i] = '\0';
        }

        if (strncmp(line, checkForOption, strlen(checkForOption)) == 0 &&
            strncmp(line, checkForOption, strlen(line)) == 0) {

            fclose(fStream);
            if (line)
                free(line);
            return 1;
        }
    }

    fclose(fStream);
    if (line)
        free(line);
    return 0;
}

