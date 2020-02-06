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
    XMEMCPY(toolChain, tc, XSTRLEN(tc));

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
    if (SoFT_check_conf_for_opt("ADD_SHA1") == 1 ||
        SoFT_check_conf_for_opt("ADD_SHA") == 1)
        SoFT_add_feature_SHA1(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);
    else
        SoFT_remove_feature_SHA1(&CHdrs, &CSrcs, &THdrs, &TSrcs, &USettings);

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
    char headerA[] = "settings.h";
    int  headerALen = (int) XSTRLEN(headerA);
    char headerB[] = "visibility.h";
    int  headerBLen = (int) XSTRLEN(headerB);
    char headerC[] = "version.h";
    int  headerCLen = (int) XSTRLEN(headerC);
    char headerD[] = "wc_port.h";
    int  headerDLen = (int) XSTRLEN(headerD);
    char headerE[] = "memory.h";
    int  headerELen = (int) XSTRLEN(headerE);
    char headerF[] = "types.h";
    int  headerFLen = (int) XSTRLEN(headerF);
    char headerG[] = "logging.h";
    int  headerGLen = (int) XSTRLEN(headerG);
    char headerH[] = "error-crypt.h";
    int  headerHLen = (int) XSTRLEN(headerH);
    char headerI[] = "misc.h";
    int  headerILen = (int) XSTRLEN(headerI);

    char srcA[] = "misc.c";
    int  srcALen = (int) XSTRLEN(srcA);
    char srcB[] = "memory.c";
    int  srcBLen = (int) XSTRLEN(srcB);
    char srcC[] = "error.c";
    int  srcCLen = (int) XSTRLEN(srcC);
    char srcD[] = "logging.c";
    int  srcDLen = (int) XSTRLEN(srcD);
    char srcE[] = "wc_port.c";
    int  srcELen = (int) XSTRLEN(srcE);


    /* Crypto Headers */
    *CHdrs = SoFT_d_lnkd_list_node_fill_single(*CHdrs, headerA, headerALen);
    *CHdrs = SoFT_d_lnkd_list_node_fill_single(*CHdrs, headerB, headerBLen);
    *CHdrs = SoFT_d_lnkd_list_node_fill_single(*CHdrs, headerD, headerDLen);
    *CHdrs = SoFT_d_lnkd_list_node_fill_single(*CHdrs, headerE, headerELen);
    *CHdrs = SoFT_d_lnkd_list_node_fill_single(*CHdrs, headerF, headerFLen);
    *CHdrs = SoFT_d_lnkd_list_node_fill_single(*CHdrs, headerG, headerGLen);
    *CHdrs = SoFT_d_lnkd_list_node_fill_single(*CHdrs, headerH, headerHLen);
    *CHdrs = SoFT_d_lnkd_list_node_fill_single(*CHdrs, headerI, headerILen);

    /* Crypto Srcs */
    *CSrcs = SoFT_d_lnkd_list_node_fill_single(*CSrcs, srcA, srcALen);
    *CSrcs = SoFT_d_lnkd_list_node_fill_single(*CSrcs, srcB, srcBLen);
    *CSrcs = SoFT_d_lnkd_list_node_fill_single(*CSrcs, srcC, srcCLen);
    *CSrcs = SoFT_d_lnkd_list_node_fill_single(*CSrcs, srcD, srcDLen);
    *CSrcs = SoFT_d_lnkd_list_node_fill_single(*CSrcs, srcE, srcELen);

    /* TLS Headers */
    *THdrs = SoFT_d_lnkd_list_node_fill_single(*THdrs, headerC, headerCLen);
    return;
}

/* DEFAULT RNG */
void SoFT_add_feature_DEFAULT_RNG(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    char headerA[] = "random.h";
    int  headerALen = (int) XSTRLEN(headerA);
    char headerB[] = "sha256.h";
    int  headerBLen = (int) XSTRLEN(headerB);
    char headerC[] = "hmac.h";
    int  headerCLen = (int) XSTRLEN(headerC);

    char srcA[] = "random.c";
    int  srcALen = (int) XSTRLEN(srcA);
    char srcB[] = "sha256.c";
    int  srcBLen = (int) XSTRLEN(srcB);
    char srcC[] = "hmac.c";
    int  srcCLen = (int) XSTRLEN(srcC);

    *CHdrs = SoFT_d_lnkd_list_node_fill_single(*CHdrs, headerA, headerALen);
    *CHdrs = SoFT_d_lnkd_list_node_fill_single(*CHdrs, headerB, headerBLen);
    *CHdrs = SoFT_d_lnkd_list_node_fill_single(*CHdrs, headerC, headerCLen);

    *CSrcs = SoFT_d_lnkd_list_node_fill_single(*CSrcs, srcA, srcALen);
    *CSrcs = SoFT_d_lnkd_list_node_fill_single(*CSrcs, srcB, srcBLen);
    *CSrcs = SoFT_d_lnkd_list_node_fill_single(*CSrcs, srcC, srcCLen);
}

void SoFT_remove_feature_DEFAULT_RNG(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS,
                                     SOFT_US)
{
    char optA[] = "WC_NO_RNG";
    int  optALen = (int) XSTRLEN(optA);

    *USettings = SoFT_d_lnkd_list_node_fill_single(*USettings, optA, optALen);

}

/* RSA */
void SoFT_add_feature_RSA(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    char headerA[] = "rsa.h";
    int  headerALen = (int) XSTRLEN(headerA);

    char srcA[] = "rsa.c";
    int  srcALen = (int) XSTRLEN(srcA);

    char tHeaderA[] = "certs_test.h";
    int  tHeaderALen = (int) XSTRLEN(tHeaderA);

    *CHdrs = SoFT_d_lnkd_list_node_fill_single(*CHdrs, headerA, headerALen);

    *CSrcs = SoFT_d_lnkd_list_node_fill_single(*CSrcs, srcA, srcALen);

    *THdrs = SoFT_d_lnkd_list_node_fill_single(*THdrs, tHeaderA, tHeaderALen);
}

void SoFT_remove_feature_RSA(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    char optA[] = "NO_RSA";
    int  optALen = (int) XSTRLEN(optA);

    *USettings = SoFT_d_lnkd_list_node_fill_single(*USettings, optA, optALen);
}

/* ECC */
void SoFT_add_feature_ECC(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    char headerA[] = "ecc.h";
    int  headerALen = (int) XSTRLEN(headerA);

    char srcA[] = "ecc.c";
    int  srcALen = (int) XSTRLEN(srcA);

    char optA[] = "HAVE_ECC";
    int  optALen = (int) XSTRLEN(optA);


    *CHdrs = SoFT_d_lnkd_list_node_fill_single(*CHdrs, headerA, headerALen);

    *CSrcs = SoFT_d_lnkd_list_node_fill_single(*CSrcs, srcA, srcALen);

    *USettings = SoFT_d_lnkd_list_node_fill_single(*USettings, optA, optALen);
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
    char optA[] = "NO_DH";
    int  optALen = (int) XSTRLEN(optA);

    *USettings = SoFT_d_lnkd_list_node_fill_single(*USettings, optA, optALen);
}

/* DSA */
void SoFT_add_feature_DSA(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
}

void SoFT_remove_feature_DSA(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    char optA[] = "NO_DSA";
    int  optALen = (int) XSTRLEN(optA);

    *USettings = SoFT_d_lnkd_list_node_fill_single(*USettings, optA, optALen);
}

/* PWDBASED */
void SoFT_add_feature_PWDBASED(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    SoFT_add_feature_HASH(CHdrs, CSrcs, THdrs, TSrcs, USettings);
}

void SoFT_remove_feature_PWDBASED(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    char optA[] = "NO_PWDBASED";
    int  optALen = (int) XSTRLEN(optA);

    *USettings = SoFT_d_lnkd_list_node_fill_single(*USettings, optA, optALen);
}

/* ASN */
void SoFT_add_feature_ASN(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    char headerA[] = "asn.h";
    int  headerALen = (int) XSTRLEN(headerA);
    char headerB[] = "asn_public.h";
    int  headerBLen = (int) XSTRLEN(headerB);
    char headerC[] = "coding.h";
    int  headerCLen = (int) XSTRLEN(headerC);

    char srcA[] = "asn.c";
    int  srcALen = (int) XSTRLEN(srcA);
    char srcB[] = "coding.c";
    int  srcBLen = (int) XSTRLEN(srcB);

    char tHeaderA[] = "certs_test.h";
    int  tHeaderALen = (int) XSTRLEN(tHeaderA);


    *CHdrs = SoFT_d_lnkd_list_node_fill_single(*CHdrs, headerA, headerALen);
    *CHdrs = SoFT_d_lnkd_list_node_fill_single(*CHdrs, headerB, headerBLen);
    *CHdrs = SoFT_d_lnkd_list_node_fill_single(*CHdrs, headerC, headerCLen);

    *CSrcs = SoFT_d_lnkd_list_node_fill_single(*CSrcs, srcA, srcALen);
    *CSrcs = SoFT_d_lnkd_list_node_fill_single(*CSrcs, srcB, srcBLen);

    *THdrs = SoFT_d_lnkd_list_node_fill_single(*THdrs, tHeaderA, tHeaderALen);
}

void SoFT_remove_feature_ASN(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    char optA[] = "NO_ASN";
    int  optALen = (int) XSTRLEN(optA);

    *USettings = SoFT_d_lnkd_list_node_fill_single(*USettings, optA, optALen);
}

/* AES */
void SoFT_add_feature_AES(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    char headerA[] = "aes.h";
    int  headerALen = (int) XSTRLEN(headerA);
    char headerB[] = "wc_encrypt.h";
    int  headerBLen = (int) XSTRLEN(headerB);

    char srcA[] = "aes.c";
    int srcALen = (int) XSTRLEN(srcA);
    char srcB[] = "wc_encrypt.c";
    int srcBLen = (int) XSTRLEN(srcB);

    *CHdrs = SoFT_d_lnkd_list_node_fill_single(*CHdrs, headerA, headerALen);
    *CHdrs = SoFT_d_lnkd_list_node_fill_single(*CHdrs, headerB, headerBLen);

    *CSrcs = SoFT_d_lnkd_list_node_fill_single(*CSrcs, srcA, srcALen);
    *CSrcs = SoFT_d_lnkd_list_node_fill_single(*CSrcs, srcB, srcBLen);

}

/* DES3 */
void SoFT_add_feature_DES3(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{

}
void SoFT_remove_feature_DES3(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    char optA[] = "NO_DES3";
    int  optALen = (int) XSTRLEN(optA);

    *USettings = SoFT_d_lnkd_list_node_fill_single(*USettings, optA, optALen);
}

/* RABBIT */
void SoFT_add_feature_RABBIT(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{

}
void SoFT_remove_feature_RABBIT(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    char optA[] = "NO_RABBIT";
    int  optALen = (int) XSTRLEN(optA);

    *USettings = SoFT_d_lnkd_list_node_fill_single(*USettings, optA, optALen);
}

/* CHACHA */
void SoFT_add_feature_CHACHA(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    char optA[] = "HAVE_CHACHA";
    int  optALen = (int) XSTRLEN(optA);

    *USettings = SoFT_d_lnkd_list_node_fill_single(*USettings, optA, optALen);

}

/* ARC4 / RC4 */
void SoFT_add_feature_ARC4(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
}
void SoFT_remove_feature_ARC4(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    char optA[] = "NO_RC4";
    int  optALen = (int) XSTRLEN(optA);

    *USettings = SoFT_d_lnkd_list_node_fill_single(*USettings, optA, optALen);
}

/* MD2 */
void SoFT_add_feature_MD2(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    char optA[] = "WOLFSSL_MD2";
    int  optALen = (int) XSTRLEN(optA);

    *USettings = SoFT_d_lnkd_list_node_fill_single(*USettings, optA, optALen);

}

/* MD4 */
void SoFT_add_feature_MD4(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{

}
void SoFT_remove_feature_MD4(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    char optA[] = "NO_MD4";
    int  optALen = (int) XSTRLEN(optA);

    *USettings = SoFT_d_lnkd_list_node_fill_single(*USettings, optA, optALen);

}

/* MD5 */
void SoFT_add_feature_MD5(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{

}
void SoFT_remove_feature_MD5(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    char optA[] = "NO_MD5";
    int  optALen = (int) XSTRLEN(optA);

    *USettings = SoFT_d_lnkd_list_node_fill_single(*USettings, optA, optALen);

}

/* SHA / SHA1 */
void SoFT_add_feature_SHA1(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    SoFT_add_feature_HASH(CHdrs, CSrcs, THdrs, TSrcs, USettings);
}

void SoFT_remove_feature_SHA1(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    char optA[] = "NO_SHA";
    int  optALen = (int) XSTRLEN(optA);

    *USettings = SoFT_d_lnkd_list_node_fill_single(*USettings, optA, optALen);

    SoFT_add_feature_HASH(CHdrs, CSrcs, THdrs, TSrcs, USettings);
}

void SoFT_add_feature_SHA256(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    char headerA[] = "sha256.h";
    int  headerALen = (int) XSTRLEN(headerA);

    *CHdrs = SoFT_d_lnkd_list_node_fill_single(*CHdrs, headerA, headerALen);

    SoFT_add_feature_HASH(CHdrs, CSrcs, THdrs, TSrcs, USettings);
}

void SoFT_remove_feature_SHA256(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    char optA[] = "NO_SHA256";
    int  optALen = (int) XSTRLEN(optA);

    *USettings = SoFT_d_lnkd_list_node_fill_single(*USettings, optA, optALen);

    SoFT_add_feature_HASH(CHdrs, CSrcs, THdrs, TSrcs, USettings);
}

void SoFT_add_feature_SHA384(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    SoFT_add_feature_HASH(CHdrs, CSrcs, THdrs, TSrcs, USettings);
}

void SoFT_add_feature_SHA512(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    SoFT_add_feature_HASH(CHdrs, CSrcs, THdrs, TSrcs, USettings);
}

/* FAST MATH */
void SoFT_add_feature_FAST_MATH(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    char headerA[] = "tfm.h";
    int  headerALen = (int) XSTRLEN(headerA);
    char headerB[] = "wolfmath.h";
    int  headerBLen = (int) XSTRLEN(headerB);

    char srcA[] = "tfm.c";
    int  srcALen = (int) XSTRLEN(srcA);
    char srcB[] = "asm.c";
    int  srcBLen = (int) XSTRLEN(srcB);
    char srcC[] = "wolfmath.c";
    int  srcCLen = (int) XSTRLEN(srcC);

    char optA[] = "TFM_TIMING_RESISTANT";
    int  optALen = (int) XSTRLEN(optA);
    char optB[] = "ECC_TIMING_RESISTANT";
    int  optBLen = (int) XSTRLEN(optB);
    char optC[] = "WC_RSA_BLINDING";
    int  optCLen = (int) XSTRLEN(optC);
    char optD[] = "USE_FAST_MATH";
    int  optDLen = (int) XSTRLEN(optD);

    *CHdrs = SoFT_d_lnkd_list_node_fill_single(*CHdrs, headerA, headerALen);
    *CHdrs = SoFT_d_lnkd_list_node_fill_single(*CHdrs, headerB, headerBLen);

    *CSrcs = SoFT_d_lnkd_list_node_fill_single(*CSrcs, srcA, srcALen);
    *CSrcs = SoFT_d_lnkd_list_node_fill_single(*CSrcs, srcB, srcBLen);
    *CSrcs = SoFT_d_lnkd_list_node_fill_single(*CSrcs, srcC, srcCLen);

    *USettings = SoFT_d_lnkd_list_node_fill_single(*USettings, optA, optALen);
    *USettings = SoFT_d_lnkd_list_node_fill_single(*USettings, optB, optBLen);
    *USettings = SoFT_d_lnkd_list_node_fill_single(*USettings, optC, optCLen);
    *USettings = SoFT_d_lnkd_list_node_fill_single(*USettings, optD, optDLen);

}

void SoFT_add_feature_NORMAL_MATH(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{

}

void SoFT_add_feature_SP_MATH(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    char headerA[] = "sp_int.h";
    int  headerALen = (int) XSTRLEN(headerA);
    char headerB[] = "sp.h";
    int  headerBLen = (int) XSTRLEN(headerB);
    char headerC[] = "tfm.h";
    int  headerCLen = (int) XSTRLEN(headerC);
    char headerD[] = "mpi_class.h";
    int  headerDLen = (int) XSTRLEN(headerD);
    char headerE[] = "mpi_superclass.h";
    int  headerELen = (int) XSTRLEN(headerE);
    char headerF[] = "wolfmath.h";
    int  headerFLen = (int) XSTRLEN(headerF);

    char srcA[] = "sp_int.c";
    int  srcALen = (int) XSTRLEN(srcA);
    char srcB[] = "asm.c";
    int  srcBLen = (int) XSTRLEN(srcB);
    char srcC[] = "wolfmath.c";
    int  srcCLen = (int) XSTRLEN(srcC);
    char srcD[] = "tfm.c";
    int  srcDLen = (int) XSTRLEN(srcD);

    char optA[] = "WOLFSSL_SP";
    int  optALen = (int) XSTRLEN(optA);
    char optB[] = "TFM_TIMING_RESISTANT";
    int  optBLen = (int) XSTRLEN(optB);
    char optC[] = "ECC_TIMING_RESISTANT";
    int  optCLen = (int) XSTRLEN(optC);
    char optD[] = "WC_RSA_BLINDING";
    int  optDLen = (int) XSTRLEN(optD);
    char optE[] = "WOLFSSL_SP_ASM";
    int  optELen = (int) XSTRLEN(optE);
    char optF[] = "USE_FAST_MATH";
    int  optFLen = (int) XSTRLEN(optF);

    *CHdrs = SoFT_d_lnkd_list_node_fill_single(*CHdrs, headerA, headerALen);
    *CHdrs = SoFT_d_lnkd_list_node_fill_single(*CHdrs, headerB, headerBLen);
    *CHdrs = SoFT_d_lnkd_list_node_fill_single(*CHdrs, headerC, headerCLen);
    *CHdrs = SoFT_d_lnkd_list_node_fill_single(*CHdrs, headerD, headerDLen);
    *CHdrs = SoFT_d_lnkd_list_node_fill_single(*CHdrs, headerE, headerELen);
    *CHdrs = SoFT_d_lnkd_list_node_fill_single(*CHdrs, headerF, headerFLen);

    *CSrcs = SoFT_d_lnkd_list_node_fill_single(*CSrcs, srcA, srcALen);
    *CSrcs = SoFT_d_lnkd_list_node_fill_single(*CSrcs, srcB, srcBLen);
    *CSrcs = SoFT_d_lnkd_list_node_fill_single(*CSrcs, srcC, srcCLen);
    *CSrcs = SoFT_d_lnkd_list_node_fill_single(*CSrcs, srcD, srcDLen);

    *USettings = SoFT_d_lnkd_list_node_fill_single(*USettings, optA, optALen);
    *USettings = SoFT_d_lnkd_list_node_fill_single(*USettings, optB, optBLen);
    *USettings = SoFT_d_lnkd_list_node_fill_single(*USettings, optC, optCLen);
    *USettings = SoFT_d_lnkd_list_node_fill_single(*USettings, optD, optDLen);
    *USettings = SoFT_d_lnkd_list_node_fill_single(*USettings, optE, optELen);
    *USettings = SoFT_d_lnkd_list_node_fill_single(*USettings, optF, optFLen);
}

/* ANY MATH */
void SoFT_remove_feature_MATH(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    char optA[] = "NO_WOLF_MATH";
    int  optALen = (int) XSTRLEN(optA);

    *USettings = SoFT_d_lnkd_list_node_fill_single(*USettings, optA, optALen);
}

/* OLD_TLS */
void SoFT_add_feature_OLD_TLS(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{

}

void SoFT_remove_feature_OLD_TLS(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    char optA[] = "NO_OLD_TLS";
    int  optALen = (int) XSTRLEN(optA);

    *USettings = SoFT_d_lnkd_list_node_fill_single(*USettings, optA, optALen);

}

/* TLS */
void SoFT_add_feature_TLS(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{

}

void SoFT_remove_feature_TLS(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    char optA[] = "WOLFCRYPT_ONLY";
    int  optALen = (int) XSTRLEN(optA);

    *USettings = SoFT_d_lnkd_list_node_fill_single(*USettings, optA, optALen);

}

/* SIG WRAPPER */
void SoFT_add_feature_SIG_WRAP(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    char headerA[] = "signature.h";
    int  headerALen = (int) XSTRLEN(headerA);

    char srcA[] = "signature.c";
    int  srcALen = (int) XSTRLEN(srcA);

    *CHdrs = SoFT_d_lnkd_list_node_fill_single(*CHdrs, headerA, headerALen);

    *CSrcs = SoFT_d_lnkd_list_node_fill_single(*CSrcs, srcA, srcALen);

}

void SoFT_remove_feature_SIG_WRAP(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    char optA[] = "NO_SIG_WRAPPER";
    int  optALen = (int) XSTRLEN(optA);

    *USettings = SoFT_d_lnkd_list_node_fill_single(*USettings, optA, optALen);
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
    char headerA[] = "hash.h";
    int  headerALen = (int) XSTRLEN(headerA);

    char srcA[] = "hash.c";
    int  srcALen = (int) XSTRLEN(srcA);

    *CHdrs = SoFT_d_lnkd_list_node_fill_single(*CHdrs, headerA, headerALen);

    *CSrcs = SoFT_d_lnkd_list_node_fill_single(*CSrcs, srcA, srcALen);


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
    char optA[] = "USE_CERT_BUFFERS_2048";
    int  optALen = (int) XSTRLEN(optA);

    *USettings = SoFT_d_lnkd_list_node_fill_single(*USettings, optA, optALen);
}

/* Cert buffers 3072 */
void SoFT_add_feature_CB3072(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    char optA[] = "USE_CERT_BUFFERS_3072";
    int  optALen = (int) XSTRLEN(optA);

    *USettings = SoFT_d_lnkd_list_node_fill_single(*USettings, optA, optALen);
}

/* Cert buffers 4096 */
void SoFT_add_feature_CB4096(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    char optA[] = "USE_CERT_BUFFERS_4096";
    int  optALen = (int) XSTRLEN(optA);

    *USettings = SoFT_d_lnkd_list_node_fill_single(*USettings, optA, optALen);
}

/* Cert buffers 256 */
void SoFT_add_feature_CB256(SOFT_CH, SOFT_CS, SOFT_TH, SOFT_TS, SOFT_US)
{
    char optA[] = "USE_CERT_BUFFERS_256";
    int  optALen = (int) XSTRLEN(optA);

    *USettings = SoFT_d_lnkd_list_node_fill_single(*USettings, optA, optALen);
}

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
    char headerA[] = "cpuid.h";
    int  headerALen = (int) XSTRLEN(headerA);

    char srcA[] = "aes_asm.S"; /* Linux */
    int  srcALen = (int) XSTRLEN(srcA);
    char srcB[] = "aes_asm.asm"; /* Windows */
    int  srcBLen = (int) XSTRLEN(srcB);
    char srcC[] = "aes_gcm_asm.S"; /* Linux */
    int  srcCLen = (int) XSTRLEN(srcC);

    *CHdrs = SoFT_d_lnkd_list_node_fill_single(*CHdrs, headerA, headerALen);

    *CSrcs = SoFT_d_lnkd_list_node_fill_single(*CSrcs, srcA, srcALen);
    *CSrcs = SoFT_d_lnkd_list_node_fill_single(*CSrcs, srcB, srcBLen);
    *CSrcs = SoFT_d_lnkd_list_node_fill_single(*CSrcs, srcC, srcCLen);
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

        if (XSTRNCMP(line, checkForOption, XSTRLEN(checkForOption)) == 0 &&
            XSTRNCMP(line, checkForOption, XSTRLEN(line)) == 0) {

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

