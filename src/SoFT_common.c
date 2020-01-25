#include <SoFT_common.h>


void SoFT_check_ret(int ret, int target, char* API)
{
    if (ret != target) {
        printf("%s call failed with return %d\n", API, ret);
        SoFT_abort();
    }
    return;
}

void SoFT_check_ret_nlte(int ret, int target, char* API)
{
    if (ret <= target) {
        printf("%s call failed with return %d\n", API, ret);
        SoFT_abort();
    }
    return;
}

void SoFT_assrt_ne_null(void* in, char* activity_description)
{
    if (in == NULL) {
        printf("%s failed\n", activity_description);
        SoFT_abort();
    }
}

void __attribute__((noreturn)) SoFT_abort(void)
{
    printf("Configurator aborting\n");
    exit(-1);
}


void SoFT_clear_cmd(char* cmd)
{
    XMEMSET(cmd, 0, SOFT_LONGEST_COMMAND);
    return;
}

void SoFT_build_cmd(char* cmd, char* a, char* b, char* c, char* d)
{

    if (a != NULL)
        XSTRNCAT(cmd, a, XSTRLEN(a));
    if (b != NULL)
        XSTRNCAT(cmd, b, XSTRLEN(b));
    if (c != NULL)
        XSTRNCAT(cmd, c, XSTRLEN(c));
    if (d != NULL)
        XSTRNCAT(cmd, d, XSTRLEN(d));

    return;
}

void SoFT_build_cd_cmd(char* cmd, char* pwd)
{
    char* part1 = "cd ";
    unsigned long part1Sz = XSTRLEN(part1);

    XSTRNCAT(cmd, part1, part1Sz);
    XSTRNCAT(cmd, pwd, XSTRLEN(pwd));

    return;
}

void SoFT_build_fname_cmd(char* cmd, char* fname, char* pwd)
{
    SoFT_clear_cmd(cmd);
    XSTRNCAT(cmd, pwd, XSTRLEN(pwd));
    XSTRNCAT(cmd, fname, XSTRLEN(fname));

    return;
}

int SoFT_get_file_size(char* fname)
{
    FILE* fStream;
    int fSize = -1;

    fStream = fopen(fname, "rb");
    if (fStream == NULL)
        return 0;

    fseek(fStream, 0L, SEEK_END);

    fSize = (int) ftell(fStream);
    if (fSize <= 0)
        return FILE_ERR;

    fclose(fStream);

    return fSize;
}

void SoFT_clone_target_repo(char* repo)
{
    char c_cmd[SOFT_LONGEST_COMMAND];
    char* gitCmd = "git clone https://github.com/";

    SoFT_clear_cmd(c_cmd);
    printf("Cloning: %s\n", repo);
    SoFT_build_cmd(c_cmd, gitCmd, repo, ".git", NULL);
    system(c_cmd);
    SoFT_clear_cmd(c_cmd);
}
