#include <configurator_common.h>


void cfg_check_ret(int ret, int target, char* API)
{
    if (ret != target) {
        printf("%s call failed with return %d\n", API, ret);
        cfg_abort();
    }
    return;
}

void cfg_check_ret_nlte(int ret, int target, char* API)
{
    if (ret <= target) {
        printf("%s call failed with return %d\n", API, ret);
        cfg_abort();
    }
    return;
}

void cfg_assrt_ne_null(void* in, char* activity_description)
{
    if (in == NULL) {
        printf("%s failed\n", activity_description);
        cfg_abort();
    }
}

void __attribute__((noreturn)) cfg_abort(void)
{
    printf("Configurator aborting\n");
    exit(-1);
}


void cfg_clear_cmd(char* cmd)
{
    XMEMSET(cmd, 0, LONGEST_COMMAND);
    return;
}

void cfg_build_cmd(char* cmd, char* a, char* b, char* c, char* d)
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

void cfg_build_cd_cmd(char* cmd, char* pwd)
{
    char* part1 = "cd ";
    unsigned long part1Sz = XSTRLEN(part1);

    XSTRNCAT(cmd, part1, part1Sz);
    XSTRNCAT(cmd, pwd, XSTRLEN(pwd));

    return;
}

void cfg_build_fname_cmd(char* cmd, char* fname, char* pwd)
{
    cfg_clear_cmd(cmd);
    XSTRNCAT(cmd, pwd, XSTRLEN(pwd));
    XSTRNCAT(cmd, fname, XSTRLEN(fname));

    return;
}

int cfg_get_file_size(char* fname)
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

void cfg_clone_target_repo(char* repo)
{
    char c_cmd[LONGEST_COMMAND];
    char* gitCmd = "git clone https://github.com/";

    cfg_clear_cmd(c_cmd);
    printf("Cloning: %s\n", repo);
    cfg_build_cmd(c_cmd, gitCmd, repo, ".git", NULL);
    system(c_cmd);
    cfg_clear_cmd(c_cmd);
}
