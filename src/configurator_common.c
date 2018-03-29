#include <configurator_common.h>


void check_ret(int ret, int target, char* API)
{
    if (ret != target) {
        printf("%s call failed with return %d\n", API, ret);
        configurator_abort();
    }
    return;
}

void check_ret_nlte(int ret, int target, char* API)
{
    if (ret <= target) {
        printf("%s call failed with return %d\n", API, ret);
        configurator_abort();
    }
    return;
}

void configurator_abort(void)
{
    printf("Configurator aborting\n");
    exit(-1);
}


void clear_command(char* cmd)
{
    XMEMSET(cmd, 0, LONGEST_COMMAND);
    return;
}

void build_cmd(char* cmd, char* a, char* b, char* c, char* d)
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

void build_cd_cmd(char* cmd, char* pwd)
{
    char* part1 = "cd ";
    unsigned long part1Sz = XSTRLEN(part1);

    XSTRNCAT(cmd, part1, part1Sz);
    XSTRNCAT(cmd, pwd, XSTRLEN(pwd));

    return;
}

void build_fname_cmd(char* cmd, char* fname, char* pwd)
{
    clear_command(cmd);
    XSTRNCAT(cmd, pwd, XSTRLEN(pwd));
    XSTRNCAT(cmd, fname, XSTRLEN(fname));

    return;
}

int get_file_size(char* fname)
{
    FILE* fStream;
    int fSize = -1;

    fStream = fopen(fname, "rb");
    if (fStream == NULL)
        return FILE_ERR;

    fseek(fStream, 0L, SEEK_END);

    fSize = (int) ftell(fStream);
    if (fSize <= 0)
        return FILE_ERR;

    fclose(fStream);

    return fSize;
}
