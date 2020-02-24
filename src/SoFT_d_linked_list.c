#include <SoFT_common.h>
#include <SoFT_pp_extractor.h>

D_LINKED_LIST_NODE* SoFT_d_lnkd_list_node_fill_single(D_LINKED_LIST_NODE* curr,
                                             char* line, int lSz)
{
    struct D_LINKED_LIST_NODE* next;
    int i;
    int duplicateCheck = -1;
    char c_tmp[SOFT_LONGEST_LINE];

    XMEMSET(c_tmp, 0, sizeof(c_tmp));

    SoFT_assrt_ne_null(curr, "Called SoFT_d_lnkd_list_node_fill_single"
                             "with null argument");

    next = curr->next;

    if (next != NULL) {
        fprintf(stderr, "Called SoFT_d_lnkd_list_node_fill_single with a node "
                        "that has a next\n");
        SoFT_abort();
    }

    next = SoFT_d_lnkd_list_node_init(next);;
    SoFT_assrt_ne_null(next, "creating next in "
                             "SoFT_d_lnkd_list_node_fill_single");

    #ifdef IGNORE_DUPLICATES
      /* get all pre_processor macros regardless of duplicates */
      duplicateCheck = SOFT_NO_DUP;
    #else
      duplicateCheck = SoFT_d_lnkd_list_check_for_dup(curr, line);
    #endif

    if (duplicateCheck == SOFT_NO_DUP) {
        for (i = 0; i < lSz; i++) {
            curr->value[i] = line[i];
        }
    } else {
        free(next);
        return curr;
    }

    curr->next = next;
    next->previous = curr;
    return next;
}

D_LINKED_LIST_NODE* SoFT_d_lnkd_list_node_init(D_LINKED_LIST_NODE* in)
{
    if (in == NULL) {
        in = (D_LINKED_LIST_NODE*) malloc(sizeof(D_LINKED_LIST_NODE));
        SoFT_assrt_ne_null(in, "SoFT_d_lnkd_list_node_init");
    }

    in->previous = NULL;
    in->next = NULL;
    XMEMSET(in->value, 0, sizeof(in->value));
    in->value[0] = '\n';
    in->isGood = -1;

    return in;
}

/* return the one passed in to keep your place in the list when this
 * is called */
D_LINKED_LIST_NODE* SoFT_d_lnkd_list_iterate(D_LINKED_LIST_NODE* in)
{
    int nodeC = 0;
    struct D_LINKED_LIST_NODE* curr = NULL;
    struct D_LINKED_LIST_NODE* storeRet = in;

    SoFT_assrt_ne_null(in, "SoFT_d_lnkd_list_iterate called with null "
                           "D_LINKED_LIST_NODE");

    curr = SoFT_d_lnkd_list_get_head(in);

    fprintf(stderr, "-------------------- LIST ----------------------------\n");

    while(curr->next != NULL) {

        #ifdef DEBUG_SOFT_CHECK_ITERATE
            {
                int i;
                fprintf(stderr, "--> %p\n", curr);
                if (curr->previous != NULL)
                    fprintf(stderr, "\t\t|-->%p\n", curr->previous);
                else
                    fprintf(stderr, "\t\t|-->(null)\n");
                if (curr->next != NULL)
                    fprintf(stderr, "\t\t|-->%p\n", curr->next);
                else
                    fprintf(stderr, "\t\t|-->(null)\n");

                fprintf(stderr, "\t\t|-->");
                for (i = 0; i < sizeof(curr->value); i++)
                    fprintf(stderr, "%c", curr->value[i]);
                fprintf(stderr, "\n");
            }
        #endif

        fprintf(stderr, "%s\n", curr->value);

        curr = curr->next;

        if (curr == NULL)
            break;

        nodeC++;
    }

    fprintf(stderr, "Total C Pre Processor Macros Identified was: %d\n", nodeC);
    fprintf(stderr, "------------------------------------------------------\n");

    return storeRet;
}

D_LINKED_LIST_NODE* SoFT_d_lnkd_list_get_head(D_LINKED_LIST_NODE* in)
{
    int counter = 0;

    SoFT_assrt_ne_null(in, "SoFT_d_lnkd_list_get_head called with null "
                           "D_LINKED_LIST_NODE");

    if (in->previous == NULL)
        return in;

    while (in->previous != NULL) {

        in = in->previous;
        counter++;
        #ifdef DEBUG_SOFT_LVL2
          fprintf(stderr, "DEBUG: Backed up %d\n", counter);
        #endif

        if (in == NULL)
            break;
    }

    return in;
}

D_LINKED_LIST_NODE* SoFT_d_lnkd_list_get_next(D_LINKED_LIST_NODE* in) {
    if (in != NULL)
        return in->next;

    return NULL; /* Default if in is NULL */
}

D_LINKED_LIST_NODE* SoFT_d_lnkd_list_get_prev(D_LINKED_LIST_NODE* in) {
    if (in != NULL)
        return in->previous;

    return NULL; /* Default if in is NULL */
}


void SoFT_d_lnkd_list_free(D_LINKED_LIST_NODE* in)
{
    struct D_LINKED_LIST_NODE* curr = NULL;
    struct D_LINKED_LIST_NODE* tmp = NULL;

    curr = SoFT_d_lnkd_list_get_head(in);

    while (curr != NULL) {
        tmp = curr->next;
        free(curr);
        curr = tmp;
    }

    return;
}

int SoFT_d_lnkd_list_check_for_dup(D_LINKED_LIST_NODE* in, char* target)
{
    struct D_LINKED_LIST_NODE* curr = NULL;


    curr = SoFT_d_lnkd_list_get_head(in);

    while (curr != NULL) {

        if (XSTRNCMP(curr->value, target, XSTRLEN(target)) == 0) {
            return SOFT_FOUND_DUP;
        }

        curr = curr->next;
    }

    return SOFT_NO_DUP;
}


