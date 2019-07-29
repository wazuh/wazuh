#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "../headers/vector_op.h"
#include "tap.h"

#define TEST_VECTOR_LENGHT 5000


int test_vector_insert(W_Vector *v) {

    int ret = 0;
    int i;

    for (i = 0 ; i < TEST_VECTOR_LENGHT; i++) {
        W_Vector_insert(v, "test");
    }

    if (W_Vector_length(v) == TEST_VECTOR_LENGHT &&
        strcmp(W_Vector_get(v, TEST_VECTOR_LENGHT - 1), "test") == 0) {
        ret = 1;
    }

    return ret;
}


int test_vector_insert_unique(W_Vector *v) {

    int ret = 0;

    if (W_Vector_insert_unique(v, "duplicated") == 0) {
        if (W_Vector_insert_unique(v, "duplicated") == 1) {
            ret = 1;
        }
    }

    return ret;
}


int main(void) {

    W_Vector *v = W_Vector_init(1);

    printf("\n\n   STARTING TEST - VECTOR_OP   \n\n");

    TAP_TEST_MSG(test_vector_insert(v), "Check insertion of new values.");

    TAP_TEST_MSG(test_vector_insert_unique(v), "Check duplicates insertion.");

    TAP_PLAN;
    TAP_SUMMARY;
    W_Vector_free(v);
    printf("\n   ENDING TEST - VECTOR_OP   \n\n");
    return 0;

}
