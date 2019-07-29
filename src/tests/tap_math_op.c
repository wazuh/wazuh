#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "../headers/math_op.h"
#include "tap.h"

int test_os_getprime() {

    int ret = 0;

    if (os_getprime(875463) == 875477) {
        ret++;
    }

    if (os_getprime(6390) == 6397) {
        ret++;
    }

    if (os_getprime(7908) == 7919) {
        ret++;
    }

    if (ret == 3) {
        return 1;
    }

    return 0;
}



int main(void) {

    printf("\n\n   STARTING TEST - MATH_OP   \n\n");

    TAP_TEST_MSG(test_os_getprime(), "Test test_os_getprime().");

    TAP_PLAN;
    TAP_SUMMARY;

    printf("\n   ENDING TEST - MATH_OP   \n\n");
    return 0;

}
