#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "../headers/regex_op.h"
#include "tap.h"


int test_OS_PRegex_ok() {

    return OS_PRegex("t.e_s-t0@test.test.ok", "^[a-z0-9_\\.-]+@[0-9a-z\\.-]+\\.[a-z\\.]{2,6}$");
}


int test_OS_PRegex_nok() {

    return OS_PRegex("t.e_s-t0@test", "^[a-z0-9_\\.-]+@[0-9a-z\\.-]+\\.[a-z\\.]{2,6}$");
}


int test_w_regexec_ok() {

    int ret = 0;
    regmatch_t match[2];
    int match_size;
    char * matched;

    const char * test_string = "t.e_s-t0@test.test.ok";

    if (w_regexec("^([a-z0-9_\\.-]+)@[0-9a-z\\.-]+\\.[a-z\\.]{2,6}$",test_string, 2, match)) {
        match_size = match[1].rm_eo - match[1].rm_so;
        matched = (char*) malloc(match_size + 1);
        snprintf(matched, match_size + 1, "%.*s", match_size, test_string + match[1].rm_so);
        if (strcmp(matched, "t.e_s-t0") == 0) {
            ret = 1;
        }
        free(matched);
    }

    return ret;
}


int test_w_regexec_nok() {

    int ret = 0;
    regmatch_t match[2];
    int match_size;
    char * matched;

    const char * test_string = "t.e_s-t0@test";

    if (w_regexec("^([a-z0-9_\\.-]+)@[0-9a-z\\.-]+\\.[a-z\\.]{2,6}$",test_string, 2, match)) {
        match_size = match[1].rm_eo - match[1].rm_so;
        matched = (char*) malloc(match_size + 1);
        snprintf(matched, match_size + 1, "%.*s", match_size, test_string + match[1].rm_so);
        if (strcmp(matched, "t.e_s-t0") == 0) {
            ret = 1;
        }
        free(matched);
    }

    return ret;
}


int main(void) {

    printf("\n\n   STARTING TEST - REGEX_OP   \n\n");

    TAP_TEST_MSG(test_OS_PRegex_ok(), "Test OS_PRegex(). Matching string.");

    TAP_TEST_MSG(!test_OS_PRegex_nok(), "Test OS_PRegex(). Non-matching string");

    TAP_TEST_MSG(test_w_regexec_ok(), "Test w_regexec(). Matching string.");

    TAP_TEST_MSG(!test_w_regexec_nok(), "Test w_regexec(). Non-matching string.");

    TAP_PLAN;
    TAP_SUMMARY;

    printf("\n   ENDING TEST - REGEX_OP   \n\n");
    return 0;

}
