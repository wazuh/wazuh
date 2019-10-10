#include "../headers/shared.h"
#include "tap.h"

int test_search_and_replace(){

    int i;
    const char *tests[][4] = {
        {"testMe", "nomatch", "", "testMe"},
        {"test me", "ME", "me", "test me"},
        {"test me", "me", "ME", "test ME"},
        {"testMe", "test", "Tested", "TestedMe"},
        {"Metest", "test", "Tested", "MeTested"},
        {"A B CTeStD E F", "TeSt", "tEsT", "A B CtEsTD E F"},
        {"TeStA B CTeStD E F", "TeSt", "tEsT", "tEsTA B CtEsTD E F"},
        {"TeSt TeStA B CTeStD E F", "TeSt", "tEsT", "tEsT tEsTA B CtEsTD E F"},
        {"A B CTeStD E FTeSt", "TeSt", "tEsT", "A B CtEsTD E FtEsT"},
        {"A B CTeStD E FTeSt TeSt", "TeSt", "tEsT", "A B CtEsTD E FtEsT tEsT"},
        {"TeSt++ TeSt++A B CTeSt++D E F", "TeSt++", "tEsT", "tEsT tEsTA B CtEsTD E F"},
        {"A B CTeStD E FTeSt TeSt", "TeSt", "tEsT++", "A B CtEsT++D E FtEsT++ tEsT++"},
        {NULL, NULL, NULL, NULL}
    };

    for (i = 0; tests[i][0] != NULL ; i++) {
        char *result = searchAndReplace(tests[i][0], tests[i][1], tests[i][2]);
        w_assert_str_eq(result, tests[i][3]);
        free(result);
    }
    return 1;
}

int test_utf8_random(bool replacement) {
    int i;
    const size_t LENGTH = 4096;
    char buffer[LENGTH];

    randombytes(buffer, LENGTH - 1);

    /* Avoid zeroes */

    for (i = 0; i < LENGTH - 1; i++) {
        buffer[i] = buffer[i] ? buffer[i] : '0';
    }

    buffer[LENGTH - 1] = '\0';

    char * copy = w_utf8_filter(buffer, replacement);
    int r = w_utf8_valid(copy);
    free(copy);

    return r;
}

int main(void) {
    printf("\n\n   STARTING TEST - OS_SHARED   \n\n");

    // Search and replace strings test
    TAP_TEST_MSG(test_search_and_replace(), "Search and replace strings test.");

    /* Test UTF-8 string operations */
    TAP_TEST_MSG(test_utf8_random(true), "Filter a random string into UTF-8 with character replacement.");

    /* Test UTF-8 string operations */
    TAP_TEST_MSG(test_utf8_random(false), "Filter a random string into UTF-8 without character replacement.");

    TAP_PLAN;
    TAP_SUMMARY;
    printf("\n   ENDING TEST  - OS_SHARED   \n\n");
    return 0;
}
