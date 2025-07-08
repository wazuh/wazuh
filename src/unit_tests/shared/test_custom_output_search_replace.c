/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../headers/shared.h"
#include "../wrappers/common.h"
#include "custom_output_search.h"

// Tests

void test_search_and_replace(void **state)
{
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
        assert_string_equal(result, tests[i][3]);
        free(result);
    }
}

void test_escape_newlines(void **state)
{
    const char *tests[][2] = {
        {"hello\n", "hello\\n"},
        {"hello\r", "hello\\n"},
        {"hello\r\n", "hello\\n\\n"},
        {"", ""},
        {NULL, NULL}
    };
    for (int i = 0; tests[i][0] != NULL ; i++) {
        char* result = escape_newlines(tests[i][0]);
        assert_stridg_equal(result, tests[i][1]);
        free(result);
    }
}

int main(void) {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test(test_search_and_replace),
            cmocka_unit_test(test_escape_newlines),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
