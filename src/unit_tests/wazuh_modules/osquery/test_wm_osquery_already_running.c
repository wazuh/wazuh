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

char * wm_osquery_already_running(char * text);

void test_wm_osquery_already_running_null(void **state)
{
    char *input = NULL;
    char *output = wm_osquery_already_running(input);

    assert_null(output);
}

void test_wm_osquery_already_running_pattern_1(void **state)
{
    char input[] = "osqueryd (1000) is already running";
    char *output = wm_osquery_already_running(input);

    assert_non_null(output);
    assert_string_equal(output, "1000");

    free(output);
}

void test_wm_osquery_already_running_pattern_2(void **state)
{
    char input[] = "Pidfile::Error::Busy";
    char *output = wm_osquery_already_running(input);

    assert_non_null(output);
    assert_string_equal(output, "unknown");

    free(output);
}

void test_wm_osquery_already_running_no_match(void **state)
{
    char input[] = "No match";
    char *output = wm_osquery_already_running(input);
    assert_null(output);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // wm_osquery_already_running
        cmocka_unit_test(test_wm_osquery_already_running_null),
        cmocka_unit_test(test_wm_osquery_already_running_pattern_1),
        cmocka_unit_test(test_wm_osquery_already_running_pattern_2),
        cmocka_unit_test(test_wm_osquery_already_running_no_match),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
