/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <setjmp.h>
#include <cmocka.h>

#include "../../os_regex/os_regex_match.c"

// Tests

void test__InternalMatch_str_NULL(void **state) {
    char * str = NULL;
    char * pattern = "pattern";
    size_t pattern_size = strlen(pattern);

    int result = _InternalMatch(pattern, str, pattern_size);
    assert_int_equal(result, FALSE);
}

void test__InternalMatch_str_empty(void **state) {
    char * str = "";
    char * pattern = "pattern";
    size_t pattern_size = strlen(pattern);

    int result = _InternalMatch(pattern, str, pattern_size);
    assert_int_equal(result, FALSE);
}

void test__InternalMatch_pattern_empty(void **state) {
    char * str = "string";
    char * pattern = "";
    size_t pattern_size = strlen(pattern);
    
    int result = _InternalMatch(pattern, str, pattern_size);
    assert_int_equal(result, TRUE);
}

void test__InternalMatch_fail(void **state) {
    char * str = "string";
    char * pattern = "^pattern";
    size_t pattern_size = strlen(pattern);

    int result = _InternalMatch(pattern, str, pattern_size);
    assert_int_equal(result, FALSE);
}

void test__InternalMatch_success(void **state) {
    char * str = "string";
    char * pattern = "^string";
    size_t pattern_size = strlen(pattern);

    int result = _InternalMatch(pattern, str, pattern_size);
    assert_int_equal(result, TRUE);
}

void test__InternalMatch_fail_iteration(void **state) {
    char * str = "this is a str";
    char * pattern = "string";
    size_t pattern_size = strlen(pattern);

    int result = _InternalMatch(pattern, str, pattern_size);
    assert_int_equal(result, FALSE);
}

void test__InternalMatch_success_iteration(void **state) {
    char * str = "this is a string";
    char * pattern = "string";
    size_t pattern_size = strlen(pattern);

    int result = _InternalMatch(pattern, str, pattern_size);
    assert_int_equal(result, TRUE);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test__InternalMatch_str_NULL),
        cmocka_unit_test(test__InternalMatch_str_empty),
        cmocka_unit_test(test__InternalMatch_pattern_empty),
        cmocka_unit_test(test__InternalMatch_fail),
        cmocka_unit_test(test__InternalMatch_success),
        cmocka_unit_test(test__InternalMatch_fail_iteration),
        cmocka_unit_test(test__InternalMatch_success_iteration)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
