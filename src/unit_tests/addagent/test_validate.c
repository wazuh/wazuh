/*
 * Copyright (C) 2026, Wazuh Inc.
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
#include <string.h>

#include "../../addagent/manage_agents.h"

/* Tests for OS_IsValidName */

/* Test valid agent names */
static void test_OS_IsValidName_valid_names(void **state) {
    (void) state;

    /* Valid alphanumeric names */
    assert_int_equal(OS_IsValidName("agent01"), 1);
    assert_int_equal(OS_IsValidName("MyAgent"), 1);
    assert_int_equal(OS_IsValidName("test-agent"), 1);
    assert_int_equal(OS_IsValidName("test_agent"), 1);
    assert_int_equal(OS_IsValidName("agent.local"), 1);
    assert_int_equal(OS_IsValidName("web-server-01"), 1);
    assert_int_equal(OS_IsValidName("db_server_prod"), 1);
    assert_int_equal(OS_IsValidName("host.domain.com"), 1);
}

/* Test dot patterns */
static void test_OS_IsValidName_dot_patterns(void **state) {
    (void) state;

    /* Names with double dots should be allowed if they don't start with dot */
    assert_int_equal(OS_IsValidName("test..name"), 1);
    assert_int_equal(OS_IsValidName("agent..local"), 1);
    assert_int_equal(OS_IsValidName("agent.."), 1);
}

/* Test names starting with dot - should be rejected */
static void test_OS_IsValidName_hidden_files(void **state) {
    (void) state;

    /* Names starting with dot */
    assert_int_equal(OS_IsValidName(".hidden"), 0);
    assert_int_equal(OS_IsValidName(".test"), 0);
    assert_int_equal(OS_IsValidName(".agent"), 0);

    /* Single dot */
    assert_int_equal(OS_IsValidName("."), 0);
}

/* Test invalid characters */
static void test_OS_IsValidName_invalid_characters(void **state) {
    (void) state;

    /* Slashes */
    assert_int_equal(OS_IsValidName("test/agent"), 0);
    assert_int_equal(OS_IsValidName("test\\agent"), 0);

    /* Special characters */
    assert_int_equal(OS_IsValidName("test@agent"), 0);
    assert_int_equal(OS_IsValidName("test#agent"), 0);
    assert_int_equal(OS_IsValidName("test$agent"), 0);
    assert_int_equal(OS_IsValidName("test%agent"), 0);
    assert_int_equal(OS_IsValidName("test&agent"), 0);
    assert_int_equal(OS_IsValidName("test*agent"), 0);
}

/* Test name length validation */
static void test_OS_IsValidName_length(void **state) {
    (void) state;

    /* Too short (less than 2 characters) */
    assert_int_equal(OS_IsValidName("a"), 0);
    assert_int_equal(OS_IsValidName(""), 0);

    /* Minimum valid length (2 characters) */
    assert_int_equal(OS_IsValidName("ab"), 1);

    /* Maximum valid length (128 characters) */
    char max_length_name[129];
    memset(max_length_name, 'a', 128);
    max_length_name[128] = '\0';
    assert_int_equal(OS_IsValidName(max_length_name), 1);

    /* Too long (more than 128 characters) */
    char too_long_name[130];
    memset(too_long_name, 'a', 129);
    too_long_name[129] = '\0';
    assert_int_equal(OS_IsValidName(too_long_name), 0);
}

/* Test edge cases and boundary conditions */
static void test_OS_IsValidName_edge_cases(void **state) {
    (void) state;

    /* Names starting with dots should be rejected */
    assert_int_equal(OS_IsValidName("."), 0);
    assert_int_equal(OS_IsValidName(".."), 0);
    assert_int_equal(OS_IsValidName("..."), 0);
    assert_int_equal(OS_IsValidName(".hidden"), 0);

    /* Valid names with dots in middle or end */
    assert_int_equal(OS_IsValidName("test."), 1);
    assert_int_equal(OS_IsValidName("test.agent"), 1);
    assert_int_equal(OS_IsValidName("host.domain.local"), 1);
}

/* Tests for OS_IsValidID */

static void test_OS_IsValidID_valid_ids(void **state) {
    (void) state;

    /* Valid numeric IDs */
    assert_int_equal(OS_IsValidID("001"), 1);
    assert_int_equal(OS_IsValidID("123"), 1);
    assert_int_equal(OS_IsValidID("99999999"), 1);
    assert_int_equal(OS_IsValidID("1"), 1);
}

static void test_OS_IsValidID_invalid_ids(void **state) {
    (void) state;

    /* NULL ID */
    assert_int_equal(OS_IsValidID(NULL), 0);

    /* Too long (more than 8 characters) */
    assert_int_equal(OS_IsValidID("123456789"), 0);

    /* Non-numeric characters */
    assert_int_equal(OS_IsValidID("abc"), 0);
    assert_int_equal(OS_IsValidID("12a"), 0);
    assert_int_equal(OS_IsValidID("1-2"), 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        /* OS_IsValidName tests */
        cmocka_unit_test(test_OS_IsValidName_valid_names),
        cmocka_unit_test(test_OS_IsValidName_dot_patterns),
        cmocka_unit_test(test_OS_IsValidName_hidden_files),
        cmocka_unit_test(test_OS_IsValidName_invalid_characters),
        cmocka_unit_test(test_OS_IsValidName_length),
        cmocka_unit_test(test_OS_IsValidName_edge_cases),

        /* OS_IsValidID tests */
        cmocka_unit_test(test_OS_IsValidID_valid_ids),
        cmocka_unit_test(test_OS_IsValidID_invalid_ids),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
