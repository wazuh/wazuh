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
#include <string.h>

#include "shared.h"
#include "../../os_maild/maild.h"

/* Global variables */
unsigned int mail_timeout;
unsigned int   _g_subject_level;
char _g_subject[SUBJECT_SIZE + 2];

static void assert_stuffed(const char *in, bool start, const char *expected, bool expected_end) {
    bool line_start = start;
    char *out = OS_DotStuff(in, &line_start);

    assert_string_equal(out, expected);
    assert_int_equal(line_start, expected_end);
    os_free(out);
}

static void test_dot_stuff_lone_dot_line(void **state) {
    assert_stuffed("first line\n.\nnext line\r\n",
                   true,
                   "first line\r\n..\r\nnext line\r\n",
                   true);
}

static void test_dot_stuff_leading_dots(void **state) {
    assert_stuffed(".start\r\n..two\r\nmid.dot", true, "..start\r\n...two\r\nmid.dot", false);
}

static void test_dot_stuff_line_breaks(void **state) {
    assert_stuffed("a\rb\nc\r\nd\n\r.e", true, "a\r\nb\r\nc\r\nd\r\n\r\n..e", false);
}

static void test_dot_stuff_split_chunks(void **state) {
    bool line_start = true;
    char *first = OS_DotStuff("abc", &line_start);
    char *second = OS_DotStuff(".def\n", &line_start);
    char *third = OS_DotStuff(".", &line_start);

    assert_string_equal(first, "abc");
    assert_string_equal(second, ".def\r\n");
    assert_string_equal(third, "..");
    assert_false(line_start);

    os_free(first);
    os_free(second);
    os_free(third);
}

static void test_dot_stuff_no_dots(void **state) {
    assert_stuffed("plain text", true, "plain text", false);
}

static void test_dot_stuff_empty(void **state) {
    assert_stuffed("", true, "", true);
    assert_stuffed("", false, "", false);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_dot_stuff_lone_dot_line),
        cmocka_unit_test(test_dot_stuff_leading_dots),
        cmocka_unit_test(test_dot_stuff_line_breaks),
        cmocka_unit_test(test_dot_stuff_split_chunks),
        cmocka_unit_test(test_dot_stuff_no_dots),
        cmocka_unit_test(test_dot_stuff_empty),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
