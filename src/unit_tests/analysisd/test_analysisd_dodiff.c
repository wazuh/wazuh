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

#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

#include "../analysisd/eventinfo.h"
#include "../analysisd/rules.h"
#include "../headers/defs.h"

#define INVALID_HOSTNAME_MSG "Invalid hostname for diff: '%s'."
#define TOO_LONG_MSG "Event size (%zd) too long for diff."

/* Run doDiff() with the given hostname and check it is rejected as unsafe */
static void assert_hostname_rejected(const char *hostname, const char *logged_name) {
    RuleInfo rule = { .sigid = 550 };
    Eventinfo lf = { .size = 4 };
    char host[OS_SIZE_256];
    char expected[OS_SIZE_512];

    snprintf(host, sizeof(host), "%s", hostname);
    lf.hostname = host;
    lf.log = "test";

    snprintf(expected, sizeof(expected), INVALID_HOSTNAME_MSG, logged_name);
    expect_string(__wrap__merror, formatted_msg, expected);

    assert_int_equal(doDiff(&rule, &lf), 0);

    /* The caller's string must be left as it was received */
    assert_string_equal(host, hostname);
}

/* Run doDiff() with a hostname that must pass validation. The event is made too big on purpose so
 * the function stops right after the hostname check without touching the filesystem. */
static void assert_hostname_accepted(const char *hostname) {
    RuleInfo rule = { .sigid = 550 };
    Eventinfo lf = { .size = OS_SIZE_65536 };
    char host[OS_SIZE_256];
    char expected[OS_SIZE_512];

    snprintf(host, sizeof(host), "%s", hostname);
    lf.hostname = host;
    lf.log = "test";

    snprintf(expected, sizeof(expected), TOO_LONG_MSG, lf.size);
    expect_string(__wrap__merror, formatted_msg, expected);

    assert_int_equal(doDiff(&rule, &lf), 0);
    assert_string_equal(host, hostname);
}

void test_doDiff_hostname_traversal(void **state) {
    assert_hostname_rejected("../../x", "../../x");
}

void test_doDiff_hostname_slash(void **state) {
    assert_hostname_rejected("a/b", "a/b");
}

void test_doDiff_hostname_dot(void **state) {
    assert_hostname_rejected(".", ".");
}

void test_doDiff_hostname_dotdot(void **state) {
    assert_hostname_rejected("..", "..");
}

void test_doDiff_hostname_agentless_traversal(void **state) {
    /* "(name) ..." form: the validated name is the one between the parentheses */
    assert_hostname_rejected("(../../x) 10.0.0.1->syslog", "../../x");
}

void test_doDiff_hostname_agentless_dotdot(void **state) {
    assert_hostname_rejected("(..) 10.0.0.1->syslog", "..");
}

void test_doDiff_hostname_valid(void **state) {
    assert_hostname_accepted("host.example.com");
}

void test_doDiff_hostname_valid_with_dots(void **state) {
    /* A dot inside a name is fine; only "." and ".." are special */
    assert_hostname_accepted("..host");
}

void test_doDiff_hostname_agentless_valid(void **state) {
    assert_hostname_accepted("(agentless-1) 10.0.0.1->syslog");
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_doDiff_hostname_traversal),
        cmocka_unit_test(test_doDiff_hostname_slash),
        cmocka_unit_test(test_doDiff_hostname_dot),
        cmocka_unit_test(test_doDiff_hostname_dotdot),
        cmocka_unit_test(test_doDiff_hostname_agentless_traversal),
        cmocka_unit_test(test_doDiff_hostname_agentless_dotdot),
        cmocka_unit_test(test_doDiff_hostname_valid),
        cmocka_unit_test(test_doDiff_hostname_valid_with_dots),
        cmocka_unit_test(test_doDiff_hostname_agentless_valid),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
