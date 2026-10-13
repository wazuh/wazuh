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
#include <string.h>
#include <stdio.h>

#include "os_win32ui.h"
#include "agent_auth_cli.h"

#define REFUSED "The manager refused the enrollment request."

/* What wazuh-agent-auth writes to stderr when the manager refuses, as the UI captures it. */
#define REFUSED_STDERR(reason) \
    "wazuh-agent-auth: the manager refused the enrollment.\r\n" \
    "  " AGENT_AUTH_MANAGER_SAID reason "\r\n" \
    "  Nothing was changed.\r\n"

static void test_manager_reason_is_appended(void **state) {
    (void) state;
    char out[512];

    agent_auth_append_manager_reason(REFUSED, REFUSED_STDERR("Duplicate name"), out, sizeof(out));

    assert_string_equal(out, "The manager refused the enrollment request: Duplicate name.");
}

static void test_reason_period_is_not_doubled(void **state) {
    (void) state;
    char out[512];

    agent_auth_append_manager_reason(REFUSED, REFUSED_STDERR("Duplicate name."), out, sizeof(out));

    assert_string_equal(out, "The manager refused the enrollment request: Duplicate name.");
}

static void test_no_reason_keeps_the_base_message(void **state) {
    (void) state;
    char out[512];

    /* A manager that never answered: wazuh-agent-auth has no reason to print. */
    agent_auth_append_manager_reason(REFUSED,
                                     "wazuh-agent-auth: the manager refused the enrollment.\r\n"
                                     "  Nothing was changed.\r\n",
                                     out, sizeof(out));

    assert_string_equal(out, REFUSED);
}

static void test_null_or_empty_output_keeps_the_base_message(void **state) {
    (void) state;
    char out[512];

    agent_auth_append_manager_reason(REFUSED, NULL, out, sizeof(out));
    assert_string_equal(out, REFUSED);

    agent_auth_append_manager_reason(REFUSED, "", out, sizeof(out));
    assert_string_equal(out, REFUSED);
}

static void test_blank_reason_keeps_the_base_message(void **state) {
    (void) state;
    char out[512];

    agent_auth_append_manager_reason(REFUSED, REFUSED_STDERR("  "), out, sizeof(out));

    assert_string_equal(out, REFUSED);
}

static void test_reason_at_end_of_output_without_newline(void **state) {
    (void) state;
    char out[512];

    agent_auth_append_manager_reason(REFUSED, "  " AGENT_AUTH_MANAGER_SAID "Duplicate IP", out,
                                     sizeof(out));

    assert_string_equal(out, "The manager refused the enrollment request: Duplicate IP.");
}

static void test_control_characters_are_neutralized(void **state) {
    (void) state;
    char out[512];

    agent_auth_append_manager_reason(REFUSED, REFUSED_STDERR("bad\tname\x07"), out, sizeof(out));

    assert_string_equal(out, "The manager refused the enrollment request: bad name.");
}

static void test_output_is_truncated_to_the_buffer(void **state) {
    (void) state;
    char out[16];

    agent_auth_append_manager_reason(REFUSED, REFUSED_STDERR("Duplicate name"), out, sizeof(out));

    assert_string_equal(out, "The manager ref");
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_manager_reason_is_appended),
        cmocka_unit_test(test_reason_period_is_not_doubled),
        cmocka_unit_test(test_no_reason_keeps_the_base_message),
        cmocka_unit_test(test_null_or_empty_output_keeps_the_base_message),
        cmocka_unit_test(test_blank_reason_keeps_the_base_message),
        cmocka_unit_test(test_reason_at_end_of_output_without_newline),
        cmocka_unit_test(test_control_characters_are_neutralized),
        cmocka_unit_test(test_output_is_truncated_to_the_buffer),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
