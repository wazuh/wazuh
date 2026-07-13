/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <setjmp.h>
#include <stdio.h>
#include <cmocka.h>
#include <stdlib.h>
#include <string.h>

#include "shared.h"
#include "active_responses.h"
#include "firewall_helpers.h"

static int not_reached_calls = 0;

static firewall_result_t stub_not_available(const char *srcip, int action, int ip_version, const char *argv0) {
    return FIREWALL_NOT_AVAILABLE;
}

static firewall_result_t stub_execution_failed(const char *srcip, int action, int ip_version, const char *argv0) {
    return FIREWALL_EXECUTION_FAILED;
}

static firewall_result_t stub_invalid_state(const char *srcip, int action, int ip_version, const char *argv0) {
    return FIREWALL_INVALID_STATE;
}

static firewall_result_t stub_success(const char *srcip, int action, int ip_version, const char *argv0) {
    return FIREWALL_SUCCESS;
}

/* Used after an expected early exit, to assert the chain never reaches later methods */
static firewall_result_t stub_not_reached(const char *srcip, int action, int ip_version, const char *argv0) {
    not_reached_calls++;
    return FIREWALL_EXECUTION_FAILED;
}

static int test_setup(void **state) {
    not_reached_calls = 0;
    return 0;
}

void test_execute_firewall_chain_all_unavailable(void **state) {
    const firewall_method_t methods[] = {
        {"m1", stub_not_available, false},
        {"m2", stub_not_available, false},
        {NULL, NULL, false}
    };

    int ret = execute_firewall_chain(methods, "203.0.113.10", ENABLE_COMMAND, 4, "test_argv0");

    assert_int_equal(ret, OS_INVALID);
}

void test_execute_firewall_chain_mixed_failures(void **state) {
    const firewall_method_t methods[] = {
        {"m1", stub_not_available, false},
        {"m2", stub_execution_failed, false},
        {"m3", stub_invalid_state, false},
        {NULL, NULL, false}
    };

    int ret = execute_firewall_chain(methods, "203.0.113.11", ENABLE_COMMAND, 4, "test_argv0");

    assert_int_equal(ret, OS_INVALID);
}

void test_execute_firewall_chain_first_method_succeeds(void **state) {
    const firewall_method_t methods[] = {
        {"m1", stub_success, false},
        {"m2", stub_not_reached, false},
        {NULL, NULL, false}
    };

    int ret = execute_firewall_chain(methods, "203.0.113.12", ENABLE_COMMAND, 4, "test_argv0");

    assert_int_equal(ret, OS_SUCCESS);
    assert_int_equal(not_reached_calls, 0);
}

void test_execute_firewall_chain_success_after_earlier_failures(void **state) {
    const firewall_method_t methods[] = {
        {"m1", stub_not_available, false},
        {"m2", stub_execution_failed, false},
        {"m3", stub_success, false},
        {"m4", stub_not_reached, false},
        {NULL, NULL, false}
    };

    int ret = execute_firewall_chain(methods, "203.0.113.13", DISABLE_COMMAND, 6, "test_argv0");

    assert_int_equal(ret, OS_SUCCESS);
    assert_int_equal(not_reached_calls, 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_execute_firewall_chain_all_unavailable, test_setup),
        cmocka_unit_test_setup(test_execute_firewall_chain_mixed_failures, test_setup),
        cmocka_unit_test_setup(test_execute_firewall_chain_first_method_succeeds, test_setup),
        cmocka_unit_test_setup(test_execute_firewall_chain_success_after_earlier_failures, test_setup),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
