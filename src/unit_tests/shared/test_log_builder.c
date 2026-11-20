/*
 * Copyright (C) Wazuh Inc.
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

#include "shared.h"
#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/agent_op_wrappers.h"

/* log_builder_init() reads logcollector.ip_update_interval only in the agent build: the function is
 * reached exclusively through mq_log_builder_init() <- logcollector, which is agent-only, so the
 * manager build has no internal option to read and the interval keeps its 0 initializer. Hence the
 * getDefine_Int* mocks below are agent-only too. */
extern int g_ip_update_interval;
extern char g_host_ip[IPSIZE];
extern time_t g_host_ip_last_update;
int log_builder_update_host_ip(log_builder_t * builder);

// Setup / teardown

static int reset_host_ip_state(void **state) {
    *g_host_ip = '\0';
    g_host_ip_last_update = 0;
    return 0;
}

// Helpers

/* Queue the mocks of one host IP request. */
static void expect_host_ip_request() {
#ifdef WIN32
    time_mock_value = 1000;
#endif
    will_return(__wrap_getPrimaryIP, strdup("1.2.3.4"));
}

static log_builder_t * init_builder(int interval, bool host_ip_used) {
#if defined(TEST_AGENT) || defined(TEST_WINAGENT)
    will_return(__wrap_getDefine_Int, interval);
#endif
    log_builder_t * builder = log_builder_init(false, host_ip_used);
#if !defined(TEST_AGENT) && !defined(TEST_WINAGENT)
    g_ip_update_interval = interval;
#endif
    assert_non_null(builder);
    return builder;
}

// Tests

void test_log_builder(void **state)
{
    const char * PATTERN = "location: $(location), log: $(log), escaped: $(json_escaped_log)";
    const char * LOG = "Hello \"World\"";
    const char * LOCATION = "test";
    const char * EXPECTED_OUTPUT = "location: test, log: Hello \"World\", escaped: Hello \\\"World\\\"";

#if defined(TEST_AGENT) || defined(TEST_WINAGENT)
    will_return_always(__wrap_getDefine_Int, 60);
#endif

    log_builder_t * builder = log_builder_init(false, false);

    char * output = log_builder_build(builder, PATTERN, LOG, LOCATION);

    assert_string_equal(output, EXPECTED_OUTPUT);

    free(output);
    log_builder_destroy(builder);
}

void test_log_builder_update(void **state)
{
#if defined(TEST_AGENT) || defined(TEST_WINAGENT)
    will_return_always(__wrap_getDefine_Int, 1);
#endif
    log_builder_t * builder = log_builder_init(false, true);
#if !defined(TEST_AGENT) && !defined(TEST_WINAGENT)
    /* Nothing set it during init in this build, and log_builder_update_host_ip() only refreshes the
     * IP while the interval is positive: set it here so the refresh path is the one under test. */
    g_ip_update_interval = 1;
#endif
    assert_int_equal(g_ip_update_interval, 1);
    assert_non_null(builder);

#ifdef WIN32
    time_mock_value = 1000;
#endif
    will_return(__wrap_getPrimaryIP, NULL);

    int r = log_builder_update_host_ip(builder);
    assert_int_equal(r, 0);
    assert_string_equal(builder->host_ip, "0.0.0.0");
    log_builder_destroy(builder);
}

void test_log_builder_not_update(void **state) {
#if defined(TEST_AGENT) || defined(TEST_WINAGENT)
    will_return_always(__wrap_getDefine_Int, 0);
#endif

    log_builder_t * builder = log_builder_init(false, true);
#if !defined(TEST_AGENT) && !defined(TEST_WINAGENT)
    /* g_ip_update_interval is a global shared by every test in this binary and the previous one left
     * it at 1: reset it, this test is the "interval disabled, no refresh" case. */
    g_ip_update_interval = 0;
#endif
    assert_int_equal(g_ip_update_interval, 0);
    assert_non_null(builder);

    int r = log_builder_update_host_ip(builder);
    assert_int_equal(r, 0);

    log_builder_destroy(builder);
}

// No mock is queued: a request would fail the test.
void test_log_builder_host_ip_not_requested_when_unused(void **state) {
    log_builder_t * builder = init_builder(60, false);

    assert_int_equal(log_builder_update_host_ip(builder), 0);
    assert_int_equal(g_host_ip_last_update, 0);
    assert_string_equal(builder->host_ip, "0.0.0.0");

    log_builder_destroy(builder);
}

void test_log_builder_host_ip_refreshed_when_used(void **state) {
    log_builder_t * builder = init_builder(60, true);

    expect_host_ip_request();
    assert_int_equal(log_builder_update_host_ip(builder), 0);
    assert_string_equal(builder->host_ip, "1.2.3.4");

    g_host_ip_last_update = 0;
    expect_host_ip_request();
    assert_int_equal(log_builder_update_host_ip(builder), 0);

    log_builder_destroy(builder);
}

void test_log_builder_host_ip_used_waits_for_interval(void **state) {
    log_builder_t * builder = init_builder(60, true);

    expect_host_ip_request();
    assert_int_equal(log_builder_update_host_ip(builder), 0);

    // Same time as the first request: the interval has not elapsed.
    assert_int_equal(log_builder_update_host_ip(builder), 0);

    log_builder_destroy(builder);
}

void test_log_builder_uses_host_ip(void **state) {
    assert_true(log_builder_uses_host_ip("ip: $(host_ip)"));
    assert_true(log_builder_uses_host_ip("$(hostname) $(host_ip): $(log)"));
    assert_false(log_builder_uses_host_ip("$(hostname) $(location): $(log)"));
    assert_false(log_builder_uses_host_ip("host_ip"));
    assert_false(log_builder_uses_host_ip(NULL));
}

int main(void) {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup(test_log_builder, reset_host_ip_state),
            cmocka_unit_test_setup(test_log_builder_update, reset_host_ip_state),
            cmocka_unit_test_setup(test_log_builder_not_update, reset_host_ip_state),
            cmocka_unit_test_setup(test_log_builder_host_ip_not_requested_when_unused, reset_host_ip_state),
            cmocka_unit_test_setup(test_log_builder_host_ip_refreshed_when_used, reset_host_ip_state),
            cmocka_unit_test_setup(test_log_builder_host_ip_used_waits_for_interval, reset_host_ip_state),
            cmocka_unit_test(test_log_builder_uses_host_ip),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
