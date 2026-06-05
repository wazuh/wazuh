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

#include "../client-agent/agentd.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

#define DUMMY_VALID_SOCKET_FD 1

/* Inline wrappers for run_notify dependencies — defined here to avoid
 * pulling in file_op.c.o via __real_getuname, which transitively
 * requires __wrap__merror_exit from libwazuh_test.a. */

time_t __wrap_w_get_monotonic_time(void) {
    return mock_type(time_t);
}

int __wrap_send_msg(const char *msg, ssize_t msg_length) {
    check_expected(msg);
    return 0;
}

void __wrap_w_agentd_state_update(w_agentd_state_update_t type, void *data) {
    check_expected(type);
}

/* Reset file-scope statics in notify.c for test isolation */
extern void notify_reset_saved_time(void);

static int setup(void **state) {
    static agent global_config;
    agt = &global_config;
    // force init value on every call
    agt->sock = DUMMY_VALID_SOCKET_FD;
    errno = 0;
    return 0;
}

static int setup_run_notify(void **state) {
    static agent global_config;
    memset(&global_config, 0, sizeof(global_config));
    agt = &global_config;
    agt->sock = DUMMY_VALID_SOCKET_FD;
    agt->notify_time = 60;
    agt->max_time_reconnect_try = 3600;
    agt->force_reconnect_interval = 0;
    agt->main_ip_update_interval = 3600;
    agt->labels = NULL;
    available_server = 2000;
    errno = 0;
    notify_reset_saved_time();
    clear_merged_hash_cache();
    return 0;
}

#ifdef TEST_AGENT
// get_agent_ip
static void get_agent_ip_fail_to_connect(void **state) {
    char *retval;

    will_return(__wrap_getsockname, -1);
    will_return(__wrap_getsockname, AF_UNSPEC);

    errno = ENOTSOCK;
    expect_string(__wrap__mdebug2, formatted_msg, "getsockname() failed: Socket operation on non-socket");

    retval = get_agent_ip();

    assert_string_equal(retval, "");

    free(retval);
}

static void get_agent_ip_invalid_socket(void **state) {
    char *retval;

    // force bad socket id
    agt->sock = 0;
    errno = EBADF;
    expect_string(__wrap__mdebug2, formatted_msg, "getsockname() failed: Bad file descriptor");

    retval = get_agent_ip();

    assert_string_equal(retval, "");

    free(retval);
}

static void get_agent_ip_unknown_address_family(void **state) {
    char *retval;

    will_return(__wrap_getsockname, 0);
    will_return(__wrap_getsockname, AF_UNIX);

    expect_string(__wrap__mdebug2, formatted_msg, "Unknown address family: 1");

    retval = get_agent_ip();

    assert_string_equal(retval, "");

    free(retval);
}

static void get_agent_ip_ipv4_updated_successfully(void **state) {
    char *retval;
    static const char* const IPV4_ADDRESS = "10.1.2.3";

    expect_any(__wrap_get_ipv4_string, address_size);
    will_return(__wrap_get_ipv4_string, OS_SUCCESS);
    will_return(__wrap_get_ipv4_string, IPV4_ADDRESS);

    will_return(__wrap_getsockname, 0);
    will_return(__wrap_getsockname, AF_INET);

    retval = get_agent_ip();

    assert_string_equal(retval, IPV4_ADDRESS);

    free(retval);
}

static void get_agent_ip_ipv6_updated_successfully(void **state) {
    char *retval;
    static const char* const IPV6_ADDRESS = "2001:0db8:3c4d:0015:0000:0000:1a2f:1a2b";

    expect_any(__wrap_get_ipv6_string, address_size);
    will_return(__wrap_get_ipv6_string, OS_SUCCESS);
    will_return(__wrap_get_ipv6_string, IPV6_ADDRESS);

    will_return(__wrap_getsockname, 0);
    will_return(__wrap_getsockname, AF_INET6);

    retval = get_agent_ip();

    assert_string_equal(retval, IPV6_ADDRESS);

    free(retval);
}

#endif // TEST_AGENT

#ifdef TEST_AGENT

/* run_notify scheduling tests — monotonic clock fix (issue #36260) */

static void test_run_notify_skips_when_not_enough_time(void **state) {
    /* First call: g_saved_time is 0, gets set to mono_now=1000.
     * Elapsed = 0 < notify_time=60 → early return, no keepalive. */
    will_return(__wrap_w_get_monotonic_time, (time_t)1000);
    will_return(__wrap_time, (time_t)2000);

    run_notify();
}

static void test_run_notify_skips_on_clock_rollback(void **state) {
    /* Initialize g_saved_time to 1000. */
    will_return(__wrap_w_get_monotonic_time, (time_t)1000);
    will_return(__wrap_time, (time_t)2000);
    run_notify();

    /* Simulate wall-clock rollback: w_get_monotonic_time() returns 500 < 1000.
     * (mono_now - g_saved_time) = -500 < notify_time=60 → early return.
     * This proves the guard is safe against backwards values. */
    will_return(__wrap_w_get_monotonic_time, (time_t)500);
    will_return(__wrap_time, (time_t)2000);
    run_notify();
}

#endif // TEST_AGENT (run_notify tests)

int main(void) {
    const struct CMUnitTest tests[] = {
#ifdef TEST_AGENT
        cmocka_unit_test_setup(get_agent_ip_fail_to_connect, setup),
        cmocka_unit_test_setup(get_agent_ip_invalid_socket, setup),
        cmocka_unit_test_setup(get_agent_ip_unknown_address_family, setup),
        cmocka_unit_test_setup(get_agent_ip_ipv4_updated_successfully, setup),
        cmocka_unit_test_setup(get_agent_ip_ipv6_updated_successfully, setup),
        cmocka_unit_test_setup(test_run_notify_skips_when_not_enough_time, setup_run_notify),
        cmocka_unit_test_setup(test_run_notify_skips_on_clock_rollback, setup_run_notify),
#endif // TEST_AGENT
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
