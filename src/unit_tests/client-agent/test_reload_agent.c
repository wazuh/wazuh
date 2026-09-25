/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <errno.h>

#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "agentd.h"
#include "../wrappers/wazuh/os_net/os_net_wrappers.h"

/* controlAgent() (reload_agent.c) is static, so reloadAgent() is driven through its
 * one public entry point and exercised via the OS_ConnectUnixDomain/sleep boundary it
 * retries against -- the same "wrap the module boundary, not the internal helper"
 * convention test_agent_report.c already uses for its own socket-based aggregator. */

static int* g_connect_errnos = NULL;
static size_t g_connect_errnos_count = 0;
static size_t g_connect_call = 0;
static int g_connect_call_count = 0;
static int g_closed_fd = -1;

int __wrap_OS_ConnectUnixDomain(const char* path, int type, int max_msg_size)
{
    check_expected(path);
    check_expected(type);
    check_expected(max_msg_size);

    g_connect_call_count++;

    if (g_connect_call >= g_connect_errnos_count)
    {
        /* No more scripted attempts: succeed. */
        return 42;
    }

    int failing_errno = g_connect_errnos[g_connect_call++];

    if (failing_errno == 0)
    {
        return 42;
    }

    errno = failing_errno;
    return -1;
}

int __wrap_OS_SendSecureTCP(int sock, uint32_t size, const void* msg)
{
    check_expected(sock);
    check_expected(size);
    check_expected(msg);

    return 0;
}

int __wrap_close(int fd)
{
    g_closed_fd = fd;
    return 0;
}

unsigned int __wrap_sleep(__attribute__((unused)) unsigned int seconds)
{
    return 0;
}

/* --- Helpers --- */

/// @brief Script the sequence of connect() outcomes controlAgent() will see:
///        one errno per failing attempt, then success. An empty/exhausted
///        sequence means every remaining attempt (beyond the scripted ones)
///        succeeds -- callers that want every attempt to fail must script one
///        entry per attempt (see test_reloadAgent_gives_up_after_max_retries).
static void given_connect_attempts(int* errnos, size_t count)
{
    g_connect_errnos = errnos;
    g_connect_errnos_count = count;
    g_connect_call = 0;
    g_connect_call_count = 0;
    g_closed_fd = -1;

    expect_string_count(__wrap_OS_ConnectUnixDomain, path, CONTROL_SOCK, -1);
    expect_value_count(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM, -1);
    expect_value_count(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR, -1);
}

/// @brief Declare the successful-dispatch expectations: the connected socket
///        actually sends the requested action string and is closed afterwards.
static void expecting_dispatch(const char* action, int expected_sock)
{
    expect_value(__wrap_OS_SendSecureTCP, sock, expected_sock);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(action));
    expect_string(__wrap_OS_SendSecureTCP, msg, action);
}

/// @brief Allow the retry/failure debug and error lines. Only tests that exercise
///        those paths declare this: cmocka fails a test that leaves the
///        expectation unused.
static void expecting_debug_logs(void)
{
    expect_any_always(__wrap__mdebug1, formatted_msg);
}

static void expecting_error_logs(void)
{
    expect_any_always(__wrap__merror, formatted_msg);
}

/* --- Tests --- */

/* Case: ENOTCONN is a real, unrelated failure now that OS_ConnectUnixDomain()
 * preserves connect()'s actual errno instead of clobbering it via shutdown()
 * inside OS_CloseSocket() -- it must fail fast, not be treated as "not ready yet". */
static void test_reloadAgent_fails_immediately_on_ENOTCONN(void** state)
{
    (void)state;
    int errnos[] = {ENOTCONN};

    given_connect_attempts(errnos, 1);
    expecting_error_logs();

    assert_false(reloadAgent());
    assert_int_equal(g_connect_call_count, 1);
}

/* Case: retry-then-succeed on ENOENT (socket file not created yet). */
static void test_reloadAgent_retries_on_ENOENT_then_succeeds(void** state)
{
    (void)state;
    int errnos[] = {ENOENT};

    given_connect_attempts(errnos, 1);
    expecting_debug_logs();
    expecting_dispatch("reload", 42);

    assert_true(reloadAgent());
    assert_int_equal(g_connect_call_count, 2);
    assert_int_equal(g_closed_fd, 42);
}

/* Case: retry-then-succeed on ECONNREFUSED (nothing listening on the socket yet,
 * e.g. modulesd hasn't started/created it, or a stale socket file with no listener). */
static void test_reloadAgent_retries_on_ECONNREFUSED_then_succeeds(void** state)
{
    (void)state;
    int errnos[] = {ECONNREFUSED};

    given_connect_attempts(errnos, 1);
    expecting_debug_logs();
    expecting_dispatch("reload", 42);

    assert_true(reloadAgent());
    assert_int_equal(g_connect_call_count, 2);
    assert_int_equal(g_closed_fd, 42);
}

/* Case: an unrelated errno is a real failure, not a "not ready yet" race -- no retry,
 * fails on the first attempt. */
static void test_reloadAgent_fails_immediately_on_unrelated_errno(void** state)
{
    (void)state;
    int errnos[] = {EACCES};

    given_connect_attempts(errnos, 1);
    expecting_error_logs();

    assert_false(reloadAgent());
    assert_int_equal(g_connect_call_count, 1);
}

/* Case: every attempt keeps failing with a retryable errno; controlAgent() gives up
 * after the configured max_retries rather than retrying forever. */
static void test_reloadAgent_gives_up_after_max_retries(void** state)
{
    (void)state;
    int errnos[CONTROL_AGENT_MAX_RETRIES];
    size_t i;

    for (i = 0; i < CONTROL_AGENT_MAX_RETRIES; i++)
    {
        errnos[i] = ECONNREFUSED;
    }

    given_connect_attempts(errnos, CONTROL_AGENT_MAX_RETRIES);
    expecting_debug_logs();
    expecting_error_logs();

    assert_false(reloadAgent());
    assert_int_equal(g_connect_call_count, CONTROL_AGENT_MAX_RETRIES);
}

int main(void)
{
    const struct CMUnitTest tests[] =
    {
        cmocka_unit_test(test_reloadAgent_fails_immediately_on_ENOTCONN),
        cmocka_unit_test(test_reloadAgent_retries_on_ENOENT_then_succeeds),
        cmocka_unit_test(test_reloadAgent_retries_on_ECONNREFUSED_then_succeeds),
        cmocka_unit_test(test_reloadAgent_fails_immediately_on_unrelated_errno),
        cmocka_unit_test(test_reloadAgent_gives_up_after_max_retries),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
