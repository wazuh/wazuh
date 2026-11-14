/*
 * Copyright (C) Wazuh Inc.
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
#include <fcntl.h>
#include <unistd.h>

#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "shared.h"
#include "os_err.h"
#include "vd_offset_client.h"

/* POSIX branch of vd_offset_client.c: how a query that gets no valid answer from agent-info is
 * logged.
 *
 * The socket wrappers are local rather than the shared os_net ones because the shared
 * OS_RecvSecureTCP wrapper cannot set errno, and errno is what tells a timeout apart. The
 * connection hands back a descriptor that is known to be closed, so the real close() that follows
 * the send or the receive fails with EBADF: a test that still sees the earlier errno proves it was
 * taken before close(). */

#define OK_RESPONSE    "{\"error\":0,\"data\":{\"changed\":true,\"pending\":false,\"pending_offset\":0}}"
#define ERROR_RESPONSE "{\"error\":5,\"message\":\"busy\"}"
#define TIMEOUT_REASON "agent-info did not answer within 5 seconds"
#define TIMEOUT_MSG    "vd_offset_client: " TIMEOUT_REASON "; will retry next notify."
#define WARN_SUFFIX    "; vulnerability rescan requests wait until it answers."

/* Not static in unit-test builds, so each test starts without a streak. */
void vd_offset_streak_reset(void);

static time_t g_now = 1000;
static int g_closed_fd = -1;

int __wrap_OS_ConnectUnixDomain(__attribute__((unused)) const char* path,
                                __attribute__((unused)) int type,
                                __attribute__((unused)) int max_msg_size)
{
    const int ret = mock_type(int);
    errno = mock_type(int);
    return ret;
}

int __wrap_OS_SetRecvTimeout(__attribute__((unused)) int socket,
                             __attribute__((unused)) long seconds,
                             __attribute__((unused)) long useconds)
{
    return 0;
}

int __wrap_OS_SendSecureTCP(__attribute__((unused)) int sock,
                            __attribute__((unused)) uint32_t size,
                            __attribute__((unused)) const void* msg)
{
    const int ret = mock_type(int);
    errno = mock_type(int);
    return ret;
}

int __wrap_OS_RecvSecureTCP(__attribute__((unused)) int sock, char* ret, uint32_t size)
{
    const char* response = mock_ptr_type(const char*);
    const int recv_errno = mock_type(int);
    const int recv_ret = mock_type(int);

    strncpy(ret, response, size);
    errno = recv_errno;
    return recv_ret;
}

/* Local rather than the shared one, which would pull in wrappers this test does not link. */
int __wrap_usleep(__attribute__((unused)) useconds_t usec)
{
    function_called();
    return 0;
}

time_t __wrap_w_get_monotonic_time(void)
{
    return g_now;
}

static int setup(void** state)
{
    (void)state;

    /* A descriptor number that is free right now, and stays free: nothing in these tests opens
     * files between here and the close() under test. */
    g_closed_fd = open("/dev/null", O_RDONLY);
    if (g_closed_fd < 0 || close(g_closed_fd) != 0)
    {
        return -1;
    }

    vd_offset_streak_reset();
    g_now = 1000;
    return 0;
}

static void expect_connected(void)
{
    will_return(__wrap_OS_ConnectUnixDomain, g_closed_fd);
    will_return(__wrap_OS_ConnectUnixDomain, 0);
}

static void expect_sent(void)
{
    will_return(__wrap_OS_SendSecureTCP, 0);
    will_return(__wrap_OS_SendSecureTCP, 0);
}

static void expect_query(int recv_ret, int recv_errno, const char* response)
{
    expect_connected();
    expect_sent();
    will_return(__wrap_OS_RecvSecureTCP, response);
    will_return(__wrap_OS_RecvSecureTCP, recv_errno);
    will_return(__wrap_OS_RecvSecureTCP, recv_ret);
}

static void expect_answer(const char* response)
{
    expect_query((int)strlen(response), 0, response);
}

static void expect_debug(const char* msg)
{
    expect_string(__wrap__mdebug1, formatted_msg, msg);
}

static void expect_warn(const char* msg)
{
    expect_string(__wrap__mwarn, formatted_msg, msg);
}

static void observe_fails(void)
{
    bool changed = true;
    bool pending = true;
    uint64_t pending_offset = 7;

    assert_false(vd_offset_client_observe(42, &changed, &pending, &pending_offset));
    assert_false(changed);
    assert_false(pending);
    assert_int_equal(pending_offset, 0);
}

static void observe_answers(void)
{
    bool changed = false;

    expect_answer(OK_RESPONSE);
    assert_true(vd_offset_client_observe(42, &changed, NULL, NULL));
    assert_true(changed);
}

static void timeout_at(time_t now)
{
    g_now = now;
    expect_query(-1, EAGAIN, "");
    expect_debug(TIMEOUT_MSG);
    observe_fails();
}

static void answer_after(time_t now, const char* recovery_msg)
{
    g_now = now;
    expect_debug(recovery_msg);
    observe_answers();
}

/* Tests */

static void test_timeout_is_debug(void** state)
{
    (void)state;

    timeout_at(1000);
    answer_after(1010, "vd_offset_client: agent-info answered again after 10 seconds (1 failed queries).");
}

static void test_peer_closed_is_debug(void** state)
{
    (void)state;

    expect_query(0, 0, "");
    expect_debug("vd_offset_client: no/invalid response from agent-info (recv_len=0); will retry next notify.");
    observe_fails();
}

static void test_oversized_response_is_an_error(void** state)
{
    (void)state;
    char msg[OS_MAXSTR];

    snprintf(msg,
             sizeof(msg),
             "vd_offset_client: agent-info response is longer than %d bytes (recv_len=%d).",
             OS_MAXSTR,
             OS_SOCKTERR);

    expect_query(OS_SOCKTERR, 0, "");
    expect_string(__wrap__merror, formatted_msg, msg);
    observe_fails();

    /* It still counts toward the streak. */
    answer_after(1000, "vd_offset_client: agent-info answered again after 0 seconds (1 failed queries).");
}

static void test_other_errno_is_debug_with_the_receive_errno(void** state)
{
    (void)state;
    char msg[OS_MAXSTR];

    snprintf(msg,
             sizeof(msg),
             "vd_offset_client: no response from agent-info: %s (%d); will retry next notify.",
             strerror(ECONNRESET),
             ECONNRESET);

    expect_query(-1, ECONNRESET, "");
    expect_debug(msg);
    observe_fails();
}

static void test_connect_failure_counts_toward_the_streak(void** state)
{
    (void)state;
    char msg[OS_MAXSTR];
    int attempt;

    /* The agent's path: the client is built with CLIENT, this test is not, so WM_LOCAL_SOCK differs here. */
    snprintf(msg,
             sizeof(msg),
             "vd_offset_client: could not connect to 'queue/sockets/wmodules' after 10 attempt(s): %s (%d); "
             "will retry next notify.",
             strerror(ECONNREFUSED),
             ECONNREFUSED);

    for (attempt = 0; attempt < 10; attempt++)
    {
        will_return(__wrap_OS_ConnectUnixDomain, -1);
        will_return(__wrap_OS_ConnectUnixDomain, ECONNREFUSED);
    }
    expect_function_calls(__wrap_usleep, 9);
    expect_debug(msg);
    observe_fails();

    answer_after(1020, "vd_offset_client: agent-info answered again after 20 seconds (1 failed queries).");
}

static void test_send_failure_is_debug_with_the_send_errno(void** state)
{
    (void)state;
    char msg[OS_MAXSTR];

    snprintf(msg,
             sizeof(msg),
             "vd_offset_client: could not send the query to agent-info: %s (%d); will retry next notify.",
             strerror(EPIPE),
             EPIPE);

    expect_connected();
    will_return(__wrap_OS_SendSecureTCP, OS_SOCKTERR);
    will_return(__wrap_OS_SendSecureTCP, EPIPE);
    expect_debug(msg);
    observe_fails();

    answer_after(1010, "vd_offset_client: agent-info answered again after 10 seconds (1 failed queries).");
}

static void test_error_answer_does_not_end_the_streak(void** state)
{
    (void)state;

    timeout_at(1000);

    /* agent-info answers, but with an error: still no valid answer. */
    g_now = 1150;
    expect_answer(ERROR_RESPONSE);
    expect_debug("vd_offset_client: agent-info reported an error (5): busy; will retry next notify.");
    observe_fails();

    g_now = 1300;
    expect_answer(ERROR_RESPONSE);
    expect_debug("vd_offset_client: agent-info reported an error (5): busy; will retry next notify.");
    expect_warn("vd_offset_client: no valid response from agent-info for 300 seconds "
                "(3 failed queries; last: agent-info reported an error (5): busy)" WARN_SUFFIX);
    observe_fails();

    answer_after(1310, "vd_offset_client: agent-info answered again after 310 seconds (3 failed queries).");
}

static void test_malformed_answer_counts_toward_the_streak(void** state)
{
    (void)state;

    expect_answer("not json");
    expect_debug("vd_offset_client: malformed response from agent-info: 'not json'; will retry next notify.");
    observe_fails();

    answer_after(1010, "vd_offset_client: agent-info answered again after 10 seconds (1 failed queries).");
}

static void test_warns_every_interval_without_an_answer(void** state)
{
    (void)state;

    timeout_at(1000);
    timeout_at(1299);

    g_now = 1300;
    expect_query(-1, EAGAIN, "");
    expect_debug(TIMEOUT_MSG);
    expect_warn("vd_offset_client: no valid response from agent-info for 300 seconds "
                "(3 failed queries; last: " TIMEOUT_REASON ")" WARN_SUFFIX);
    observe_fails();

    timeout_at(1301);
    timeout_at(1599);

    g_now = 1600;
    expect_query(-1, EAGAIN, "");
    expect_debug(TIMEOUT_MSG);
    expect_warn("vd_offset_client: no valid response from agent-info for 600 seconds "
                "(6 failed queries; last: " TIMEOUT_REASON ")" WARN_SUFFIX);
    observe_fails();

    answer_after(1601, "vd_offset_client: agent-info answered again after 601 seconds (6 failed queries).");
}

static void test_an_answer_restarts_the_interval(void** state)
{
    (void)state;

    timeout_at(2000);
    answer_after(2290, "vd_offset_client: agent-info answered again after 290 seconds (1 failed queries).");

    /* 350 s after the first failure, but the answer in between started a new streak. */
    timeout_at(2350);
    timeout_at(2649);

    g_now = 2650;
    expect_query(-1, EAGAIN, "");
    expect_debug(TIMEOUT_MSG);
    expect_warn("vd_offset_client: no valid response from agent-info for 300 seconds "
                "(3 failed queries; last: " TIMEOUT_REASON ")" WARN_SUFFIX);
    observe_fails();

    answer_after(2651, "vd_offset_client: agent-info answered again after 301 seconds (3 failed queries).");
}

static void test_a_gap_without_queries_starts_a_new_streak(void** state)
{
    (void)state;

    /* One failure, then 20 minutes without any query (agent disconnected, or no offset sent). */
    timeout_at(1000);
    timeout_at(2200);

    /* The streak runs from 2200, not from 1000. */
    timeout_at(2499);

    g_now = 2500;
    expect_query(-1, EAGAIN, "");
    expect_debug(TIMEOUT_MSG);
    expect_warn("vd_offset_client: no valid response from agent-info for 300 seconds "
                "(3 failed queries; last: " TIMEOUT_REASON ")" WARN_SUFFIX);
    observe_fails();

    answer_after(2510, "vd_offset_client: agent-info answered again after 310 seconds (3 failed queries).");
}

static void test_a_gap_up_to_the_interval_keeps_the_streak(void** state)
{
    (void)state;

    timeout_at(1000);

    g_now = 1300;
    expect_query(-1, EAGAIN, "");
    expect_debug(TIMEOUT_MSG);
    expect_warn("vd_offset_client: no valid response from agent-info for 300 seconds "
                "(2 failed queries; last: " TIMEOUT_REASON ")" WARN_SUFFIX);
    observe_fails();
}

static void test_answer_without_a_streak_logs_nothing(void** state)
{
    (void)state;

    observe_answers();
}

static void test_clear_pending_timeout_is_debug(void** state)
{
    (void)state;

    expect_query(-1, EWOULDBLOCK, "");
    expect_debug(TIMEOUT_MSG);
    assert_false(vd_offset_client_clear_pending(42));

    g_now = 1005;
    expect_debug("vd_offset_client: agent-info answered again after 5 seconds (1 failed queries).");
    expect_answer("{\"error\":0,\"data\":{\"cleared\":true}}");
    assert_true(vd_offset_client_clear_pending(42));
}

static void test_clear_pending_error_answer_counts_toward_the_streak(void** state)
{
    (void)state;

    expect_answer(ERROR_RESPONSE);
    expect_debug("vd_offset_client: agent-info reported an error (5): busy; will retry next notify.");
    assert_false(vd_offset_client_clear_pending(42));

    answer_after(1010, "vd_offset_client: agent-info answered again after 10 seconds (1 failed queries).");
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_timeout_is_debug, setup),
        cmocka_unit_test_setup(test_peer_closed_is_debug, setup),
        cmocka_unit_test_setup(test_oversized_response_is_an_error, setup),
        cmocka_unit_test_setup(test_other_errno_is_debug_with_the_receive_errno, setup),
        cmocka_unit_test_setup(test_connect_failure_counts_toward_the_streak, setup),
        cmocka_unit_test_setup(test_send_failure_is_debug_with_the_send_errno, setup),
        cmocka_unit_test_setup(test_error_answer_does_not_end_the_streak, setup),
        cmocka_unit_test_setup(test_malformed_answer_counts_toward_the_streak, setup),
        cmocka_unit_test_setup(test_warns_every_interval_without_an_answer, setup),
        cmocka_unit_test_setup(test_an_answer_restarts_the_interval, setup),
        cmocka_unit_test_setup(test_a_gap_without_queries_starts_a_new_streak, setup),
        cmocka_unit_test_setup(test_a_gap_up_to_the_interval_keeps_the_streak, setup),
        cmocka_unit_test_setup(test_answer_without_a_streak_logs_nothing, setup),
        cmocka_unit_test_setup(test_clear_pending_timeout_is_debug, setup),
        cmocka_unit_test_setup(test_clear_pending_error_answer_counts_toward_the_streak, setup),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
