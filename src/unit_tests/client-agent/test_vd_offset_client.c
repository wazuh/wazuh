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

#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "shared.h"
#include "os_err.h"
#include "vd_offset_client.h"

/* POSIX branch of vd_offset_client.c: how a query that gets no answer from agent-info is logged.
 *
 * The socket wrappers are local rather than the shared os_net ones because the shared
 * OS_RecvSecureTCP wrapper cannot set errno, and errno is what tells a timeout apart. The
 * connection hands back a descriptor that is not open, so the real close() that follows the
 * receive fails with EBADF: a test that still sees the receive's errno proves it was taken
 * before close().
 *
 * The no-answer streak is file-static state in the client, and only a valid answer ends it, so
 * every test that fails a query finishes with one. */

#define TEST_SOCK 999
#define OK_RESPONSE "{\"error\":0,\"data\":{\"changed\":true,\"pending\":false,\"pending_offset\":0}}"
#define TIMEOUT_MSG "vd_offset_client: agent-info did not answer within 5 seconds; will retry next notify."

static time_t g_now = 1000;

int __wrap_OS_ConnectUnixDomain(__attribute__((unused)) const char *path,
                                __attribute__((unused)) int type,
                                __attribute__((unused)) int max_msg_size) {
    return mock();
}

int __wrap_OS_SetRecvTimeout(__attribute__((unused)) int socket,
                             __attribute__((unused)) long seconds,
                             __attribute__((unused)) long useconds) {
    return 0;
}

int __wrap_OS_SendSecureTCP(__attribute__((unused)) int sock,
                            __attribute__((unused)) uint32_t size,
                            __attribute__((unused)) const void *msg) {
    return 0;
}

int __wrap_OS_RecvSecureTCP(__attribute__((unused)) int sock, char *ret, uint32_t size) {
    const char *response = mock_ptr_type(const char *);
    const int recv_errno = mock_type(int);
    const int recv_ret = mock_type(int);

    strncpy(ret, response, size);
    errno = recv_errno;
    return recv_ret;
}

time_t __wrap_w_get_monotonic_time(void) {
    return g_now;
}

static void expect_query(int recv_ret, int recv_errno, const char *response) {
    will_return(__wrap_OS_ConnectUnixDomain, TEST_SOCK);
    will_return(__wrap_OS_RecvSecureTCP, response);
    will_return(__wrap_OS_RecvSecureTCP, recv_errno);
    will_return(__wrap_OS_RecvSecureTCP, recv_ret);
}

static void expect_debug(const char *msg) {
    expect_string(__wrap__mdebug1, formatted_msg, msg);
}

static void observe_fails(void) {
    bool changed = true;
    bool pending = true;
    uint64_t pending_offset = 7;

    assert_false(vd_offset_client_observe(42, &changed, &pending, &pending_offset));
    assert_false(changed);
    assert_false(pending);
    assert_int_equal(pending_offset, 0);
}

static void observe_answers(void) {
    bool changed = false;

    expect_query((int)strlen(OK_RESPONSE), 0, OK_RESPONSE);
    assert_true(vd_offset_client_observe(42, &changed, NULL, NULL));
    assert_true(changed);
}

static void timeout_at(time_t now) {
    g_now = now;
    expect_query(-1, EAGAIN, "");
    expect_debug(TIMEOUT_MSG);
    observe_fails();
}

static void answer_after(time_t now, const char *recovery_msg) {
    g_now = now;
    expect_debug(recovery_msg);
    observe_answers();
}

/* Tests */

static void test_timeout_is_debug(void **state) {
    (void)state;

    timeout_at(1000);
    answer_after(1010, "vd_offset_client: agent-info answered again after 10 seconds.");
}

static void test_peer_closed_is_debug(void **state) {
    (void)state;

    g_now = 1000;
    expect_query(0, 0, "");
    expect_debug("vd_offset_client: no/invalid response from agent-info (recv_len=0); will retry next notify.");
    observe_fails();

    answer_after(1000, "vd_offset_client: agent-info answered again after 0 seconds.");
}

static void test_oversized_response_is_debug(void **state) {
    (void)state;

    g_now = 1000;
    expect_query(OS_SOCKTERR, 0, "");
    expect_debug("vd_offset_client: no/invalid response from agent-info (recv_len=-6); will retry next notify.");
    observe_fails();

    answer_after(1000, "vd_offset_client: agent-info answered again after 0 seconds.");
}

static void test_other_errno_is_debug_with_the_receive_errno(void **state) {
    (void)state;
    char msg[OS_MAXSTR];

    snprintf(msg, sizeof(msg), "vd_offset_client: no response from agent-info: %s (%d); will retry next notify.",
             strerror(ECONNRESET), ECONNRESET);

    g_now = 1000;
    expect_query(-1, ECONNRESET, "");
    expect_debug(msg);
    observe_fails();

    answer_after(1000, "vd_offset_client: agent-info answered again after 0 seconds.");
}

static void test_warns_every_interval_without_an_answer(void **state) {
    (void)state;

    timeout_at(1000);
    timeout_at(1299);

    g_now = 1300;
    expect_query(-1, EAGAIN, "");
    expect_debug(TIMEOUT_MSG);
    expect_string(__wrap__mwarn, formatted_msg,
                  "vd_offset_client: no valid response from agent-info for 300 seconds; "
                  "vulnerability rescan requests wait until it answers.");
    observe_fails();

    timeout_at(1301);
    timeout_at(1599);

    g_now = 1600;
    expect_query(-1, EAGAIN, "");
    expect_debug(TIMEOUT_MSG);
    expect_string(__wrap__mwarn, formatted_msg,
                  "vd_offset_client: no valid response from agent-info for 600 seconds; "
                  "vulnerability rescan requests wait until it answers.");
    observe_fails();

    answer_after(1601, "vd_offset_client: agent-info answered again after 601 seconds.");
}

static void test_an_answer_restarts_the_interval(void **state) {
    (void)state;

    timeout_at(2000);
    answer_after(2290, "vd_offset_client: agent-info answered again after 290 seconds.");

    /* 350 s after the first failure, but the answer in between started a new streak. */
    timeout_at(2350);
    timeout_at(2649);

    g_now = 2650;
    expect_query(-1, EAGAIN, "");
    expect_debug(TIMEOUT_MSG);
    expect_string(__wrap__mwarn, formatted_msg,
                  "vd_offset_client: no valid response from agent-info for 300 seconds; "
                  "vulnerability rescan requests wait until it answers.");
    observe_fails();

    answer_after(2651, "vd_offset_client: agent-info answered again after 301 seconds.");
}

static void test_answer_without_a_streak_logs_nothing(void **state) {
    (void)state;

    g_now = 3000;
    observe_answers();
}

static void test_clear_pending_timeout_is_debug(void **state) {
    (void)state;

    g_now = 4000;
    expect_query(-1, EWOULDBLOCK, "");
    expect_debug(TIMEOUT_MSG);
    assert_false(vd_offset_client_clear_pending(42));

    answer_after(4005, "vd_offset_client: agent-info answered again after 5 seconds.");
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_timeout_is_debug),
        cmocka_unit_test(test_peer_closed_is_debug),
        cmocka_unit_test(test_oversized_response_is_debug),
        cmocka_unit_test(test_other_errno_is_debug_with_the_receive_errno),
        cmocka_unit_test(test_warns_every_interval_without_an_answer),
        cmocka_unit_test(test_an_answer_restarts_the_interval),
        cmocka_unit_test(test_answer_without_a_streak_logs_nothing),
        cmocka_unit_test(test_clear_pending_timeout_is_debug),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
