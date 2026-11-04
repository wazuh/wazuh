/*
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Tests for wm_sendmsg_with_reconnect(), the send helper that reopens the queue
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <errno.h>
#include <stdint.h>

#include "wmodules.h"

#define MESSAGE "{\"event\":\"test\"}"
#define LOCMSG "ms-graph"
#define TAG "wazuh-modulesd:ms-graph"
#define OLD_QUEUE 5
#define NEW_QUEUE 7

typedef bool (*predicate_t)(void);

// The predicates the helper hands to each wait, send and reopen, in call order.
static predicate_t predicates[8];
static size_t predicate_count;

// expect_check() callbacks: keep the predicate passed, and optionally stand in for a SIGTERM to modulesd
// arriving during the wait.
static int keep_predicate(const LargestIntegralType value, __attribute__((unused)) const LargestIntegralType data) {
    if (predicate_count < sizeof(predicates) / sizeof(predicates[0])) {
        predicates[predicate_count++] = (predicate_t)(uintptr_t)value;
    }
    return 1;
}

static int shutdown_during_wait(const LargestIntegralType value, const LargestIntegralType data) {
    wm_shutdown_requested = 1;
    return keep_predicate(value, data);
}

static int setup(__attribute__((unused)) void **state) {
    wm_shutdown_requested = 0;
    predicate_count = 0;
    errno = ECONNREFUSED;
    return 0;
}

static int teardown(__attribute__((unused)) void **state) {
    wm_shutdown_requested = 0;
    return 0;
}

static void expect_wait(void) {
    expect_check(__wrap_os_wait_predicate, fn_ptr, keep_predicate, 0);
}

static void expect_shutdown_during_wait(void) {
    expect_check(__wrap_os_wait_predicate, fn_ptr, shutdown_during_wait, 0);
}

static void expect_send(int queue, int ret) {
    expect_value(__wrap_SendMSGPredicated, queue, queue);
    expect_string(__wrap_SendMSGPredicated, message, MESSAGE);
    expect_string(__wrap_SendMSGPredicated, locmsg, LOCMSG);
    expect_value(__wrap_SendMSGPredicated, loc, LOCALFILE_MQ);
    expect_check(__wrap_SendMSGPredicated, fn_ptr, keep_predicate, 0);
    will_return(__wrap_SendMSGPredicated, ret);

    if (ret < 0) {
        expect_string(__wrap__mdebug1, formatted_msg, "Unable to send message to queue: (Connection refused)");
    }
}

static void expect_reopen(int ret) {
    expect_string(__wrap_MQReconnectPredicated, path, DEFAULTQUEUE);
    expect_check(__wrap_MQReconnectPredicated, fn_ptr, keep_predicate, 0);
    will_return(__wrap_MQReconnectPredicated, ret);

    if (ret >= 0) {
        expect_string(__wrap__mtinfo, tag, TAG);
        expect_string(__wrap__mtinfo, formatted_msg, "(8300): Successfully reconnected to 'queue/sockets/queue'");
    }
}

struct timeval wm_sendmsg_timeval(int usec);

static void test_delay_keeps_microseconds_below_a_second(__attribute__((unused)) void **state) {
    struct timeval one_second = wm_sendmsg_timeval(1000000);
    struct timeval short_delay = wm_sendmsg_timeval(10000);
    struct timeval long_delay = wm_sendmsg_timeval(2500000);

    // max_eps=1: select() on macOS refuses tv_usec of a second or more, and then doesn't wait at all.
    assert_int_equal(one_second.tv_sec, 1);
    assert_int_equal(one_second.tv_usec, 0);
    assert_int_equal(short_delay.tv_sec, 0);
    assert_int_equal(short_delay.tv_usec, 10000);
    assert_int_equal(long_delay.tv_sec, 2);
    assert_int_equal(long_delay.tv_usec, 500000);
}

static void expect_not_sent_log(void) {
    expect_string(__wrap__mtdebug1, tag, TAG);
    expect_string(__wrap__mtdebug1, formatted_msg,
                  "Message not sent: modulesd is stopping and the agent can't reach the manager.");
}

static int send_message(int *queue) {
    return wm_sendmsg_with_reconnect(0, queue, MESSAGE, LOCMSG, LOCALFILE_MQ, TAG);
}

static void test_sent_on_first_try(__attribute__((unused)) void **state) {
    int queue = OLD_QUEUE;

    expect_wait();
    expect_send(OLD_QUEUE, 0);

    assert_int_equal(send_message(&queue), 0);
    assert_int_equal(queue, OLD_QUEUE);
}

static void test_failed_send_reopens_and_resends(__attribute__((unused)) void **state) {
    int queue = OLD_QUEUE;

    expect_wait();
    expect_send(OLD_QUEUE, -1);
    expect_reopen(NEW_QUEUE);
    expect_wait();
    expect_send(NEW_QUEUE, 0);

    assert_int_equal(send_message(&queue), 0);
    assert_int_equal(queue, NEW_QUEUE);
}

static void test_failed_resend_drops_the_queue(__attribute__((unused)) void **state) {
    int queue = OLD_QUEUE;

    expect_wait();
    expect_send(OLD_QUEUE, -1);
    expect_reopen(NEW_QUEUE);
    expect_wait();
    expect_send(NEW_QUEUE, -1);

    assert_int_equal(send_message(&queue), -1);
    // SendMSGAction() closed the reopened descriptor too, and another thread may get its number next.
    assert_int_equal(queue, -1);
}

static void test_shutdown_while_reopening(__attribute__((unused)) void **state) {
    int queue = OLD_QUEUE;

    expect_wait();
    expect_send(OLD_QUEUE, -1);
    expect_reopen(-1);

    assert_int_equal(send_message(&queue), -1);
    // The stale descriptor is not kept: SendMSGAction() already closed it and the number may be reused.
    assert_int_equal(queue, -1);
}

static void test_shutdown_while_the_agent_is_paused_sends_nothing(__attribute__((unused)) void **state) {
    int queue = OLD_QUEUE;

    // The agent can't reach the manager and may stop before it does: the caller keeps the message.
    expect_shutdown_during_wait();
    will_return(__wrap_os_iswait, true);
    expect_not_sent_log();

    assert_int_equal(send_message(&queue), -1);
    assert_int_equal(queue, OLD_QUEUE);
}

static void test_shutdown_with_the_agent_connected_still_sends(__attribute__((unused)) void **state) {
    int queue = OLD_QUEUE;

    // A reload stops modulesd but keeps wazuh-agentd running, connected: the message still reaches it.
    expect_shutdown_during_wait();
    will_return(__wrap_os_iswait, false);
    expect_send(OLD_QUEUE, 0);

    assert_int_equal(send_message(&queue), 0);
}

static void test_once_stopping_the_helper_waits_no_more(__attribute__((unused)) void **state) {
    int queue = OLD_QUEUE;

    // No os_wait_predicate() expectation: a wait, and its log lines, would fail the test.
    wm_shutdown_requested = 1;
    will_return(__wrap_os_iswait, true);
    expect_not_sent_log();

    assert_int_equal(send_message(&queue), -1);
    assert_int_equal(queue, OLD_QUEUE);
}

static void test_shutdown_after_reopening_keeps_the_new_queue(__attribute__((unused)) void **state) {
    int queue = OLD_QUEUE;

    expect_wait();
    expect_send(OLD_QUEUE, -1);
    expect_reopen(NEW_QUEUE);
    expect_shutdown_during_wait();
    will_return(__wrap_os_iswait, true);
    expect_not_sent_log();

    assert_int_equal(send_message(&queue), -1);
    // Nothing was sent through it: the reopened descriptor is still open and stays the caller's.
    assert_int_equal(queue, NEW_QUEUE);
}

static void test_waits_stop_on_shutdown_and_sends_wait_no_more(__attribute__((unused)) void **state) {
    int queue = OLD_QUEUE;

    expect_wait();
    expect_send(OLD_QUEUE, -1);
    expect_reopen(NEW_QUEUE);
    expect_wait();
    expect_send(NEW_QUEUE, 0);

    send_message(&queue);

    // In call order: wait, send, reopen, wait, send. The waits and the reopen end on shutdown; the sends
    // don't wait again, since the helper has just waited.
    assert_int_equal(predicate_count, 5);
    assert_ptr_equal(predicates[2], predicates[0]);
    assert_ptr_equal(predicates[3], predicates[0]);
    assert_ptr_equal(predicates[4], predicates[1]);
    assert_true(predicates[1]());
    assert_false(predicates[0]());
    wm_shutdown_requested = 1;
    assert_true(predicates[0]());
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_delay_keeps_microseconds_below_a_second),
        cmocka_unit_test_setup_teardown(test_sent_on_first_try, setup, teardown),
        cmocka_unit_test_setup_teardown(test_failed_send_reopens_and_resends, setup, teardown),
        cmocka_unit_test_setup_teardown(test_failed_resend_drops_the_queue, setup, teardown),
        cmocka_unit_test_setup_teardown(test_shutdown_while_reopening, setup, teardown),
        cmocka_unit_test_setup_teardown(test_shutdown_while_the_agent_is_paused_sends_nothing, setup, teardown),
        cmocka_unit_test_setup_teardown(test_shutdown_with_the_agent_connected_still_sends, setup, teardown),
        cmocka_unit_test_setup_teardown(test_once_stopping_the_helper_waits_no_more, setup, teardown),
        cmocka_unit_test_setup_teardown(test_shutdown_after_reopening_keeps_the_new_queue, setup, teardown),
        cmocka_unit_test_setup_teardown(test_waits_stop_on_shutdown_and_sends_wait_no_more, setup, teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
