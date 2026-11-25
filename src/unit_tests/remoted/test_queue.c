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

#include "../../remoted/remoted.h"
#include "../../headers/shared.h"

#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

// Room for a single message, so a second push is discarded.
#define QUEUE_SIZE 2

static struct sockaddr_storage peer_info;

time_t __wrap_w_get_monotonic_time(void) {
    return mock_type(time_t);
}

void __wrap_rem_inc_recv_discarded() {
    function_called();
}

static void expect_discard(time_t now) {
    will_return(__wrap_w_get_monotonic_time, now);
    expect_string(__wrap__mdebug2, formatted_msg, "Discarding event from host.");
    expect_function_call(__wrap_rem_inc_recv_discarded);
}

/* setup/teardown */

static int setup_group(void ** state) {
    memset(&peer_info, 0, sizeof(struct sockaddr_storage));
    rem_msginit(QUEUE_SIZE);
    return 0;
}

static int teardown_group(void ** state) {
    while (rem_get_qsize() > 0) {
        rem_msgfree(rem_msgpop());
    }
    return 0;
}

/* tests */

// The tests share the queue and the warning state of rem_msgpush(), so they run in order.

void test_rem_msgpush_ok_no_warning(void ** state) {
    assert_int_equal(rem_msgpush("message", 7, &peer_info, 1), 0);
    assert_int_equal(rem_get_qsize(), 1);
}

void test_rem_msgpush_first_discard_warns(void ** state) {
    expect_discard(1000);
    expect_string(__wrap__mwarn, formatted_msg, "Message queue is full (2). Events may be lost.");

    assert_int_equal(rem_msgpush("message", 7, &peer_info, 1), -1);
}

void test_rem_msgpush_discard_within_interval_no_warning(void ** state) {
    expect_discard(1001);
    assert_int_equal(rem_msgpush("message", 7, &peer_info, 1), -1);

    expect_discard(1059);
    assert_int_equal(rem_msgpush("message", 7, &peer_info, 1), -1);
}

void test_rem_msgpush_discard_after_interval_warns_count(void ** state) {
    expect_discard(1060);
    expect_string(__wrap__mwarn, formatted_msg, "Message queue is full (2). 3 events discarded since the last warning.");

    assert_int_equal(rem_msgpush("message", 7, &peer_info, 1), -1);
}

void test_rem_msgpush_ok_does_not_rearm_warning(void ** state) {
    message_t * message = rem_msgpop();
    assert_non_null(message);
    rem_msgfree(message);

    assert_int_equal(rem_msgpush("message", 7, &peer_info, 1), 0);

    expect_discard(1061);
    assert_int_equal(rem_msgpush("message", 7, &peer_info, 1), -1);
}

void test_rem_msgpush_ok_after_interval_warns_pending(void ** state) {
    message_t * message = rem_msgpop();
    assert_non_null(message);
    rem_msgfree(message);

    will_return(__wrap_w_get_monotonic_time, 1120);
    expect_string(__wrap__mwarn, formatted_msg, "Message queue was full (2). 1 events discarded since the last warning.");

    assert_int_equal(rem_msgpush("message", 7, &peer_info, 1), 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_rem_msgpush_ok_no_warning),
        cmocka_unit_test(test_rem_msgpush_first_discard_warns),
        cmocka_unit_test(test_rem_msgpush_discard_within_interval_no_warning),
        cmocka_unit_test(test_rem_msgpush_discard_after_interval_warns_count),
        cmocka_unit_test(test_rem_msgpush_ok_does_not_rearm_warning),
        cmocka_unit_test(test_rem_msgpush_ok_after_interval_warns_pending),
    };
    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
