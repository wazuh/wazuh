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

#include "remoted/remoted.h"
#include "remoted/state.h"

#include "../wrappers/posix/time_wrappers.h"
#include "../wrappers/wazuh/remoted/queue_wrappers.h"

extern remoted_state_t remoted_state;

/* setup/teardown */

static int test_setup(void ** state) {
    remoted_state.tcp_sessions = 5;
    remoted_state.recv_bytes = 123456;
    remoted_state.sent_bytes = 234567;
    remoted_state.keys_reload_count = 15;
    remoted_state.update_shared_files_count = 39;
    remoted_state.recv_breakdown.evt_count = 1234;
    remoted_state.recv_breakdown.ctrl_count = 2345;
    remoted_state.recv_breakdown.ping_count = 18;
    remoted_state.recv_breakdown.unknown_count = 8;
    remoted_state.recv_breakdown.dequeued_count = 4;
    remoted_state.recv_breakdown.discarded_count = 95;
    remoted_state.recv_breakdown.ctrl_breakdown.keepalive_count = 1115;
    remoted_state.recv_breakdown.ctrl_breakdown.startup_count = 48;
    remoted_state.recv_breakdown.ctrl_breakdown.shutdown_count = 12;
    remoted_state.recv_breakdown.ctrl_breakdown.request_count = 2;
    remoted_state.sent_breakdown.queued_count = 4567;
    remoted_state.sent_breakdown.ack_count = 1114;
    remoted_state.sent_breakdown.shared_count = 2540;
    remoted_state.sent_breakdown.ar_count = 18;
    remoted_state.sent_breakdown.cfga_count = 8;
    remoted_state.sent_breakdown.request_count = 9;
    remoted_state.sent_breakdown.discarded_count = 85;

    return 0;
}

static int test_teardown(void ** state) {
    cJSON* json = *state;
    cJSON_Delete(json);
    return 0;
}

/* Tests */

void test_rem_create_state_json(void ** state) {

    will_return(__wrap_time, 123456789);
    will_return(__wrap_rem_get_qsize, 789);
    will_return(__wrap_rem_get_tsize, 100000);

    cJSON* state_json = rem_create_state_json();

    *state = (void *)state_json;

    assert_non_null(state_json);

    assert_non_null(cJSON_GetObjectItem(state_json, "statistics"));
    cJSON* statistics = cJSON_GetObjectItem(state_json, "statistics");

    assert_non_null(cJSON_GetObjectItem(statistics, "tcp_sessions"));
    assert_int_equal(cJSON_GetObjectItem(statistics, "tcp_sessions")->valueint, 5);
    assert_non_null(cJSON_GetObjectItem(statistics, "received_bytes"));
    assert_int_equal(cJSON_GetObjectItem(statistics, "received_bytes")->valueint, 123456);
    assert_non_null(cJSON_GetObjectItem(statistics, "sent_bytes"));
    assert_int_equal(cJSON_GetObjectItem(statistics, "sent_bytes")->valueint, 234567);
    assert_non_null(cJSON_GetObjectItem(statistics, "keys_reload_count"));
    assert_int_equal(cJSON_GetObjectItem(statistics, "keys_reload_count")->valueint, 15);
    assert_non_null(cJSON_GetObjectItem(statistics, "update_shared_files_count"));
    assert_int_equal(cJSON_GetObjectItem(statistics, "update_shared_files_count")->valueint, 39);

    assert_non_null(cJSON_GetObjectItem(statistics, "messages_received_breakdown"));
    cJSON* recv = cJSON_GetObjectItem(statistics, "messages_received_breakdown");

    assert_non_null(cJSON_GetObjectItem(recv, "event_messages"));
    assert_int_equal(cJSON_GetObjectItem(recv, "event_messages")->valueint, 1234);
    assert_non_null(cJSON_GetObjectItem(recv, "control_messages"));
    assert_int_equal(cJSON_GetObjectItem(recv, "control_messages")->valueint, 2345);
    assert_non_null(cJSON_GetObjectItem(recv, "ping_messages"));
    assert_int_equal(cJSON_GetObjectItem(recv, "ping_messages")->valueint, 18);
    assert_non_null(cJSON_GetObjectItem(recv, "unknown_messages"));
    assert_int_equal(cJSON_GetObjectItem(recv, "unknown_messages")->valueint, 8);
    assert_non_null(cJSON_GetObjectItem(recv, "dequeued_after_close_messages"));
    assert_int_equal(cJSON_GetObjectItem(recv, "dequeued_after_close_messages")->valueint, 4);
    assert_non_null(cJSON_GetObjectItem(recv, "discarded_messages"));
    assert_int_equal(cJSON_GetObjectItem(recv, "discarded_messages")->valueint, 95);

    assert_non_null(cJSON_GetObjectItem(recv, "control_breakdown"));
    cJSON* ctrl = cJSON_GetObjectItem(recv, "control_breakdown");

    assert_non_null(cJSON_GetObjectItem(ctrl, "request_messages"));
    assert_int_equal(cJSON_GetObjectItem(ctrl, "request_messages")->valueint, 2);
    assert_non_null(cJSON_GetObjectItem(ctrl, "startup_messages"));
    assert_int_equal(cJSON_GetObjectItem(ctrl, "startup_messages")->valueint, 48);
    assert_non_null(cJSON_GetObjectItem(ctrl, "shutdown_messages"));
    assert_int_equal(cJSON_GetObjectItem(ctrl, "shutdown_messages")->valueint, 12);
    assert_non_null(cJSON_GetObjectItem(ctrl, "keepalive_messages"));
    assert_int_equal(cJSON_GetObjectItem(ctrl, "keepalive_messages")->valueint, 1115);

    assert_non_null(cJSON_GetObjectItem(statistics, "messages_sent_breakdown"));
    cJSON* sent = cJSON_GetObjectItem(statistics, "messages_sent_breakdown");

    assert_non_null(cJSON_GetObjectItem(sent, "queued_messages"));
    assert_int_equal(cJSON_GetObjectItem(sent, "queued_messages")->valueint, 4567);
    assert_non_null(cJSON_GetObjectItem(sent, "ack_messages"));
    assert_int_equal(cJSON_GetObjectItem(sent, "ack_messages")->valueint, 1114);
    assert_non_null(cJSON_GetObjectItem(sent, "shared_file_messages"));
    assert_int_equal(cJSON_GetObjectItem(sent, "shared_file_messages")->valueint, 2540);
    assert_non_null(cJSON_GetObjectItem(sent, "ar_messages"));
    assert_int_equal(cJSON_GetObjectItem(sent, "ar_messages")->valueint, 18);
    assert_non_null(cJSON_GetObjectItem(sent, "cfga_messages"));
    assert_int_equal(cJSON_GetObjectItem(sent, "cfga_messages")->valueint, 8);
    assert_non_null(cJSON_GetObjectItem(sent, "request_messages"));
    assert_int_equal(cJSON_GetObjectItem(sent, "request_messages")->valueint, 9);
    assert_non_null(cJSON_GetObjectItem(sent, "discarded_messages"));
    assert_int_equal(cJSON_GetObjectItem(sent, "discarded_messages")->valueint, 85);

    assert_non_null(cJSON_GetObjectItem(statistics, "queue_status"));
    cJSON* queue = cJSON_GetObjectItem(statistics, "queue_status");

    assert_non_null(cJSON_GetObjectItem(queue, "receive_queue_usage"));
    assert_int_equal(cJSON_GetObjectItem(queue, "receive_queue_usage")->valueint, 789);
    assert_non_null(cJSON_GetObjectItem(queue, "receive_queue_size"));
    assert_int_equal(cJSON_GetObjectItem(queue, "receive_queue_size")->valueint, 100000);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // Test w_get_pri_header_len
        cmocka_unit_test_setup_teardown(test_rem_create_state_json, test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
