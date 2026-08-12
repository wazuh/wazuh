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

#include "remoted.h"
#include "../../remoted/src/state.h"

#include "../wrappers/posix/time_wrappers.h"
#include "../wrappers/wazuh/remoted/queue_wrappers.h"

#include "../wrappers/common.h"

extern remoted_state_t remoted_state;

/* setup/teardown */

static int test_setup(void ** state) {
    remoted_state.uptime = 123456789;
    remoted_state.tcp_sessions = 5;
    remoted_state.recv_bytes = 123456;
    remoted_state.sent_bytes = 234567;
    remoted_state.keys_reload_count = 15;
    remoted_state.recv_breakdown.events_count = 1234;
    remoted_state.recv_breakdown.ctrl_count = 2345;
    remoted_state.recv_breakdown.states_count = 333;
    remoted_state.recv_breakdown.upgrade_ack_count = 11;
    remoted_state.recv_breakdown.ping_count = 18;
    remoted_state.recv_breakdown.unknown_count = 8;
    remoted_state.recv_breakdown.dequeued_count = 4;
    remoted_state.recv_breakdown.discarded_count = 95;
    remoted_state.recv_breakdown.events_failed_count = 7;
    remoted_state.recv_breakdown.ctrl_breakdown.keepalive_count = 1115;
    remoted_state.recv_breakdown.ctrl_breakdown.startup_count = 48;
    remoted_state.recv_breakdown.ctrl_breakdown.shutdown_count = 12;
    remoted_state.recv_breakdown.ctrl_breakdown.request_count = 2;
    remoted_state.sent_breakdown.ack_count = 1114;
    remoted_state.sent_breakdown.shared_count = 2540;
    remoted_state.sent_breakdown.ar_count = 18;
    remoted_state.sent_breakdown.request_count = 9;
    remoted_state.sent_breakdown.discarded_count = 85;

    return 0;
}

/* Tests */

void test_rem_create_state_json(void ** state) {
    will_return(__wrap_time, 123456789);
    will_return(__wrap_rem_get_input_bytes_used, 789);
    will_return(__wrap_rem_get_input_max_bytes, 100000);

    cJSON* state_json = rem_create_state_json();

    assert_non_null(state_json);

    assert_int_equal(cJSON_GetObjectItem(state_json, "uptime")->valueint, 123456789);

    assert_non_null(cJSON_GetObjectItem(state_json, "metrics"));
    cJSON* metrics = cJSON_GetObjectItem(state_json, "metrics");

    assert_non_null(cJSON_GetObjectItem(metrics, "bytes"));
    cJSON* bytes = cJSON_GetObjectItem(metrics, "bytes");

    assert_non_null(cJSON_GetObjectItem(bytes, "received"));
    assert_int_equal(cJSON_GetObjectItem(bytes, "received")->valueint, 123456);
    assert_non_null(cJSON_GetObjectItem(bytes, "sent"));
    assert_int_equal(cJSON_GetObjectItem(bytes, "sent")->valueint, 234567);

    assert_non_null(cJSON_GetObjectItem(metrics, "messages"));
    cJSON* messages = cJSON_GetObjectItem(metrics, "messages");

    assert_non_null(cJSON_GetObjectItem(messages, "received_breakdown"));
    cJSON* recv = cJSON_GetObjectItem(messages, "received_breakdown");

    assert_non_null(cJSON_GetObjectItem(recv, "events"));
    assert_int_equal(cJSON_GetObjectItem(recv, "events")->valueint, 1234);
    assert_non_null(cJSON_GetObjectItem(recv, "control"));
    assert_int_equal(cJSON_GetObjectItem(recv, "control")->valueint, 2345);
    assert_non_null(cJSON_GetObjectItem(recv, "states"));
    assert_int_equal(cJSON_GetObjectItem(recv, "states")->valueint, 333);
    assert_non_null(cJSON_GetObjectItem(recv, "upgrade_ack"));
    assert_int_equal(cJSON_GetObjectItem(recv, "upgrade_ack")->valueint, 11);
    assert_non_null(cJSON_GetObjectItem(recv, "ping"));
    assert_int_equal(cJSON_GetObjectItem(recv, "ping")->valueint, 18);
    assert_non_null(cJSON_GetObjectItem(recv, "unknown"));
    assert_int_equal(cJSON_GetObjectItem(recv, "unknown")->valueint, 8);
    assert_non_null(cJSON_GetObjectItem(recv, "dequeued_after"));
    assert_int_equal(cJSON_GetObjectItem(recv, "dequeued_after")->valueint, 4);
    assert_non_null(cJSON_GetObjectItem(recv, "discarded"));
    assert_int_equal(cJSON_GetObjectItem(recv, "discarded")->valueint, 95);
    assert_non_null(cJSON_GetObjectItem(recv, "events_failed"));
    assert_int_equal(cJSON_GetObjectItem(recv, "events_failed")->valueint, 7);

    assert_non_null(cJSON_GetObjectItem(recv, "control_breakdown"));
    cJSON* ctrl = cJSON_GetObjectItem(recv, "control_breakdown");

    assert_non_null(cJSON_GetObjectItem(ctrl, "request"));
    assert_int_equal(cJSON_GetObjectItem(ctrl, "request")->valueint, 2);
    assert_non_null(cJSON_GetObjectItem(ctrl, "startup"));
    assert_int_equal(cJSON_GetObjectItem(ctrl, "startup")->valueint, 48);
    assert_non_null(cJSON_GetObjectItem(ctrl, "shutdown"));
    assert_int_equal(cJSON_GetObjectItem(ctrl, "shutdown")->valueint, 12);
    assert_non_null(cJSON_GetObjectItem(ctrl, "keepalive"));
    assert_int_equal(cJSON_GetObjectItem(ctrl, "keepalive")->valueint, 1115);

    assert_non_null(cJSON_GetObjectItem(messages, "sent_breakdown"));
    cJSON* sent = cJSON_GetObjectItem(messages, "sent_breakdown");

    assert_non_null(cJSON_GetObjectItem(sent, "ack"));
    assert_int_equal(cJSON_GetObjectItem(sent, "ack")->valueint, 1114);
    assert_non_null(cJSON_GetObjectItem(sent, "shared"));
    assert_int_equal(cJSON_GetObjectItem(sent, "shared")->valueint, 2540);
    assert_non_null(cJSON_GetObjectItem(sent, "ar"));
    assert_int_equal(cJSON_GetObjectItem(sent, "ar")->valueint, 18);
    assert_non_null(cJSON_GetObjectItem(sent, "request"));
    assert_int_equal(cJSON_GetObjectItem(sent, "request")->valueint, 9);
    assert_non_null(cJSON_GetObjectItem(sent, "discarded"));
    assert_int_equal(cJSON_GetObjectItem(sent, "discarded")->valueint, 85);

    assert_non_null(cJSON_GetObjectItem(metrics, "tcp_sessions"));
    assert_int_equal(cJSON_GetObjectItem(metrics, "tcp_sessions")->valueint, 5);
    assert_non_null(cJSON_GetObjectItem(metrics, "keys_reload_count"));
    assert_int_equal(cJSON_GetObjectItem(metrics, "keys_reload_count")->valueint, 15);

    assert_non_null(cJSON_GetObjectItem(metrics, "queues"));
    cJSON* queue = cJSON_GetObjectItem(metrics, "queues");

    cJSON* received = cJSON_GetObjectItem(queue, "received");
    assert_non_null(cJSON_GetObjectItem(received, "usage"));
    assert_int_equal(cJSON_GetObjectItem(received, "usage")->valueint, 789);
    assert_non_null(cJSON_GetObjectItem(received, "size"));
    assert_int_equal(cJSON_GetObjectItem(received, "size")->valueint, 100000);

    cJSON_Delete(state_json);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // Test rem_create_state_json
        cmocka_unit_test_setup(test_rem_create_state_json, test_setup),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
