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

#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/hash_op_wrappers.h"
#include "../wrappers/wazuh/shared/cluster_utils_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_global_helpers_wrappers.h"

extern remoted_state_t remoted_state;
remoted_agent_state_t *agent_state;
extern OSHash *remoted_agents_state;
OSHashNode *hash_node;

remoted_agent_state_t * get_node(const char *agent_id);
void w_remoted_clean_agents_state();

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
    remoted_state.sent_breakdown.ack_count = 1114;
    remoted_state.sent_breakdown.shared_count = 2540;
    remoted_state.sent_breakdown.ar_count = 18;
    remoted_state.sent_breakdown.cfga_count = 8;
    remoted_state.sent_breakdown.request_count = 9;
    remoted_state.sent_breakdown.discarded_count = 85;

    test_mode = 0;
    will_return(__wrap_time, 123456789);
    remoted_agents_state = __wrap_OSHash_Create();

    os_calloc(1, sizeof(remoted_agent_state_t), agent_state);

    agent_state->recv_evt_count = 12568;
    agent_state->recv_ctrl_count = 2568;
    agent_state->ctrl_breakdown.keepalive_count = 1234;
    agent_state->ctrl_breakdown.startup_count = 2345;
    agent_state->ctrl_breakdown.shutdown_count = 234;
    agent_state->ctrl_breakdown.request_count = 127;
    agent_state->sent_breakdown.ack_count = 2346;
    agent_state->sent_breakdown.shared_count = 235;
    agent_state->sent_breakdown.ar_count = 514;
    agent_state->sent_breakdown.cfga_count = 134;
    agent_state->sent_breakdown.request_count = 153;
    agent_state->sent_breakdown.discarded_count = 235;

    OSHash_Add_ex(remoted_agents_state, "001", agent_state);
    test_mode = 1;

    os_calloc(1, sizeof(OSHashNode), hash_node);
    hash_node->key = "001";
    hash_node->data = agent_state;

    return 0;
}

static int test_teardown(void ** state) {
    cJSON* json = *state;
    cJSON_Delete(json);

    if (remoted_agents_state) {
        OSHash_Free(remoted_agents_state);
        remoted_agents_state = NULL;
    }

    os_free(hash_node);

    return 0;
}

static int test_setup_empty_hash_table() {
    test_mode = 0;
    will_return(__wrap_time, 123456789);
    remoted_agents_state = __wrap_OSHash_Create();
    test_mode = 1;

    os_calloc(1, sizeof(remoted_agent_state_t), agent_state);

    return 0;
}

static int test_teardown_empty_hash_table() {
    if (remoted_agents_state) {
        OSHash_Free(remoted_agents_state);
        remoted_agents_state = NULL;
    }

    os_free(agent_state);

    return 0;
}

/* Tests */

void test_rem_create_state_json(void ** state) {

    will_return(__wrap_time, 123456789);
    will_return(__wrap_rem_get_qsize, 789);
    will_return(__wrap_rem_get_tsize, 100000);

    expect_value(__wrap_OSHash_Begin, self, remoted_agents_state);
    will_return(__wrap_OSHash_Begin, hash_node);

    expect_value(__wrap_OSHash_Next, self, remoted_agents_state);
    will_return(__wrap_OSHash_Next, NULL);

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

    assert_non_null(cJSON_GetObjectItem(state_json, "agents_connected"));
    cJSON* agents_connected = cJSON_GetObjectItem(state_json, "agents_connected");

    assert_non_null(cJSON_GetArrayItem(agents_connected, 0));
    cJSON* agent_connected = cJSON_GetArrayItem(agents_connected, 0);
    assert_int_equal(cJSON_GetObjectItem(agent_connected, "agent_id")->valueint, 1);

    assert_non_null(cJSON_GetObjectItem(agent_connected, "statistics"));
    cJSON* agent_statistics = cJSON_GetObjectItem(agent_connected, "statistics");

    assert_non_null(cJSON_GetObjectItem(agent_statistics, "messages_received_breakdown"));
    cJSON* messages_received_breakdown = cJSON_GetObjectItem(agent_statistics, "messages_received_breakdown");

    assert_int_equal(cJSON_GetObjectItem(messages_received_breakdown, "event_messages")->valueint, 12568);
    assert_int_equal(cJSON_GetObjectItem(messages_received_breakdown, "control_messages")->valueint, 2568);

    assert_non_null(cJSON_GetObjectItem(messages_received_breakdown, "control_breakdown"));
    cJSON* control_breakdown = cJSON_GetObjectItem(messages_received_breakdown, "control_breakdown");

    assert_int_equal(cJSON_GetObjectItem(control_breakdown, "request_messages")->valueint, 127);
    assert_int_equal(cJSON_GetObjectItem(control_breakdown, "startup_messages")->valueint, 2345);
    assert_int_equal(cJSON_GetObjectItem(control_breakdown, "shutdown_messages")->valueint, 234);
    assert_int_equal(cJSON_GetObjectItem(control_breakdown, "keepalive_messages")->valueint, 1234);

    assert_non_null(cJSON_GetObjectItem(agent_statistics, "messages_sent_breakdown"));
    cJSON* messages_sent_breakdown = cJSON_GetObjectItem(agent_statistics, "messages_sent_breakdown");

    assert_int_equal(cJSON_GetObjectItem(messages_sent_breakdown, "ack_messages")->valueint, 2346);
    assert_int_equal(cJSON_GetObjectItem(messages_sent_breakdown, "shared_file_messages")->valueint, 235);
    assert_int_equal(cJSON_GetObjectItem(messages_sent_breakdown, "ar_messages")->valueint, 514);
    assert_int_equal(cJSON_GetObjectItem(messages_sent_breakdown, "cfga_messages")->valueint, 134);
    assert_int_equal(cJSON_GetObjectItem(messages_sent_breakdown, "request_messages")->valueint, 153);
    assert_int_equal(cJSON_GetObjectItem(messages_sent_breakdown, "discarded_messages")->valueint, 235);

    os_free(agent_state);
}

void test_rem_get_node_new_node() {
    const char *agent_id = "001";

    expect_value(__wrap_OSHash_Get_ex, self, remoted_agents_state);
    expect_string(__wrap_OSHash_Get_ex, key, agent_id);
    will_return(__wrap_OSHash_Get_ex, NULL);

    expect_value(__wrap_OSHash_Add_ex, self, remoted_agents_state);
    expect_string(__wrap_OSHash_Add_ex, key, agent_id);
    expect_memory(__wrap_OSHash_Add_ex, data, agent_state, sizeof(agent_state));
    will_return(__wrap_OSHash_Add_ex, 2);

    remoted_agent_state_t *agent_state_returned = get_node(agent_id);

    assert_non_null(agent_state_returned);

    os_free(agent_state_returned);
}

void test_rem_get_node_existing_node() {
    const char *agent_id = "001";

    expect_value(__wrap_OSHash_Get_ex, self, remoted_agents_state);
    expect_string(__wrap_OSHash_Get_ex, key, agent_id);
    will_return(__wrap_OSHash_Get_ex, agent_state);

    remoted_agent_state_t *agent_state_returned = get_node(agent_id);

    assert_non_null(agent_state_returned);

    os_free(agent_state);
}

void test_w_remoted_clean_agents_state_empty_table() {
    expect_value(__wrap_OSHash_Begin, self, remoted_agents_state);
    will_return(__wrap_OSHash_Begin, NULL);

    w_remoted_clean_agents_state();
}

void test_w_remoted_clean_agents_state_completed() {
    expect_value(__wrap_OSHash_Begin, self, remoted_agents_state);
    will_return(__wrap_OSHash_Begin, hash_node);

    char *cluster_node_name = NULL;
    cluster_node_name = strdup("node01");
    int *connected_agents = NULL;
    os_calloc(1, sizeof(int), connected_agents);
    connected_agents[0] = OS_INVALID;

    will_return(__wrap_get_node_name, cluster_node_name);

    expect_string(__wrap_wdb_get_agents_by_connection_status, status, AGENT_CS_ACTIVE);
    expect_string(__wrap_wdb_get_agents_by_connection_status, node_name, cluster_node_name);
    will_return(__wrap_wdb_get_agents_by_connection_status, connected_agents);

    expect_value(__wrap_OSHash_Next, self, remoted_agents_state);
    will_return(__wrap_OSHash_Next, NULL);

    expect_value(__wrap_OSHash_Delete_ex, self, remoted_agents_state);
    expect_value(__wrap_OSHash_Delete_ex, key, "001");
    will_return(__wrap_OSHash_Delete_ex, agent_state);

    w_remoted_clean_agents_state();

    os_free(connected_agents);
}

void test_w_remoted_clean_agents_state_completed_without_delete() {
    expect_value(__wrap_OSHash_Begin, self, remoted_agents_state);
    will_return(__wrap_OSHash_Begin, hash_node);

    char *cluster_node_name = NULL;
    cluster_node_name = strdup("node01");
    int *connected_agents = NULL;
    os_calloc(1, sizeof(int), connected_agents);
    connected_agents[0] = 1;

    will_return(__wrap_get_node_name, cluster_node_name);

    expect_string(__wrap_wdb_get_agents_by_connection_status, status, AGENT_CS_ACTIVE);
    expect_string(__wrap_wdb_get_agents_by_connection_status, node_name, cluster_node_name);
    will_return(__wrap_wdb_get_agents_by_connection_status, connected_agents);

    expect_value(__wrap_OSHash_Next, self, remoted_agents_state);
    will_return(__wrap_OSHash_Next, NULL);

    w_remoted_clean_agents_state();

    os_free(connected_agents);
    os_free(agent_state);
}

void test_w_remoted_clean_agents_state_query_fail() {
    expect_value(__wrap_OSHash_Begin, self, remoted_agents_state);
    will_return(__wrap_OSHash_Begin, hash_node);

    char *cluster_node_name = NULL;
    cluster_node_name = strdup("node01");
    int *connected_agents = NULL;

    will_return(__wrap_get_node_name, cluster_node_name);

    expect_string(__wrap_wdb_get_agents_by_connection_status, status, AGENT_CS_ACTIVE);
    expect_string(__wrap_wdb_get_agents_by_connection_status, node_name, cluster_node_name);
    will_return(__wrap_wdb_get_agents_by_connection_status, connected_agents);

    expect_string(__wrap__merror, formatted_msg, "Unable to get connected agents.");

    w_remoted_clean_agents_state();

    os_free(agent_state);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // Test rem_create_state_json
        cmocka_unit_test_setup_teardown(test_rem_create_state_json, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_rem_get_node_new_node, test_setup_empty_hash_table, test_teardown_empty_hash_table),
        cmocka_unit_test_setup_teardown(test_rem_get_node_existing_node, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_w_remoted_clean_agents_state_empty_table, test_setup_empty_hash_table, test_teardown_empty_hash_table),
        cmocka_unit_test_setup_teardown(test_w_remoted_clean_agents_state_completed, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_w_remoted_clean_agents_state_completed_without_delete, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_w_remoted_clean_agents_state_query_fail, test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
