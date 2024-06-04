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
#include "../../remoted/state.h"

#include "../wrappers/posix/time_wrappers.h"
#include "../wrappers/wazuh/remoted/queue_wrappers.h"

#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/hash_op_wrappers.h"
#include "../wrappers/wazuh/shared/cluster_utils_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_global_helpers_wrappers.h"

typedef struct test_struct {
    remoted_agent_state_t *agent_state;
    OSHashNode *hash_node;
    cJSON * state_json;
} test_struct_t;

extern remoted_state_t remoted_state;
extern OSHash *remoted_agents_state;

remoted_agent_state_t * get_node(const char *agent_id);
void w_remoted_clean_agents_state(int *sock);

/* setup/teardown */

static int test_setup(void ** state) {
    remoted_state.uptime = 123456789;
    remoted_state.tcp_sessions = 5;
    remoted_state.recv_bytes = 123456;
    remoted_state.sent_bytes = 234567;
    remoted_state.keys_reload_count = 15;
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
    remoted_state.sent_breakdown.sca_count = 8;
    remoted_state.sent_breakdown.request_count = 9;
    remoted_state.sent_breakdown.discarded_count = 85;

    return 0;
}

static int test_setup_agent(void ** state) {
    test_struct_t *test_data = NULL;
    os_calloc(1, sizeof(test_struct_t),test_data);
    os_calloc(1, sizeof(remoted_agent_state_t), test_data->agent_state);
    os_calloc(1, sizeof(OSHashNode), test_data->hash_node);

    test_mode = 0;
    will_return(__wrap_time, 123456789);
    remoted_agents_state = __wrap_OSHash_Create();

    test_data->agent_state->uptime = 123456789;
    test_data->agent_state->recv_evt_count = 12568;
    test_data->agent_state->recv_ctrl_count = 2568;
    test_data->agent_state->ctrl_breakdown.keepalive_count = 1234;
    test_data->agent_state->ctrl_breakdown.startup_count = 2345;
    test_data->agent_state->ctrl_breakdown.shutdown_count = 234;
    test_data->agent_state->ctrl_breakdown.request_count = 127;
    test_data->agent_state->sent_breakdown.ack_count = 2346;
    test_data->agent_state->sent_breakdown.shared_count = 235;
    test_data->agent_state->sent_breakdown.ar_count = 514;
    test_data->agent_state->sent_breakdown.sca_count = 134;
    test_data->agent_state->sent_breakdown.request_count = 153;
    test_data->agent_state->sent_breakdown.discarded_count = 235;

    OSHash_Add_ex(remoted_agents_state, "001", test_data->agent_state);
    test_mode = 1;

    test_data->hash_node->key = "001";
    test_data->hash_node->data = test_data->agent_state;

    *state = test_data;

    return 0;
}

static int test_teardown_agent(void ** state) {
    test_struct_t *test_data  = (test_struct_t *)*state;

    cJSON_Delete(test_data->state_json);

    if (remoted_agents_state) {
        OSHash_Free(remoted_agents_state);
        remoted_agents_state = NULL;
    }

    os_free(test_data->hash_node);
    os_free(test_data);

    return 0;
}

static int test_setup_empty_hash_table(void ** state) {
    test_struct_t *test_data = NULL;
    os_calloc(1, sizeof(test_struct_t),test_data);
    os_calloc(1, sizeof(remoted_agent_state_t), test_data->agent_state);

    test_data->agent_state->uptime = 123456789;

    test_mode = 0;
    will_return(__wrap_time, 123456789);
    remoted_agents_state = __wrap_OSHash_Create();
    test_mode = 1;

    *state = test_data;

    return 0;
}

static int test_teardown_empty_hash_table(void ** state) {
    test_struct_t *test_data  = (test_struct_t *)*state;

    if (remoted_agents_state) {
        OSHash_Free(remoted_agents_state);
        remoted_agents_state = NULL;
    }

    os_free(test_data->agent_state);
    os_free(test_data);

    return 0;
}

/* Tests */

void test_rem_create_state_json(void ** state) {
    will_return(__wrap_time, 123456789);
    will_return(__wrap_rem_get_qsize, 789);
    will_return(__wrap_rem_get_tsize, 100000);

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

    assert_non_null(cJSON_GetObjectItem(recv, "event"));
    assert_int_equal(cJSON_GetObjectItem(recv, "event")->valueint, 1234);
    assert_non_null(cJSON_GetObjectItem(recv, "control"));
    assert_int_equal(cJSON_GetObjectItem(recv, "control")->valueint, 2345);
    assert_non_null(cJSON_GetObjectItem(recv, "ping"));
    assert_int_equal(cJSON_GetObjectItem(recv, "ping")->valueint, 18);
    assert_non_null(cJSON_GetObjectItem(recv, "unknown"));
    assert_int_equal(cJSON_GetObjectItem(recv, "unknown")->valueint, 8);
    assert_non_null(cJSON_GetObjectItem(recv, "dequeued_after"));
    assert_int_equal(cJSON_GetObjectItem(recv, "dequeued_after")->valueint, 4);
    assert_non_null(cJSON_GetObjectItem(recv, "discarded"));
    assert_int_equal(cJSON_GetObjectItem(recv, "discarded")->valueint, 95);

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
    assert_non_null(cJSON_GetObjectItem(sent, "sca"));
    assert_int_equal(cJSON_GetObjectItem(sent, "sca")->valueint, 8);
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

void test_rem_create_agents_state_json(void ** state) {
    test_struct_t *test_data  = (test_struct_t *)*state;
    int *agents_ids = NULL;
    os_calloc(2, sizeof(int), agents_ids);
    agents_ids[0] = 1;
    agents_ids[1] = OS_INVALID;
    const char *agent_id = "001";

    will_return(__wrap_time, 123456789);

    expect_value(__wrap_OSHash_Get_ex, self, remoted_agents_state);
    expect_string(__wrap_OSHash_Get_ex, key, agent_id);
    will_return(__wrap_OSHash_Get_ex, test_data->hash_node->data);

    test_data->state_json = rem_create_agents_state_json(agents_ids);

    assert_non_null(test_data->state_json);

    assert_non_null(cJSON_GetObjectItem(test_data->state_json, "agents"));
    cJSON* agents = cJSON_GetObjectItem(test_data->state_json, "agents");

    assert_non_null(cJSON_GetArrayItem(agents, 0));
    cJSON* agent = cJSON_GetArrayItem(agents, 0);
    assert_int_equal(cJSON_GetObjectItem(agent, "id")->valueint, 1);
    assert_int_equal(cJSON_GetObjectItem(agent, "uptime")->valueint, 123456789);

    assert_non_null(cJSON_GetObjectItem(agent, "metrics"));
    cJSON* agent_metrics = cJSON_GetObjectItem(agent, "metrics");

    assert_non_null(cJSON_GetObjectItem(agent_metrics, "messages"));
    cJSON* messages = cJSON_GetObjectItem(agent_metrics, "messages");

    assert_non_null(cJSON_GetObjectItem(messages, "received_breakdown"));
    cJSON* messages_received_breakdown = cJSON_GetObjectItem(messages, "received_breakdown");

    assert_int_equal(cJSON_GetObjectItem(messages_received_breakdown, "event")->valueint, 12568);
    assert_int_equal(cJSON_GetObjectItem(messages_received_breakdown, "control")->valueint, 2568);

    assert_non_null(cJSON_GetObjectItem(messages_received_breakdown, "control_breakdown"));
    cJSON* control_breakdown = cJSON_GetObjectItem(messages_received_breakdown, "control_breakdown");

    assert_int_equal(cJSON_GetObjectItem(control_breakdown, "request")->valueint, 127);
    assert_int_equal(cJSON_GetObjectItem(control_breakdown, "startup")->valueint, 2345);
    assert_int_equal(cJSON_GetObjectItem(control_breakdown, "shutdown")->valueint, 234);
    assert_int_equal(cJSON_GetObjectItem(control_breakdown, "keepalive")->valueint, 1234);

    assert_non_null(cJSON_GetObjectItem(messages, "sent_breakdown"));
    cJSON* messages_sent_breakdown = cJSON_GetObjectItem(messages, "sent_breakdown");

    assert_int_equal(cJSON_GetObjectItem(messages_sent_breakdown, "ack")->valueint, 2346);
    assert_int_equal(cJSON_GetObjectItem(messages_sent_breakdown, "shared")->valueint, 235);
    assert_int_equal(cJSON_GetObjectItem(messages_sent_breakdown, "ar")->valueint, 514);
    assert_int_equal(cJSON_GetObjectItem(messages_sent_breakdown, "sca")->valueint, 134);
    assert_int_equal(cJSON_GetObjectItem(messages_sent_breakdown, "request")->valueint, 153);
    assert_int_equal(cJSON_GetObjectItem(messages_sent_breakdown, "discarded")->valueint, 235);

    os_free(test_data->agent_state);
    os_free(agents_ids);
}

void test_rem_get_node_new_node(void ** state) {
    test_struct_t *test_data  = (test_struct_t *)*state;
    const char *agent_id = "001";

    expect_value(__wrap_OSHash_Get_ex, self, remoted_agents_state);
    expect_string(__wrap_OSHash_Get_ex, key, agent_id);
    will_return(__wrap_OSHash_Get_ex, NULL);

    will_return(__wrap_time, 123456789);

    expect_value(__wrap_OSHash_Add_ex, self, remoted_agents_state);
    expect_string(__wrap_OSHash_Add_ex, key, agent_id);
    expect_memory(__wrap_OSHash_Add_ex, data, test_data->agent_state, sizeof(test_data->agent_state));
    will_return(__wrap_OSHash_Add_ex, 2);

    remoted_agent_state_t *agent_state_returned = get_node(agent_id);

    assert_non_null(agent_state_returned);

    os_free(agent_state_returned);
}

void test_rem_get_node_existing_node(void ** state) {
    test_struct_t *test_data  = (test_struct_t *)*state;
    const char *agent_id = "001";

    expect_value(__wrap_OSHash_Get_ex, self, remoted_agents_state);
    expect_string(__wrap_OSHash_Get_ex, key, agent_id);
    will_return(__wrap_OSHash_Get_ex, test_data->agent_state);

    remoted_agent_state_t *agent_state_returned = get_node(agent_id);

    assert_non_null(agent_state_returned);

    os_free(test_data->agent_state);
}

void test_w_remoted_clean_agents_state_empty_table(void ** state) {
    expect_value(__wrap_OSHash_Begin_ex, self, remoted_agents_state);
    will_return(__wrap_OSHash_Begin_ex, NULL);

    int sock = 1;

    w_remoted_clean_agents_state(&sock);
}

void test_w_remoted_clean_agents_state_completed(void ** state) {
    test_struct_t *test_data  = (test_struct_t *)*state;

    expect_value(__wrap_OSHash_Begin_ex, self, remoted_agents_state);
    will_return(__wrap_OSHash_Begin_ex, test_data->hash_node);

    int *connected_agents = NULL;
    os_calloc(1, sizeof(int), connected_agents);
    connected_agents[0] = OS_INVALID;

    expect_string(__wrap_wdb_get_agents_ids_of_current_node, status, AGENT_CS_ACTIVE);
    expect_value(__wrap_wdb_get_agents_ids_of_current_node, last_id, 0);
    expect_value(__wrap_wdb_get_agents_ids_of_current_node, limit, -1);
    will_return(__wrap_wdb_get_agents_ids_of_current_node, connected_agents);

    expect_value(__wrap_OSHash_Next, self, remoted_agents_state);
    will_return(__wrap_OSHash_Next, NULL);

    expect_value(__wrap_OSHash_Delete_ex, self, remoted_agents_state);
    expect_value(__wrap_OSHash_Delete_ex, key, "001");
    will_return(__wrap_OSHash_Delete_ex, test_data->agent_state);

    int sock = 1;

    w_remoted_clean_agents_state(&sock);
}

void test_w_remoted_clean_agents_state_completed_without_delete(void ** state) {
    test_struct_t *test_data  = (test_struct_t *)*state;

    expect_value(__wrap_OSHash_Begin_ex, self, remoted_agents_state);
    will_return(__wrap_OSHash_Begin_ex, test_data->hash_node);

    int *connected_agents = NULL;
    os_calloc(1, sizeof(int), connected_agents);
    connected_agents[0] = 1;

    expect_string(__wrap_wdb_get_agents_ids_of_current_node, status, AGENT_CS_ACTIVE);
    expect_value(__wrap_wdb_get_agents_ids_of_current_node, last_id, 0);
    expect_value(__wrap_wdb_get_agents_ids_of_current_node, limit, -1);
    will_return(__wrap_wdb_get_agents_ids_of_current_node, connected_agents);

    expect_value(__wrap_OSHash_Next, self, remoted_agents_state);
    will_return(__wrap_OSHash_Next, NULL);

    int sock = 1;

    w_remoted_clean_agents_state(&sock);

    os_free(test_data->agent_state);
}

void test_w_remoted_clean_agents_state_query_fail(void ** state) {
    test_struct_t *test_data  = (test_struct_t *)*state;

    expect_value(__wrap_OSHash_Begin_ex, self, remoted_agents_state);
    will_return(__wrap_OSHash_Begin_ex, test_data->hash_node);

    int *connected_agents = NULL;

    expect_string(__wrap_wdb_get_agents_ids_of_current_node, status, AGENT_CS_ACTIVE);
    expect_value(__wrap_wdb_get_agents_ids_of_current_node, last_id, 0);
    expect_value(__wrap_wdb_get_agents_ids_of_current_node, limit, -1);
    will_return(__wrap_wdb_get_agents_ids_of_current_node, connected_agents);

    int sock = 1;

    w_remoted_clean_agents_state(&sock);

    os_free(test_data->agent_state);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // Test rem_create_state_json
        cmocka_unit_test_setup(test_rem_create_state_json, test_setup),
        // Test rem_create_agents_state_json
        cmocka_unit_test_setup_teardown(test_rem_create_agents_state_json, test_setup_agent, test_teardown_agent),
        // Test get_node
        cmocka_unit_test_setup_teardown(test_rem_get_node_new_node, test_setup_empty_hash_table, test_teardown_empty_hash_table),
        cmocka_unit_test_setup_teardown(test_rem_get_node_existing_node, test_setup_agent, test_teardown_agent),
        // Test w_remoted_clean_agents_state
        cmocka_unit_test_setup_teardown(test_w_remoted_clean_agents_state_empty_table, test_setup_empty_hash_table, test_teardown_empty_hash_table),
        cmocka_unit_test_setup_teardown(test_w_remoted_clean_agents_state_completed, test_setup_agent, test_teardown_agent),
        cmocka_unit_test_setup_teardown(test_w_remoted_clean_agents_state_completed_without_delete, test_setup_agent, test_teardown_agent),
        cmocka_unit_test_setup_teardown(test_w_remoted_clean_agents_state_query_fail, test_setup_agent, test_teardown_agent),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
