/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 * November, 2020.
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
#include <stdlib.h>
#include <stdio.h>

#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/mq_op_wrappers.h"
#include "../wrappers/wazuh/shared/hash_op_wrappers.h"
#include "../wrappers/wazuh/os_net/os_net_wrappers.h"
#include "../wrappers/wazuh//monitord/monitord_wrappers.h"
#include "../wrappers/posix/stat_wrappers.h"
#include "../wrappers/wazuh/shared/auth_client_wrappers.h"
#include "../wrappers/wazuh/shared/agent_op_wrappers.h"

#include "config/client-config.h"
#include "headers/store_op.h"
#include "monitord/monitord.h"
#include "headers/defs.h"
#include "headers/shared.h"
#include "config/config.h"

/* redefinitons/wrapping */

time_t __wrap_time(__attribute__((unused)) time_t *t) {
    return mock_type(time_t);
}

extern monitor_time_control mond_time_control;

/* setup/teardown */

int setup_monitord(void **state) {
    test_mode = 1;
    mond.global.agents_disconnection_alert_time = 0;
    mond.global.agents_disconnection_time = 0;

    mond.delete_old_agents = 0;
    mond.a_queue = -1;
    mond.day_wait = 0;
    mond.rotate_log = 1;
    mond.size_rotate = 0;
    mond.monitor_agents = 0;

    mond_time_control.disconnect_counter = 0;
    mond_time_control.alert_counter = 0;
    mond_time_control.delete_counter = 0;
    mond_time_control.today = 0;
    mond_time_control.thismonth = 0;
    mond_time_control.thisyear = 0;

    return 0;
}

int teardown_monitord(void **state) {
    test_mode = 0;

    mond.global.agents_disconnection_alert_time = 0;
    mond.global.agents_disconnection_time = 0;

    mond.delete_old_agents = 0;
    mond.a_queue = -1;
    mond.day_wait = 0;
    mond.rotate_log = 1;
    mond.size_rotate = 0;
    mond.monitor_agents = 0;

    mond_time_control.disconnect_counter = 0;
    mond_time_control.alert_counter = 0;
    mond_time_control.delete_counter = 0;
    mond_time_control.today = 0;
    mond_time_control.thismonth = 0;
    mond_time_control.thisyear = 0;

    return 0;
}

// Tests

/* Tests monitor_send_deletion_msg */

void test_monitor_send_deletion_msg_success(void **state) {
    char *agent = "Agent1-any";
    char msg_to_send[OS_SIZE_1024];

    snprintf(msg_to_send, OS_SIZE_1024, OS_AG_REMOVED, agent);
    mond.a_queue = 1;

    expect_string(__wrap_SendMSG, message, msg_to_send);
    expect_string(__wrap_SendMSG, locmsg, ARGV0);
    expect_value(__wrap_SendMSG, loc, LOCALFILE_MQ);
    will_return(__wrap_SendMSG, 1);

    monitor_send_deletion_msg(agent);

    assert_int_equal(1, mond.a_queue);
}

void test_monitor_send_deletion_msg_fail(void **state) {
    char *agent = "Agent1-any";
    char msg_to_send[OS_SIZE_1024];

    snprintf(msg_to_send, OS_SIZE_1024, OS_AG_REMOVED, agent);
    mond.a_queue = 1;

    expect_string(__wrap_SendMSG, message, msg_to_send);
    expect_string(__wrap_SendMSG, locmsg, ARGV0);
    expect_value(__wrap_SendMSG, loc, LOCALFILE_MQ);
    will_return(__wrap_SendMSG, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Could not generate removed agent alert for 'Agent1-any'");
    expect_string(__wrap__merror, formatted_msg, QUEUE_SEND);

    monitor_send_deletion_msg(agent);

    assert_int_equal(-1, mond.a_queue);
}

/* Tests monitor_send_disconnection_msg */

void test_monitor_send_disconnection_msg_success(void **state) {
    char *agent = "Agent1-any";
    char msg_to_send[OS_SIZE_1024];
    char header[OS_SIZE_256];

    expect_string(__wrap_wdb_find_agent, name, "Agent1");
    expect_string(__wrap_wdb_find_agent, ip, "any");
    will_return(__wrap_wdb_find_agent, 1);

    snprintf(msg_to_send, OS_SIZE_1024, AG_DISCON_MSG, agent);
    snprintf(header, OS_SIZE_256, "[%03d] (%s) %s", 1, "Agent1", "any");

    expect_string(__wrap_SendMSG, message, msg_to_send);
    expect_string(__wrap_SendMSG, locmsg, header);
    expect_value(__wrap_SendMSG, loc, SECURE_MQ);
    will_return(__wrap_SendMSG, 1);
    mond.a_queue = 1;

    monitor_send_disconnection_msg(agent);

    assert_int_equal(1, mond.a_queue);
}

void test_monitor_send_disconnection_msg_send_msg_fail(void **state) {
    char *agent = "Agent1-any";
    char msg_to_send[OS_SIZE_1024];
    char header[OS_SIZE_256];

    expect_string(__wrap_wdb_find_agent, name, "Agent1");
    expect_string(__wrap_wdb_find_agent, ip, "any");
    will_return(__wrap_wdb_find_agent, 1);

    snprintf(msg_to_send, OS_SIZE_1024, AG_DISCON_MSG, agent);
    snprintf(header, OS_SIZE_256, "[%03d] (%s) %s", 1, "Agent1", "any");

    expect_string(__wrap_SendMSG, message, msg_to_send);
    expect_string(__wrap_SendMSG, locmsg, header);
    expect_value(__wrap_SendMSG, loc, SECURE_MQ);
    will_return(__wrap_SendMSG, -1);
    mond.a_queue = 1;
    expect_string(__wrap__merror, formatted_msg, QUEUE_SEND);
    expect_string(__wrap__mdebug1, formatted_msg, "Could not generate disconnected agent alert for 'Agent1-any'");

    monitor_send_disconnection_msg(agent);

    assert_int_equal(-1, mond.a_queue);
}

void test_monitor_send_disconnection_msg_agent_removed(void **state) {
    char *agent = "Agent1-any";
    char msg_to_send[OS_SIZE_1024];

    expect_string(__wrap_wdb_find_agent, name, "Agent1");
    expect_string(__wrap_wdb_find_agent, ip, "any");
    will_return(__wrap_wdb_find_agent, -2);

    // monitor_send_deletion_msg
    snprintf(msg_to_send, OS_SIZE_1024, OS_AG_REMOVED, agent);
    expect_string(__wrap_SendMSG, message, msg_to_send);
    expect_string(__wrap_SendMSG, locmsg, ARGV0);
    expect_value(__wrap_SendMSG, loc, LOCALFILE_MQ);
    will_return(__wrap_SendMSG, 1);
    mond.a_queue = 1;

    monitor_send_disconnection_msg(agent);

    assert_int_equal(1, mond.a_queue);
}

void test_monitor_send_disconnection_msg_fail(void **state) {
    char *agent = "Agent1-any";

    expect_string(__wrap_wdb_find_agent, name, "Agent1");
    expect_string(__wrap_wdb_find_agent, ip, "any");
    will_return(__wrap_wdb_find_agent, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "Could not generate disconnected agent alert for 'Agent1-any'");
    mond.a_queue = 1;

    monitor_send_disconnection_msg(agent);

    assert_int_equal(1, mond.a_queue);
}

/* Tests monitor_agents_disconnection */

void test_monitor_agents_disconnection(void **state) {
    int *agents_array_test = NULL;
    // Arbitraty date 03 Nov 2020 11:39:10
    int last_keepalive = 1604403550;

    os_calloc(3, sizeof(int), agents_array_test);
    // Arbitrary agent's ID 13,5
    agents_array_test[0] = 13;
    agents_array_test[1] =  5;
    agents_array_test[2] = -1;

    mond.global.agents_disconnection_time = 100;
    mond.monitor_agents = 1;

    expect_value(__wrap_wdb_disconnect_agents, keepalive, last_keepalive - mond.global.agents_disconnection_time);
    expect_string(__wrap_wdb_disconnect_agents, sync_status, "synced");
    will_return(__wrap_wdb_disconnect_agents, agents_array_test);

    will_return_count(__wrap_time, 1604403550, -1);
    will_return(__wrap_OSHash_Add, 2);
    will_return(__wrap_OSHash_Add, 0);
    expect_string(__wrap_OSHash_Add, key, "13");
    expect_string(__wrap_OSHash_Add, key, "5");

    expect_string(__wrap__mdebug1, formatted_msg, "Can't add agent ID '5' to the alerts hash table");

    monitor_agents_disconnection();
}

void test_monitor_send_disconnection_ip_fail(void **state) {
    char *agent = "Agent1";

    expect_string(__wrap__mdebug1, formatted_msg, "Could not generate disconnected agent alert for 'Agent1'");

    monitor_send_disconnection_msg(agent);
}

void test_monitor_send_disconnection_name_size_fail(void **state) {
    char *agent = NULL;
    char *agent_append = "text";
    char debug_message[OS_SIZE_512];

    // Creating a long name
    do {wm_strcat(&agent, agent_append, 0);} while (strlen(agent) < 256);
    wm_strcat(&agent, "any", '-');

    snprintf(debug_message, OS_SIZE_512, "Could not generate disconnected agent alert for '%s'", agent);
    expect_string(__wrap__mdebug1, formatted_msg, debug_message);

    monitor_send_disconnection_msg(agent);

    os_free(agent);
}

/* Tests monitor_agents_alert */

void test_monitor_agents_alert_active() {
    // Setting an arbitrary last_keepalive = 100
    cJSON *j_agent_info = cJSON_Parse("[{\"connection_status\":\"active\",\"last_keepalive\":100,\"name\":\"Agent1\",\"register_ip\":\"any\"}]");
    OSHashNode *current_node = NULL;

    os_calloc(1, sizeof(OSHashNode), current_node);
    current_node->next = NULL;
    current_node->key = "1";

    expect_value(__wrap_OSHash_Begin, self, agents_to_alert_hash);
    will_return(__wrap_OSHash_Begin, current_node);

    expect_value(__wrap_OSHash_Next, self, agents_to_alert_hash);
    will_return(__wrap_OSHash_Next, NULL);

    expect_value(__wrap_wdb_get_agent_info, id, 1);
    will_return(__wrap_wdb_get_agent_info, j_agent_info);

    expect_value(__wrap_OSHash_Delete, self, agents_to_alert_hash);
    expect_value(__wrap_OSHash_Delete, key, "1");
    will_return(__wrap_OSHash_Delete, 2);

    monitor_agents_alert();

    os_free(current_node);
}

void test_monitor_agents_alert_agent_info_fail() {
    cJSON *j_agent_info = NULL;
    OSHashNode *current_node = NULL;

    os_calloc(1, sizeof(OSHashNode), current_node);
    current_node->next = NULL;
    current_node->key = "1";

    expect_value(__wrap_OSHash_Begin, self, agents_to_alert_hash);
    will_return(__wrap_OSHash_Begin, current_node);

    expect_value(__wrap_OSHash_Next, self, agents_to_alert_hash);
    will_return(__wrap_OSHash_Next, NULL);

    expect_value(__wrap_wdb_get_agent_info, id, 1);
    will_return(__wrap_wdb_get_agent_info, j_agent_info);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to retrieve agent's '1' data from Wazuh DB");
    expect_value(__wrap_OSHash_Delete, self, agents_to_alert_hash);
    expect_value(__wrap_OSHash_Delete, key, "1");
    will_return(__wrap_OSHash_Delete, 2);

    monitor_agents_alert();

    os_free(current_node);
}

void test_monitor_agents_alert_message_sent() {
    // Setting an arbitrary last_keepalive = 100
    cJSON *j_agent_info = cJSON_Parse("[{\"connection_status\":\"disconnected\",\
    \"last_keepalive\":100,\"name\":\"Agent1\",\"register_ip\":\"any\"}]");
    OSHashNode *current_node = NULL;
    char msg_to_send[OS_SIZE_1024];
    char header[OS_SIZE_256];

    os_calloc(1, sizeof(OSHashNode), current_node);
    current_node->next = NULL;
    current_node->key = "1";

    expect_value(__wrap_OSHash_Begin, self, agents_to_alert_hash);
    will_return(__wrap_OSHash_Begin, current_node);

    expect_value(__wrap_OSHash_Next, self, agents_to_alert_hash);
    will_return(__wrap_OSHash_Next, NULL);

    expect_value(__wrap_wdb_get_agent_info, id, 1);
    will_return(__wrap_wdb_get_agent_info, j_agent_info);

    mond.global.agents_disconnection_time = 20;
    mond.global.agents_disconnection_alert_time = 100;
    will_return(__wrap_time, 1000);

    // monitor_send_disconnection_msg
    expect_string(__wrap_wdb_find_agent, name, "Agent1");
    expect_string(__wrap_wdb_find_agent, ip, "any");
    will_return(__wrap_wdb_find_agent, 1);
    snprintf(msg_to_send, OS_SIZE_1024, AG_DISCON_MSG, "Agent1-any");
    snprintf(header, OS_SIZE_256, "[%03d] (%s) %s", 1, "Agent1", "any");
    expect_string(__wrap_SendMSG, message, msg_to_send);
    expect_string(__wrap_SendMSG, locmsg, header);
    expect_value(__wrap_SendMSG, loc, SECURE_MQ);
    will_return(__wrap_SendMSG, 1);

    expect_value(__wrap_OSHash_Delete, self, agents_to_alert_hash);
    expect_value(__wrap_OSHash_Delete, key, "1");
    will_return(__wrap_OSHash_Delete, 2);

    monitor_agents_alert();

    os_free(current_node);
}

/* Tests monitor_agents_deletion */

void test_monitor_agents_deletion_success() {
    int *agents_array_test = NULL;
    char msg_to_send[OS_SIZE_1024];
    char *agent_id_str = NULL;
    // Setting an arbitrary last_keepalive = 100
    cJSON *j_agent_info = cJSON_Parse("[{\"last_keepalive\":100,\"name\":\"Agent13\",\"register_ip\":\"any\"}]");

    os_calloc(2, sizeof(int), agents_array_test);
    // Arbitrary agent's ID 13
    agents_array_test[0] = 13;
    agents_array_test[1] = -1;

    mond.global.agents_disconnection_time = 20;
    mond.delete_old_agents = 2;
    will_return(__wrap_time, 1000);

    expect_string(__wrap_wdb_get_agents_by_connection_status, status, "disconnected");
    will_return(__wrap_wdb_get_agents_by_connection_status, agents_array_test);

    expect_value(__wrap_wdb_get_agent_info, id, 13);
    will_return(__wrap_wdb_get_agent_info, j_agent_info);

    // delete_old_agent
    os_strdup("13", agent_id_str);
    will_return(__wrap_get_agent_id_from_name, agent_id_str);
    will_return(__wrap_auth_connect, 1);
    expect_string(__wrap_auth_remove_agent, id, agent_id_str);
    will_return(__wrap_auth_remove_agent, 0);

    // monitor_send_deletion_msg
    snprintf(msg_to_send, OS_SIZE_1024, OS_AG_REMOVED, "Agent13-any");
    expect_string(__wrap_SendMSG, message, msg_to_send);
    expect_string(__wrap_SendMSG, locmsg, ARGV0);
    expect_value(__wrap_SendMSG, loc, LOCALFILE_MQ);
    will_return(__wrap_SendMSG, 1);

    monitor_agents_deletion();
}

void test_monitor_agents_deletion_agent_info_fail() {
    int *agents_array_test = NULL;

    os_calloc(2, sizeof(int), agents_array_test);
    // Arbitrary agent's ID 13
    agents_array_test[0] = 13;
    agents_array_test[1] = -1;

    expect_string(__wrap_wdb_get_agents_by_connection_status, status, "disconnected");
    will_return(__wrap_wdb_get_agents_by_connection_status, agents_array_test);

    expect_value(__wrap_wdb_get_agent_info, id, 13);
    will_return(__wrap_wdb_get_agent_info, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to retrieve agent's '13' data from Wazuh DB");
    expect_value(__wrap_OSHash_Delete, self, agents_to_alert_hash);
    expect_string(__wrap_OSHash_Delete, key, "13");
    will_return(__wrap_OSHash_Delete, 2);

    monitor_agents_deletion();
}

void test_monitor_agents_deletion_auth_fail() {
    int *agents_array_test = NULL;
    char *agent_id_str = NULL;
    // Setting an arbitrary last_keepalive = 100
    cJSON *j_agent_info = cJSON_Parse("[{\"last_keepalive\":100,\"name\":\"Agent13\",\"register_ip\":\"any\"}]");

    os_calloc(2, sizeof(int), agents_array_test);
    // Arbitrary agent's ID 13
    agents_array_test[0] = 13;
    agents_array_test[1] = -1;

    mond.global.agents_disconnection_time = 20;
    mond.delete_old_agents = 2;
    will_return(__wrap_time, 1000);

    expect_string(__wrap_wdb_get_agents_by_connection_status, status, "disconnected");
    will_return(__wrap_wdb_get_agents_by_connection_status, agents_array_test);

    expect_value(__wrap_wdb_get_agent_info, id, 13);
    will_return(__wrap_wdb_get_agent_info, j_agent_info);

    // delete_old_agent
    os_strdup("13", agent_id_str);
    will_return(__wrap_get_agent_id_from_name, agent_id_str);
    will_return(__wrap_auth_connect, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Monitord could not connect to to Authd socket. Is Authd running?");

    monitor_agents_deletion();
}

void test_monitor_agents_deletion_agent_id_fail() {
    int *agents_array_test = NULL;
    // Setting an arbitrary last_keepalive = 100
    cJSON *j_agent_info = cJSON_Parse("[{\"last_keepalive\":100,\"name\":\"Agent13\",\"register_ip\":\"any\"}]");

    os_calloc(2, sizeof(int), agents_array_test);
    // Arbitrary agent's ID 13
    agents_array_test[0] = 13;
    agents_array_test[1] = -1;

    mond.global.agents_disconnection_time = 20;
    mond.delete_old_agents = 2;
    will_return(__wrap_time, 1000);

    expect_string(__wrap_wdb_get_agents_by_connection_status, status, "disconnected");
    will_return(__wrap_wdb_get_agents_by_connection_status, agents_array_test);

    expect_value(__wrap_wdb_get_agent_info, id, 13);
    will_return(__wrap_wdb_get_agent_info, j_agent_info);

    // delete_old_agent
    will_return(__wrap_get_agent_id_from_name, NULL);

    monitor_agents_deletion();
}

/* Tests monitor_logs */

 void test_monitor_logs_size_false() {
    bool check_logs_size = FALSE;
    char path[PATH_MAX] = "/path";
    char path_json[PATH_MAX] = "/path_json";

    mond.day_wait = 0;
    mond.rotate_log = 1;

    monitor_logs(check_logs_size, path, path_json);
 }

 void test_monitor_logs_size_true() {
    bool check_logs_size = TRUE;
    char path[PATH_MAX] = "/path";
    char path_json[PATH_MAX] = "/path_json";

    mond.day_wait = 0;
    mond.rotate_log = 1;
    mond.size_rotate = 10;

    expect_string(__wrap_stat, __file, path);
    will_return(__wrap_stat, 100);
    will_return(__wrap_stat, 0);

    expect_string(__wrap_stat, __file, path_json);
    will_return(__wrap_stat, 100);
    will_return(__wrap_stat, 0);

    monitor_logs(check_logs_size, path, path_json);
 }

int main()
{
    const struct CMUnitTest tests[] =
    {
        /* Tests monitor_send_deletion_msg */
        cmocka_unit_test_setup_teardown(test_monitor_send_deletion_msg_success, setup_monitord, teardown_monitord),
        cmocka_unit_test_setup_teardown(test_monitor_send_deletion_msg_fail, setup_monitord, teardown_monitord),
        /* Tests monitor_send_disconnection_msg */
        cmocka_unit_test_setup_teardown(test_monitor_send_disconnection_msg_success, setup_monitord, teardown_monitord),
        cmocka_unit_test_setup_teardown(test_monitor_send_disconnection_msg_send_msg_fail, setup_monitord, teardown_monitord),
        cmocka_unit_test_setup_teardown(test_monitor_send_disconnection_msg_agent_removed, setup_monitord, teardown_monitord),
        cmocka_unit_test_setup_teardown(test_monitor_send_disconnection_msg_fail, setup_monitord, teardown_monitord),
        cmocka_unit_test_setup_teardown(test_monitor_send_disconnection_ip_fail, setup_monitord, teardown_monitord),
        cmocka_unit_test_setup_teardown(test_monitor_send_disconnection_name_size_fail, setup_monitord, teardown_monitord),
        /* Tests monitor_agents_disconnection */
        cmocka_unit_test_setup_teardown(test_monitor_agents_disconnection, setup_monitord, teardown_monitord),
        /* Tests monitor_agents_alert */
        cmocka_unit_test_setup_teardown(test_monitor_agents_alert_active, setup_monitord, teardown_monitord),
        cmocka_unit_test_setup_teardown(test_monitor_agents_alert_agent_info_fail, setup_monitord, teardown_monitord),
        cmocka_unit_test_setup_teardown(test_monitor_agents_alert_message_sent, setup_monitord, teardown_monitord),
        /* Tests monitor_agents_deletion */
        cmocka_unit_test_setup_teardown(test_monitor_agents_deletion_success, setup_monitord, teardown_monitord),
        cmocka_unit_test_setup_teardown(test_monitor_agents_deletion_agent_info_fail, setup_monitord, teardown_monitord),
        cmocka_unit_test_setup_teardown(test_monitor_agents_deletion_auth_fail, setup_monitord, teardown_monitord),
        cmocka_unit_test_setup_teardown(test_monitor_agents_deletion_agent_id_fail, setup_monitord, teardown_monitord),
        /* Tests monitor_logs */
        cmocka_unit_test_setup_teardown(test_monitor_logs_size_false, setup_monitord, teardown_monitord),
        cmocka_unit_test_setup_teardown(test_monitor_logs_size_true, setup_monitord, teardown_monitord),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
