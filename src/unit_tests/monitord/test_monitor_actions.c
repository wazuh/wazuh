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

#include "headers/store_op.h"
#include "monitord/monitord.h"
#include "headers/defs.h"
#include "headers/shared.h"
#include "config/config.h"

/*
#include "wazuh_db/wdb.h"
#include "wazuhdb_op.h"
#include "hash_op.h"

#include "../wrappers/posix/pthread_wrappers.h"
#include "../wrappers/wazuh/shared/hash_op_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/externals/sqlite/sqlite3_wrappers.h"
*/

time_t __wrap_time(__attribute__((unused)) time_t *t) {
    return mock_type(time_t);
}

typedef struct test_struct {
    monitor_config mond;
    monitor_time_control mond_time_control;
} test_struct_t;

extern monitor_time_control mond_time_control;

/* setup/teardown */

int setup_monitord(void **state) {
    test_mode = 1;
    test_struct_t *init_data = NULL;
    os_calloc(1,sizeof(test_struct_t),init_data);
    *state = init_data;

    mond.global.agents_disconnection_alert_time = 0;
    mond.global.agents_disconnection_time = 0;

    mond.delete_old_agents = 0;
    mond.a_queue = -1;

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
    test_struct_t *data  = (test_struct_t *)*state;
    os_free(data);
    mond.global.agents_disconnection_alert_time = 0;
    mond.global.agents_disconnection_time = 0;

    mond.delete_old_agents = 0;
    mond.a_queue = -1;

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

void test_monitor_send_disconnection_msg_agent_removed(void **state) {
    char *agent = "Agent1-any";
    char msg_to_send[OS_SIZE_1024];

    expect_string(__wrap_wdb_find_agent, name, "Agent1");
    expect_string(__wrap_wdb_find_agent, ip, "any");
    will_return(__wrap_wdb_find_agent, -2);

    // monitor_send_deletion_msg()
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

int main()
{
    const struct CMUnitTest tests[] =
    {
        /* Tests monitor_send_deletion_msg */
        cmocka_unit_test_setup_teardown(test_monitor_send_deletion_msg_success, setup_monitord, teardown_monitord),
        cmocka_unit_test_setup_teardown(test_monitor_send_deletion_msg_fail, setup_monitord, teardown_monitord),
        /* Tests monitor_send_disconnection_msg */
        cmocka_unit_test_setup_teardown(test_monitor_send_disconnection_msg_success, setup_monitord, teardown_monitord),
        cmocka_unit_test_setup_teardown(test_monitor_send_disconnection_msg_agent_removed, setup_monitord, teardown_monitord),
        cmocka_unit_test_setup_teardown(test_monitor_send_disconnection_msg_fail, setup_monitord, teardown_monitord),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
