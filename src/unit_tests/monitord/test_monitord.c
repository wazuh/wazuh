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

/* Tests monitor_init_time */

void test_monitor_init_time_success(void **state) {
    // Setting an arbitrary date 02-Nov-20 12:10:01
    time_t tm = 1604319001;
    struct tm test_time;
    localtime_r(&tm, &test_time);

    will_return(__wrap_time, 1604319001);
    // Setting random data
    mond_time_control.disconnect_counter = 123;
    mond_time_control.alert_counter = 456;
    mond_time_control.delete_counter = 789;

    monitor_init_time_control();

    assert_int_equal(0, mond_time_control.disconnect_counter);
    assert_int_equal(0, mond_time_control.alert_counter);
    assert_int_equal(0, mond_time_control.delete_counter);

    assert_int_equal(test_time.tm_sec, mond_time_control.current_time.tm_sec);
    assert_int_equal(test_time.tm_min, mond_time_control.current_time.tm_min);
    assert_int_equal(test_time.tm_hour, mond_time_control.current_time.tm_hour);
    assert_int_equal(test_time.tm_mday, mond_time_control.current_time.tm_mday);
    assert_int_equal(test_time.tm_mon, mond_time_control.current_time.tm_mon);
    assert_int_equal(test_time.tm_year, mond_time_control.current_time.tm_year);

    assert_int_equal(mond_time_control.today, mond_time_control.current_time.tm_mday);
    assert_int_equal(mond_time_control.thismonth, mond_time_control.current_time.tm_mon);
    assert_int_equal(mond_time_control.thisyear, mond_time_control.current_time.tm_year + 1900);
}

/* Tests monitor_step_time */

void test_monitor_step_time_success(void **state) {
    // Setting an arbitrary date 02-Nov-20 12:20:01
    time_t tm = 1604319601;
    struct tm test_time;
    localtime_r(&tm, &test_time);

    mond.delete_old_agents = 1;
    mond_time_control.disconnect_counter = 0;
    mond_time_control.alert_counter = 0;
    mond_time_control.delete_counter = 0;
    will_return(__wrap_time, 1604319601);

    monitor_step_time();

    assert_int_equal(1, mond_time_control.disconnect_counter);
    assert_int_equal(1, mond_time_control.alert_counter);
    assert_int_equal(1, mond_time_control.delete_counter);

    assert_int_equal(test_time.tm_sec, mond_time_control.current_time.tm_sec);
    assert_int_equal(test_time.tm_min, mond_time_control.current_time.tm_min);
    assert_int_equal(test_time.tm_hour, mond_time_control.current_time.tm_hour);
    assert_int_equal(test_time.tm_mday, mond_time_control.current_time.tm_mday);
    assert_int_equal(test_time.tm_mon, mond_time_control.current_time.tm_mon);
    assert_int_equal(test_time.tm_year, mond_time_control.current_time.tm_year);
}

void test_monitor_step_time_no_old_agents_success(void **state) {
    // Setting an arbitrary date 02-Nov-20 12:20:01
    time_t tm = 1604319601;
    struct tm test_time;
    localtime_r(&tm, &test_time);

    mond.delete_old_agents = 0;
    mond_time_control.disconnect_counter = 0;
    mond_time_control.alert_counter = 0;
    mond_time_control.delete_counter = 0;
    will_return(__wrap_time, 1604319601);

    monitor_step_time();

    assert_int_equal(1, mond_time_control.disconnect_counter);
    assert_int_equal(1, mond_time_control.alert_counter);
    assert_int_equal(0, mond_time_control.delete_counter);

    assert_int_equal(test_time.tm_sec, mond_time_control.current_time.tm_sec);
    assert_int_equal(test_time.tm_min, mond_time_control.current_time.tm_min);
    assert_int_equal(test_time.tm_hour, mond_time_control.current_time.tm_hour);
    assert_int_equal(test_time.tm_mday, mond_time_control.current_time.tm_mday);
    assert_int_equal(test_time.tm_mon, mond_time_control.current_time.tm_mon);
    assert_int_equal(test_time.tm_year, mond_time_control.current_time.tm_year);
}

/* Tests monitor_update_date */

void test_monitor_update_date_success(void **state) {
    // Setting an arbitrary date 02-Nov-20 12:30:01
    time_t tm = 1604320201;
    localtime_r(&tm, &mond_time_control.current_time);

    mond_time_control.today = 0;
    mond_time_control.thismonth= 0;
    mond_time_control.thisyear = 0;

    monitor_update_date();

    assert_int_equal(mond_time_control.today, mond_time_control.current_time.tm_mday);
    assert_int_equal(mond_time_control.thismonth, mond_time_control.current_time.tm_mon);
    assert_int_equal(mond_time_control.thisyear, mond_time_control.current_time.tm_year + 1900);
}

/* Tests check_disconnection_trigger */

void test_check_disconnection_trigger_true(void **state) {
    int result = 0;
    mond_time_control.disconnect_counter = 100;
    mond.global.agents_disconnection_time = 10;

    result = check_disconnection_trigger();

    assert_int_equal(result, 1);
}

void test_check_disconnection_trigger_false(void **state) {
    int result = 0;
    mond_time_control.disconnect_counter = 1;
    mond.global.agents_disconnection_time = 10;

    result = check_disconnection_trigger();

    assert_int_equal(result, 0);
}

/* Tests check_alert_trigger */

void test_check_alert_trigger_true(void **state) {
    int result = 0;
    mond_time_control.alert_counter = 100;
    mond.global.agents_disconnection_alert_time = 10;

    result = check_alert_trigger();

    assert_int_equal(result, 1);
}

void test_check_alert_trigger_false(void **state) {
    int result = 0;
    mond_time_control.alert_counter = 1;
    mond.global.agents_disconnection_alert_time = 10;

    result = check_alert_trigger();

    assert_int_equal(result, 0);
}

/* Tests check_deletion_trigger */

void test_check_deletion_trigger_true(void **state) {
    int result = 0;
    mond_time_control.delete_counter = 200;
    mond.delete_old_agents = 2;

    result = check_deletion_trigger();

    assert_int_equal(result, 1);
}

void test_check_deletion_trigger_false(void **state) {
    int result = 0;
    mond_time_control.delete_counter = 100;
    mond.delete_old_agents = 2;

    result = check_deletion_trigger();

    assert_int_equal(result, 0);
}

void test_check_deletion_trigger_no_old_agents_false(void **state) {
    int result = 0;
    mond_time_control.delete_counter = 0;
    mond.delete_old_agents = 0;

    result = check_deletion_trigger();

    assert_int_equal(result, 0);
}

/* Tests check_logs_time_trigger */

void test_check_logs_time_trigger_true(void **state) {
    int result = 0;
    mond_time_control.today = 5;
    mond_time_control.current_time.tm_mday = 6;

    result = check_logs_time_trigger();

    assert_int_equal(result, 1);
}

void test_check_logs_time_trigger_false(void **state) {
    int result = 0;
    mond_time_control.today = 5;
    mond_time_control.current_time.tm_mday = 5;

    result = check_logs_time_trigger();

    assert_int_equal(result, 0);
}

/* Tests monitor_queue_connect */

void test_monitor_queue_connect_fail(void **state) {
    expect_string(__wrap_StartMQ, path, DEFAULTQUEUE);
    expect_value(__wrap_StartMQ, type, WRITE);
    will_return(__wrap_StartMQ, -1);

    monitor_queue_connect();

    assert_int_equal(mond.a_queue, -1);
}

void test_monitor_queue_connect_success(void **state) {
    expect_string(__wrap_StartMQ, path, DEFAULTQUEUE);
    expect_value(__wrap_StartMQ, type, WRITE);
    will_return(__wrap_StartMQ, 1);
    expect_string(__wrap_SendMSG, message, OS_AD_STARTED);
    expect_string(__wrap_SendMSG, locmsg, ARGV0);
    expect_value(__wrap_SendMSG, loc, LOCALFILE_MQ);
    will_return(__wrap_SendMSG, 1);

    monitor_queue_connect();

    assert_int_equal(mond.a_queue, 1);
}

void test_monitor_queue_connect_msg_fail(void **state) {
    expect_string(__wrap_StartMQ, path, DEFAULTQUEUE);
    expect_value(__wrap_StartMQ, type, WRITE);
    will_return(__wrap_StartMQ, 1);
    expect_string(__wrap_SendMSG, message, OS_AD_STARTED);
    expect_string(__wrap_SendMSG, locmsg, ARGV0);
    expect_value(__wrap_SendMSG, loc, LOCALFILE_MQ);
    will_return(__wrap_SendMSG, -1);
    expect_string(__wrap__merror, formatted_msg, QUEUE_SEND);

    monitor_queue_connect();

    assert_int_equal(mond.a_queue, -1);
}

int main()
{
    const struct CMUnitTest tests[] =
    {
        /* Tests monitor_init_time */
        cmocka_unit_test_setup_teardown(test_monitor_init_time_success, setup_monitord, teardown_monitord),
        /* Tests monitor_step_time */
        cmocka_unit_test_setup_teardown(test_monitor_step_time_success, setup_monitord, teardown_monitord),
        cmocka_unit_test_setup_teardown(test_monitor_step_time_no_old_agents_success, setup_monitord, teardown_monitord),
        /* Tests monitor_update_date */
        cmocka_unit_test_setup_teardown(test_monitor_update_date_success, setup_monitord, teardown_monitord),
        /* Tests check_disconnection_trigger */
        cmocka_unit_test_setup_teardown(test_check_disconnection_trigger_true, setup_monitord, teardown_monitord),
        cmocka_unit_test_setup_teardown(test_check_disconnection_trigger_false, setup_monitord, teardown_monitord),
        /* Tests check_alert_trigger */
        cmocka_unit_test_setup_teardown(test_check_alert_trigger_true, setup_monitord, teardown_monitord),
        cmocka_unit_test_setup_teardown(test_check_alert_trigger_false, setup_monitord, teardown_monitord),
        /* Tests check_deletion_trigger */
        cmocka_unit_test_setup_teardown(test_check_deletion_trigger_true, setup_monitord, teardown_monitord),
        cmocka_unit_test_setup_teardown(test_check_deletion_trigger_false, setup_monitord, teardown_monitord),
        cmocka_unit_test_setup_teardown(test_check_deletion_trigger_no_old_agents_false, setup_monitord, teardown_monitord),
        /* Tests check_logs_time_trigger */
        cmocka_unit_test_setup_teardown(test_check_logs_time_trigger_true, setup_monitord, teardown_monitord),
        cmocka_unit_test_setup_teardown(test_check_logs_time_trigger_false, setup_monitord, teardown_monitord),
        /* Tests monitor_queue_connect */
        cmocka_unit_test_setup_teardown(test_monitor_queue_connect_fail, setup_monitord, teardown_monitord),
        cmocka_unit_test_setup_teardown(test_monitor_queue_connect_success, setup_monitord, teardown_monitord),
        cmocka_unit_test_setup_teardown(test_monitor_queue_connect_msg_fail, setup_monitord, teardown_monitord),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
