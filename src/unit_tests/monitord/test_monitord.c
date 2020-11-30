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
#include "../wrappers/wazuh/shared/validate_op_wrappers.h"

#include "../external/cJSON/cJSON.h"
#include "headers/store_op.h"
#include "monitord/monitord.h"
#include "headers/defs.h"
#include "headers/shared.h"
#include "config/config.h"
#include "os_err.h"

/* redefinitons/wrapping */

time_t __wrap_time(__attribute__((unused)) time_t *t) {
    return mock_type(time_t);
}

int __wrap_ReadConfig(int modules, const char *cfgfile, __attribute__((unused)) void *d1, __attribute__((unused)) void *d2) {
    check_expected(modules);
    check_expected(cfgfile);
    return mock();
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
    mond.compress = 0;
    mond.sign = 0;
    mond.monitor_agents = 0;
    mond.keep_log_days = 0;
    mond.rotate_log = 0;
    mond.size_rotate = 0;
    mond.daily_rotations = 0;
    mond.delete_old_agents = 0;

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
    mond.compress = 0;
    mond.sign = 0;
    mond.monitor_agents = 0;
    mond.keep_log_days = 0;
    mond.rotate_log = 0;
    mond.size_rotate = 0;
    mond.daily_rotations = 0;
    mond.delete_old_agents = 0;

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
    mond.monitor_agents = 1;
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
    mond.monitor_agents = 1;
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
    mond.monitor_agents = 1;

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
    mond.monitor_agents = 1;

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

/* Tests getMonitorInternalOptions */

void test_getMonitorInternalOptions_success(void **state) {
    cJSON *root = NULL;
    cJSON *object = NULL;

    // Arbitrary configuration
    mond.day_wait = 2;
    mond.compress = 1;
    mond.sign = 0;
    mond.monitor_agents = 1;
    mond.keep_log_days = 10;
    mond.rotate_log = 1;
    mond.size_rotate = 0;
    mond.daily_rotations = 100;
    mond.delete_old_agents = 3;

    root = getMonitorInternalOptions();

    if (root) {
        object = cJSON_GetObjectItem(root->child, "day_wait");
        assert_int_equal(object->valueint, mond.day_wait);
        object = cJSON_GetObjectItem(root->child, "compress");
        assert_int_equal(object->valueint, mond.compress);
        object = cJSON_GetObjectItem(root->child, "sign");
        assert_int_equal(object->valueint, mond.sign);
        object = cJSON_GetObjectItem(root->child, "monitor_agents");
        assert_int_equal(object->valueint, mond.monitor_agents);
        object = cJSON_GetObjectItem(root->child, "keep_log_days");
        assert_int_equal(object->valueint, mond.keep_log_days);
        object = cJSON_GetObjectItem(root->child, "rotate_log");
        assert_int_equal(object->valueint, mond.rotate_log);
        object = cJSON_GetObjectItem(root->child, "size_rotate");
        assert_int_equal(object->valueint, mond.size_rotate);
        object = cJSON_GetObjectItem(root->child, "daily_rotations");
        assert_int_equal(object->valueint, mond.daily_rotations);
        object = cJSON_GetObjectItem(root->child, "delete_old_agents");
        assert_int_equal(object->valueint, mond.delete_old_agents);
    }

    cJSON_Delete(root);
}

/* Tests getMonitorGlobalOptions */

void test_getMonitorGlobalOptions_success(void **state) {
    cJSON *root = NULL;
    cJSON *object = NULL;

    // Arbitrary configuration
    mond.global.agents_disconnection_time = 20;
    mond.global.agents_disconnection_alert_time = 100;

    root = getMonitorGlobalOptions();

    if (root) {
        object = cJSON_GetObjectItem(root->child, "agents_disconnection_time");
        assert_int_equal(object->valueint, mond.global.agents_disconnection_time);
        object = cJSON_GetObjectItem(root->child, "agents_disconnection_alert_time");
        assert_int_equal(object->valueint, mond.global.agents_disconnection_alert_time);
    }

    cJSON_Delete(root);
}

/* Tests getReportsOptions */

void test_getReportsOptions_success(void **state) {
    cJSON *root = NULL;
    report_config **reports_array = NULL;
    report_config *report = NULL;
    char **email_array = NULL;
    char *expected_output = "{\"reports\":[{\"title\":\"Title\",\"group\":\"Group\",\"rule\":\"Rule\",\
\"level\":\"Level\",\"srcip\":\"SourceIP\",\"user\":\"User\",\"showlogs\":\"yes\",\"email_to\":[\"emailto_test\"]}]}";
    char *result = NULL;

    os_calloc(2, sizeof(report_config*), reports_array);
    os_calloc(1, sizeof(report_config), report);
    os_calloc(2, sizeof(char*), email_array);

    reports_array[0] = report;
    reports_array[1] = NULL;
    os_strdup("emailto_test", email_array[0]);
    email_array[1] = NULL;

    // Arbitrary configuration
    report->title = "Title";
    report->r_filter.group = "Group";
    report->r_filter.rule = "Rule";
    report->r_filter.level = "Level";
    report->r_filter.srcip = "SourceIP";
    report->r_filter.user = "User";
    report->r_filter.show_alerts = 1;
    report->emailto = email_array;
    mond.reports = reports_array;

    root = getReportsOptions();

    result = cJSON_PrintUnformatted(root);
    assert_string_equal(expected_output, result);

    cJSON_Delete(root);
    os_free(report);
    os_free(reports_array);
    os_free(email_array[0]);
    os_free(email_array);
    os_free(result);
}

/* Tests ReadConfig */

void test_MonitordConfig_success(void **state) {
    int result = 0;
    char *cfg = "/config_path";
    int no_agents = 0;
    short day_wait = -1;

    will_return_count(__wrap_getDefine_Int, 1, -1);

    expect_value(__wrap_ReadConfig, modules, CREPORTS);
    expect_string(__wrap_ReadConfig, cfgfile, cfg);
    will_return(__wrap_ReadConfig, 0);
    expect_value(__wrap_ReadConfig, modules, CGLOBAL);
    expect_string(__wrap_ReadConfig, cfgfile, cfg);
    will_return(__wrap_ReadConfig, 0);

    result = MonitordConfig(cfg, &mond, no_agents, day_wait);

    assert_int_equal(result, OS_SUCCESS);
    assert_int_equal(mond.global.agents_disconnection_time, 20);
    assert_int_equal(mond.global.agents_disconnection_alert_time, 100);

    assert_null(mond.agents);
    assert_null(mond.smtpserver);
    assert_null(mond.emailfrom);
    assert_null(mond.emailidsname);

    assert_int_equal(mond.day_wait, 1);
    assert_int_equal(mond.compress, 1);
    assert_int_equal(mond.sign, 1);
    assert_int_equal(mond.monitor_agents, 1);
    assert_int_equal(mond.rotate_log, 1);
    assert_int_equal(mond.keep_log_days, 1);
    assert_int_equal(mond.size_rotate, 1 * 1024 * 1024);
    assert_int_equal(mond.daily_rotations, 1);
    assert_int_equal(mond.delete_old_agents, 1);
}

void test_MonitordConfig_fail(void **state) {
    char *cfg = "/config_path";
    int no_agents = 0;
    short day_wait = -1;

    will_return_count(__wrap_getDefine_Int, 1, -1);

    expect_value(__wrap_ReadConfig, modules, CREPORTS);
    expect_string(__wrap_ReadConfig, cfgfile, cfg);
    will_return(__wrap_ReadConfig, -1);

    expect_string(__wrap__merror_exit, formatted_msg, "(1202): Configuration error at '/config_path'.");

    MonitordConfig(cfg, &mond, no_agents, day_wait);
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
        /* Tests getMonitorInternalOptions */
        cmocka_unit_test_setup_teardown(test_getMonitorInternalOptions_success, setup_monitord, teardown_monitord),
        /* Tests getMonitorGlobalOptions */
        cmocka_unit_test_setup_teardown(test_getMonitorGlobalOptions_success, setup_monitord, teardown_monitord),
        /* Tests getReportsOptions */
        cmocka_unit_test_setup_teardown(test_getReportsOptions_success, setup_monitord, teardown_monitord),
        /* Tests MonitordConfig */
        cmocka_unit_test_setup_teardown(test_MonitordConfig_success, setup_monitord, teardown_monitord),
        cmocka_unit_test_setup_teardown(test_MonitordConfig_fail, setup_monitord, teardown_monitord),

    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
