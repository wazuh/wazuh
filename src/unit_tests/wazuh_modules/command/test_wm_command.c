/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Test corresponding to the scheduling capacities
 * for command Module
 * */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <time.h>

#include "shared.h"
#include "../../../wazuh_modules/wmodules.h"
#include "../../../wazuh_modules/wm_command.h"

#include "../scheduling/wmodules_scheduling_helpers.h"
#include "../../wrappers/common.h"
#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../wrappers/wazuh/wazuh_modules/wm_exec_wrappers.h"
#include "../../wrappers/wazuh/shared/mq_op_wrappers.h"
#include "../../wrappers/wazuh/wazuh_modules/wmodules_wrappers.h"

#define TEST_MAX_DATES 5

static wmodule *command_module;
static OS_XML *lxml;
extern int test_mode;

/****************************************************************/
static void wmodule_cleanup(wmodule *module){
    wm_command_t* module_data = (wm_command_t *)module->data;
    free(module_data->sha256_hash);
    free(module_data->sha1_hash);
    free(module_data->full_command);
    free(module_data->command);
    free(module_data->tag);
    free(module_data);
    free(module->tag);
    free(module);
}

/***  SETUPS/TEARDOWNS  ******/
static int setup_module() {
    command_module = calloc(1, sizeof(wmodule));
    const char *string =
        "<disabled>no</disabled>\n"
        "<tag>test</tag>\n"
        "<command>/bin/bash /root/script.sh</command>\n"
        "<interval>1d</interval>\n"
        "<ignore_output>no</ignore_output>\n"
        "<run_on_start>no</run_on_start>\n"
        "<timeout>0</timeout>\n"
        "<verify_sha1>da39a3ee5e6b4b0d3255bfef95601890afd80709</verify_sha1>\n"
        "<verify_sha256>292a188e498caea5c5fbfb0beca413c980e7a5edf40d47cf70e1dbc33e4f395e</verify_sha256>\n"
        "<interval>10m</interval>\n"
        "<skip_verification>yes</skip_verification>"
    ;
    lxml = malloc(sizeof(OS_XML));
    XML_NODE nodes = string_to_xml_node(string, lxml);

    int ret = wm_command_read(nodes, command_module, 0);
    OS_ClearNode(nodes);
    test_mode = 1;
    return ret;
}

static int teardown_module(){
    test_mode = 0;
    wmodule_cleanup(command_module);
    OS_ClearXML(lxml);
    return 0;
}

static int setup_test_executions(void **state){
    wm_max_eps = 1;
    return 0;
}

static int teardown_test_executions(void **state){
    wm_command_t* module_data = (wm_command_t *) *state;
    sched_scan_free(&(module_data->scan_config));
    return 0;
}

static int setup_test_read(void **state) {
    test_structure *test = calloc(1, sizeof(test_structure));
    test->module =  calloc(1, sizeof(wmodule));
    *state = test;
    return 0;
}

static int teardown_test_read(void **state) {
    test_structure *test = *state;
    OS_ClearNode(test->nodes);
    OS_ClearXML(&(test->xml));
    wm_command_t *module_data = (wm_command_t*)test->module->data;
    sched_scan_free(&(module_data->scan_config));
    wmodule_cleanup(test->module);
    os_free(test);
    return 0;
}

/** Tests **/
void test_interval_execution(void **state) {
    wm_command_t* module_data = (wm_command_t *)command_module->data;
    *state = module_data;
    module_data->scan_config.next_scheduled_scan_time = 0;
    module_data->scan_config.scan_day = 0;
    module_data->scan_config.scan_wday = -1;
    module_data->scan_config.interval = 60; // 1min
    module_data->scan_config.month_interval = false;

    expect_string(__wrap_StartMQ, path, DEFAULTQUEUE);
    expect_value(__wrap_StartMQ, type, WRITE);
    will_return(__wrap_StartMQ, 0);

    expect_any_always(__wrap_wm_exec, command);
    expect_any_always(__wrap_wm_exec, secs);
    expect_any_always(__wrap_wm_exec, add_path);

    will_return_always(__wrap_wm_exec, 0);

    will_return_count(__wrap_FOREVER, 1, TEST_MAX_DATES);
    will_return(__wrap_FOREVER, 0);
    expect_any_always(__wrap__mtinfo, tag);
    expect_any_always(__wrap__mtinfo, formatted_msg);
    expect_any_always(__wrap__mtdebug1, tag);
    expect_any_always(__wrap__mtdebug1, formatted_msg);

    expect_any_always(__wrap_wm_validate_command, command);
    expect_any_always(__wrap_wm_validate_command, digest);
    expect_any_always(__wrap_wm_validate_command, ctype);
    will_return_always(__wrap_wm_validate_command, 1);

    command_module->context->start(module_data);
}

void test_fake_tag(void **state) {
    const char *string =
        "<fake>True</fake>\n"
        "<disabled>no</disabled>\n"
        "<tag>test</tag>\n"
        "<command>/bin/bash /root/script.sh</command>\n"
        "<timeout>1800</timeout>\n"
        "<time>19:55</time>\n"
        "<ignore_output>no</ignore_output>\n"
        "<run_on_start>no</run_on_start>\n"
        "<timeout>0</timeout>\n"
        "<verify_sha1>da39a3ee5e6b4b0d3255bfef95601890afd80709</verify_sha1>\n"
        "<verify_sha256>292a188e498caea5c5fbfb0beca413c980e7a5edf40d47cf70e1dbc33e4f395e</verify_sha256>\n"
        "<interval>10m</interval>\n"
        "<skip_verification>yes</skip_verification>";
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "No such tag 'fake' at module 'command'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_command_read(test->nodes, test->module, 0),-1);
}

void test_read_scheduling_monthday_configuration(void **state) {
    const char *string =
        "<disabled>no</disabled>\n"
        "<tag>test</tag>\n"
        "<time>12:05</time>\n"
        "<day>1</day>\n"
        "<command>/bin/bash /root/script.sh</command>\n"
        "<timeout>1800</timeout>\n"
        "<ignore_output>no</ignore_output>\n"
        "<run_on_start>no</run_on_start>\n"
        "<timeout>0</timeout>\n"
        "<verify_sha1>da39a3ee5e6b4b0d3255bfef95601890afd80709</verify_sha1>\n"
        "<verify_sha256>292a188e498caea5c5fbfb0beca413c980e7a5edf40d47cf70e1dbc33e4f395e</verify_sha256>\n"
        "<skip_verification>yes</skip_verification>"
    ;
    test_structure *test = *state;
    expect_string(__wrap__mwarn, formatted_msg, "Interval must be a multiple of one month. New interval value: 1M");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_command_read(test->nodes, test->module, 0),0);
    wm_command_t *module_data = (wm_command_t*)test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 1);
    assert_int_equal(module_data->scan_config.interval, 1);
    assert_int_equal(module_data->scan_config.month_interval, true);
    assert_int_equal(module_data->scan_config.scan_wday, -1);
    assert_string_equal(module_data->scan_config.scan_time, "12:05");
}

void test_read_scheduling_weekday_configuration(void **state) {
    const char *string =
        "<disabled>no</disabled>\n"
        "<tag>test</tag>\n"
        "<time>10:59</time>\n"
        "<wday>Tuesday</wday>\n"
        "<command>/bin/bash /root/script.sh</command>\n"
        "<timeout>1800</timeout>\n"
        "<ignore_output>no</ignore_output>\n"
        "<run_on_start>no</run_on_start>\n"
        "<timeout>0</timeout>\n"
        "<verify_sha1>da39a3ee5e6b4b0d3255bfef95601890afd80709</verify_sha1>\n"
        "<verify_sha256>292a188e498caea5c5fbfb0beca413c980e7a5edf40d47cf70e1dbc33e4f395e</verify_sha256>\n"
        "<skip_verification>yes</skip_verification>"
    ;
    test_structure *test = *state;
    expect_string(__wrap__mwarn, formatted_msg, "Interval must be a multiple of one week. New interval value: 1w");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_command_read(test->nodes, test->module, 0),0);
    wm_command_t *module_data = (wm_command_t*)test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, 604800);
    assert_int_equal(module_data->scan_config.month_interval, false);
    assert_int_equal(module_data->scan_config.scan_wday, 2);
    assert_string_equal(module_data->scan_config.scan_time, "10:59");
}

void test_read_scheduling_daytime_configuration(void **state) {
    const char *string =
        "<disabled>no</disabled>\n"
        "<tag>test</tag>\n"
        "<time>10:53</time>\n"
        "<command>/bin/bash /root/script.sh</command>\n"
        "<timeout>1800</timeout>\n"
        "<ignore_output>no</ignore_output>\n"
        "<run_on_start>no</run_on_start>\n"
        "<timeout>0</timeout>\n"
        "<verify_sha1>da39a3ee5e6b4b0d3255bfef95601890afd80709</verify_sha1>\n"
        "<verify_sha256>292a188e498caea5c5fbfb0beca413c980e7a5edf40d47cf70e1dbc33e4f395e</verify_sha256>\n"
        "<skip_verification>yes</skip_verification>"
    ;
    test_structure *test = *state;
    expect_string(__wrap__mwarn, formatted_msg, "Interval must be a multiple of one day. New interval value: 1d");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_command_read(test->nodes, test->module, 0),0);
    wm_command_t *module_data = (wm_command_t*)test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, WM_DEF_INTERVAL);
    assert_int_equal(module_data->scan_config.month_interval, false);
    assert_int_equal(module_data->scan_config.scan_wday, -1);
    assert_string_equal(module_data->scan_config.scan_time, "10:53");
}

void test_read_scheduling_interval_configuration(void **state) {
    const char *string =
        "<disabled>no</disabled>\n"
        "<tag>test</tag>\n"
        "<interval>10s</interval>\n"
        "<command>/bin/bash /root/script.sh</command>\n"
        "<timeout>1800</timeout>\n"
        "<ignore_output>no</ignore_output>\n"
        "<run_on_start>no</run_on_start>\n"
        "<timeout>0</timeout>\n"
        "<verify_sha1>da39a3ee5e6b4b0d3255bfef95601890afd80709</verify_sha1>\n"
        "<verify_sha256>292a188e498caea5c5fbfb0beca413c980e7a5edf40d47cf70e1dbc33e4f395e</verify_sha256>\n"
        "<skip_verification>yes</skip_verification>"
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_command_read(test->nodes, test->module, 0),0);
    wm_command_t *module_data = (wm_command_t*)test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, 10); // 10 seconds
    assert_int_equal(module_data->scan_config.month_interval, false);
    assert_int_equal(module_data->scan_config.scan_wday, -1);
}

void test_validate_checksum_sha256_success(void **state) {
    wm_command_t command = {0};
    command.full_command = strdup("/test/file.sh");
    command.sha256_hash = strdup("e69ee96c1f3f6117391ce27b4656193e54b7b187d66c9920806eced9dd4a4129");
    command.skip_verification = 0;

    expect_string(__wrap_wm_validate_command, command, "/test/file.sh");
    expect_string(__wrap_wm_validate_command, digest, "e69ee96c1f3f6117391ce27b4656193e54b7b187d66c9920806eced9dd4a4129");
    expect_value(__wrap_wm_validate_command, ctype, SHA256SUM);
    will_return(__wrap_wm_validate_command, 1);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:command");
    expect_string(__wrap__mtdebug1, formatted_msg, "'SHA256' checksum verification succeded for command '/test/file.sh'.");

    int result = validate_checksum(&command, SHA256SUM);
    assert_int_equal(result, 0);

    free(command.full_command);
    free(command.sha256_hash);
}

void test_validate_checksum_sha1_success(void **state) {
    wm_command_t command = {0};
    command.full_command = strdup("/test/file.sh");
    command.sha1_hash = strdup("da39a3ee5e6b4b0d3255bfef95601890afd80709");
    command.skip_verification = 0;

    expect_string(__wrap_wm_validate_command, command, "/test/file.sh");
    expect_string(__wrap_wm_validate_command, digest, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    expect_value(__wrap_wm_validate_command, ctype, SHA1SUM);
    will_return(__wrap_wm_validate_command, 1);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:command");
    expect_string(__wrap__mtdebug1, formatted_msg, "'SHA1' checksum verification succeded for command '/test/file.sh'.");

    int result = validate_checksum(&command, SHA1SUM);
    assert_int_equal(result, 0);

    free(command.full_command);
    free(command.sha1_hash);
}

void test_validate_checksum_md5_success(void **state) {
    wm_command_t command = {0};
    command.full_command = strdup("/test/file.sh");
    command.md5_hash = strdup("d41d8cd98f00b204e9800998ecf8427e");
    command.skip_verification = 0;

    expect_string(__wrap_wm_validate_command, command, "/test/file.sh");
    expect_string(__wrap_wm_validate_command, digest, "d41d8cd98f00b204e9800998ecf8427e");
    expect_value(__wrap_wm_validate_command, ctype, MD5SUM);
    will_return(__wrap_wm_validate_command, 1);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:command");
    expect_string(__wrap__mtdebug1, formatted_msg, "'MD5' checksum verification succeded for command '/test/file.sh'.");

    int result = validate_checksum(&command, MD5SUM);
    assert_int_equal(result, 0);

    free(command.full_command);
    free(command.md5_hash);
}

void test_validate_checksum_failure_no_skip(void **state) {
    wm_command_t command = {0};
    command.full_command = strdup("/test/file.sh");
    command.sha256_hash = strdup("invalid_hash");
    command.skip_verification = 0;

    expect_string(__wrap_wm_validate_command, command, "/test/file.sh");
    expect_string(__wrap_wm_validate_command, digest, "invalid_hash");
    expect_value(__wrap_wm_validate_command, ctype, SHA256SUM);
    will_return(__wrap_wm_validate_command, 0);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:command");
    expect_string(__wrap__mterror, formatted_msg, "'SHA256' checksum verification failed for command '/test/file.sh'.");

    int result = validate_checksum(&command, SHA256SUM);
    assert_int_equal(result, -1);

    free(command.full_command);
    free(command.sha256_hash);
}

void test_validate_checksum_failure_with_skip(void **state) {
    wm_command_t command = {0};
    command.full_command = strdup("/test/file.sh");
    command.sha256_hash = strdup("invalid_hash");
    command.skip_verification = 1;

    expect_string(__wrap_wm_validate_command, command, "/test/file.sh");
    expect_string(__wrap_wm_validate_command, digest, "invalid_hash");
    expect_value(__wrap_wm_validate_command, ctype, SHA256SUM);
    will_return(__wrap_wm_validate_command, 0);

    expect_string(__wrap__mtwarn, tag, "wazuh-modulesd:command");
    expect_string(__wrap__mtwarn, formatted_msg, "'SHA256' checksum verification failed for command '/test/file.sh'. Skipping...");

    int result = validate_checksum(&command, SHA256SUM);
    assert_int_equal(result, 0);

    free(command.full_command);
    free(command.sha256_hash);
}

void test_validate_checksum_invalid_ctype(void **state) {
    wm_command_t command = {0};
    command.full_command = strdup("/test/file.sh");

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:command");
    expect_string(__wrap__mterror, formatted_msg, "Checksum verification failed for command '/test/file.sh' due to invalid ctype.");

    int result = validate_checksum(&command, 999);
    assert_int_equal(result, 0);

    free(command.full_command);
}

int main(void) {
    const struct CMUnitTest tests_with_startup[] = {
        cmocka_unit_test_setup_teardown(test_interval_execution, setup_test_executions, teardown_test_executions)
    };
    const struct CMUnitTest tests_without_startup[] = {
        cmocka_unit_test_setup_teardown(test_fake_tag, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_scheduling_monthday_configuration, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_scheduling_weekday_configuration, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_scheduling_daytime_configuration, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_scheduling_interval_configuration, setup_test_read, teardown_test_read)
    };
    const struct CMUnitTest tests_validate_checksum[] = {
        cmocka_unit_test(test_validate_checksum_sha256_success),
        cmocka_unit_test(test_validate_checksum_sha1_success),
        cmocka_unit_test(test_validate_checksum_md5_success),
        cmocka_unit_test(test_validate_checksum_failure_no_skip),
        cmocka_unit_test(test_validate_checksum_failure_with_skip),
        cmocka_unit_test(test_validate_checksum_invalid_ctype)
    };
    int result;
    result = cmocka_run_group_tests(tests_with_startup, setup_module, teardown_module);
    result += cmocka_run_group_tests(tests_without_startup, NULL, NULL);
    result += cmocka_run_group_tests(tests_validate_checksum, NULL, NULL);
    return result;
}
