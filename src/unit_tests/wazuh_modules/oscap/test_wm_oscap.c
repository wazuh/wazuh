/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Test corresponding to the scheduling capacities
 * for oscap Module
 * */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <time.h>
#include "shared.h"
#include "wazuh_modules/wmodules.h"
#include "wazuh_modules/wm_oscap.h"
#include "../scheduling/wmodules_scheduling_helpers.h"
#include "../../wrappers/common.h"
#include "../../wrappers/libc/stdlib_wrappers.h"
#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../wrappers/wazuh/shared/mq_op_wrappers.h"
#include "../../wrappers/wazuh/wazuh_modules/wmodules_wrappers.h"
#include "../../wrappers/wazuh/wazuh_modules/wm_exec_wrappers.h"

#define TEST_MAX_DATES 5

static wmodule *oscap_module;
static OS_XML *lxml;
extern int test_mode;

/******* Helpers **********/

static void wmodule_cleanup(wmodule *module){
    wm_oscap* module_data = (wm_oscap *)module->data;
    if (module_data->evals) {
        wm_oscap_eval* eval = module_data->evals;
        while(eval->next){
            wm_oscap_eval* aux= eval;
            eval = eval->next;
            free(aux->path);
            free(aux);
        }
        free(module_data->evals->path);
        free(module_data->evals);
    }
    free(module_data);
    free(module->tag);
    free(module);
}

/***  SETUPS/TEARDOWNS  ******/
static int setup_module() {
    oscap_module = calloc(1, sizeof(wmodule));
    const char *string =
        "<timeout>1800</timeout>\n"
        "<interval>12h</interval>\n"
        "<scan-on-start>no</scan-on-start>\n"
        // Only one contect type to avoid repeating wm_exec command
        "<content type=\"xccdf\" path=\"ssg-centos-6-ds.xml\"/>\n";
    lxml = malloc(sizeof(OS_XML));
    XML_NODE nodes = string_to_xml_node(string, lxml);
    int ret = wm_oscap_read(lxml, nodes, oscap_module);
    OS_ClearNode(nodes);
    test_mode = 1;
    return ret;
}

static int teardown_module(){
    test_mode = 0;
    wmodule_cleanup(oscap_module);
    OS_ClearXML(lxml);
    return 0;
}

static int setup_test_executions(void **state) {
    wm_max_eps = 1;
    return 0;
}

static int teardown_test_executions(void **state){
    wm_oscap* module_data = (wm_oscap *) *state;
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
    wm_oscap *module_data = (wm_oscap*)test->module->data;
    sched_scan_free(&(module_data->scan_config));
    wmodule_cleanup(test->module);
    os_free(test);
    return 0;
}

/****************************************************************/

/** Tests **/
void test_interval_execution(void **state) {
    wm_oscap* module_data = (wm_oscap *)oscap_module->data;
    int i = 0;

    *state = module_data;
    module_data->scan_config.next_scheduled_scan_time = 0;
    module_data->scan_config.scan_day = 0;
    module_data->scan_config.scan_wday = -1;
    module_data->scan_config.interval = 60; // 1min
    module_data->scan_config.month_interval = false;

    expect_any_count(__wrap_SendMSG, message, TEST_MAX_DATES + 1);
    expect_string_count(__wrap_SendMSG, locmsg, xml_rootcheck, TEST_MAX_DATES + 1);
    expect_value_count(__wrap_SendMSG, loc, ROOTCHECK_MQ, TEST_MAX_DATES + 1);
    will_return_count(__wrap_SendMSG, 1, TEST_MAX_DATES + 1);

    for (i = 0; i < TEST_MAX_DATES + 1; i++) {
        expect_any(__wrap_wm_exec, command);
        expect_any(__wrap_wm_exec, secs);
        expect_any(__wrap_wm_exec, add_path);

        will_return(__wrap_wm_exec, strdup("TEST_STRING"));
        will_return(__wrap_wm_exec, 0);
        will_return(__wrap_wm_exec, 0);
    }

    expect_string(__wrap_StartMQ, path, DEFAULTQPATH);
    expect_value(__wrap_StartMQ, type, WRITE);
    will_return(__wrap_StartMQ, 0);

    will_return_count(__wrap_FOREVER, 1, TEST_MAX_DATES);
    will_return(__wrap_FOREVER, 0);

    expect_string(__wrap_wm_state_io, tag, "open-scap");
    expect_value(__wrap_wm_state_io, op, WM_IO_READ);
    expect_value(__wrap_wm_state_io, state, &module_data->state);
    expect_value(__wrap_wm_state_io, size, sizeof(module_data->state));
    will_return(__wrap_wm_state_io, 1);

    for (i = 0; i < TEST_MAX_DATES + 1; i++) {
        expect_string(__wrap_wm_state_io, tag, "open-scap");
        expect_value(__wrap_wm_state_io, op, WM_IO_WRITE);
        expect_value(__wrap_wm_state_io, state, &module_data->state);
        expect_value(__wrap_wm_state_io, size, sizeof(module_data->state));
        will_return(__wrap_wm_state_io, -1);
    }

    expect_string_count(__wrap__mterror, tag, "wazuh-modulesd:oscap", TEST_MAX_DATES + 1);
    expect_string_count(__wrap__mterror, formatted_msg, "Couldn't save running state.", TEST_MAX_DATES + 1);
    expect_any_always(__wrap__mtinfo, tag);
    expect_any_always(__wrap__mtinfo, formatted_msg);

    oscap_module->context->start(module_data);
}

void test_fake_tag(void **state) {
    const char *string =
        "<timeout>1800</timeout>\n"
        "<time>1:15</time>\n"
        "<scan-on-start>no</scan-on-start>\n"
        // Only one contect type to avoid repeating wm_exec command
        "<fake_tag>null<fake_tag/>\n";
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    expect_string(__wrap__merror, formatted_msg, "No such tag 'fake_tag' at module 'open-scap'.");
    assert_int_equal(wm_oscap_read(&(test->xml), test->nodes, test->module),-1);
}

void test_read_scheduling_monthday_configuration(void **state) {
    const char *string =
        "<timeout>1800</timeout>\n"
        "<day>8</day>\n"
        "<time>01:15</time>\n"
        "<scan-on-start>no</scan-on-start>\n"
        // Only one contect type to avoid repeating wm_exec command
    ;
    test_structure *test = *state;
    expect_string(__wrap__mwarn, formatted_msg, "Interval must be a multiple of one month. New interval value: 1M");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_oscap_read(&(test->xml), test->nodes, test->module),0);
    wm_oscap *module_data = (wm_oscap*) test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 8);
    assert_int_equal(module_data->scan_config.interval, 1);
    assert_int_equal(module_data->scan_config.month_interval, true);
    assert_int_equal(module_data->scan_config.scan_wday, -1);
    assert_string_equal(module_data->scan_config.scan_time, "01:15");
}

void test_read_scheduling_weekday_configuration(void **state) {
    const char *string =
        "<timeout>1800</timeout>\n"
        "<wday>Saturday</wday>\n"
        "<time>01:15</time>\n"
        "<scan-on-start>no</scan-on-start>\n"
        // Only one contect type to avoid repeating wm_exec command
    ;
    test_structure *test = *state;
    expect_string(__wrap__mwarn, formatted_msg, "Interval must be a multiple of one week. New interval value: 1w");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_oscap_read(&(test->xml), test->nodes, test->module),0);
    wm_oscap *module_data = (wm_oscap*) test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, 604800);
    assert_int_equal(module_data->scan_config.month_interval, false);
    assert_int_equal(module_data->scan_config.scan_wday, 6);
    assert_string_equal(module_data->scan_config.scan_time, "01:15");
}

void test_read_scheduling_daytime_configuration(void **state) {
    const char *string =
        "<timeout>1800</timeout>\n"
        "<time>21:43</time>\n"
        "<scan-on-start>no</scan-on-start>\n"
        // Only one contect type to avoid repeating wm_exec command
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_oscap_read(&(test->xml), test->nodes, test->module),0);
    wm_oscap *module_data = (wm_oscap*) test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, WM_DEF_INTERVAL);
    assert_int_equal(module_data->scan_config.month_interval, false);
    assert_int_equal(module_data->scan_config.scan_wday, -1);
    assert_string_equal(module_data->scan_config.scan_time, "21:43");
}

void test_read_scheduling_interval_configuration(void **state) {
    const char *string =
        "<timeout>1800</timeout>\n"
        "<interval>90m</interval>\n"
        "<scan-on-start>no</scan-on-start>\n"
        // Only one contect type to avoid repeating wm_exec command
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_oscap_read(&(test->xml), test->nodes, test->module),0);
    wm_oscap *module_data = (wm_oscap*) test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, 90*60);
    assert_int_equal(module_data->scan_config.month_interval, false);
    assert_int_equal(module_data->scan_config.scan_wday, -1);
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
    int result;
    result = cmocka_run_group_tests(tests_with_startup, setup_module, teardown_module);
    result += cmocka_run_group_tests(tests_without_startup, NULL, NULL);
    return result;
}
