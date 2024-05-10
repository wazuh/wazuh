/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Test corresponding to the scheduling capacities
 * for docker Module
 * */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <time.h>

#include "shared.h"
#include "../../wrappers/common.h"
#include "../../wrappers/libc/stdio_wrappers.h"
#include "../../wrappers/libc/stdlib_wrappers.h"
#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../wrappers/wazuh/shared/exec_op_wrappers.h"
#include "../../../wazuh_modules/wmodules.h"
#include "../../../wazuh_modules/wm_docker.h"
#include "../scheduling/wmodules_scheduling_helpers.h"

#define TEST_MAX_DATES 5

static wmodule *docker_module;
static OS_XML *lxml;
extern int test_mode;

typedef struct {
    wfd_t * wfd;
    wm_docker_t* module_data;
} states;

/******* Helpers **********/

static void wmodule_cleanup(wmodule *module){
    free(module->data);
    free(module->tag);
    free(module);
}

/***  SETUPS/TEARDOWNS  ******/
static int setup_module() {
    docker_module = calloc(1, sizeof(wmodule));
    const char *string =
        "<interval>10m</interval>\n"
        "<attempts>10</attempts>\n"
        "<run_on_start>no</run_on_start>\n"
        "<disabled>no</disabled>\n";
    lxml = malloc(sizeof(OS_XML));
    XML_NODE nodes = string_to_xml_node(string, lxml);
    int ret = wm_docker_read(nodes, docker_module);
    OS_ClearNode(nodes);
    test_mode = 1;
    wm_children_pool_init();
    return ret;
}

static int teardown_module(){
    test_mode = 0;
    wmodule_cleanup(docker_module);
    OS_ClearXML(lxml);
    return 0;
}

static int setup_test_executions(void **state) {
    states *states_ptr = calloc(1, sizeof(*states_ptr));
    states_ptr->wfd = calloc(1, sizeof(wfd_t));
    *state = states_ptr;
    wm_max_eps = 1;

    return 0;
}

static int teardown_test_executions(void **state){
    states *states_ptr = *state;
    wm_docker_t* module_data = states_ptr->module_data;
    sched_scan_free(&(module_data->scan_config));

    free(states_ptr->wfd);
    free(states_ptr);
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
    wm_docker_t *module_data = (wm_docker_t*)test->module->data;
    sched_scan_free(&(module_data->scan_config));
    wmodule_cleanup(test->module);
    os_free(test);
    return 0;
}

/****************************************************************/

/** Tests **/
void test_interval_execution(void **state) {
    states *states_ptr = *state;
    wm_docker_t* module_data = (wm_docker_t *)docker_module->data;
    wfd_t * wfd = states_ptr->wfd;

    states_ptr->module_data = module_data;
    module_data->scan_config.next_scheduled_scan_time = 0;
    module_data->scan_config.scan_day = 0;
    module_data->scan_config.scan_wday = -1;
    module_data->scan_config.interval = 60 * 25; // 25min
    module_data->scan_config.month_interval = false;

    will_return_count(__wrap_wpopenl, wfd, TEST_MAX_DATES + 1);
    will_return_count(__wrap_wpclose, 0, TEST_MAX_DATES + 1);
    expect_any_count(__wrap_fgets, __stream, TEST_MAX_DATES + 1);
    will_return_count(__wrap_fgets, 0, TEST_MAX_DATES + 1);
    will_return_count(__wrap_FOREVER, 1, TEST_MAX_DATES);
    will_return(__wrap_FOREVER, 0);
    expect_any_always(__wrap__mtinfo, tag);
    expect_any_always(__wrap__mtinfo, formatted_msg);
    expect_any_always(__wrap__mtwarn, tag);
    expect_any_always(__wrap__mtwarn, formatted_msg);

    docker_module->context->start(module_data);
}

void test_fake_tag(void **state) {
    const char *string =
        "<time>19:55</time>\n"
        "<interval>10m</interval>\n"
        "<attempts>10</attempts>\n"
        "<run_on_start>no</run_on_start>\n"
        "<disabled>no</disabled>\n"
        "<extra-tag>extra</extra-tag>\n";
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "No such tag 'extra-tag' at module 'docker-listener'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_docker_read(test->nodes, test->module),-1);
}

void test_read_scheduling_monthday_configuration(void **state) {
    const char *string =
        "<time>19:55</time>\n"
        "<day>10</day>\n"
        "<attempts>10</attempts>\n"
        "<run_on_start>no</run_on_start>\n"
        "<disabled>no</disabled>\n"
    ;
    test_structure *test = *state;
    expect_string(__wrap__mwarn, formatted_msg, "Interval must be a multiple of one month. New interval value: 1M");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_docker_read(test->nodes, test->module),0);
    wm_docker_t *module_data = (wm_docker_t*)test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 10);
    assert_int_equal(module_data->scan_config.interval, 1);
    assert_int_equal(module_data->scan_config.month_interval, true);
    assert_int_equal(module_data->scan_config.scan_wday, -1);
    assert_string_equal(module_data->scan_config.scan_time, "19:55");
}

void test_read_scheduling_weekday_configuration(void **state) {
    const char *string =
        "<time>18:55</time>\n"
        "<wday>Thursday</wday>\n"
        "<attempts>10</attempts>\n"
        "<run_on_start>no</run_on_start>\n"
        "<disabled>no</disabled>\n"
    ;
    test_structure *test = *state;
    expect_string(__wrap__mwarn, formatted_msg, "Interval must be a multiple of one week. New interval value: 1w");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_docker_read(test->nodes, test->module),0);
    wm_docker_t *module_data = (wm_docker_t*)test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, 604800);
    assert_int_equal(module_data->scan_config.month_interval, false);
    assert_int_equal(module_data->scan_config.scan_wday, 4);
    assert_string_equal(module_data->scan_config.scan_time, "18:55");
}

void test_read_scheduling_daytime_configuration(void **state) {
    const char *string =
        "<time>17:20</time>\n"
        "<attempts>10</attempts>\n"
        "<run_on_start>no</run_on_start>\n"
        "<disabled>no</disabled>\n"
    ;
    test_structure *test = *state;
    expect_string(__wrap__mwarn, formatted_msg, "Interval must be a multiple of one day. New interval value: 1d");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_docker_read(test->nodes, test->module),0);
    wm_docker_t *module_data = (wm_docker_t*)test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, WM_DEF_INTERVAL);
    assert_int_equal(module_data->scan_config.month_interval, false);
    assert_int_equal(module_data->scan_config.scan_wday, -1);
    assert_string_equal(module_data->scan_config.scan_time, "17:20");
}

void test_read_scheduling_interval_configuration(void **state) {
    const char *string =
        "<interval>1d</interval>\n"
        "<attempts>10</attempts>\n"
        "<run_on_start>no</run_on_start>\n"
        "<disabled>no</disabled>\n"
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_docker_read(test->nodes, test->module),0);
    wm_docker_t *module_data = (wm_docker_t*)test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, WM_DEF_INTERVAL); // 1 day
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
        cmocka_unit_test_setup_teardown(test_read_scheduling_interval_configuration, setup_test_read, teardown_test_read),
    };
    int result;
    result = cmocka_run_group_tests(tests_with_startup, setup_module, teardown_module);
    result += cmocka_run_group_tests(tests_without_startup, NULL, NULL);
    return result;
}
