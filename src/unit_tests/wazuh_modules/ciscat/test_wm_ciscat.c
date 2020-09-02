/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Test corresponding to the scheduling capacities
 * for ciscat Module
 * */

#define ENABLE_CISCAT
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <time.h>
#include "shared.h"
#include "wazuh_modules/wmodules.h"
#include "wazuh_modules/wm_ciscat.h"
#include "../scheduling/wmodules_scheduling_helpers.h"
#include "../../wrappers/common.h"
#include "../../wrappers/libc/stdlib_wrappers.h"
#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../wrappers/wazuh/shared/file_op_wrappers.h"
#include "../../wrappers/wazuh/shared/randombytes_wrappers.h"

#define TEST_MAX_DATES 5

static wmodule *ciscat_module;
static OS_XML *lxml;
extern int test_mode;

static void wmodule_cleanup(wmodule *module){
    wm_ciscat* module_data = (wm_ciscat *) module->data;
    wm_ciscat_eval *eval = module_data->evals;
    while(eval != 0) {
        wm_ciscat_eval *aux = eval;
        eval = eval->next;
        free(aux->profile);
        free(aux->path);
        free(aux);
    }
    free(module_data->ciscat_path);
    free(module_data->java_path);
    free(module_data);
    free(module->tag);
    free(module);
}

/***  SETUPS/TEARDOWNS  ******/
static int setup_module() {
    ciscat_module = calloc(1, sizeof(wmodule));
    const char *string =
        "<disabled>no</disabled>\n"
        "<timeout>1800</timeout>\n"
        "<interval>3m</interval>\n"
        "<scan-on-start>no</scan-on-start>\n"
        "<java_path>/usr/lib/jvm/java-1.8.0-openjdk-amd64/jre/bin</java_path>\n"
        "<ciscat_path>wodles/ciscat</ciscat_path>\n"
        "<content type=\"xccdf\" path=\"benchmarks/CIS_Ubuntu_Linux_16.04_LTS_Benchmark_v1.0.0-xccdf.xml\">\n"
        "    <profile>xccdf_org.cisecurity.benchmarks_profile_Level_2_-_Server</profile>\n"
        "</content>\n"
    ;
    lxml = malloc(sizeof(OS_XML));
    XML_NODE nodes = string_to_xml_node(string, lxml);
    int ret = wm_ciscat_read(lxml, nodes, ciscat_module);
    OS_ClearNode(nodes);
    test_mode = 1;
    return ret;
}

static int teardown_module(){
    test_mode = 0;
    wmodule_cleanup(ciscat_module);
    OS_ClearXML(lxml);
    return 0;
}

static int setup_test_executions() {
    return 0;
}

static int teardown_test_executions(void **state){
    wm_ciscat* module_data = (wm_ciscat *) *state;
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
    wm_ciscat *module_data = (wm_ciscat*)test->module->data;
    sched_scan_free(&(module_data->scan_config));
    wmodule_cleanup(test->module);
    os_free(test);
    return 0;
}
/************************************/

void test_interval_execution(void **state) {
    wm_ciscat* module_data = (wm_ciscat *)ciscat_module->data;
    *state = module_data;
    module_data->scan_config.next_scheduled_scan_time = 0;
    module_data->scan_config.scan_day = 0;
    module_data->scan_config.scan_wday = -1;
    module_data->scan_config.interval = 120; // 2min
    module_data->scan_config.month_interval = false;

    expect_string(__wrap_IsDir, file, "/var/ossec/wodles/ciscat");
    will_return(__wrap_IsDir, 0);
    will_return_count(__wrap_FOREVER, 1, TEST_MAX_DATES);
    will_return(__wrap_FOREVER, 0);
    expect_string_count(__wrap__mterror, tag, "wazuh-modulesd:ciscat", TEST_MAX_DATES + 1);
    expect_string_count(__wrap__mterror, formatted_msg, "Benchmark file '/var/ossec/wodles/ciscat/benchmarks/CIS_Ubuntu_Linux_16.04_LTS_Benchmark_v1.0.0-xccdf.xml' not found.", TEST_MAX_DATES + 1);
    expect_any_always(__wrap__mtinfo, tag);
    expect_any_always(__wrap__mtinfo, formatted_msg);

    ciscat_module->context->start(module_data);
}

void test_fake_tag(void **state) {
    const char *string =
        "<disabled>no</disabled>\n"
        "<timeout>1800</timeout>\n"
        "<time>14:59</time>\n"
        "<scan-on-start>no</scan-on-start>\n"
        "<java_path>/usr/lib/jvm/java-1.8.0-openjdk-amd64/jre/bin</java_path>\n"
        "<ciscat_path>wodles/ciscat</ciscat_path>\n"
        "<invalid-tag>laklsdaklsa</invalid-tag>"
        "<content type=\"xccdf\" path=\"benchmarks/CIS_Ubuntu_Linux_16.04_LTS_Benchmark_v1.0.0-xccdf.xml\">\n"
        "    <profile>xccdf_org.cisecurity.benchmarks_profile_Level_2_-_Server</profile>\n"
        "</content>\n"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "No such tag 'invalid-tag' at module 'cis-cat'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_ciscat_read(&(test->xml), test->nodes, test->module),-1);
}

void test_read_scheduling_monthday_configuration(void **state) {
    const char *string =
        "<disabled>no</disabled>\n"
        "<timeout>1800</timeout>\n"
        "<time>14:59</time>\n"
        "<day>5</day>\n"
        "<scan-on-start>no</scan-on-start>\n"
        "<java_path>/usr/lib/jvm/java-1.8.0-openjdk-amd64/jre/bin</java_path>\n"
        "<ciscat_path>wodles/ciscat</ciscat_path>\n"
        "<content type=\"xccdf\" path=\"benchmarks/CIS_Ubuntu_Linux_16.04_LTS_Benchmark_v1.0.0-xccdf.xml\">\n"
        "    <profile>xccdf_org.cisecurity.benchmarks_profile_Level_2_-_Server</profile>\n"
        "</content>\n"
    ;
    test_structure *test = *state;
    expect_string(__wrap__mwarn, formatted_msg, "Interval must be a multiple of one month. New interval value: 1M");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_ciscat_read(&(test->xml), test->nodes, test->module),0);
    wm_ciscat* module_data = (wm_ciscat *)test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 5);
    assert_int_equal(module_data->scan_config.interval, 1);
    assert_int_equal(module_data->scan_config.month_interval, true);
    assert_int_equal(module_data->scan_config.scan_wday, -1);
    assert_string_equal(module_data->scan_config.scan_time, "14:59");
}

void test_read_scheduling_weekday_configuration(void** state) {
    const char *string =
        "<disabled>no</disabled>\n"
        "<timeout>1800</timeout>\n"
        "<time>23:59</time>\n"
        "<wday>Wednesday</wday>\n"
        "<scan-on-start>no</scan-on-start>\n"
        "<java_path>/usr/lib/jvm/java-1.8.0-openjdk-amd64/jre/bin</java_path>\n"
        "<ciscat_path>wodles/ciscat</ciscat_path>\n"
        "<content type=\"xccdf\" path=\"benchmarks/CIS_Ubuntu_Linux_16.04_LTS_Benchmark_v1.0.0-xccdf.xml\">\n"
        "    <profile>xccdf_org.cisecurity.benchmarks_profile_Level_2_-_Server</profile>\n"
        "</content>\n"
    ;
    test_structure *test = *state;
    expect_string(__wrap__mwarn, formatted_msg, "Interval must be a multiple of one week. New interval value: 1w");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_ciscat_read(&(test->xml), test->nodes, test->module),0);
    wm_ciscat* module_data = (wm_ciscat *)test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, 604800);
    assert_int_equal(module_data->scan_config.month_interval, false);
    assert_int_equal(module_data->scan_config.scan_wday, 3);
    assert_string_equal(module_data->scan_config.scan_time, "23:59");
}

void test_read_scheduling_daytime_configuration(void **state) {
    const char *string =
        "<disabled>no</disabled>\n"
        "<timeout>1800</timeout>\n"
        "<time>11:45</time>\n"
        "<scan-on-start>no</scan-on-start>\n"
        "<java_path>/usr/lib/jvm/java-1.8.0-openjdk-amd64/jre/bin</java_path>\n"
        "<ciscat_path>wodles/ciscat</ciscat_path>\n"
        "<content type=\"xccdf\" path=\"benchmarks/CIS_Ubuntu_Linux_16.04_LTS_Benchmark_v1.0.0-xccdf.xml\">\n"
        "    <profile>xccdf_org.cisecurity.benchmarks_profile_Level_2_-_Server</profile>\n"
        "</content>\n"
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_ciscat_read(&(test->xml), test->nodes, test->module),0);
    wm_ciscat* module_data = (wm_ciscat *)test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, WM_DEF_INTERVAL);
    assert_int_equal(module_data->scan_config.month_interval, false);
    assert_int_equal(module_data->scan_config.scan_wday, -1);
    assert_string_equal(module_data->scan_config.scan_time, "11:45");
}

void test_read_scheduling_interval_configuration(void **state) {
    const char *string =
        "<disabled>no</disabled>\n"
        "<timeout>1800</timeout>\n"
        "<interval>1h</interval>\n"
        "<scan-on-start>no</scan-on-start>\n"
        "<java_path>/usr/lib/jvm/java-1.8.0-openjdk-amd64/jre/bin</java_path>\n"
        "<ciscat_path>wodles/ciscat</ciscat_path>\n"
        "<content type=\"xccdf\" path=\"benchmarks/CIS_Ubuntu_Linux_16.04_LTS_Benchmark_v1.0.0-xccdf.xml\">\n"
        "    <profile>xccdf_org.cisecurity.benchmarks_profile_Level_2_-_Server</profile>\n"
        "</content>\n"
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_ciscat_read(&(test->xml), test->nodes, test->module),0);
    wm_ciscat* module_data = (wm_ciscat *)test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, 3600);
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
    result &= cmocka_run_group_tests(tests_without_startup, NULL, NULL);
    return result;
}
