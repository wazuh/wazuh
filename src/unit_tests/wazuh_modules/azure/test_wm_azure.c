/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Test corresponding to the scheduling capacities
 * for azure Module
 * */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <time.h>

#include "shared.h"
#include "../../../wazuh_modules/wmodules.h"
#include "../../../wazuh_modules/wm_azure.h"

#include "../scheduling/wmodules_scheduling_helpers.h"
#include "../../wrappers/common.h"
#include "../../wrappers/libc/stdlib_wrappers.h"
#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../wrappers/wazuh/shared/mq_op_wrappers.h"
#include "../../wrappers/wazuh/wazuh_modules/wm_exec_wrappers.h"

#define TEST_MAX_DATES 5

static wmodule *azure_module;
static OS_XML *lxml;
extern int test_mode;

static void wmodule_cleanup(wmodule *module){
    wm_azure_t* module_data = (wm_azure_t *)module->data;
    if(module_data->api_config){
        free(module_data->api_config->auth_path);
        free(module_data->api_config->tenantdomain);
        free(module_data->api_config->request->time_offset);
        free(module_data->api_config->request->workspace);
        free(module_data->api_config->request->query);
        free(module_data->api_config->request->tag);
        free(module_data->api_config->request);
        free(module_data->api_config);
    }
    free(module_data);
    free(module->tag);
    free(module);
}


/***  SETUPS/TEARDOWNS  ******/
static int setup_module() {
    azure_module = calloc(1, sizeof(wmodule));
    const char *string =
        "<disabled>no</disabled>\n"
        "<interval>5m</interval>\n"
        "<run_on_start>no</run_on_start>\n"
        "<log_analytics>\n"
        "    <auth_path>/var/ossec/wodles/azure/credentials.txt</auth_path>\n"
        "    <tenantdomain>wazuh.onmicrosoft.com</tenantdomain>\n"
        "    <request>\n"
        "        <tag>azure-activity</tag>\n"
        "        <query>AzureActivity | where SubscriptionId == 2d7...61d </query>\n"
        "        <workspace>d6b...efa</workspace>\n"
        "        <time_offset>36h</time_offset>\n"
        "    </request>\n"
        "</log_analytics>\n"
    ;
    lxml = malloc(sizeof(OS_XML));
    XML_NODE nodes = string_to_xml_node(string, lxml);
    int ret = wm_azure_read(lxml, nodes, azure_module);
    OS_ClearNode(nodes);
    test_mode = 1;
    return ret;
}

static int teardown_module(){
    test_mode = 0;
    wmodule_cleanup(azure_module);
    OS_ClearXML(lxml);
    return 0;
}

static int setup_test_executions(void **state) {
    return 0;
}

static int teardown_test_executions(void **state){
    wm_azure_t* module_data = (wm_azure_t *) *state;
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
    wm_azure_t *module_data = (wm_azure_t*)test->module->data;
    sched_scan_free(&(module_data->scan_config));
    wmodule_cleanup(test->module);
    os_free(test);
    return 0;
}
/************************************/

void test_interval_execution(void **state) {
    wm_azure_t* module_data = (wm_azure_t *)azure_module->data;
    *state = module_data;
    module_data->scan_config.next_scheduled_scan_time = 0;
    module_data->scan_config.scan_day = 0;
    module_data->scan_config.scan_wday = -1;
    module_data->scan_config.interval = 1200; // 20min
    module_data->scan_config.month_interval = false;

    expect_any_count(__wrap_SendMSG, message, (TEST_MAX_DATES + 1) * 2);
    expect_string_count(__wrap_SendMSG, locmsg, xml_rootcheck, (TEST_MAX_DATES + 1) * 2);
    expect_value_count(__wrap_SendMSG, loc, ROOTCHECK_MQ, (TEST_MAX_DATES + 1) * 2);
    will_return_count(__wrap_SendMSG, 1, (TEST_MAX_DATES + 1) * 2);

    expect_any_always(__wrap_wm_exec, command);
    expect_any_always(__wrap_wm_exec, secs);
    expect_any_always(__wrap_wm_exec, add_path);

    will_return_always(__wrap_wm_exec, 0);

    expect_string(__wrap_StartMQ, path, DEFAULTQUEUE);
    expect_value(__wrap_StartMQ, type, WRITE);
    will_return(__wrap_StartMQ, 0);

    will_return_count(__wrap_FOREVER, 1, TEST_MAX_DATES);
    will_return(__wrap_FOREVER, 0);
    expect_any_always(__wrap__mtinfo, tag);
    expect_any_always(__wrap__mtinfo, formatted_msg);

    azure_module->context->start(module_data);
}

void test_fake_tag(void **state) {
    const char *string =
        "<disabled>no</disabled>\n"
        "<fake_tag>1</fake_tag>\n"
        "<time>00:01</time>\n"
        "<run_on_start>no</run_on_start>\n"
        "<log_analytics>\n"
        "    <auth_path>/var/ossec/wodles/azure/credentials.txt</auth_path>\n"
        "    <tenantdomain>wazuh.onmicrosoft.com</tenantdomain>\n"
        "    <request>\n"
        "        <tag>azure-activity</tag>\n"
        "        <query>AzureActivity | where SubscriptionId == 2d7...61d </query>\n"
        "        <workspace>d6b...efa</workspace>\n"
        "        <time_offset>36h</time_offset>\n"
        "    </request>\n"
        "</log_analytics>\n"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "No such tag 'fake_tag' at module 'azure-logs'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_azure_read(&(test->xml), test->nodes, test->module),-1);
}

void test_read_scheduling_monthday_configuration(void **state) {
    const char *string =
        "<disabled>no</disabled>\n"
        "<time>00:01</time>\n"
        "<day>4</day>\n"
        "<run_on_start>no</run_on_start>\n"
        "<log_analytics>\n"
        "    <auth_path>/var/ossec/wodles/azure/credentials.txt</auth_path>\n"
        "    <tenantdomain>wazuh.onmicrosoft.com</tenantdomain>\n"
        "    <request>\n"
        "        <tag>azure-activity</tag>\n"
        "        <query>AzureActivity | where SubscriptionId == 2d7...61d </query>\n"
        "        <workspace>d6b...efa</workspace>\n"
        "        <time_offset>36h</time_offset>\n"
        "    </request>\n"
        "</log_analytics>\n"
    ;
    test_structure *test = *state;
    expect_string(__wrap__mwarn, formatted_msg, "Interval must be a multiple of one month. New interval value: 1M");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_azure_read(&(test->xml), test->nodes, test->module),0);
    wm_azure_t *module_data = (wm_azure_t*)test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 4);
    assert_int_equal(module_data->scan_config.interval, 1);
    assert_int_equal(module_data->scan_config.month_interval, true);
    assert_int_equal(module_data->scan_config.scan_wday, -1);
    assert_string_equal(module_data->scan_config.scan_time, "00:01");
}

void test_read_scheduling_weekday_configuration(void **state) {
    const char *string =
        "<disabled>no</disabled>\n"
        "<time>00:01</time>\n"
        "<wday>Friday</wday>\n"
        "<run_on_start>no</run_on_start>\n"
        "<log_analytics>\n"
        "    <auth_path>/var/ossec/wodles/azure/credentials.txt</auth_path>\n"
        "    <tenantdomain>wazuh.onmicrosoft.com</tenantdomain>\n"
        "    <request>\n"
        "        <tag>azure-activity</tag>\n"
        "        <query>AzureActivity | where SubscriptionId == 2d7...61d </query>\n"
        "        <workspace>d6b...efa</workspace>\n"
        "        <time_offset>36h</time_offset>\n"
        "    </request>\n"
        "</log_analytics>\n"
    ;
    test_structure *test = *state;
    expect_string(__wrap__mwarn, formatted_msg, "Interval must be a multiple of one week. New interval value: 1w");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_azure_read(&(test->xml), test->nodes, test->module),0);
    wm_azure_t *module_data = (wm_azure_t*)test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, 604800);
    assert_int_equal(module_data->scan_config.month_interval, false);
    assert_int_equal(module_data->scan_config.scan_wday, 5);
    assert_string_equal(module_data->scan_config.scan_time, "00:01");
}

void test_read_scheduling_daytime_configuration(void **state) {
    const char *string =
        "<disabled>no</disabled>\n"
        "<time>00:10</time>\n"
        "<run_on_start>no</run_on_start>\n"
        "<log_analytics>\n"
        "    <auth_path>/var/ossec/wodles/azure/credentials.txt</auth_path>\n"
        "    <tenantdomain>wazuh.onmicrosoft.com</tenantdomain>\n"
        "    <request>\n"
        "        <tag>azure-activity</tag>\n"
        "        <query>AzureActivity | where SubscriptionId == 2d7...61d </query>\n"
        "        <workspace>d6b...efa</workspace>\n"
        "        <time_offset>36h</time_offset>\n"
        "    </request>\n"
        "</log_analytics>\n"
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_azure_read(&(test->xml), test->nodes, test->module),0);
    wm_azure_t *module_data = (wm_azure_t*)test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, WM_DEF_INTERVAL);
    assert_int_equal(module_data->scan_config.month_interval, false);
    assert_int_equal(module_data->scan_config.scan_wday, -1);
    assert_string_equal(module_data->scan_config.scan_time, "00:10");
}

void test_read_scheduling_interval_configuration(void **state) {
    const char *string =
        "<disabled>no</disabled>\n"
        "<interval>3h</interval>\n"
        "<run_on_start>no</run_on_start>\n"
        "<log_analytics>\n"
        "    <auth_path>/var/ossec/wodles/azure/credentials.txt</auth_path>\n"
        "    <tenantdomain>wazuh.onmicrosoft.com</tenantdomain>\n"
        "    <request>\n"
        "        <tag>azure-activity</tag>\n"
        "        <query>AzureActivity | where SubscriptionId == 2d7...61d </query>\n"
        "        <workspace>d6b...efa</workspace>\n"
        "        <time_offset>36h</time_offset>\n"
        "    </request>\n"
        "</log_analytics>\n"
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_azure_read(&(test->xml), test->nodes, test->module),0);
    wm_azure_t *module_data = (wm_azure_t*)test->module->data;
    assert_int_equal(module_data->scan_config.scan_day, 0);
    assert_int_equal(module_data->scan_config.interval, 3600*3);
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
