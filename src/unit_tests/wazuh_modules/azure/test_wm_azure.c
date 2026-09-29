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
#include "wmodules.h"
#include "wm_azure.h"

#include "../scheduling/wmodules_scheduling_helpers.h"
#include "../../wrappers/common.h"
#include "../../wrappers/libc/stdlib_wrappers.h"
#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../wrappers/wazuh/shared/mq_op_wrappers.h"
#include "../../wrappers/wazuh/wazuh_modules/wm_exec_wrappers.h"
#include "../../wrappers/externals/pcre2/pcre2_wrappers.h"

#define TEST_MAX_DATES 5


static wmodule *azure_module;
static OS_XML *lxml;
static wmodule *azure_runners_module;
static OS_XML runners_lxml;
extern int test_mode;
extern w_expression_t *azure_script_log_regex;

void wm_setup_logging_capture();
void wm_integrations_parse_output(char * const output, int exit_status);
bool wm_azure_graphs(wm_azure_api_t *graph);
bool wm_azure_storage(wm_azure_storage_t *storage);

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
    w_test_pcre2_wrappers(false);
    return ret;
}

static int teardown_module(){
    test_mode = 0;
    w_test_pcre2_wrappers(true);
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
    // Every module start compiles it again
    w_free_expression_t(&azure_script_log_regex);
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

static int setup_runners(void **state) {
    const char *string =
        "<disabled>no</disabled>\n"
        "<interval>5m</interval>\n"
        "<run_on_start>no</run_on_start>\n"
        "<graph>\n"
        "    <auth_path>/var/ossec/wodles/azure/credentials.txt</auth_path>\n"
        "    <tenantdomain>wazuh.onmicrosoft.com</tenantdomain>\n"
        "    <request>\n"
        "        <tag>microsoft-entra_id</tag>\n"
        "        <query>auditLogs/directoryaudits</query>\n"
        "        <time_offset>1d</time_offset>\n"
        "    </request>\n"
        "</graph>\n"
        "<storage>\n"
        "    <auth_path>/var/ossec/wodles/azure/credentials.txt</auth_path>\n"
        "    <tag>azure-storage</tag>\n"
        "    <container name=\"insights-logs\">\n"
        "        <blobs>.json</blobs>\n"
        "        <content_type>json_inline</content_type>\n"
        "        <time_offset>24h</time_offset>\n"
        "    </container>\n"
        "</storage>\n"
    ;
    azure_runners_module = calloc(1, sizeof(wmodule));
    XML_NODE nodes = string_to_xml_node(string, &runners_lxml);
    int ret = wm_azure_read(&runners_lxml, nodes, azure_runners_module);
    OS_ClearNode(nodes);
    w_test_pcre2_wrappers(false);
    wm_setup_logging_capture();
    return ret;
}

static int teardown_runners(void **state) {
    w_test_pcre2_wrappers(true);
    wm_azure_t *module_data = (wm_azure_t *)azure_runners_module->data;
    sched_scan_free(&(module_data->scan_config));
    // Also frees the script log regex
    azure_runners_module->context->destroy(module_data);
    free(azure_runners_module->tag);
    free(azure_runners_module);
    OS_ClearXML(&runners_lxml);
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

    expect_string_count(__wrap__mtinfo, tag, WM_AZURE_LOGTAG, -1);
    expect_string_count(__wrap__mtwarn, tag, WM_AZURE_LOGTAG, -1);

    expect_any_count(__wrap_SendMSG, message, (TEST_MAX_DATES + 1) * 2);
    expect_string_count(__wrap_SendMSG, locmsg, xml_rootcheck, (TEST_MAX_DATES + 1) * 2);
    expect_value_count(__wrap_SendMSG, loc, ROOTCHECK_MQ, (TEST_MAX_DATES + 1) * 2);
    will_return_count(__wrap_SendMSG, 1, (TEST_MAX_DATES + 1) * 2);

    expect_string(__wrap__mtinfo, formatted_msg, "Module started.");
    expect_any_always(__wrap_wm_exec, command);
    expect_any_always(__wrap_wm_exec, secs);
    expect_any_always(__wrap_wm_exec, add_path);

    for (int iterations = 0; iterations <= TEST_MAX_DATES; ++iterations) {
        expect_string(__wrap__mtinfo, formatted_msg, "Starting fetching of logs.");
        expect_string(__wrap__mtinfo, formatted_msg, "Starting Log Analytics collection for the domain 'wazuh.onmicrosoft.com'.");
        will_return(__wrap_wm_exec, "2025/05/28 17:55:00 azure: INFO: info message\nnot valid logline\n2025/05/28 17:55:00 azure: WARNING: warning message");
        will_return(__wrap_wm_exec, 0);
        will_return(__wrap_wm_exec, 0);
        expect_string(__wrap__mtinfo, formatted_msg, "info message");
        expect_string(__wrap__mtwarn, formatted_msg, "warning message");
        expect_string(__wrap__mtinfo, formatted_msg, "Finished Log Analytics collection for request 'azure-activity'.");
        expect_string(__wrap__mtinfo, formatted_msg, "Finished Log Analytics collection for the domain 'wazuh.onmicrosoft.com'.");
    }

    expect_string(__wrap_StartMQ, path, DEFAULTQUEUE);
    expect_value(__wrap_StartMQ, type, WRITE);
    will_return(__wrap_StartMQ, 0);

    will_return_count(__wrap_FOREVER, 1, TEST_MAX_DATES);
    will_return(__wrap_FOREVER, 0);

    azure_module->context->start(module_data);
}

void test_failed_execution_is_not_logged_as_finished(void **state) {
    wm_azure_t* module_data = (wm_azure_t *)azure_module->data;
    *state = module_data;
    module_data->scan_config.next_scheduled_scan_time = 0;
    module_data->scan_config.scan_day = 0;
    module_data->scan_config.scan_wday = -1;
    module_data->scan_config.interval = 1200; // 20min
    module_data->scan_config.month_interval = false;

    expect_string_count(__wrap__mtinfo, tag, WM_AZURE_LOGTAG, -1);
    expect_string_count(__wrap__mtwarn, tag, WM_AZURE_LOGTAG, -1);
    expect_string_count(__wrap__mterror, tag, WM_AZURE_LOGTAG, -1);

    expect_any_count(__wrap_SendMSG, message, 2);
    expect_string_count(__wrap_SendMSG, locmsg, xml_rootcheck, 2);
    expect_value_count(__wrap_SendMSG, loc, ROOTCHECK_MQ, 2);
    will_return_count(__wrap_SendMSG, 1, 2);

    expect_string(__wrap__mtinfo, formatted_msg, "Module started.");
    expect_any(__wrap_wm_exec, command);
    expect_any(__wrap_wm_exec, secs);
    expect_any(__wrap_wm_exec, add_path);

    expect_string(__wrap__mtinfo, formatted_msg, "Starting fetching of logs.");
    expect_string(__wrap__mtinfo, formatted_msg, "Starting Log Analytics collection for the domain 'wazuh.onmicrosoft.com'.");
    will_return(__wrap_wm_exec, "Traceback (most recent call last):\nImportError: cannot import name 'ParserError'");
    will_return(__wrap_wm_exec, 1);
    will_return(__wrap_wm_exec, 0);
    expect_string(__wrap__mtwarn, formatted_msg, "Command returned exit code 1");
    expect_string(__wrap__mterror, formatted_msg, "Traceback (most recent call last):\nImportError: cannot import name 'ParserError'");
    expect_string(__wrap__mtwarn, formatted_msg, "Log Analytics collection for request 'azure-activity' failed.");
    expect_string(__wrap__mtwarn, formatted_msg, "Log Analytics collection for the domain 'wazuh.onmicrosoft.com' failed for one or more requests.");

    expect_string(__wrap_StartMQ, path, DEFAULTQUEUE);
    expect_value(__wrap_StartMQ, type, WRITE);
    will_return(__wrap_StartMQ, 0);

    will_return(__wrap_FOREVER, 0);

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

void test_parse_output_success_ignores_unparsed_lines(void **state) {
    char output[] = "2025/05/28 17:55:00 azure: INFO: info message\nnot valid logline";

    expect_string(__wrap__mtinfo, tag, WM_AZURE_LOGTAG);
    expect_string(__wrap__mtinfo, formatted_msg, "info message");

    wm_integrations_parse_output(output, 0);
}

void test_parse_output_failure_surfaces_unparsed_lines_after_error(void **state) {
    // Storage's get_blobs() logs the error and re-raises it, so a traceback follows
    char output[] =
        "2025/05/28 17:55:00 azure: ERROR: Storage: Error getting blobs from \"insights-logs\": \"boom\".\n"
        "Traceback (most recent call last):\n"
        "  File \"/var/ossec/wodles/azure/azure-logs\", line 38, in <module>\n"
        "azure.core.exceptions.AzureError: boom";

    expect_string_count(__wrap__mterror, tag, WM_AZURE_LOGTAG, 2);
    expect_string(__wrap__mterror, formatted_msg, "Storage: Error getting blobs from \"insights-logs\": \"boom\".");
    expect_string(__wrap__mterror, formatted_msg,
                  "Traceback (most recent call last):\n"
                  "  File \"/var/ossec/wodles/azure/azure-logs\", line 38, in <module>\n"
                  "azure.core.exceptions.AzureError: boom");

    wm_integrations_parse_output(output, 1);
}

void test_parse_output_failure_keeps_tail_of_oversized_output(void **state) {
    const char *last_line = "ImportError: cannot import name 'ParserError'";
    char *output = NULL;
    char *expected = NULL;

    os_calloc(OS_SIZE_6144 + strlen(last_line) + 2, sizeof(char), output);
    memset(output, 'A', OS_SIZE_6144);
    output[OS_SIZE_6144] = '\n';
    strcpy(output + OS_SIZE_6144 + 1, last_line);
    // Copied before parsing, which tokenizes the output in place
    os_strdup(output + strlen(output) - (OS_SIZE_6144 - 1), expected);

    expect_string(__wrap__mterror, tag, WM_AZURE_LOGTAG);
    expect_string(__wrap__mterror, formatted_msg, expected);

    wm_integrations_parse_output(output, 1);

    os_free(expected);
    os_free(output);
}

void test_graphs_killed_script_is_not_logged_as_finished(void **state) {
    wm_azure_t *module_data = (wm_azure_t *)azure_runners_module->data;
    assert_int_equal(module_data->api_config->type, GRAPHS);

    expect_any(__wrap_wm_exec, command);
    expect_any(__wrap_wm_exec, secs);
    expect_any(__wrap_wm_exec, add_path);
    will_return(__wrap_wm_exec, "");
    will_return(__wrap_wm_exec, 128 + SIGKILL);
    will_return(__wrap_wm_exec, 0);

    expect_string_count(__wrap__mtwarn, tag, WM_AZURE_LOGTAG, 2);
    expect_string(__wrap__mtwarn, formatted_msg, "Command returned exit code 137");
    expect_string(__wrap__mtwarn, formatted_msg, "Graphs log collection for request 'microsoft-entra_id' failed.");

    assert_false(wm_azure_graphs(module_data->api_config));
}

void test_storage_timeout_is_not_logged_as_finished(void **state) {
    wm_azure_t *module_data = (wm_azure_t *)azure_runners_module->data;

    expect_any(__wrap_wm_exec, command);
    expect_any(__wrap_wm_exec, secs);
    expect_any(__wrap_wm_exec, add_path);
    will_return(__wrap_wm_exec, NULL);
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, WM_ERROR_TIMEOUT);

    expect_string(__wrap__mterror, tag, WM_AZURE_LOGTAG);
    expect_string(__wrap__mterror, formatted_msg, "Timeout expired at request 'insights-logs'.");
    expect_string(__wrap__mtwarn, tag, WM_AZURE_LOGTAG);
    expect_string(__wrap__mtwarn, formatted_msg, "Storage log collection for container 'insights-logs' failed.");

    assert_false(wm_azure_storage(module_data->storage));
}

void test_storage_success_is_logged_as_finished(void **state) {
    wm_azure_t *module_data = (wm_azure_t *)azure_runners_module->data;

    expect_any(__wrap_wm_exec, command);
    expect_any(__wrap_wm_exec, secs);
    expect_any(__wrap_wm_exec, add_path);
    will_return(__wrap_wm_exec, "");
    will_return(__wrap_wm_exec, 0);
    will_return(__wrap_wm_exec, 0);

    expect_string(__wrap__mtinfo, tag, WM_AZURE_LOGTAG);
    expect_string(__wrap__mtinfo, formatted_msg, "Finished Storage log collection for container 'insights-logs'.");

    assert_true(wm_azure_storage(module_data->storage));
}

int main(void) {
    const struct CMUnitTest tests_with_startup[] = {
        cmocka_unit_test_setup_teardown(test_interval_execution, setup_test_executions, teardown_test_executions),
        cmocka_unit_test_setup_teardown(test_failed_execution_is_not_logged_as_finished, setup_test_executions, teardown_test_executions)
    };
    const struct CMUnitTest tests_runners[] = {
        cmocka_unit_test(test_parse_output_success_ignores_unparsed_lines),
        cmocka_unit_test(test_parse_output_failure_surfaces_unparsed_lines_after_error),
        cmocka_unit_test(test_parse_output_failure_keeps_tail_of_oversized_output),
        cmocka_unit_test(test_graphs_killed_script_is_not_logged_as_finished),
        cmocka_unit_test(test_storage_timeout_is_not_logged_as_finished),
        cmocka_unit_test(test_storage_success_is_logged_as_finished)
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
    result += cmocka_run_group_tests(tests_runners, setup_runners, teardown_runners);
    result += cmocka_run_group_tests(tests_without_startup, NULL, NULL);
    return result;
}
