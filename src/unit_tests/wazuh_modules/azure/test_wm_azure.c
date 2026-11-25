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
#include "../../wrappers/externals/pcre2/pcre2_wrappers.h"

#define TEST_MAX_DATES 5

static wmodule *azure_module;
static OS_XML *lxml;
extern int test_mode;

cJSON *wm_azure_dump(const wm_azure_t *azure);

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
    if (module_data->storage) {
        wm_azure_container_t *container = module_data->storage->container;
        while (container) {
            wm_azure_container_t *next = container->next;
            free(container->name);
            free(container->blobs);
            free(container->content_type);
            free(container->time_offset);
            free(container->path);
            free(container->path_lookback);
            free(container);
            container = next;
        }
        free(module_data->storage->auth_path);
        free(module_data->storage->tag);
        free(module_data->storage);
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

void test_dump_requests_and_containers(void **state) {
    wm_azure_request_t second_request = { .tag = "azure-signin", .query = "SigninLogs", .time_offset = "1d", .timeout = 60 };
    wm_azure_request_t first_request = { .tag = "azure-activity", .query = "AzureActivity", .time_offset = "36h",
                                         .workspace = "d6b-efa", .next = &second_request };
    wm_azure_request_t graph_request = { .tag = "azure-ad-graph", .query = "auditLogs/directoryAudits", .time_offset = "1d" };
    wm_azure_api_t graph = { .type = GRAPHS, .auth_path = "/var/ossec/wodles/azure/graph.txt",
                             .tenantdomain = "wazuh.onmicrosoft.com", .request = &graph_request };
    wm_azure_api_t analytics = { .type = LOG_ANALYTICS, .auth_path = "/var/ossec/wodles/azure/analytics.txt",
                                 .tenantdomain = "wazuh.onmicrosoft.com", .request = &first_request, .next = &graph };
    wm_azure_container_t second_container = { .name = "insights-operational-logs", .blobs = "*", .content_type = "file",
                                              .time_offset = "2d", .path = "logs/%Y%m%d/", .path_lookback = "6h",
                                              .path_max_folders = 48, .timeout = 30 };
    wm_azure_container_t first_container = { .name = "insights-activity-logs", .blobs = ".json", .content_type = "json_inline",
                                             .time_offset = "24h", .next = &second_container };
    wm_azure_storage_t storage = { .auth_path = "/var/ossec/wodles/azure/storage.txt", .tag = "azure-storage",
                                   .container = &first_container };
    wm_azure_t azure = { .flags.enabled = 1, .api_config = &analytics, .storage = &storage, .scan_config.scan_wday = -1 };

    cJSON *root = wm_azure_dump(&azure);
    char *text = cJSON_PrintUnformatted(root);

    assert_string_equal(text, "{\"azure-logs\":{\"disabled\":\"no\",\"run_on_start\":\"no\",\"timeout\":0,\"content\":["
                              "{\"type\":\"log_analytics\",\"tenantdomain\":\"wazuh.onmicrosoft.com\","
                              "\"auth_path\":\"/var/ossec/wodles/azure/analytics.txt\",\"requests\":["
                              "{\"tag\":\"azure-activity\",\"query\":\"AzureActivity\",\"time_offset\":\"36h\",\"workspace\":\"d6b-efa\"},"
                              "{\"tag\":\"azure-signin\",\"query\":\"SigninLogs\",\"time_offset\":\"1d\",\"timeout\":60}]},"
                              "{\"type\":\"graph\",\"tenantdomain\":\"wazuh.onmicrosoft.com\","
                              "\"auth_path\":\"/var/ossec/wodles/azure/graph.txt\",\"requests\":["
                              "{\"tag\":\"azure-ad-graph\",\"query\":\"auditLogs/directoryAudits\",\"time_offset\":\"1d\"}]},"
                              "{\"tag\":\"azure-storage\",\"auth_path\":\"/var/ossec/wodles/azure/storage.txt\",\"containers\":["
                              "{\"name\":\"insights-activity-logs\",\"blobs\":\".json\",\"content_type\":\"json_inline\",\"time_offset\":\"24h\"},"
                              "{\"name\":\"insights-operational-logs\",\"blobs\":\"*\",\"content_type\":\"file\",\"time_offset\":\"2d\","
                              "\"prefix\":\"logs/%Y%m%d/\",\"path_lookback\":\"6h\",\"path_max_folders\":48,\"timeout\":30}]}]}}");

    cJSON_free(text);
    cJSON_Delete(root);
}

#define STORAGE_CONFIG(container_options)                                   \
    "<disabled>no</disabled>\n"                                             \
    "<run_on_start>yes</run_on_start>\n"                                    \
    "<storage>\n"                                                           \
    "    <auth_path>/var/ossec/wodles/azure/storage.txt</auth_path>\n"      \
    "    <tag>azure-storage</tag>\n"                                        \
    "    <container name=\"insights-logs\">\n"                              \
    "        <blobs>.json</blobs>\n"                                        \
    container_options                                                       \
    "    </container>\n"                                                    \
    "</storage>\n"

void test_read_storage_path_limits(void **state) {
    const char *string = STORAGE_CONFIG(
        "        <path>logs/%Y%m%d/</path>\n"
        "        <path_lookback>0h</path_lookback>\n"
        "        <path_max_folders>100000</path_max_folders>\n");
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_azure_read(&(test->xml), test->nodes, test->module), 0);
    wm_azure_t *module_data = (wm_azure_t*)test->module->data;
    assert_non_null(module_data->storage);
    assert_string_equal(module_data->storage->container->path, "logs/%Y%m%d/");
    assert_string_equal(module_data->storage->container->path_lookback, "0h");
    assert_int_equal(module_data->storage->container->path_max_folders, 100000);
}

void test_read_storage_without_path_limits(void **state) {
    const char *string = STORAGE_CONFIG("        <path>logs/%Y%m%d/</path>\n");
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_azure_read(&(test->xml), test->nodes, test->module), 0);
    wm_azure_t *module_data = (wm_azure_t*)test->module->data;
    assert_non_null(module_data->storage);
    assert_null(module_data->storage->container->path_lookback);
    assert_int_equal(module_data->storage->container->path_max_folders, 0);
}

void test_read_storage_path_limits_without_date_fields(void **state) {
    const char *string = STORAGE_CONFIG(
        "        <path>logs/%%d0/100%</path>\n"
        "        <path_max_folders>10</path_max_folders>\n");
    test_structure *test = *state;
    expect_string(__wrap__mwarn, formatted_msg,
                  "At module 'azure-logs': The tags <path_lookback> and <path_max_folders> only apply to a <path> with date fields.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_azure_read(&(test->xml), test->nodes, test->module), 0);
    wm_azure_t *module_data = (wm_azure_t*)test->module->data;
    assert_int_equal(module_data->storage->container->path_max_folders, 10);
}

void test_read_storage_path_limits_with_date_field_after_escaped_percent(void **state) {
    const char *string = STORAGE_CONFIG(
        "        <path>logs/%%%d/</path>\n"
        "        <path_max_folders>10</path_max_folders>\n");
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_azure_read(&(test->xml), test->nodes, test->module), 0);
    wm_azure_t *module_data = (wm_azure_t*)test->module->data;
    assert_string_equal(module_data->storage->container->path, "logs/%%%d/");
    assert_int_equal(module_data->storage->container->path_max_folders, 10);
}

void test_read_storage_path_lookback_without_path(void **state) {
    const char *string = STORAGE_CONFIG("        <path_lookback>2h</path_lookback>\n");
    test_structure *test = *state;
    expect_string(__wrap__mwarn, formatted_msg,
                  "At module 'azure-logs': The tags <path_lookback> and <path_max_folders> only apply to a <path> with date fields.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_azure_read(&(test->xml), test->nodes, test->module), 0);
    wm_azure_t *module_data = (wm_azure_t*)test->module->data;
    assert_string_equal(module_data->storage->container->path_lookback, "2h");
}

void test_storage_command_with_path_limits(void **state) {
    const char *string = STORAGE_CONFIG(
        "        <path>logs/%Y%m%d/</path>\n"
        "        <path_lookback>6h</path_lookback>\n"
        "        <path_max_folders>48</path_max_folders>\n");
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_azure_read(&(test->xml), test->nodes, test->module), 0);
    wm_azure_t *module_data = (wm_azure_t*)test->module->data;

    expect_any_always(__wrap__mtinfo, tag);
    expect_any_always(__wrap__mtinfo, formatted_msg);
    expect_any_always(__wrap_SendMSG, message);
    expect_any_always(__wrap_SendMSG, locmsg);
    expect_any_always(__wrap_SendMSG, loc);
    will_return_always(__wrap_SendMSG, 1);

    expect_string(__wrap_StartMQ, path, DEFAULTQUEUE);
    expect_value(__wrap_StartMQ, type, WRITE);
    will_return(__wrap_StartMQ, 0);

    expect_wm_exec("wodles/azure/azure-logs --storage --storage_auth_path /var/ossec/wodles/azure/storage.txt "
                   "--container \"insights-logs\" --blobs \".json\" --storage_tag azure-storage "
                   "--prefix logs/%Y%m%d/ --storage_path_lookback 6h --storage_path_max_folders 48",
                   0, NULL, "", 0, 0);

    will_return(__wrap_FOREVER, 0);

    test_mode = 1;
    w_test_pcre2_wrappers(false);
    test->module->context->start(module_data);
    w_test_pcre2_wrappers(true);
    test_mode = 0;
}

static void assert_invalid_container(void **state, const char *string, const char *error) {
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, error);
    expect_string(__wrap__merror, formatted_msg, "At module 'azure-logs': No container defined. Skipping block...");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_azure_read(&(test->xml), test->nodes, test->module), 0);
    wm_azure_t *module_data = (wm_azure_t*)test->module->data;
    assert_null(module_data->storage);
}

static const char *INVALID_LOOKBACK_ERROR =
    "At module 'azure-logs': Invalid path lookback. It should be a number of minutes, hours or days (m, h, d), up to 3650d.";
static const char *INVALID_MAX_FOLDERS_ERROR =
    "At module 'azure-logs': Invalid path max folders. It should be a number from 1 to 100000.";

void test_read_storage_invalid_path_lookback_unit(void **state) {
    assert_invalid_container(state, STORAGE_CONFIG("        <path_lookback>1w</path_lookback>\n"), INVALID_LOOKBACK_ERROR);
}

void test_read_storage_invalid_path_lookback_negative(void **state) {
    assert_invalid_container(state, STORAGE_CONFIG("        <path_lookback>-1d</path_lookback>\n"), INVALID_LOOKBACK_ERROR);
}

void test_read_storage_invalid_path_lookback_no_unit(void **state) {
    assert_invalid_container(state, STORAGE_CONFIG("        <path_lookback>12</path_lookback>\n"), INVALID_LOOKBACK_ERROR);
}

void test_read_storage_invalid_path_lookback_trailing(void **state) {
    assert_invalid_container(state, STORAGE_CONFIG("        <path_lookback>1d2</path_lookback>\n"), INVALID_LOOKBACK_ERROR);
}

void test_read_storage_invalid_path_lookback_too_long(void **state) {
    assert_invalid_container(state, STORAGE_CONFIG("        <path_lookback>87601h</path_lookback>\n"), INVALID_LOOKBACK_ERROR);
}

void test_read_storage_path_lookback_max(void **state) {
    const char *string = STORAGE_CONFIG(
        "        <path>y=%Y/m=%m/</path>\n"
        "        <path_lookback>5256000m</path_lookback>\n");
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_azure_read(&(test->xml), test->nodes, test->module), 0);
    wm_azure_t *module_data = (wm_azure_t*)test->module->data;
    assert_string_equal(module_data->storage->container->path_lookback, "5256000m");
}

void test_read_storage_invalid_path_max_folders_zero(void **state) {
    assert_invalid_container(state, STORAGE_CONFIG("        <path_max_folders>0</path_max_folders>\n"), INVALID_MAX_FOLDERS_ERROR);
}

void test_read_storage_invalid_path_max_folders_too_many(void **state) {
    assert_invalid_container(state, STORAGE_CONFIG("        <path_max_folders>100001</path_max_folders>\n"), INVALID_MAX_FOLDERS_ERROR);
}

void test_read_storage_invalid_path_max_folders_text(void **state) {
    assert_invalid_container(state, STORAGE_CONFIG("        <path_max_folders>10x</path_max_folders>\n"), INVALID_MAX_FOLDERS_ERROR);
}

void test_read_storage_invalid_path_max_folders_negative(void **state) {
    assert_invalid_container(state, STORAGE_CONFIG("        <path_max_folders>-5</path_max_folders>\n"), INVALID_MAX_FOLDERS_ERROR);
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
        cmocka_unit_test(test_dump_requests_and_containers),
        cmocka_unit_test_setup_teardown(test_read_storage_path_limits, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_storage_without_path_limits, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_storage_path_limits_without_date_fields, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_storage_command_with_path_limits, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_storage_path_limits_with_date_field_after_escaped_percent, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_storage_path_lookback_without_path, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_storage_invalid_path_lookback_unit, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_storage_invalid_path_lookback_negative, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_storage_invalid_path_lookback_no_unit, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_storage_invalid_path_lookback_trailing, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_storage_invalid_path_lookback_too_long, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_storage_path_lookback_max, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_storage_invalid_path_max_folders_zero, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_storage_invalid_path_max_folders_too_many, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_storage_invalid_path_max_folders_text, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_storage_invalid_path_max_folders_negative, setup_test_read, teardown_test_read)
    };
    int result;
    result = cmocka_run_group_tests(tests_with_startup, setup_module, teardown_module);
    result += cmocka_run_group_tests(tests_without_startup, NULL, NULL);
    return result;
}
