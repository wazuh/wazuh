/*
 * Copyright (C) 2023, InfoDefense Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Test corresponding to the scheduling capacities
 * for ms-graph Module
 * */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <time.h>
#include <stdlib.h>

#include "shared.h"
#include "../../wazuh_modules/wmodules.h"
#include "../../wazuh_modules/wm_ms_graph.h"
#include "../../wazuh_modules/wm_ms_graph.c"

#include "../scheduling/wmodules_scheduling_helpers.h"
#include "../../wrappers/common.h"
#include "../../wrappers/libc/stdlib_wrappers.h"
#include "../../wrappers/wazuh/shared/mq_op_wrappers.h"
#include "../../wrappers/wazuh/wazuh_modules/wmodules_wrappers.h"
#include "../../wrappers/wazuh/shared/time_op_wrappers.h"
#include "../../wrappers/wazuh/shared/url_wrappers.h"
#include "../../wrappers/wazuh/shared/schedule_scan_wrappers.h"
#include "../../wrappers/libc/time_wrappers.h"
#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../wrappers/wazuh/wazuh_modules/wm_exec_wrappers.h"

#define TEST_MAX_DATES 5
#define TEST_MAX_TENANT 3

static wmodule *ms_graph_module;
static OS_XML *lxml;

unsigned int __wrap_gmtime_r(__attribute__ ((__unused__)) const time_t *t, __attribute__ ((__unused__)) struct tm *tm) {
    return mock_type(unsigned int);
}

int __wrap_isDebug() {
    return mock();
}

static void wmodule_cleanup(wmodule *module){
    wm_ms_graph* module_data = (wm_ms_graph*)module->data;
    if(module_data){
        os_free(module_data->version);
        for(unsigned int resource = 0; resource < module_data->num_resources; resource++){
            for(unsigned int relationship = 0; relationship < module_data->resources[resource].num_relationships; relationship++){
                os_free(module_data->resources[resource].relationships[relationship]);
            }
            os_free(module_data->resources[resource].relationships);
            os_free(module_data->resources[resource].name);
        }
        os_free(module_data->resources);
        for(int i = 0; module_data->auth_config[i]; i++) {
            os_free(module_data->auth_config[i]->tenant_id);
            os_free(module_data->auth_config[i]->client_id);
            os_free(module_data->auth_config[i]->secret_value);
            os_free(module_data->auth_config[i]->access_token);
            os_free(module_data->auth_config[i]->login_fqdn);
            os_free(module_data->auth_config[i]->query_fqdn);

            os_free(module_data->auth_config[i]);
        }

        os_free(module_data->auth_config);
        os_free(module_data);
    }
    os_free(module->tag);
    os_free(module);
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
    wm_ms_graph* module_data = (wm_ms_graph*)test->module->data;
    if(module_data && &(module_data->scan_config)){
        sched_scan_free(&(module_data->scan_config));
    }
    wmodule_cleanup(test->module);
    os_free(test);
    return 0;
}

static int setup_conf(void **state) {
    wm_ms_graph* init_data = NULL;
    os_calloc(1,sizeof(wm_ms_graph), init_data);
    test_mode = true;
    *state = init_data;
    return 0;
}

static int teardown_conf(void **state) {
    wm_ms_graph *data  = (wm_ms_graph *)*state;
    test_mode = false;
    wm_ms_graph_destroy(data);
    return 0;
}

// XML reading tests
void test_bad_tag(void **state) {
    const char* config =
        "<invalid>yes</invalid>\n"
        "<only_future_events>yes</only_future_events>\n"
        "<curl_max_size>1M</curl_max_size>\n"
        "<run_on_start>yes</run_on_start>\n"
        "<interval>5m</interval>\n"
        "<version>v1.0</version>\n"
        "<api_auth>\n"
        "  <client_id>example_string</client_id>\n"
        "  <tenant_id>example_string</tenant_id>\n"
        "  <secret_value>example_string</secret_value>\n"
        "  <api_type>global</api_type>\n"
        "</api_auth>\n"
        "<resource>\n"
        "  <name>security</name>\n"
        "  <relationship>alerts_v2</relationship>\n"
        "  <relationship>incidents</relationship>\n"
        "</resource>\n"
        "<resource>\n"
        "  <name>identityProtection</name>\n"
        "  <relationship>riskyUsers</relationship>\n"
        "</resource>\n"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "(1233): Invalid attribute 'invalid' in the configuration: 'ms-graph'.");
    test->nodes = string_to_xml_node(config, &(test->xml));
    assert_int_equal(wm_ms_graph_read(&(test->xml), test->nodes, test->module), OS_CFGERR);
}

void test_empty_module(void **state) {
    const char* config = "";
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "Empty configuration found in module 'ms-graph'.");
    test->nodes = string_to_xml_node(config, &(test->xml));
    assert_int_equal(wm_ms_graph_read(&(test->xml), test->nodes, test->module), OS_CFGERR);
}

void test_invalid_enabled(void **state) {
    const char* config =
        "<enabled>invalid</enabled>\n"
        "<only_future_events>yes</only_future_events>\n"
        "<curl_max_size>1M</curl_max_size>\n"
        "<run_on_start>yes</run_on_start>\n"
        "<interval>5m</interval>\n"
        "<version>v1.0</version>\n"
        "<api_auth>\n"
        "  <client_id>example_string</client_id>\n"
        "  <tenant_id>example_string</tenant_id>\n"
        "  <secret_value>example_string</secret_value>\n"
        "  <api_type>global</api_type>\n"
        "</api_auth>\n"
        "<resource>\n"
        "  <name>security</name>\n"
        "  <relationship>alerts_v2</relationship>\n"
        "  <relationship>incidents</relationship>\n"
        "</resource>\n"
        "<resource>\n"
        "  <name>identityProtection</name>\n"
        "  <relationship>riskyUsers</relationship>\n"
        "</resource>\n"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'enabled' at module 'ms-graph'.");
    test->nodes = string_to_xml_node(config, &(test->xml));
    assert_int_equal(wm_ms_graph_read(&(test->xml), test->nodes, test->module), OS_CFGERR);
}

void test_enabled_no(void **state) {
    const char* config =
        "<enabled>no</enabled>\n"
        "<only_future_events>yes</only_future_events>\n"
        "<curl_max_size>1M</curl_max_size>\n"
        "<run_on_start>yes</run_on_start>\n"
        "<interval>5m</interval>\n"
        "<version>v1.0</version>\n"
        "<api_auth>\n"
        "  <client_id>example_string</client_id>\n"
        "  <tenant_id>example_string</tenant_id>\n"
        "  <secret_value>example_string</secret_value>\n"
        "  <api_type>global</api_type>\n"
        "</api_auth>\n"
        "<resource>\n"
        "  <name>security</name>\n"
        "  <relationship>alerts_v2</relationship>\n"
        "  <relationship>incidents</relationship>\n"
        "</resource>\n"
        "<resource>\n"
        "  <name>identityProtection</name>\n"
        "  <relationship>riskyUsers</relationship>\n"
        "</resource>\n"
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(config, &(test->xml));
    assert_int_equal(wm_ms_graph_read(&(test->xml), test->nodes, test->module), OS_SUCCESS);
    wm_ms_graph *module_data = (wm_ms_graph*)test->module->data;
    assert_int_equal(module_data->enabled, 0);
    assert_int_equal(module_data->only_future_events, 1);
    assert_int_equal(module_data->curl_max_size, OS_SIZE_1048576);
    assert_int_equal(module_data->run_on_start, 1);
    assert_string_equal(module_data->version, "v1.0");

    assert_string_equal(module_data->auth_config[0]->tenant_id, "example_string");
    assert_string_equal(module_data->auth_config[0]->client_id, "example_string");
    assert_string_equal(module_data->auth_config[0]->secret_value, "example_string");
    assert_int_equal(module_data->num_resources, 2);
    assert_string_equal(module_data->resources[0].name, "security");
    assert_int_equal(module_data->resources[0].num_relationships, 2);
    assert_string_equal(module_data->resources[0].relationships[0], "alerts_v2");
    assert_string_equal(module_data->resources[0].relationships[1], "incidents");
    assert_string_equal(module_data->resources[1].name, "identityProtection");
    assert_int_equal(module_data->resources[1].num_relationships, 1);
    assert_string_equal(module_data->resources[1].relationships[0], "riskyUsers");
}

void test_invalid_only_future_events(void **state) {
    const char* config =
        "<enabled>yes</enabled>\n"
        "<only_future_events>invalid</only_future_events>\n"
        "<curl_max_size>1M</curl_max_size>\n"
        "<run_on_start>yes</run_on_start>\n"
        "<interval>5m</interval>\n"
        "<version>v1.0</version>\n"
        "<api_auth>\n"
        "  <client_id>example_string</client_id>\n"
        "  <tenant_id>example_string</tenant_id>\n"
        "  <secret_value>example_string</secret_value>\n"
        "  <api_type>global</api_type>\n"
        "</api_auth>\n"
        "<resource>\n"
        "  <name>security</name>\n"
        "  <relationship>alerts_v2</relationship>\n"
        "  <relationship>incidents</relationship>\n"
        "</resource>\n"
        "<resource>\n"
        "  <name>identityProtection</name>\n"
        "  <relationship>riskyUsers</relationship>\n"
        "</resource>\n"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'only_future_events' at module 'ms-graph'.");
    test->nodes = string_to_xml_node(config, &(test->xml));
    assert_int_equal(wm_ms_graph_read(&(test->xml), test->nodes, test->module), OS_CFGERR);
}

void test_disabled_only_future_events(void **state) {
    const char* config =
        "<enabled>yes</enabled>\n"
        "<only_future_events>no</only_future_events>\n"
        "<curl_max_size>1M</curl_max_size>\n"
        "<run_on_start>yes</run_on_start>\n"
        "<interval>5m</interval>\n"
        "<version>v1.0</version>\n"
        "<api_auth>\n"
        "  <client_id>example_string</client_id>\n"
        "  <tenant_id>example_string</tenant_id>\n"
        "  <secret_value>example_string</secret_value>\n"
        "  <api_type>global</api_type>\n"
        "</api_auth>\n"
        "<resource>\n"
        "  <name>security</name>\n"
        "  <relationship>alerts_v2</relationship>\n"
        "  <relationship>incidents</relationship>\n"
        "</resource>\n"
        "<resource>\n"
        "  <name>identityProtection</name>\n"
        "  <relationship>riskyUsers</relationship>\n"
        "</resource>\n"
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(config, &(test->xml));
    assert_int_equal(wm_ms_graph_read(&(test->xml), test->nodes, test->module), OS_SUCCESS);
    wm_ms_graph *module_data = (wm_ms_graph*)test->module->data;
    assert_int_equal(module_data->enabled, 1);
    assert_int_equal(module_data->only_future_events, 0);
    assert_int_equal(module_data->curl_max_size, OS_SIZE_1048576);
    assert_int_equal(module_data->run_on_start, 1);
    assert_string_equal(module_data->version, "v1.0");
    assert_string_equal(module_data->auth_config[0]->tenant_id, "example_string");
    assert_string_equal(module_data->auth_config[0]->client_id, "example_string");
    assert_string_equal(module_data->auth_config[0]->secret_value, "example_string");
    assert_int_equal(module_data->num_resources, 2);
    assert_string_equal(module_data->resources[0].name, "security");
    assert_int_equal(module_data->resources[0].num_relationships, 2);
    assert_string_equal(module_data->resources[0].relationships[0], "alerts_v2");
    assert_string_equal(module_data->resources[0].relationships[1], "incidents");
    assert_string_equal(module_data->resources[1].name, "identityProtection");
    assert_int_equal(module_data->resources[1].num_relationships, 1);
    assert_string_equal(module_data->resources[1].relationships[0], "riskyUsers");
}

void test_invalid_curl_max_size(void **state) {
    const char* config =
        "<enabled>yes</enabled>\n"
        "<only_future_events>yes</only_future_events>\n"
        "<curl_max_size>invalid</curl_max_size>\n"
        "<run_on_start>yes</run_on_start>\n"
        "<interval>5m</interval>\n"
        "<version>v1.0</version>\n"
        "<api_auth>\n"
        "  <client_id>example_string</client_id>\n"
        "  <tenant_id>example_string</tenant_id>\n"
        "  <secret_value>example_string</secret_value>\n"
        "  <api_type>global</api_type>\n"
        "</api_auth>\n"
        "<resource>\n"
        "  <name>security</name>\n"
        "  <relationship>alerts_v2</relationship>\n"
        "  <relationship>incidents</relationship>\n"
        "</resource>\n"
        "<resource>\n"
        "  <name>identityProtection</name>\n"
        "  <relationship>riskyUsers</relationship>\n"
        "</resource>\n"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'curl_max_size' at module 'ms-graph'. The minimum value allowed is 1KB.");
    test->nodes = string_to_xml_node(config, &(test->xml));
    assert_int_equal(wm_ms_graph_read(&(test->xml), test->nodes, test->module), OS_CFGERR);
}

void test_invalid_negative_curl_max_size(void **state) {
    const char* config =
        "<enabled>yes</enabled>\n"
        "<only_future_events>yes</only_future_events>\n"
        "<curl_max_size>-1</curl_max_size>\n"
        "<run_on_start>yes</run_on_start>\n"
        "<interval>5m</interval>\n"
        "<version>v1.0</version>\n"
        "<api_auth>\n"
        "  <client_id>example_string</client_id>\n"
        "  <tenant_id>example_string</tenant_id>\n"
        "  <secret_value>example_string</secret_value>\n"
        "  <api_type>global</api_type>\n"
        "</api_auth>\n"
        "<resource>\n"
        "  <name>security</name>\n"
        "  <relationship>alerts_v2</relationship>\n"
        "  <relationship>incidents</relationship>\n"
        "</resource>\n"
        "<resource>\n"
        "  <name>identityProtection</name>\n"
        "  <relationship>riskyUsers</relationship>\n"
        "</resource>\n"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'curl_max_size' at module 'ms-graph'. The minimum value allowed is 1KB.");
    test->nodes = string_to_xml_node(config, &(test->xml));
    assert_int_equal(wm_ms_graph_read(&(test->xml), test->nodes, test->module), OS_CFGERR);
}

void test_value_curl_max_size(void **state) {
    const char* config =
        "<enabled>yes</enabled>\n"
        "<only_future_events>yes</only_future_events>\n"
        "<curl_max_size>4k</curl_max_size>\n"
        "<run_on_start>yes</run_on_start>\n"
        "<interval>5m</interval>\n"
        "<version>v1.0</version>\n"
        "<api_auth>\n"
        "  <client_id>example_string</client_id>\n"
        "  <tenant_id>example_string</tenant_id>\n"
        "  <secret_value>example_string</secret_value>\n"
        "  <api_type>global</api_type>\n"
        "</api_auth>\n"
        "<resource>\n"
        "  <name>security</name>\n"
        "  <relationship>alerts_v2</relationship>\n"
        "  <relationship>incidents</relationship>\n"
        "</resource>\n"
        "<resource>\n"
        "  <name>identityProtection</name>\n"
        "  <relationship>riskyUsers</relationship>\n"
        "</resource>\n"
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(config, &(test->xml));
    assert_int_equal(wm_ms_graph_read(&(test->xml), test->nodes, test->module), OS_SUCCESS);
    wm_ms_graph *module_data = (wm_ms_graph*)test->module->data;
    assert_int_equal(module_data->curl_max_size, 4096);
}

void test_invalid_run_on_start(void **state) {
    const char* config =
        "<enabled>yes</enabled>\n"
        "<only_future_events>yes</only_future_events>\n"
        "<curl_max_size>1M</curl_max_size>\n"
        "<run_on_start>invalid</run_on_start>\n"
        "<interval>5m</interval>\n"
        "<version>v1.0</version>\n"
        "<api_auth>\n"
        "  <client_id>example_string</client_id>\n"
        "  <tenant_id>example_string</tenant_id>\n"
        "  <secret_value>example_string</secret_value>\n"
        "  <api_type>global</api_type>\n"
        "</api_auth>\n"
        "<resource>\n"
        "  <name>security</name>\n"
        "  <relationship>alerts_v2</relationship>\n"
        "  <relationship>incidents</relationship>\n"
        "</resource>\n"
        "<resource>\n"
        "  <name>identityProtection</name>\n"
        "  <relationship>riskyUsers</relationship>\n"
        "</resource>\n"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'run_on_start' at module 'ms-graph'.");
    test->nodes = string_to_xml_node(config, &(test->xml));
    assert_int_equal(wm_ms_graph_read(&(test->xml), test->nodes, test->module), OS_CFGERR);
}

void test_disabled_run_on_start(void **state) {
    const char* config =
        "<enabled>yes</enabled>\n"
        "<only_future_events>yes</only_future_events>\n"
        "<curl_max_size>1M</curl_max_size>\n"
        "<run_on_start>no</run_on_start>\n"
        "<interval>5m</interval>\n"
        "<version>v1.0</version>\n"
        "<api_auth>\n"
        "  <client_id>example_string</client_id>\n"
        "  <tenant_id>example_string</tenant_id>\n"
        "  <secret_value>example_string</secret_value>\n"
        "  <api_type>global</api_type>\n"
        "</api_auth>\n"
        "<resource>\n"
        "  <name>security</name>\n"
        "  <relationship>alerts_v2</relationship>\n"
        "  <relationship>incidents</relationship>\n"
        "</resource>\n"
        "<resource>\n"
        "  <name>identityProtection</name>\n"
        "  <relationship>riskyUsers</relationship>\n"
        "</resource>\n"
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(config, &(test->xml));
    assert_int_equal(wm_ms_graph_read(&(test->xml), test->nodes, test->module), OS_SUCCESS);
    wm_ms_graph *module_data = (wm_ms_graph*)test->module->data;
    assert_int_equal(module_data->enabled, 1);
    assert_int_equal(module_data->only_future_events, 1);
    assert_int_equal(module_data->curl_max_size, OS_SIZE_1048576);
    assert_int_equal(module_data->run_on_start, 0);
    assert_string_equal(module_data->version, "v1.0");
    assert_string_equal(module_data->auth_config[0]->tenant_id, "example_string");
    assert_string_equal(module_data->auth_config[0]->client_id, "example_string");
    assert_string_equal(module_data->auth_config[0]->secret_value, "example_string");
    assert_int_equal(module_data->num_resources, 2);
    assert_string_equal(module_data->resources[0].name, "security");
    assert_int_equal(module_data->resources[0].num_relationships, 2);
    assert_string_equal(module_data->resources[0].relationships[0], "alerts_v2");
    assert_string_equal(module_data->resources[0].relationships[1], "incidents");
    assert_string_equal(module_data->resources[1].name, "identityProtection");
    assert_int_equal(module_data->resources[1].num_relationships, 1);
    assert_string_equal(module_data->resources[1].relationships[0], "riskyUsers");
}

void test_invalid_interval(void **state) {
    const char* config =
        "<enabled>yes</enabled>\n"
        "<only_future_events>yes</only_future_events>\n"
        "<curl_max_size>1M</curl_max_size>\n"
        "<run_on_start>yes</run_on_start>\n"
        "<interval>invalid</interval>\n"
        "<version>v1.0</version>\n"
        "<api_auth>\n"
        "  <client_id>example_string</client_id>\n"
        "  <tenant_id>example_string</tenant_id>\n"
        "  <secret_value>example_string</secret_value>\n"
        "  <api_type>global</api_type>\n"
        "</api_auth>\n"
        "<resource>\n"
        "  <name>security</name>\n"
        "  <relationship>alerts_v2</relationship>\n"
        "  <relationship>incidents</relationship>\n"
        "</resource>\n"
        "<resource>\n"
        "  <name>identityProtection</name>\n"
        "  <relationship>riskyUsers</relationship>\n"
        "</resource>\n"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'interval' at module 'ms-graph'.");
    test->nodes = string_to_xml_node(config, &(test->xml));
    assert_int_equal(wm_ms_graph_read(&(test->xml), test->nodes, test->module), OS_INVALID);
}

void test_invalid_version(void **state) {
    const char* config =
        "<enabled>yes</enabled>\n"
        "<only_future_events>yes</only_future_events>\n"
        "<curl_max_size>1M</curl_max_size>\n"
        "<run_on_start>yes</run_on_start>\n"
        "<interval>5m</interval>\n"
        "<version>invalid</version>\n"
        "<api_auth>\n"
        "  <client_id>example_string</client_id>\n"
        "  <tenant_id>example_string</tenant_id>\n"
        "  <secret_value>example_string</secret_value>\n"
        "  <api_type>global</api_type>\n"
        "</api_auth>\n"
        "<resource>\n"
        "  <name>security</name>\n"
        "  <relationship>alerts_v2</relationship>\n"
        "  <relationship>incidents</relationship>\n"
        "</resource>\n"
        "<resource>\n"
        "  <name>identityProtection</name>\n"
        "  <relationship>riskyUsers</relationship>\n"
        "</resource>\n"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'version' at module 'ms-graph'.");
    test->nodes = string_to_xml_node(config, &(test->xml));
    assert_int_equal(wm_ms_graph_read(&(test->xml), test->nodes, test->module), OS_CFGERR);
}

void test_missing_api_auth(void **state) {
    const char* config =
        "<enabled>yes</enabled>\n"
        "<only_future_events>yes</only_future_events>\n"
        "<curl_max_size>1M</curl_max_size>\n"
        "<run_on_start>yes</run_on_start>\n"
        "<interval>5m</interval>\n"
        "<version>v1.0</version>\n"
        "<resource>\n"
        "  <name>security</name>\n"
        "  <relationship>alerts_v2</relationship>\n"
        "  <relationship>incidents</relationship>\n"
        "</resource>\n"
        "<resource>\n"
        "  <name>identityProtection</name>\n"
        "  <relationship>riskyUsers</relationship>\n"
        "</resource>\n"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "(1228): Element 'api_auth' without any option.");
    test->nodes = string_to_xml_node(config, &(test->xml));
    assert_int_equal(wm_ms_graph_read(&(test->xml), test->nodes, test->module), OS_NOTFOUND);
}

void test_empty_api_auth(void **state) {
    const char* config =
        "<enabled>yes</enabled>\n"
        "<only_future_events>yes</only_future_events>\n"
        "<curl_max_size>1M</curl_max_size>\n"
        "<run_on_start>yes</run_on_start>\n"
        "<interval>5m</interval>\n"
        "<version>v1.0</version>\n"
        "<api_auth></api_auth>\n"
        "<resource>\n"
        "  <name>security</name>\n"
        "  <relationship>alerts_v2</relationship>\n"
        "  <relationship>incidents</relationship>\n"
        "</resource>\n"
        "<resource>\n"
        "  <name>identityProtection</name>\n"
        "  <relationship>riskyUsers</relationship>\n"
        "</resource>\n"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "Empty content for tag 'api_auth' at module 'ms-graph'.");
    test->nodes = string_to_xml_node(config, &(test->xml));
    assert_int_equal(wm_ms_graph_read(&(test->xml), test->nodes, test->module), OS_CFGERR);
}

void test_invalid_client_id(void **state) {
    const char* config =
        "<enabled>yes</enabled>\n"
        "<only_future_events>yes</only_future_events>\n"
        "<curl_max_size>1M</curl_max_size>\n"
        "<run_on_start>yes</run_on_start>\n"
        "<interval>5m</interval>\n"
        "<version>v1.0</version>\n"
        "<api_auth>\n"
        "  <client_id></client_id>\n"
        "  <tenant_id>example_string</tenant_id>\n"
        "  <secret_value>example_string</secret_value>\n"
        "  <api_type>global</api_type>\n"
        "</api_auth>\n"
        "<resource>\n"
        "  <name>security</name>\n"
        "  <relationship>alerts_v2</relationship>\n"
        "  <relationship>incidents</relationship>\n"
        "</resource>\n"
        "<resource>\n"
        "  <name>identityProtection</name>\n"
        "  <relationship>riskyUsers</relationship>\n"
        "</resource>\n"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "Empty content for tag 'client_id' at module 'ms-graph'.");
    test->nodes = string_to_xml_node(config, &(test->xml));
    assert_int_equal(wm_ms_graph_read(&(test->xml), test->nodes, test->module), OS_CFGERR);
}

void test_missing_client_id(void **state) {
    const char* config =
        "<enabled>yes</enabled>\n"
        "<only_future_events>yes</only_future_events>\n"
        "<curl_max_size>1M</curl_max_size>\n"
        "<run_on_start>yes</run_on_start>\n"
        "<interval>5m</interval>\n"
        "<version>v1.0</version>\n"
        "<api_auth>\n"
        "  <tenant_id>example_string</tenant_id>\n"
        "  <secret_value>example_string</secret_value>\n"
        "  <api_type>global</api_type>\n"
        "</api_auth>\n"
        "<resource>\n"
        "  <name>security</name>\n"
        "  <relationship>alerts_v2</relationship>\n"
        "  <relationship>incidents</relationship>\n"
        "</resource>\n"
        "<resource>\n"
        "  <name>identityProtection</name>\n"
        "  <relationship>riskyUsers</relationship>\n"
        "</resource>\n"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "(1228): Element 'client_id' without any option.");
    test->nodes = string_to_xml_node(config, &(test->xml));
    assert_int_equal(wm_ms_graph_read(&(test->xml), test->nodes, test->module), OS_NOTFOUND);
}

void test_invalid_tenant_id(void **state) {
    const char* config =
        "<enabled>yes</enabled>\n"
        "<only_future_events>yes</only_future_events>\n"
        "<curl_max_size>1M</curl_max_size>\n"
        "<run_on_start>yes</run_on_start>\n"
        "<interval>5m</interval>\n"
        "<version>v1.0</version>\n"
        "<api_auth>\n"
        "  <client_id>example_string</client_id>\n"
        "  <tenant_id></tenant_id>\n"
        "  <secret_value>example_string</secret_value>\n"
        "  <api_type>global</api_type>\n"
        "</api_auth>\n"
        "<resource>\n"
        "  <name>security</name>\n"
        "  <relationship>alerts_v2</relationship>\n"
        "  <relationship>incidents</relationship>\n"
        "</resource>\n"
        "<resource>\n"
        "  <name>identityProtection</name>\n"
        "  <relationship>riskyUsers</relationship>\n"
        "</resource>\n"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "Empty content for tag 'tenant_id' at module 'ms-graph'.");
    test->nodes = string_to_xml_node(config, &(test->xml));
    assert_int_equal(wm_ms_graph_read(&(test->xml), test->nodes, test->module), OS_CFGERR);
}

void test_missing_tenant_id(void **state) {
    const char* config =
        "<enabled>yes</enabled>\n"
        "<only_future_events>yes</only_future_events>\n"
        "<curl_max_size>1M</curl_max_size>\n"
        "<run_on_start>yes</run_on_start>\n"
        "<interval>5m</interval>\n"
        "<version>v1.0</version>\n"
        "<api_auth>\n"
        "  <client_id>example_string</client_id>\n"
        "  <secret_value>example_string</secret_value>\n"
        "  <api_type>global</api_type>\n"
        "</api_auth>\n"
        "<resource>\n"
        "  <name>security</name>\n"
        "  <relationship>alerts_v2</relationship>\n"
        "  <relationship>incidents</relationship>\n"
        "</resource>\n"
        "<resource>\n"
        "  <name>identityProtection</name>\n"
        "  <relationship>riskyUsers</relationship>\n"
        "</resource>\n"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "(1228): Element 'tenant_id' without any option.");
    test->nodes = string_to_xml_node(config, &(test->xml));
    assert_int_equal(wm_ms_graph_read(&(test->xml), test->nodes, test->module), OS_NOTFOUND);
}

void test_invalid_secret_value(void **state) {
    const char* config =
        "<enabled>yes</enabled>\n"
        "<only_future_events>yes</only_future_events>\n"
        "<curl_max_size>1M</curl_max_size>\n"
        "<run_on_start>yes</run_on_start>\n"
        "<interval>5m</interval>\n"
        "<version>v1.0</version>\n"
        "<api_auth>\n"
        "  <client_id>example_string</client_id>\n"
        "  <tenant_id>example_string</tenant_id>\n"
        "  <secret_value></secret_value>\n"
        "  <api_type>global</api_type>\n"
        "</api_auth>\n"
        "<resource>\n"
        "  <name>security</name>\n"
        "  <relationship>alerts_v2</relationship>\n"
        "  <relationship>incidents</relationship>\n"
        "</resource>\n"
        "<resource>\n"
        "  <name>identityProtection</name>\n"
        "  <relationship>riskyUsers</relationship>\n"
        "</resource>\n"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "Empty content for tag 'secret_value' at module 'ms-graph'.");
    test->nodes = string_to_xml_node(config, &(test->xml));
    assert_int_equal(wm_ms_graph_read(&(test->xml), test->nodes, test->module), OS_CFGERR);
}

void test_missing_secret_value(void **state) {
    const char* config =
        "<enabled>yes</enabled>\n"
        "<only_future_events>yes</only_future_events>\n"
        "<curl_max_size>1M</curl_max_size>\n"
        "<run_on_start>yes</run_on_start>\n"
        "<interval>5m</interval>\n"
        "<version>v1.0</version>\n"
        "<api_auth>\n"
        "  <client_id>example_string</client_id>\n"
        "  <tenant_id>example_string</tenant_id>\n"
        "  <api_type>global</api_type>\n"
        "</api_auth>\n"
        "<resource>\n"
        "  <name>security</name>\n"
        "  <relationship>alerts_v2</relationship>\n"
        "  <relationship>incidents</relationship>\n"
        "</resource>\n"
        "<resource>\n"
        "  <name>identityProtection</name>\n"
        "  <relationship>riskyUsers</relationship>\n"
        "</resource>\n"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "(1228): Element 'secret_value' without any option.");
    test->nodes = string_to_xml_node(config, &(test->xml));
    assert_int_equal(wm_ms_graph_read(&(test->xml), test->nodes, test->module), OS_NOTFOUND);
}

void test_invalid_api_type(void **state){
    const char* config =
        "<enabled>yes</enabled>\n"
        "<only_future_events>yes</only_future_events>\n"
        "<curl_max_size>1M</curl_max_size>\n"
        "<run_on_start>yes</run_on_start>\n"
        "<interval>5m</interval>\n"
        "<version>v1.0</version>\n"
        "<api_auth>\n"
        "  <client_id>example_string</client_id>\n"
        "  <tenant_id>example_string</tenant_id>\n"
        "  <secret_value>example_string</secret_value>\n"
        "  <api_type>invalid</api_type>\n"
        "</api_auth>\n"
        "<resource>\n"
        "  <name>security</name>\n"
        "  <relationship>alerts_v2</relationship>\n"
        "  <relationship>incidents</relationship>\n"
        "</resource>\n"
        "<resource>\n"
        "  <name>identityProtection</name>\n"
        "  <relationship>riskyUsers</relationship>\n"
        "</resource>\n"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'api_type' at module 'ms-graph'.");
    test->nodes = string_to_xml_node(config, &(test->xml));
    assert_int_equal(wm_ms_graph_read(&(test->xml), test->nodes, test->module), OS_CFGERR);
}

void test_missing_api_type(void **state){
    const char* config =
        "<enabled>yes</enabled>\n"
        "<only_future_events>yes</only_future_events>\n"
        "<curl_max_size>1M</curl_max_size>\n"
        "<run_on_start>yes</run_on_start>\n"
        "<interval>5m</interval>\n"
        "<version>v1.0</version>\n"
        "<api_auth>\n"
        "  <client_id>example_string</client_id>\n"
        "  <tenant_id>example_string</tenant_id>\n"
        "  <secret_value>example_string</secret_value>\n"
        "</api_auth>\n"
        "<resource>\n"
        "  <name>security</name>\n"
        "  <relationship>alerts_v2</relationship>\n"
        "  <relationship>incidents</relationship>\n"
        "</resource>\n"
        "<resource>\n"
        "  <name>identityProtection</name>\n"
        "  <relationship>riskyUsers</relationship>\n"
        "</resource>\n"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "(1228): Element 'api_type' without any option.");
    test->nodes = string_to_xml_node(config, &(test->xml));
    assert_int_equal(wm_ms_graph_read(&(test->xml), test->nodes, test->module), OS_NOTFOUND);
}

void test_empty_api_type(void **state){
    const char* config =
        "<enabled>yes</enabled>\n"
        "<only_future_events>yes</only_future_events>\n"
        "<curl_max_size>1M</curl_max_size>\n"
        "<run_on_start>yes</run_on_start>\n"
        "<interval>5m</interval>\n"
        "<version>v1.0</version>\n"
        "<api_auth>\n"
        "  <client_id>example_string</client_id>\n"
        "  <tenant_id>example_string</tenant_id>\n"
        "  <secret_value>example_string</secret_value>\n"
        "  <api_type></api_type>\n"
        "</api_auth>\n"
        "<resource>\n"
        "  <name>security</name>\n"
        "  <relationship>alerts_v2</relationship>\n"
        "  <relationship>incidents</relationship>\n"
        "</resource>\n"
        "<resource>\n"
        "  <name>identityProtection</name>\n"
        "  <relationship>riskyUsers</relationship>\n"
        "</resource>\n"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "Empty content for tag 'api_type' at module 'ms-graph'.");
    test->nodes = string_to_xml_node(config, &(test->xml));
    assert_int_equal(wm_ms_graph_read(&(test->xml), test->nodes, test->module), OS_CFGERR);
}

void test_invalid_attribute_api_type(void **state) {
    const char* config =
        "<enabled>yes</enabled>\n"
        "<only_future_events>yes</only_future_events>\n"
        "<curl_max_size>1M</curl_max_size>\n"
        "<run_on_start>yes</run_on_start>\n"
        "<interval>5m</interval>\n"
        "<version>v1.0</version>\n"
        "<api_auth>\n"
        "  <client_id>example_string</client_id>\n"
        "  <tenant_id>example_string</tenant_id>\n"
        "  <secret_value>example_string</secret_value>\n"
        "  <api_type>global</api_type>\n"
        "  <invalid>attribute</invalid>\n"
        "</api_auth>\n"
        "<resource>\n"
        "  <name>identityProtection</name>\n"
        "  <relationship>riskyUsers</relationship>\n"
        "</resource>\n"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "(1233): Invalid attribute 'invalid' in the configuration: 'ms-graph'.");
    test->nodes = string_to_xml_node(config, &(test->xml));
    assert_int_equal(wm_ms_graph_read(&(test->xml), test->nodes, test->module), OS_CFGERR);
}

void test_missing_resource(void **state) {
    const char* config =
        "<enabled>yes</enabled>\n"
        "<only_future_events>yes</only_future_events>\n"
        "<curl_max_size>1M</curl_max_size>\n"
        "<run_on_start>yes</run_on_start>\n"
        "<interval>5m</interval>\n"
        "<version>v1.0</version>\n"
        "<api_auth>\n"
        "  <client_id>example_string</client_id>\n"
        "  <tenant_id>example_string</tenant_id>\n"
        "  <secret_value>example_string</secret_value>\n"
        "  <api_type>global</api_type>\n"
        "</api_auth>\n"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "(1228): Element 'resource' without any option.");
    test->nodes = string_to_xml_node(config, &(test->xml));
    assert_int_equal(wm_ms_graph_read(&(test->xml), test->nodes, test->module), OS_NOTFOUND);
}

void test_empty_resource(void **state) {
    const char* config =
        "<enabled>yes</enabled>\n"
        "<only_future_events>yes</only_future_events>\n"
        "<curl_max_size>1M</curl_max_size>\n"
        "<run_on_start>yes</run_on_start>\n"
        "<interval>5m</interval>\n"
        "<version>v1.0</version>\n"
        "<api_auth>\n"
        "  <client_id>example_string</client_id>\n"
        "  <tenant_id>example_string</tenant_id>\n"
        "  <secret_value>example_string</secret_value>\n"
        "  <api_type>global</api_type>\n"
        "</api_auth>\n"
        "<resource></resource>\n"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "Empty content for tag 'resource' at module 'ms-graph'.");
    test->nodes = string_to_xml_node(config, &(test->xml));
    assert_int_equal(wm_ms_graph_read(&(test->xml), test->nodes, test->module), OS_CFGERR);
}

void test_missing_name(void **state) {
    const char* config =
        "<enabled>yes</enabled>\n"
        "<only_future_events>yes</only_future_events>\n"
        "<curl_max_size>1M</curl_max_size>\n"
        "<run_on_start>yes</run_on_start>\n"
        "<interval>5m</interval>\n"
        "<version>v1.0</version>\n"
        "<api_auth>\n"
        "  <client_id>example_string</client_id>\n"
        "  <tenant_id>example_string</tenant_id>\n"
        "  <secret_value>example_string</secret_value>\n"
        "  <api_type>global</api_type>\n"
        "</api_auth>\n"
        "<resource>\n"
        "  <relationship>alerts_v2</relationship>\n"
        "  <relationship>incidents</relationship>\n"
        "</resource>\n"
        "<resource>\n"
        "  <name>identityProtection</name>\n"
        "  <relationship>riskyUsers</relationship>\n"
        "</resource>\n"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "(1228): Element 'name' without any option.");
    test->nodes = string_to_xml_node(config, &(test->xml));
    assert_int_equal(wm_ms_graph_read(&(test->xml), test->nodes, test->module), OS_NOTFOUND);
}

void test_empty_name(void **state) {
    const char* config =
        "<enabled>yes</enabled>\n"
        "<only_future_events>yes</only_future_events>\n"
        "<curl_max_size>1M</curl_max_size>\n"
        "<run_on_start>yes</run_on_start>\n"
        "<interval>5m</interval>\n"
        "<version>v1.0</version>\n"
        "<api_auth>\n"
        "  <client_id>example_string</client_id>\n"
        "  <tenant_id>example_string</tenant_id>\n"
        "  <secret_value>example_string</secret_value>\n"
        "  <api_type>global</api_type>\n"
        "</api_auth>\n"
        "<resource>\n"
        "  <name></name>\n"
        "  <relationship>alerts_v2</relationship>\n"
        "  <relationship>incidents</relationship>\n"
        "</resource>\n"
        "<resource>\n"
        "  <name>identityProtection</name>\n"
        "  <relationship>riskyUsers</relationship>\n"
        "</resource>\n"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "Empty content for tag 'name' at module 'ms-graph'.");
    test->nodes = string_to_xml_node(config, &(test->xml));
    assert_int_equal(wm_ms_graph_read(&(test->xml), test->nodes, test->module), OS_CFGERR);
}

void test_missing_relationship(void **state) {
    const char* config =
        "<enabled>yes</enabled>\n"
        "<only_future_events>yes</only_future_events>\n"
        "<curl_max_size>1M</curl_max_size>\n"
        "<run_on_start>yes</run_on_start>\n"
        "<interval>5m</interval>\n"
        "<version>v1.0</version>\n"
        "<api_auth>\n"
        "  <client_id>example_string</client_id>\n"
        "  <tenant_id>example_string</tenant_id>\n"
        "  <secret_value>example_string</secret_value>\n"
        "  <api_type>global</api_type>\n"
        "</api_auth>\n"
        "<resource>\n"
        "  <name>security</name>\n"
        "</resource>\n"
        "<resource>\n"
        "  <name>identityProtection</name>\n"
        "  <relationship>riskyUsers</relationship>\n"
        "</resource>\n"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "(1228): Element 'relationship' without any option.");
    test->nodes = string_to_xml_node(config, &(test->xml));
    assert_int_equal(wm_ms_graph_read(&(test->xml), test->nodes, test->module), OS_NOTFOUND);
}

void test_empty_relationship(void **state) {
    const char* config =
        "<enabled>yes</enabled>\n"
        "<only_future_events>yes</only_future_events>\n"
        "<curl_max_size>1M</curl_max_size>\n"
        "<run_on_start>yes</run_on_start>\n"
        "<interval>5m</interval>\n"
        "<version>v1.0</version>\n"
        "<api_auth>\n"
        "  <client_id>example_string</client_id>\n"
        "  <tenant_id>example_string</tenant_id>\n"
        "  <secret_value>example_string</secret_value>\n"
        "  <api_type>global</api_type>\n"
        "</api_auth>\n"
        "<resource>\n"
        "  <name>security</name>\n"
        "  <relationship></relationship>\n"
        "</resource>\n"
        "<resource>\n"
        "  <name>identityProtection</name>\n"
        "  <relationship>riskyUsers</relationship>\n"
        "</resource>\n"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "Empty content for tag 'relationship' at module 'ms-graph'.");
    test->nodes = string_to_xml_node(config, &(test->xml));
    assert_int_equal(wm_ms_graph_read(&(test->xml), test->nodes, test->module), OS_CFGERR);
}

void test_invalid_attribute_resource(void **state) {
    const char* config =
        "<enabled>yes</enabled>\n"
        "<only_future_events>yes</only_future_events>\n"
        "<curl_max_size>1M</curl_max_size>\n"
        "<run_on_start>yes</run_on_start>\n"
        "<interval>5m</interval>\n"
        "<version>v1.0</version>\n"
        "<api_auth>\n"
        "  <client_id>example_string</client_id>\n"
        "  <tenant_id>example_string</tenant_id>\n"
        "  <secret_value>example_string</secret_value>\n"
        "  <api_type>global</api_type>\n"
        "</api_auth>\n"
        "<resource>\n"
        "  <name>security</name>\n"
        "  <invalid>resource</invalid>\n"
        "</resource>\n"
        "<resource>\n"
        "  <name>identityProtection</name>\n"
        "  <relationship>riskyUsers</relationship>\n"
        "</resource>\n"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "(1233): Invalid attribute 'invalid' in the configuration: 'ms-graph'.");
    test->nodes = string_to_xml_node(config, &(test->xml));
    assert_int_equal(wm_ms_graph_read(&(test->xml), test->nodes, test->module), OS_CFGERR);
}

// Main program tests
void test_normal_config(void **state) {
    const char* config =
        "<enabled>yes</enabled>\n"
        "<only_future_events>yes</only_future_events>\n"
        "<curl_max_size>1M</curl_max_size>\n"
        "<run_on_start>yes</run_on_start>\n"
        "<interval>5m</interval>\n"
        "<version>v1.0</version>\n"
        "<api_auth>\n"
        "  <client_id>example_string</client_id>\n"
        "  <tenant_id>example_string</tenant_id>\n"
        "  <secret_value>example_string</secret_value>\n"
        "  <api_type>global</api_type>\n"
        "</api_auth>\n"
        "<resource>\n"
        "  <name>security</name>\n"
        "  <relationship>alerts_v2</relationship>\n"
        "  <relationship>incidents</relationship>\n"
        "</resource>\n"
        "<resource>\n"
        "  <name>identityProtection</name>\n"
        "  <relationship>riskyUsers</relationship>\n"
        "</resource>\n"
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(config, &(test->xml));
    assert_int_equal(wm_ms_graph_read(&(test->xml), test->nodes, test->module), OS_SUCCESS);
    wm_ms_graph *module_data = (wm_ms_graph*)test->module->data;
    assert_int_equal(module_data->enabled, 1);
    assert_int_equal(module_data->only_future_events, 1);
    assert_int_equal(module_data->curl_max_size, OS_SIZE_1048576);
    assert_int_equal(module_data->run_on_start, 1);
    assert_string_equal(module_data->version, "v1.0");
    assert_string_equal(module_data->auth_config[0]->tenant_id, "example_string");
    assert_string_equal(module_data->auth_config[0]->client_id, "example_string");
    assert_string_equal(module_data->auth_config[0]->secret_value, "example_string");
    assert_int_equal(module_data->num_resources, 2);
    assert_string_equal(module_data->resources[0].name, "security");
    assert_int_equal(module_data->resources[0].num_relationships, 2);
    assert_string_equal(module_data->resources[0].relationships[0], "alerts_v2");
    assert_string_equal(module_data->resources[0].relationships[1], "incidents");
    assert_string_equal(module_data->resources[1].name, "identityProtection");
    assert_int_equal(module_data->resources[1].num_relationships, 1);
    assert_string_equal(module_data->resources[1].relationships[0], "riskyUsers");
}

void test_normal_config_api_type_gcc(void **state) {
    const char* config =
        "<enabled>yes</enabled>\n"
        "<only_future_events>yes</only_future_events>\n"
        "<curl_max_size>1M</curl_max_size>\n"
        "<run_on_start>yes</run_on_start>\n"
        "<interval>5m</interval>\n"
        "<version>v1.0</version>\n"
        "<api_auth>\n"
        "  <client_id>example_string</client_id>\n"
        "  <tenant_id>example_string</tenant_id>\n"
        "  <secret_value>example_string</secret_value>\n"
        "  <api_type>gcc-high</api_type>\n"
        "</api_auth>\n"
        "<resource>\n"
        "  <name>security</name>\n"
        "  <relationship>alerts_v2</relationship>\n"
        "  <relationship>incidents</relationship>\n"
        "</resource>\n"
        "<resource>\n"
        "  <name>identityProtection</name>\n"
        "  <relationship>riskyUsers</relationship>\n"
        "</resource>\n"
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(config, &(test->xml));
    assert_int_equal(wm_ms_graph_read(&(test->xml), test->nodes, test->module), OS_SUCCESS);
    wm_ms_graph *module_data = (wm_ms_graph*)test->module->data;
    assert_int_equal(module_data->enabled, 1);
    assert_int_equal(module_data->only_future_events, 1);
    assert_int_equal(module_data->curl_max_size, OS_SIZE_1048576);
    assert_int_equal(module_data->run_on_start, 1);
    assert_string_equal(module_data->version, "v1.0");
    assert_string_equal(module_data->auth_config[0]->tenant_id, "example_string");
    assert_string_equal(module_data->auth_config[0]->client_id, "example_string");
    assert_string_equal(module_data->auth_config[0]->secret_value, "example_string");
    assert_string_equal(module_data->auth_config[0]->login_fqdn, "login.microsoftonline.us");
    assert_string_equal(module_data->auth_config[0]->query_fqdn, "graph.microsoft.us");
    assert_int_equal(module_data->num_resources, 2);
    assert_string_equal(module_data->resources[0].name, "security");
    assert_int_equal(module_data->resources[0].num_relationships, 2);
    assert_string_equal(module_data->resources[0].relationships[0], "alerts_v2");
    assert_string_equal(module_data->resources[0].relationships[1], "incidents");
    assert_string_equal(module_data->resources[1].name, "identityProtection");
    assert_int_equal(module_data->resources[1].num_relationships, 1);
    assert_string_equal(module_data->resources[1].relationships[0], "riskyUsers");
}

void test_normal_config_api_type_dod(void **state) {
    const char* config =
        "<enabled>yes</enabled>\n"
        "<only_future_events>yes</only_future_events>\n"
        "<curl_max_size>1M</curl_max_size>\n"
        "<run_on_start>yes</run_on_start>\n"
        "<interval>5m</interval>\n"
        "<version>v1.0</version>\n"
        "<api_auth>\n"
        "  <client_id>example_string</client_id>\n"
        "  <tenant_id>example_string</tenant_id>\n"
        "  <secret_value>example_string</secret_value>\n"
        "  <api_type>dod</api_type>\n"
        "</api_auth>\n"
        "<resource>\n"
        "  <name>security</name>\n"
        "  <relationship>alerts_v2</relationship>\n"
        "  <relationship>incidents</relationship>\n"
        "</resource>\n"
        "<resource>\n"
        "  <name>identityProtection</name>\n"
        "  <relationship>riskyUsers</relationship>\n"
        "</resource>\n"
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(config, &(test->xml));
    assert_int_equal(wm_ms_graph_read(&(test->xml), test->nodes, test->module), OS_SUCCESS);
    wm_ms_graph *module_data = (wm_ms_graph*)test->module->data;
    assert_int_equal(module_data->enabled, 1);
    assert_int_equal(module_data->only_future_events, 1);
    assert_int_equal(module_data->curl_max_size, OS_SIZE_1048576);
    assert_int_equal(module_data->run_on_start, 1);
    assert_string_equal(module_data->version, "v1.0");
    assert_string_equal(module_data->auth_config[0]->tenant_id, "example_string");
    assert_string_equal(module_data->auth_config[0]->client_id, "example_string");
    assert_string_equal(module_data->auth_config[0]->secret_value, "example_string");
    assert_string_equal(module_data->auth_config[0]->login_fqdn, "login.microsoftonline.us");
    assert_string_equal(module_data->auth_config[0]->query_fqdn, "dod-graph.microsoft.us");
    assert_int_equal(module_data->num_resources, 2);
    assert_string_equal(module_data->resources[0].name, "security");
    assert_int_equal(module_data->resources[0].num_relationships, 2);
    assert_string_equal(module_data->resources[0].relationships[0], "alerts_v2");
    assert_string_equal(module_data->resources[0].relationships[1], "incidents");
    assert_string_equal(module_data->resources[1].name, "identityProtection");
    assert_int_equal(module_data->resources[1].num_relationships, 1);
    assert_string_equal(module_data->resources[1].relationships[0], "riskyUsers");
}

void test_cleanup() {
    expect_string(__wrap__mtinfo, tag, WM_MS_GRAPH_LOGTAG);
    expect_string(__wrap__mtinfo, formatted_msg, "Module shutdown.");
    wm_ms_graph_cleanup();
}

void test_setup_complete(void **state) {
    wm_ms_graph* module_data = (wm_ms_graph *)*state;

    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config);
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config[0]);

    module_data->enabled = true;
    module_data->only_future_events = false;
    module_data->curl_max_size = 1024L;
    module_data->page_size = 100;
    module_data->time_delay = 10;
    module_data->run_on_start = true;
    os_strdup("v1.0", module_data->version);
    os_strdup("example_string", module_data->auth_config[0]->client_id);
    os_strdup("example_string", module_data->auth_config[0]->tenant_id);
    os_strdup("example_string", module_data->auth_config[0]->secret_value);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_LOGIN_FQDN, module_data->auth_config[0]->login_fqdn);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_QUERY_FQDN, module_data->auth_config[0]->query_fqdn);
    os_malloc(sizeof(wm_ms_graph_resource) * 2, module_data->resources);
    os_strdup("security", module_data->resources[0].name);
    os_strdup("identityProtection", module_data->resources[1].name);
    module_data->num_resources = 2;
    os_malloc(sizeof(char*) * 2, module_data->resources[0].relationships);
    os_strdup("alerts_v2", module_data->resources[0].relationships[0]);
    os_strdup("incidents", module_data->resources[0].relationships[1]);
    module_data->resources[0].num_relationships = 2;
    os_malloc(sizeof(char*) * 2, module_data->resources[1].relationships);
    os_strdup("alerts_v1", module_data->resources[1].relationships[0]);
    os_strdup("incidents1", module_data->resources[1].relationships[1]);
    module_data->resources[1].num_relationships = 2;

    expect_string(__wrap_wm_state_io, tag, "ms-graph");
    expect_value(__wrap_wm_state_io, op, WM_IO_READ);
    expect_value(__wrap_wm_state_io, state, &module_data->state);
    expect_value(__wrap_wm_state_io, size, sizeof(module_data->state));
    will_return(__wrap_wm_state_io, -1);

    expect_string(__wrap_StartMQ, path, DEFAULTQUEUE);
    expect_value(__wrap_StartMQ, type, WRITE);
    will_return(__wrap_StartMQ, -1);

    expect_string(__wrap__mterror, tag, WM_MS_GRAPH_LOGTAG);
    expect_string(__wrap__mterror, formatted_msg, "Unable to connect to Message Queue. Exiting...");

    wm_ms_graph_setup(module_data);
}

void test_main_token(void **state) {
    current_time = 1;
    unsigned int run_on_start = 1;
    wm_ms_graph* module_data = (wm_ms_graph *)*state;
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config);
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config[0]);
    module_data->enabled = true;
    module_data->only_future_events = false;
    module_data->curl_max_size = 1024L;
    module_data->page_size = 100;
    module_data->time_delay = 10;
    module_data->run_on_start = true;
    os_strdup("v1.0", module_data->version);
    os_strdup("example_client", module_data->auth_config[0]->client_id);
    os_strdup("example_tenant", module_data->auth_config[0]->tenant_id);
    os_strdup("example_secret", module_data->auth_config[0]->secret_value);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_LOGIN_FQDN, module_data->auth_config[0]->login_fqdn);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_QUERY_FQDN, module_data->auth_config[0]->query_fqdn);
    os_malloc(sizeof(wm_ms_graph_resource), module_data->resources);
    os_strdup("security", module_data->resources[0].name);
    module_data->num_resources = 1;
    os_malloc(sizeof(char*), module_data->resources[0].relationships);
    os_strdup("alerts_v2", module_data->resources[0].relationships[0]);
    module_data->resources[0].num_relationships = 1;
    size_t max_size = OS_SIZE_8192;
    curl_response* response;

    os_calloc(1, sizeof(curl_response), response);
    response->status_code = 200;
    response->max_size_reached = false;
    os_strdup("{\"access_token\":\"token_value\",\"expires_in\":-1}", response->body);
    os_strdup("test", response->header);

    will_return(__wrap_FOREVER, 1);

    expect_string(__wrap_wm_state_io, tag, "ms-graph");
    expect_value(__wrap_wm_state_io, op, WM_IO_READ);
    expect_value(__wrap_wm_state_io, state, &module_data->state);
    expect_value(__wrap_wm_state_io, size, sizeof(module_data->state));
    will_return(__wrap_wm_state_io, -1);

    expect_string(__wrap_StartMQ, path, DEFAULTQUEUE);
    expect_value(__wrap_StartMQ, type, WRITE);
    will_return(__wrap_StartMQ, 1);

    expect_string(__wrap__mtinfo, tag, WM_MS_GRAPH_LOGTAG);
    expect_string(__wrap__mtinfo, formatted_msg, "Started module.");

    expect_value(__wrap_sched_scan_get_time_until_next_scan, config, &module_data->scan_config);
    expect_string(__wrap_sched_scan_get_time_until_next_scan, MODULE_TAG, WM_MS_GRAPH_LOGTAG);
    expect_value(__wrap_sched_scan_get_time_until_next_scan, run_on_start, 1);
    will_return(__wrap_sched_scan_get_time_until_next_scan, 1);

    char* test_date = strdup("2023/08/07 12:00:00");
    expect_value(__wrap_w_get_timestamp, time, 0);
    will_return(__wrap_w_get_timestamp, test_date);

    expect_string(__wrap__mtdebug1, tag, WM_MS_GRAPH_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Waiting until: 2023/08/07 12:00:00");

    expect_string(__wrap__mtinfo, tag, WM_MS_GRAPH_LOGTAG);
    expect_string(__wrap__mtinfo, formatted_msg, "Obtaining access token.");

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mtdebug1, formatted_msg, "Microsoft Graph API Access Token URL: 'https://login.microsoftonline.com/example_tenant/oauth2/v2.0/token'");

    expect_any(__wrap_wurl_http_request, method);
    expect_any(__wrap_wurl_http_request, header);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_MS_GRAPH_DEFAULT_TIMEOUT);
    expect_any(__wrap_wurl_http_request, ssl_verify);
    will_return(__wrap_wurl_http_request, response);

    will_return(__wrap_FOREVER, 0);

    wm_ms_graph_main(module_data);
}

void test_main_relationships(void **state) {
    wm_ms_graph* module_data = (wm_ms_graph *)*state;
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config);
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config[0]);
    module_data->enabled = true;
    module_data->only_future_events = false;
    module_data->curl_max_size = 1024L;
    module_data->page_size = 100;
    module_data->time_delay = 10;
    module_data->run_on_start = true;
    module_data->scan_config.interval = 60;
    os_strdup("v1.0", module_data->version);
    os_strdup("example_client", module_data->auth_config[0]->client_id);
    os_strdup("example_tenant", module_data->auth_config[0]->tenant_id);
    os_strdup("example_secret", module_data->auth_config[0]->secret_value);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_LOGIN_FQDN, module_data->auth_config[0]->login_fqdn);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_QUERY_FQDN, module_data->auth_config[0]->query_fqdn);
    os_malloc(sizeof(wm_ms_graph_resource), module_data->resources);
    os_strdup("security", module_data->resources[0].name);
    module_data->num_resources = 1;
    os_malloc(sizeof(char*), module_data->resources[0].relationships);
    os_strdup("alerts_v2", module_data->resources[0].relationships[0]);
    module_data->resources[0].num_relationships = 1;
    size_t max_size = OS_SIZE_8192;
    bool initial = true;

    os_strdup("token", module_data->auth_config[0]->access_token);
    module_data->auth_config[0]->token_expiration_time = 276447231;

    will_return(__wrap_FOREVER, 1);

#ifdef TEST_WINAGENT
    will_return_count(__wrap_os_random, 12345, 2);
#else
    will_return(__wrap_os_random, 12345);
#endif

    expect_string(__wrap_wm_state_io, tag, "ms-graph");
    expect_value(__wrap_wm_state_io, op, WM_IO_READ);
    expect_value(__wrap_wm_state_io, state, &module_data->state);
    expect_value(__wrap_wm_state_io, size, sizeof(module_data->state));
    will_return(__wrap_wm_state_io, -1);

    expect_string(__wrap_StartMQ, path, DEFAULTQUEUE);
    expect_value(__wrap_StartMQ, type, WRITE);
    will_return(__wrap_StartMQ, 1);

    expect_value(__wrap_sched_scan_get_time_until_next_scan, config, &module_data->scan_config);
    expect_string(__wrap_sched_scan_get_time_until_next_scan, MODULE_TAG, WM_MS_GRAPH_LOGTAG);
    expect_value(__wrap_sched_scan_get_time_until_next_scan, run_on_start, 1);
    will_return(__wrap_sched_scan_get_time_until_next_scan, 0);

    expect_string(__wrap__mtinfo, tag, WM_MS_GRAPH_LOGTAG);
    expect_string(__wrap__mtinfo, formatted_msg, "Started module.");

    expect_string(__wrap__mtinfo, tag, WM_MS_GRAPH_LOGTAG);
    expect_string(__wrap__mtinfo, formatted_msg, "Scanning tenant 'example_tenant'");

    expect_string(__wrap_wm_state_io, tag, "ms-graph-example_tenant-security-alerts_v2");
    expect_value(__wrap_wm_state_io, op, WM_IO_READ);
    expect_any(__wrap_wm_state_io, state);
    expect_any(__wrap_wm_state_io, size);
    will_return(__wrap_wm_state_io, -1);

    will_return(__wrap_isDebug, 1);

#ifndef WIN32
    will_return(__wrap_gmtime_r, 1);
#endif
    will_return(__wrap_strftime,"2023-02-08T12:24:56Z");
    will_return(__wrap_strftime, 20);

    expect_string(__wrap_wm_state_io, tag, "ms-graph-example_tenant-security-alerts_v2");
    expect_value(__wrap_wm_state_io, op, WM_IO_WRITE);
    expect_any(__wrap_wm_state_io, state);
    expect_any(__wrap_wm_state_io, size);
    will_return(__wrap_wm_state_io, 1);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mtdebug1, formatted_msg, "Bookmark updated to '2023-02-08T12:24:56Z' for tenant 'example_tenant' resource 'security' and relationship 'alerts_v2', waiting '60' seconds to run first scan.");

    will_return(__wrap_FOREVER, 0);

    wm_ms_graph_main(module_data);
}

void test_disabled(void **state) {
    wm_ms_graph* module_data = (wm_ms_graph *)*state;
    module_data->enabled = false;

    expect_string(__wrap__mtinfo, tag, WM_MS_GRAPH_LOGTAG);
    expect_string(__wrap__mtinfo, formatted_msg, "Module disabled. Exiting...");

    wm_ms_graph_main(module_data);
}

void test_no_resources(void **state) {
    wm_ms_graph* module_data = (wm_ms_graph *)*state;
    module_data->enabled = true;
    module_data->num_resources = 0;

    expect_string(__wrap__mterror, tag, WM_MS_GRAPH_LOGTAG);
    expect_string(__wrap__mterror, formatted_msg, "Invalid module configuration (Missing API info, resources, relationships). Exiting...");

    wm_ms_graph_main(module_data);
}

void test_no_relationships(void **state) {
    wm_ms_graph* module_data = (wm_ms_graph *)*state;
    module_data->enabled = true;
    os_malloc(sizeof(wm_ms_graph_resource), module_data->resources);
    module_data->resources[0].num_relationships = 0;
    module_data->num_resources = 1;

    expect_string(__wrap__mterror, tag, WM_MS_GRAPH_LOGTAG);
    expect_string(__wrap__mterror, formatted_msg, "Invalid module configuration (Missing API info, resources, relationships). Exiting...");

    wm_ms_graph_main(module_data);

    os_free(module_data->resources);
    module_data->num_resources = 0;
}

void test_dump(void **state) {
    /*
    <enabled>yes</enabled>
    <only_future_events>no</only_future_events>
    <curl_max_size>1M</curl_max_size>
    <page_size>100</page_size>
    <time_delay>10</time_delay>
    <run_on_start>yes</run_on_start>
    <version>v1.0</version>
    <api_auth>
      <client_id>example_string</client_id>
      <tenant_id>example_string</tenant_id>
      <secret_value>example_string</secret_value>
      <api_type>global</api_type>
    </api_auth>
    <resource>
      <name>security</name>
      <relationship>alerts_v2</relationship>
    </resource>
    */
    wm_ms_graph* module_data = (wm_ms_graph *)*state;
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config);
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config[0]);
    module_data->enabled = true;
    module_data->only_future_events = false;
    module_data->curl_max_size = 1024L;
    module_data->page_size = 100;
    module_data->time_delay = 10;
    module_data->run_on_start = true;
    os_strdup("v1.0", module_data->version);
    os_strdup("example_string", module_data->auth_config[0]->client_id);
    os_strdup("example_string", module_data->auth_config[0]->tenant_id);
    os_strdup("example_string", module_data->auth_config[0]->secret_value);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_LOGIN_FQDN, module_data->auth_config[0]->login_fqdn);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_QUERY_FQDN, module_data->auth_config[0]->query_fqdn);
    os_malloc(sizeof(wm_ms_graph_resource), module_data->resources);
    os_strdup("security", module_data->resources[0].name);
    module_data->num_resources = 1;
    os_malloc(sizeof(char*), module_data->resources[0].relationships);
    os_strdup("alerts_v2", module_data->resources[0].relationships[0]);
    module_data->resources[0].num_relationships = 1;

    cJSON* dump = wm_ms_graph_dump(module_data);
    char* dump_text = cJSON_PrintUnformatted(dump);

    assert_string_equal(dump_text, "{\"ms_graph\":{\"enabled\":\"yes\",\"only_future_events\":\"no\",\"curl_max_size\":1024,\"page_size\":100,\"time_delay\":10,\"run_on_start\":\"yes\",\"version\":\"v1.0\",\"wday\":\"sunday\",\"api_auth\":{\"client_id\":\"example_string\",\"tenant_id\":\"example_string\",\"secret_value\":\"example_string\",\"api_type\":\"global\",\"name\":\"security\"},\"resources\":[{\"relationship\":\"alerts_v2\"}]}}");

    cJSON_Delete(dump);
    os_free(dump_text);
}

void test_dump_gcc_configuration(void **state) {
    /*
    <enabled>no</enabled>
    <only_future_events>yes</only_future_events>
    <curl_max_size>1M</curl_max_size>
    <page_size>100</page_size>
    <time_delay>10</time_delay>
    <run_on_start>no</run_on_start>
    <version>v1.0</version>
    <api_auth>
      <client_id>example_string</client_id>
      <tenant_id>example_string</tenant_id>
      <secret_value>example_string</secret_value>
      <api_type>gcc-high</api_type>
    </api_auth>
    <resource>
    </resource>
    */
    wm_ms_graph* module_data = (wm_ms_graph *)*state;
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config);
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config[0]);
    module_data->enabled = false;
    module_data->only_future_events = true;
    module_data->curl_max_size = 1024L;
    module_data->page_size = 100;
    module_data->time_delay = 10;
    module_data->run_on_start = false;
    os_strdup("v1.0", module_data->version);
    os_strdup("example_string", module_data->auth_config[0]->client_id);
    os_strdup("example_string", module_data->auth_config[0]->tenant_id);
    os_strdup("example_string", module_data->auth_config[0]->secret_value);
    os_strdup(WM_MS_GRAPH_GCC_HIGH_API_LOGIN_FQDN, module_data->auth_config[0]->login_fqdn);
    os_strdup(WM_MS_GRAPH_GCC_HIGH_API_QUERY_FQDN, module_data->auth_config[0]->query_fqdn);
    os_malloc(sizeof(wm_ms_graph_resource), module_data->resources);
    module_data->resources[0].name = NULL;
    module_data->num_resources = 1;

    cJSON* dump = wm_ms_graph_dump(module_data);
    char* dump_text = cJSON_PrintUnformatted(dump);

    assert_string_equal(dump_text, "{\"ms_graph\":{\"enabled\":\"no\",\"only_future_events\":\"yes\",\"curl_max_size\":1024,\"page_size\":100,\"time_delay\":10,\"run_on_start\":\"no\",\"version\":\"v1.0\",\"wday\":\"sunday\",\"api_auth\":{\"client_id\":\"example_string\",\"tenant_id\":\"example_string\",\"secret_value\":\"example_string\",\"api_type\":\"gcc-high\"}}}");

    cJSON_Delete(dump);
    os_free(dump_text);
    os_free(module_data->resources[0].name);
    os_free(module_data->resources);
    module_data->num_resources = 0;
}

void test_dump_dod_configuration(void **state) {
    /*
    <enabled>no</enabled>
    <only_future_events>yes</only_future_events>
    <curl_max_size>1M</curl_max_size>
    <page_size>100</page_size>
    <time_delay>10</time_delay>
    <run_on_start>no</run_on_start>
    <version>v1.0</version>
    <api_auth>
      <client_id>example_string</client_id>
      <tenant_id>example_string</tenant_id>
      <secret_value>example_string</secret_value>
      <api_type>dod</api_type>
    </api_auth>
    <resource>
    </resource>
    */
    wm_ms_graph* module_data = (wm_ms_graph *)*state;
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config);
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config[0]);
    module_data->enabled = false;
    module_data->only_future_events = true;
    module_data->curl_max_size = 1024L;
    module_data->page_size = 100;
    module_data->time_delay = 10;
    module_data->run_on_start = false;
    os_strdup("v1.0", module_data->version);
    os_strdup("example_string", module_data->auth_config[0]->client_id);
    os_strdup("example_string", module_data->auth_config[0]->tenant_id);
    os_strdup("example_string", module_data->auth_config[0]->secret_value);
    os_strdup(WM_MS_GRAPH_DOD_API_LOGIN_FQDN, module_data->auth_config[0]->login_fqdn);
    os_strdup(WM_MS_GRAPH_DOD_API_QUERY_FQDN, module_data->auth_config[0]->query_fqdn);

    cJSON* dump = wm_ms_graph_dump(module_data);
    char* dump_text = cJSON_PrintUnformatted(dump);

    assert_string_equal(dump_text, "{\"ms_graph\":{\"enabled\":\"no\",\"only_future_events\":\"yes\",\"curl_max_size\":1024,\"page_size\":100,\"time_delay\":10,\"run_on_start\":\"no\",\"version\":\"v1.0\",\"wday\":\"sunday\",\"api_auth\":{\"client_id\":\"example_string\",\"tenant_id\":\"example_string\",\"secret_value\":\"example_string\",\"api_type\":\"dod\"}}}");

    cJSON_Delete(dump);
    os_free(dump_text);
}

void test_wm_ms_graph_get_access_token_no_response(void **state) {
    /*
    <enabled>yes</enabled>
    <only_future_events>no</only_future_events>
    <curl_max_size>1M</curl_max_size>
    <page_size>100</page_size>
    <time_delay>10</time_delay>
    <run_on_start>yes</run_on_start>
    <version>v1.0</version>
    <api_auth>
      <client_id>example_string</client_id>
      <tenant_id>example_string</tenant_id>
      <secret_value>example_string</secret_value>
      <api_type>global</api_type>
    </api_auth>
    <resource>
      <name>security</name>
      <relationship>alerts_v2</relationship>
    </resource>
    */
    wm_ms_graph* module_data = (wm_ms_graph *)*state;
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config);
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config[0]);
    module_data->enabled = true;
    module_data->only_future_events = false;
    module_data->curl_max_size = 1024L;
    module_data->page_size = 100;
    module_data->time_delay = 10;
    module_data->run_on_start = true;
    os_strdup("v1.0", module_data->version);
    os_strdup("example_client", module_data->auth_config[0]->client_id);
    os_strdup("example_tenant", module_data->auth_config[0]->tenant_id);
    os_strdup("example_secret", module_data->auth_config[0]->secret_value);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_LOGIN_FQDN, module_data->auth_config[0]->login_fqdn);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_QUERY_FQDN, module_data->auth_config[0]->query_fqdn);
    os_malloc(sizeof(wm_ms_graph_resource), module_data->resources);
    os_strdup("security", module_data->resources[0].name);
    module_data->num_resources = 1;
    os_malloc(sizeof(char*), module_data->resources[0].relationships);
    os_strdup("alerts_v2", module_data->resources[0].relationships[0]);
    module_data->resources[0].num_relationships = 1;
    size_t max_size = OS_SIZE_8192;

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mtdebug1, formatted_msg, "Microsoft Graph API Access Token URL: 'https://login.microsoftonline.com/example_tenant/oauth2/v2.0/token'");

    expect_any(__wrap_wurl_http_request, method);
    expect_any(__wrap_wurl_http_request, header);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_MS_GRAPH_DEFAULT_TIMEOUT);
    expect_any(__wrap_wurl_http_request, ssl_verify);
    will_return(__wrap_wurl_http_request, NULL);

    expect_string(__wrap__mtwarn, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mtwarn, formatted_msg, "No response received when attempting to obtain access token.");

    wm_ms_graph_get_access_token(module_data->auth_config[0], max_size);

    assert_null(module_data->auth_config[0]->access_token);
}

void test_wm_ms_graph_get_access_token_unsuccessful_status_code(void **state) {
    /*
    <enabled>yes</enabled>
    <only_future_events>no</only_future_events>
    <curl_max_size>1M</curl_max_size>
    <page_size>100</page_size>
    <time_delay>10</time_delay>
    <run_on_start>yes</run_on_start>
    <version>v1.0</version>
    <api_auth>
      <client_id>example_string</client_id>
      <tenant_id>example_string</tenant_id>
      <secret_value>example_string</secret_value>
      <api_type>global</api_type>
    </api_auth>
    <resource>
      <name>security</name>
      <relationship>alerts_v2</relationship>
    </resource>
    */
    wm_ms_graph* module_data = (wm_ms_graph *)*state;
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config);
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config[0]);
    module_data->enabled = true;
    module_data->only_future_events = false;
    module_data->curl_max_size = 1024L;
    module_data->page_size = 100;
    module_data->time_delay = 10;
    module_data->run_on_start = true;
    os_strdup("v1.0", module_data->version);
    os_strdup("example_client", module_data->auth_config[0]->client_id);
    os_strdup("example_tenant", module_data->auth_config[0]->tenant_id);
    os_strdup("example_secret", module_data->auth_config[0]->secret_value);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_LOGIN_FQDN, module_data->auth_config[0]->login_fqdn);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_QUERY_FQDN, module_data->auth_config[0]->query_fqdn);
    os_malloc(sizeof(wm_ms_graph_resource), module_data->resources);
    os_strdup("security", module_data->resources[0].name);
    module_data->num_resources = 1;
    os_malloc(sizeof(char*), module_data->resources[0].relationships);
    os_strdup("alerts_v2", module_data->resources[0].relationships[0]);
    module_data->resources[0].num_relationships = 1;
    size_t max_size = OS_SIZE_8192;
    curl_response* response;

    os_calloc(1, sizeof(curl_response), response);
    response->status_code = 400;
    os_strdup("{\"error\":\"bad_request\"}", response->body);
    os_strdup("test", response->header);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mtdebug1, formatted_msg, "Microsoft Graph API Access Token URL: 'https://login.microsoftonline.com/example_tenant/oauth2/v2.0/token'");

    expect_any(__wrap_wurl_http_request, method);
    expect_any(__wrap_wurl_http_request, header);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_MS_GRAPH_DEFAULT_TIMEOUT);
    expect_any(__wrap_wurl_http_request, ssl_verify);
    will_return(__wrap_wurl_http_request, response);

    expect_string(__wrap__mtwarn, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mtwarn, formatted_msg, "Received unsuccessful status code when attempting to obtain access token: Status code was '400' & response was '{\"error\":\"bad_request\"}'");

    wm_ms_graph_get_access_token(module_data->auth_config[0], max_size);

    assert_null(module_data->auth_config[0]->access_token);
}

void test_wm_ms_graph_get_access_token_curl_max_size(void **state) {
    /*
    <enabled>yes</enabled>
    <only_future_events>no</only_future_events>
    <curl_max_size>1M</curl_max_size>
    <page_size>100</page_size>
    <time_delay>10</time_delay>
    <run_on_start>yes</run_on_start>
    <version>v1.0</version>
    <api_auth>
      <client_id>example_string</client_id>
      <tenant_id>example_string</tenant_id>
      <secret_value>example_string</secret_value>
      <api_type>global</api_type>
    </api_auth>
    <resource>
      <name>security</name>
      <relationship>alerts_v2</relationship>
    </resource>
    */
    wm_ms_graph* module_data = (wm_ms_graph *)*state;
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config);
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config[0]);
    module_data->enabled = true;
    module_data->only_future_events = false;
    module_data->curl_max_size = 1024L;
    module_data->page_size = 100;
    module_data->time_delay = 10;
    module_data->run_on_start = true;
    os_strdup("v1.0", module_data->version);
    os_strdup("example_client", module_data->auth_config[0]->client_id);
    os_strdup("example_tenant", module_data->auth_config[0]->tenant_id);
    os_strdup("example_secret", module_data->auth_config[0]->secret_value);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_LOGIN_FQDN, module_data->auth_config[0]->login_fqdn);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_QUERY_FQDN, module_data->auth_config[0]->query_fqdn);
    os_malloc(sizeof(wm_ms_graph_resource), module_data->resources);
    os_strdup("security", module_data->resources[0].name);
    module_data->num_resources = 1;
    os_malloc(sizeof(char*), module_data->resources[0].relationships);
    os_strdup("alerts_v2", module_data->resources[0].relationships[0]);
    module_data->resources[0].num_relationships = 1;
    size_t max_size = OS_SIZE_8192;
    curl_response* response;

    os_calloc(1, sizeof(curl_response), response);
    response->status_code = 200;
    response->max_size_reached = true;
    os_strdup("{\"error\":\"bad_request\"}", response->body);
    os_strdup("test", response->header);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mtdebug1, formatted_msg, "Microsoft Graph API Access Token URL: 'https://login.microsoftonline.com/example_tenant/oauth2/v2.0/token'");

    expect_any(__wrap_wurl_http_request, method);
    expect_any(__wrap_wurl_http_request, header);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_MS_GRAPH_DEFAULT_TIMEOUT);
    expect_any(__wrap_wurl_http_request, ssl_verify);
    will_return(__wrap_wurl_http_request, response);
    expect_string(__wrap__mtwarn, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mtwarn, formatted_msg, "Reached maximum CURL size when attempting to obtain access token. Consider increasing the value of 'curl_max_size'.");

    wm_ms_graph_get_access_token(module_data->auth_config[0], max_size);

    assert_null(module_data->auth_config[0]->access_token);
}

void test_wm_ms_graph_get_access_token_parse_json_fail(void **state) {
    /*
    <enabled>yes</enabled>
    <only_future_events>no</only_future_events>
    <curl_max_size>1M</curl_max_size>
    <page_size>100</page_size>
    <time_delay>10</time_delay>
    <run_on_start>yes</run_on_start>
    <version>v1.0</version>
    <api_auth>
      <client_id>example_string</client_id>
      <tenant_id>example_string</tenant_id>
      <secret_value>example_string</secret_value>
      <api_type>global</api_type>
    </api_auth>
    <resource>
      <name>security</name>
      <relationship>alerts_v2</relationship>
    </resource>
    */
    wm_ms_graph* module_data = (wm_ms_graph *)*state;
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config);
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config[0]);
    module_data->enabled = true;
    module_data->only_future_events = false;
    module_data->curl_max_size = 1024L;
    module_data->page_size = 100;
    module_data->time_delay = 10;
    module_data->run_on_start = true;
    os_strdup("v1.0", module_data->version);
    os_strdup("example_client", module_data->auth_config[0]->client_id);
    os_strdup("example_tenant", module_data->auth_config[0]->tenant_id);
    os_strdup("example_secret", module_data->auth_config[0]->secret_value);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_LOGIN_FQDN, module_data->auth_config[0]->login_fqdn);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_QUERY_FQDN, module_data->auth_config[0]->query_fqdn);
    os_malloc(sizeof(wm_ms_graph_resource), module_data->resources);
    os_strdup("security", module_data->resources[0].name);
    module_data->num_resources = 1;
    os_malloc(sizeof(char*), module_data->resources[0].relationships);
    os_strdup("alerts_v2", module_data->resources[0].relationships[0]);
    module_data->resources[0].num_relationships = 1;
    size_t max_size = OS_SIZE_8192;
    curl_response* response;

    os_calloc(1, sizeof(curl_response), response);
    response->status_code = 200;
    response->max_size_reached = false;
    os_strdup("no json", response->body);
    os_strdup("test", response->header);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mtdebug1, formatted_msg, "Microsoft Graph API Access Token URL: 'https://login.microsoftonline.com/example_tenant/oauth2/v2.0/token'");

    expect_any(__wrap_wurl_http_request, method);
    expect_any(__wrap_wurl_http_request, header);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_MS_GRAPH_DEFAULT_TIMEOUT);
    expect_any(__wrap_wurl_http_request, ssl_verify);
    will_return(__wrap_wurl_http_request, response);
    expect_string(__wrap__mtwarn, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mtwarn, formatted_msg, "Failed to parse access token JSON body.");

    wm_ms_graph_get_access_token(module_data->auth_config[0], max_size);

    assert_null(module_data->auth_config[0]->access_token);
}

void test_wm_ms_graph_get_access_token_success(void **state) {
    /*
    <enabled>yes</enabled>
    <only_future_events>no</only_future_events>
    <curl_max_size>1M</curl_max_size>
    <page_size>100</page_size>
    <time_delay>10</time_delay>
    <run_on_start>yes</run_on_start>
    <version>v1.0</version>
    <api_auth>
      <client_id>example_string</client_id>
      <tenant_id>example_string</tenant_id>
      <secret_value>example_string</secret_value>
      <api_type>global</api_type>
    </api_auth>
    <resource>
      <name>security</name>
      <relationship>alerts_v2</relationship>
    </resource>
    */
    wm_ms_graph* module_data = (wm_ms_graph *)*state;
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config);
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config[0]);
    module_data->enabled = true;
    module_data->only_future_events = false;
    module_data->curl_max_size = 1024L;
    module_data->page_size = 100;
    module_data->time_delay = 10;
    module_data->run_on_start = true;
    os_strdup("v1.0", module_data->version);
    os_strdup("example_client", module_data->auth_config[0]->client_id);
    os_strdup("example_tenant", module_data->auth_config[0]->tenant_id);
    os_strdup("example_secret", module_data->auth_config[0]->secret_value);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_LOGIN_FQDN, module_data->auth_config[0]->login_fqdn);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_QUERY_FQDN, module_data->auth_config[0]->query_fqdn);
    os_malloc(sizeof(wm_ms_graph_resource), module_data->resources);
    os_strdup("security", module_data->resources[0].name);
    module_data->num_resources = 1;
    os_malloc(sizeof(char*), module_data->resources[0].relationships);
    os_strdup("alerts_v2", module_data->resources[0].relationships[0]);
    module_data->resources[0].num_relationships = 1;
    size_t max_size = OS_SIZE_8192;
    curl_response* response;
    current_time = 100;

    os_calloc(1, sizeof(curl_response), response);
    response->status_code = 200;
    response->max_size_reached = false;
    os_strdup("{\"access_token\":\"token_value\",\"expires_in\":123}", response->body);
    os_strdup("test", response->header);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mtdebug1, formatted_msg, "Microsoft Graph API Access Token URL: 'https://login.microsoftonline.com/example_tenant/oauth2/v2.0/token'");

    expect_any(__wrap_wurl_http_request, method);
    expect_any(__wrap_wurl_http_request, header);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_MS_GRAPH_DEFAULT_TIMEOUT);
    expect_any(__wrap_wurl_http_request, ssl_verify);
    will_return(__wrap_wurl_http_request, response);

    wm_ms_graph_get_access_token(module_data->auth_config[0], max_size);

    assert_string_equal(module_data->auth_config[0]->access_token, "token_value");
#ifdef WIN32
    assert_int_equal(module_data->auth_config[0]->token_expiration_time, 123);
#else
    assert_int_equal(module_data->auth_config[0]->token_expiration_time, 223);
#endif
}

void test_wm_ms_graph_get_access_token_no_access_token(void **state) {
    /*
    <enabled>yes</enabled>
    <only_future_events>no</only_future_events>
    <curl_max_size>1M</curl_max_size>
    <page_size>100</page_size>
    <time_delay>10</time_delay>
    <run_on_start>yes</run_on_start>
    <version>v1.0</version>
    <api_auth>
      <client_id>example_string</client_id>
      <tenant_id>example_string</tenant_id>
      <secret_value>example_string</secret_value>
      <api_type>global</api_type>
    </api_auth>
    <resource>
      <name>security</name>
      <relationship>alerts_v2</relationship>
    </resource>
    */
    wm_ms_graph* module_data = (wm_ms_graph *)*state;
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config);
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config[0]);
    module_data->enabled = true;
    module_data->only_future_events = false;
    module_data->curl_max_size = 1024L;
    module_data->page_size = 100;
    module_data->time_delay = 10;
    module_data->run_on_start = true;
    os_strdup("v1.0", module_data->version);
    os_strdup("example_client", module_data->auth_config[0]->client_id);
    os_strdup("example_tenant", module_data->auth_config[0]->tenant_id);
    os_strdup("example_secret", module_data->auth_config[0]->secret_value);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_LOGIN_FQDN, module_data->auth_config[0]->login_fqdn);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_QUERY_FQDN, module_data->auth_config[0]->query_fqdn);
    os_malloc(sizeof(wm_ms_graph_resource), module_data->resources);
    os_strdup("security", module_data->resources[0].name);
    module_data->num_resources = 1;
    os_malloc(sizeof(char*), module_data->resources[0].relationships);
    os_strdup("alerts_v2", module_data->resources[0].relationships[0]);
    module_data->resources[0].num_relationships = 1;
    size_t max_size = OS_SIZE_8192;
    curl_response* response;

    os_calloc(1, sizeof(curl_response), response);
    response->status_code = 200;
    response->max_size_reached = false;
    os_strdup("{\"no_access_token\":\"token_value\",\"expires_in\":123}", response->body);
    os_strdup("test", response->header);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mtdebug1, formatted_msg, "Microsoft Graph API Access Token URL: 'https://login.microsoftonline.com/example_tenant/oauth2/v2.0/token'");

    expect_any(__wrap_wurl_http_request, method);
    expect_any(__wrap_wurl_http_request, header);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_MS_GRAPH_DEFAULT_TIMEOUT);
    expect_any(__wrap_wurl_http_request, ssl_verify);
    will_return(__wrap_wurl_http_request, response);

    expect_string(__wrap__mtwarn, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mtwarn, formatted_msg, "Incomplete access token response, value or expiration time not present.");

    wm_ms_graph_get_access_token(module_data->auth_config[0], max_size);
}

void test_wm_ms_graph_get_access_token_no_expire_time(void **state) {
    /*
    <enabled>yes</enabled>
    <only_future_events>no</only_future_events>
    <curl_max_size>1M</curl_max_size>
    <page_size>100</page_size>
    <time_delay>10</time_delay>
    <run_on_start>yes</run_on_start>
    <version>v1.0</version>
    <api_auth>
      <client_id>example_string</client_id>
      <tenant_id>example_string</tenant_id>
      <secret_value>example_string</secret_value>
      <api_type>global</api_type>
    </api_auth>
    <resource>
      <name>security</name>
      <relationship>alerts_v2</relationship>
    </resource>
    */
    wm_ms_graph* module_data = (wm_ms_graph *)*state;
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config);
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config[0]);
    module_data->enabled = true;
    module_data->only_future_events = false;
    module_data->curl_max_size = 1024L;
    module_data->page_size = 100;
    module_data->time_delay = 10;
    module_data->run_on_start = true;
    os_strdup("v1.0", module_data->version);
    os_strdup("example_client", module_data->auth_config[0]->client_id);
    os_strdup("example_tenant", module_data->auth_config[0]->tenant_id);
    os_strdup("example_secret", module_data->auth_config[0]->secret_value);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_LOGIN_FQDN, module_data->auth_config[0]->login_fqdn);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_QUERY_FQDN, module_data->auth_config[0]->query_fqdn);
    os_malloc(sizeof(wm_ms_graph_resource), module_data->resources);
    os_strdup("security", module_data->resources[0].name);
    module_data->num_resources = 1;
    os_malloc(sizeof(char*), module_data->resources[0].relationships);
    os_strdup("alerts_v2", module_data->resources[0].relationships[0]);
    module_data->resources[0].num_relationships = 1;
    size_t max_size = OS_SIZE_8192;
    curl_response* response;

    os_calloc(1, sizeof(curl_response), response);
    response->status_code = 200;
    response->max_size_reached = false;
    os_strdup("{\"access_token\":\"token_value\",\"no_expires_in\":123}", response->body);
    os_strdup("test", response->header);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mtdebug1, formatted_msg, "Microsoft Graph API Access Token URL: 'https://login.microsoftonline.com/example_tenant/oauth2/v2.0/token'");

    expect_any(__wrap_wurl_http_request, method);
    expect_any(__wrap_wurl_http_request, header);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_MS_GRAPH_DEFAULT_TIMEOUT);
    expect_any(__wrap_wurl_http_request, ssl_verify);
    will_return(__wrap_wurl_http_request, response);

    expect_string(__wrap__mtwarn, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mtwarn, formatted_msg, "Incomplete access token response, value or expiration time not present.");

    wm_ms_graph_get_access_token(module_data->auth_config[0], max_size);
}

void test_wm_ms_graph_scan_relationships_single_initial_only_no(void **state) {
    /*
    <enabled>yes</enabled>
    <only_future_events>no</only_future_events>
    <curl_max_size>1M</curl_max_size>
    <page_size>100</page_size>
    <time_delay>10</time_delay>
    <run_on_start>yes</run_on_start>
    <version>v1.0</version>
    <api_auth>
      <client_id>example_client</client_id>
      <tenant_id>example_tenant</tenant_id>
      <secret_value>example_secret</secret_value>
      <api_type>global</api_type>
    </api_auth>
    <resource>
      <name>security</name>
      <relationship>alerts_v2</relationship>
    </resource>
    */
    wm_ms_graph* module_data = (wm_ms_graph *)*state;
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config);
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config[0]);
    module_data->enabled = true;
    module_data->only_future_events = false;
    module_data->curl_max_size = 1024L;
    module_data->page_size = 100;
    module_data->time_delay = 10;
    module_data->run_on_start = true;
    module_data->scan_config.interval = 60;
    os_strdup("v1.0", module_data->version);
    os_strdup("example_client", module_data->auth_config[0]->client_id);
    os_strdup("example_tenant", module_data->auth_config[0]->tenant_id);
    os_strdup("example_secret", module_data->auth_config[0]->secret_value);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_LOGIN_FQDN, module_data->auth_config[0]->login_fqdn);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_QUERY_FQDN, module_data->auth_config[0]->query_fqdn);
    os_malloc(sizeof(wm_ms_graph_resource), module_data->resources);
    os_strdup("security", module_data->resources[0].name);
    module_data->num_resources = 1;
    os_malloc(sizeof(char*), module_data->resources[0].relationships);
    os_strdup("alerts_v2", module_data->resources[0].relationships[0]);
    module_data->resources[0].num_relationships = 1;
    size_t max_size = OS_SIZE_8192;
    bool initial = true;

#ifdef TEST_WINAGENT
    will_return_count(__wrap_os_random, 12345, 2);
#else
    will_return(__wrap_os_random, 12345);
#endif

    expect_string(__wrap_wm_state_io, tag, "ms-graph-example_tenant-security-alerts_v2");
    expect_value(__wrap_wm_state_io, op, WM_IO_READ);
    expect_any(__wrap_wm_state_io, state);
    expect_any(__wrap_wm_state_io, size);
    will_return(__wrap_wm_state_io, -1);

    will_return(__wrap_isDebug, 1);

#ifndef WIN32
    will_return(__wrap_gmtime_r, 1);
#endif
    will_return(__wrap_strftime,"2023-02-08T12:24:56Z");
    will_return(__wrap_strftime, 20);

    expect_string(__wrap_wm_state_io, tag, "ms-graph-example_tenant-security-alerts_v2");
    expect_value(__wrap_wm_state_io, op, WM_IO_WRITE);
    expect_any(__wrap_wm_state_io, state);
    expect_any(__wrap_wm_state_io, size);
    will_return(__wrap_wm_state_io, 1);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mtdebug1, formatted_msg, "Bookmark updated to '2023-02-08T12:24:56Z' for tenant 'example_tenant' resource 'security' and relationship 'alerts_v2', waiting '60' seconds to run first scan.");

    wm_ms_graph_scan_relationships(module_data, module_data->auth_config[0], initial);
}

void test_wm_ms_graph_scan_relationships_single_initial_only_yes_fail_write(void **state) {
    /*
    <enabled>yes</enabled>
    <only_future_events>yes</only_future_events>
    <curl_max_size>1M</curl_max_size>
    <page_size>100</page_size>
    <time_delay>10</time_delay>
    <run_on_start>yes</run_on_start>
    <version>v1.0</version>
    <api_auth>
      <client_id>example_client</client_id>
      <tenant_id>example_tenant</tenant_id>
      <secret_value>example_secret</secret_value>
      <api_type>global</api_type>
    </api_auth>
    <resource>
      <name>security</name>
      <relationship>alerts_v2</relationship>
    </resource>
    */
    wm_ms_graph* module_data = (wm_ms_graph *)*state;
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config);
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config[0]);
    module_data->enabled = true;
    module_data->only_future_events = true;
    module_data->curl_max_size = 1024L;
    module_data->page_size = 100;
    module_data->time_delay = 10;
    module_data->run_on_start = true;
    module_data->scan_config.interval = 60;
    os_strdup("v1.0", module_data->version);
    os_strdup("example_client", module_data->auth_config[0]->client_id);
    os_strdup("example_tenant", module_data->auth_config[0]->tenant_id);
    os_strdup("example_secret", module_data->auth_config[0]->secret_value);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_LOGIN_FQDN, module_data->auth_config[0]->login_fqdn);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_QUERY_FQDN, module_data->auth_config[0]->query_fqdn);
    os_malloc(sizeof(wm_ms_graph_resource), module_data->resources);
    os_strdup("security", module_data->resources[0].name);
    module_data->num_resources = 1;
    os_malloc(sizeof(char*), module_data->resources[0].relationships);
    os_strdup("alerts_v2", module_data->resources[0].relationships[0]);
    module_data->resources[0].num_relationships = 1;
    size_t max_size = OS_SIZE_8192;
    bool initial = true;

#ifdef TEST_WINAGENT
    will_return_count(__wrap_os_random, 12345, 2);
#else
    will_return(__wrap_os_random, 12345);
#endif

    expect_string(__wrap_wm_state_io, tag, "ms-graph-example_tenant-security-alerts_v2");
    expect_value(__wrap_wm_state_io, op, WM_IO_READ);
    expect_any(__wrap_wm_state_io, state);
    expect_any(__wrap_wm_state_io, size);
    will_return(__wrap_wm_state_io, -1);

    expect_string(__wrap_wm_state_io, tag, "ms-graph-example_tenant-security-alerts_v2");
    expect_value(__wrap_wm_state_io, op, WM_IO_WRITE);
    expect_any(__wrap_wm_state_io, state);
    expect_any(__wrap_wm_state_io, size);
    will_return(__wrap_wm_state_io, -1);

    expect_string(__wrap__mterror, tag, WM_MS_GRAPH_LOGTAG);
    expect_string(__wrap__mterror, formatted_msg, "Couldn't save running state.");

    wm_ms_graph_scan_relationships(module_data, module_data->auth_config[0], initial);
}

void test_wm_ms_graph_scan_relationships_single_initial_only_no_next_time_no_response(void **state) {
    /*
    <enabled>yes</enabled>
    <only_future_events>no</only_future_events>
    <curl_max_size>1M</curl_max_size>
    <page_size>50</page_size>
    <time_delay>5</time_delay>
    <run_on_start>yes</run_on_start>
    <version>v1.0</version>
    <api_auth>
      <client_id>example_client</client_id>
      <tenant_id>example_tenant</tenant_id>
      <secret_value>example_secret</secret_value>
      <api_type>global</api_type>
    </api_auth>
    <resource>
      <name>security</name>
      <relationship>alerts_v2</relationship>
    </resource>
    */
    wm_ms_graph* module_data = (wm_ms_graph *)*state;
    wm_ms_graph_state_t relationship_state_struc;
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config);
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config[0]);
    relationship_state_struc.next_time = 10;
    module_data->enabled = true;
    module_data->only_future_events = false;
    module_data->curl_max_size = 1024L;
    module_data->page_size = 50;
    module_data->time_delay = 5;
    module_data->run_on_start = true;
    module_data->scan_config.interval = 60;
    os_strdup("v1.0", module_data->version);
    os_strdup("example_client", module_data->auth_config[0]->client_id);
    os_strdup("example_tenant", module_data->auth_config[0]->tenant_id);
    os_strdup("example_secret", module_data->auth_config[0]->secret_value);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_LOGIN_FQDN, module_data->auth_config[0]->login_fqdn);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_QUERY_FQDN, module_data->auth_config[0]->query_fqdn);
    os_strdup("token", module_data->auth_config[0]->access_token);
    module_data->auth_config[0]->token_expiration_time = time(NULL) + 100;
    os_malloc(sizeof(wm_ms_graph_resource), module_data->resources);
    os_strdup("security", module_data->resources[0].name);
    module_data->num_resources = 1;
    os_malloc(sizeof(char*), module_data->resources[0].relationships);
    os_strdup("alerts_v2", module_data->resources[0].relationships[0]);
    module_data->resources[0].num_relationships = 1;
    size_t max_size = OS_SIZE_8192;
    bool initial = true;

#ifdef TEST_WINAGENT
    will_return_count(__wrap_os_random, 12345, 2);
#else
    will_return(__wrap_os_random, 12345);
#endif

    expect_string(__wrap_wm_state_io, tag, "ms-graph-example_tenant-security-alerts_v2");
    expect_value(__wrap_wm_state_io, op, WM_IO_READ);
    expect_any(__wrap_wm_state_io, state);
    expect_any(__wrap_wm_state_io, size);
    will_return(__wrap_wm_state_io, 0);
    will_return(__wrap_wm_state_io, (void *)&relationship_state_struc);

#ifndef WIN32
    will_return(__wrap_gmtime_r, 1);
#endif
    will_return(__wrap_strftime,"2023-02-08T12:24:56Z");
    will_return(__wrap_strftime, 20);

#ifndef WIN32
    will_return(__wrap_gmtime_r, 1);
#endif
    will_return(__wrap_strftime,"2023-02-08T12:25:56Z");
    will_return(__wrap_strftime, 20);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mtdebug1, formatted_msg, "Microsoft Graph API Log URL: 'https://graph.microsoft.com/v1.0/security/alerts_v2?$top=50&$filter=createdDateTime+ge+2023-02-08T12:24:56Z+and+createdDateTime+lt+2023-02-08T12:25:56Z'");

    expect_any(__wrap_wurl_http_request, method);
    expect_any(__wrap_wurl_http_request, header);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_MS_GRAPH_DEFAULT_TIMEOUT);
    expect_any(__wrap_wurl_http_request, ssl_verify);
    will_return(__wrap_wurl_http_request, NULL);

    expect_string(__wrap__mtwarn, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mtwarn, formatted_msg, "No response received when attempting to get relationship 'alerts_v2' from resource 'security' on API version 'v1.0'.");

    wm_ms_graph_scan_relationships(module_data, module_data->auth_config[0], initial);
}

void test_wm_ms_graph_scan_relationships_single_no_initial_no_timestamp(void **state) {
    /*
    <enabled>yes</enabled>
    <only_future_events>no</only_future_events>
    <curl_max_size>1M</curl_max_size>
    <page_size>50</page_size>
    <time_delay>5</time_delay>
    <run_on_start>yes</run_on_start>
    <version>v1.0</version>
    <api_auth>
      <client_id>example_client</client_id>
      <tenant_id>example_tenant</tenant_id>
      <secret_value>example_secret</secret_value>
      <api_type>global</api_type>
    </api_auth>
    <resource>
      <name>security</name>
      <relationship>alerts_v2</relationship>
    </resource>
    */
    wm_ms_graph* module_data = (wm_ms_graph *)*state;
    wm_ms_graph_state_t relationship_state_struc;
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config);
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config[0]);
    relationship_state_struc.next_time = 10;
    module_data->enabled = true;
    module_data->only_future_events = false;
    module_data->curl_max_size = 1024L;
    module_data->page_size = 50;
    module_data->time_delay = 5;
    module_data->run_on_start = true;
    module_data->scan_config.interval = 60;
    os_strdup("v1.0", module_data->version);
    os_strdup("example_client", module_data->auth_config[0]->client_id);
    os_strdup("example_tenant", module_data->auth_config[0]->tenant_id);
    os_strdup("example_secret", module_data->auth_config[0]->secret_value);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_LOGIN_FQDN, module_data->auth_config[0]->login_fqdn);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_QUERY_FQDN, module_data->auth_config[0]->query_fqdn);
    os_malloc(sizeof(wm_ms_graph_resource), module_data->resources);
    os_strdup("security", module_data->resources[0].name);
    module_data->num_resources = 1;
    os_malloc(sizeof(char*), module_data->resources[0].relationships);
    os_strdup("alerts_v2", module_data->resources[0].relationships[0]);
    module_data->resources[0].num_relationships = 1;
    size_t max_size = OS_SIZE_8192;
    bool initial = false;

#ifdef TEST_WINAGENT
    will_return_count(__wrap_os_random, 12345, 2);
#else
    will_return(__wrap_os_random, 12345);
#endif

    expect_string(__wrap_wm_state_io, tag, "ms-graph-example_tenant-security-alerts_v2");
    expect_value(__wrap_wm_state_io, op, WM_IO_READ);
    expect_any(__wrap_wm_state_io, state);
    expect_any(__wrap_wm_state_io, size);
    will_return(__wrap_wm_state_io, -1);

    will_return(__wrap_isDebug, 1);

#ifndef WIN32
    will_return(__wrap_gmtime_r, 1);
#endif
    will_return(__wrap_strftime,"2023-02-08T12:24:56Z");
    will_return(__wrap_strftime, 20);

    expect_string(__wrap_wm_state_io, tag, "ms-graph-example_tenant-security-alerts_v2");
    expect_value(__wrap_wm_state_io, op, WM_IO_WRITE);
    expect_any(__wrap_wm_state_io, state);
    expect_any(__wrap_wm_state_io, size);
    will_return(__wrap_wm_state_io, 1);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mtdebug1, formatted_msg, "Bookmark updated to '2023-02-08T12:24:56Z' for tenant 'example_tenant' resource 'security' and relationship 'alerts_v2', waiting '60' seconds to run first scan.");

    wm_ms_graph_scan_relationships(module_data, module_data->auth_config[0], initial);
}

void test_wm_ms_graph_scan_relationships_single_unsuccessful_status_code(void **state) {
    /*
    <enabled>yes</enabled>
    <only_future_events>no</only_future_events>
    <curl_max_size>1M</curl_max_size>
    <page_size>50</page_size>
    <time_delay>5</time_delay>
    <run_on_start>yes</run_on_start>
    <version>v1.0</version>
    <api_auth>
      <client_id>example_client</client_id>
      <tenant_id>example_tenant</tenant_id>
      <secret_value>example_secret</secret_value>
      <api_type>global</api_type>
    </api_auth>
    <resource>
      <name>security</name>
      <relationship>alerts_v2</relationship>
    </resource>
    */
    wm_ms_graph* module_data = (wm_ms_graph *)*state;
    wm_ms_graph_state_t relationship_state_struc;
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config);
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config[0]);
    relationship_state_struc.next_time = 10;
    module_data->enabled = true;
    module_data->only_future_events = false;
    module_data->curl_max_size = 1024L;
    module_data->page_size = 50;
    module_data->time_delay = 5;
    module_data->run_on_start = true;
    module_data->scan_config.interval = 60;
    os_strdup("v1.0", module_data->version);
    os_strdup("example_client", module_data->auth_config[0]->client_id);
    os_strdup("example_tenant", module_data->auth_config[0]->tenant_id);
    os_strdup("example_secret", module_data->auth_config[0]->secret_value);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_LOGIN_FQDN, module_data->auth_config[0]->login_fqdn);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_QUERY_FQDN, module_data->auth_config[0]->query_fqdn);
    os_strdup("token", module_data->auth_config[0]->access_token);
    module_data->auth_config[0]->token_expiration_time = time(NULL) + 100;
    os_malloc(sizeof(wm_ms_graph_resource), module_data->resources);
    os_strdup("security", module_data->resources[0].name);
    module_data->num_resources = 1;
    os_malloc(sizeof(char*), module_data->resources[0].relationships);
    os_strdup("alerts_v2", module_data->resources[0].relationships[0]);
    module_data->resources[0].num_relationships = 1;
    size_t max_size = OS_SIZE_8192;
    bool initial = false;
    curl_response* response;

    os_calloc(1, sizeof(curl_response), response);
    response->status_code = 400;
    os_strdup("{\"error\":\"bad_request\"}", response->body);
    os_strdup("test", response->header);

#ifdef TEST_WINAGENT
    will_return_count(__wrap_os_random, 12345, 2);
#else
    will_return(__wrap_os_random, 12345);
#endif

    expect_string(__wrap_wm_state_io, tag, "ms-graph-example_tenant-security-alerts_v2");
    expect_value(__wrap_wm_state_io, op, WM_IO_READ);
    expect_any(__wrap_wm_state_io, state);
    expect_any(__wrap_wm_state_io, size);
    will_return(__wrap_wm_state_io, 0);
    will_return(__wrap_wm_state_io, (void *)&relationship_state_struc);

#ifndef WIN32
    will_return(__wrap_gmtime_r, 1);
#endif
    will_return(__wrap_strftime,"2023-02-08T12:24:56Z");
    will_return(__wrap_strftime, 20);

#ifndef WIN32
    will_return(__wrap_gmtime_r, 1);
#endif
    will_return(__wrap_strftime,"2023-02-08T12:25:56Z");
    will_return(__wrap_strftime, 20);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mtdebug1, formatted_msg, "Microsoft Graph API Log URL: 'https://graph.microsoft.com/v1.0/security/alerts_v2?$top=50&$filter=createdDateTime+ge+2023-02-08T12:24:56Z+and+createdDateTime+lt+2023-02-08T12:25:56Z'");

    expect_any(__wrap_wurl_http_request, method);
    expect_any(__wrap_wurl_http_request, header);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_MS_GRAPH_DEFAULT_TIMEOUT);
    expect_any(__wrap_wurl_http_request, ssl_verify);
    will_return(__wrap_wurl_http_request, response);

    expect_string(__wrap__mtwarn, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mtwarn, formatted_msg, "Received unsuccessful status code when attempting to get relationship 'alerts_v2' logs: Status code was '400' & response was '{\"error\":\"bad_request\"}'");

    wm_ms_graph_scan_relationships(module_data, module_data->auth_config[0], initial);
}

void test_wm_ms_graph_scan_relationships_single_reached_curl_size(void **state) {
    /*
    <enabled>yes</enabled>
    <only_future_events>no</only_future_events>
    <curl_max_size>1M</curl_max_size>
    <page_size>50</page_size>
    <time_delay>5</time_delay>
    <run_on_start>yes</run_on_start>
    <version>v1.0</version>
    <api_auth>
      <client_id>example_client</client_id>
      <tenant_id>example_tenant</tenant_id>
      <secret_value>example_secret</secret_value>
      <api_type>global</api_type>
    </api_auth>
    <resource>
      <name>security</name>
      <relationship>alerts_v2</relationship>
    </resource>
    */
    wm_ms_graph* module_data = (wm_ms_graph *)*state;
    wm_ms_graph_state_t relationship_state_struc;
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config);
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config[0]);
    relationship_state_struc.next_time = 10;
    module_data->enabled = true;
    module_data->only_future_events = false;
    module_data->curl_max_size = 1024L;
    module_data->page_size = 50;
    module_data->time_delay = 5;
    module_data->run_on_start = true;
    module_data->scan_config.interval = 60;
    os_strdup("v1.0", module_data->version);
    os_strdup("example_client", module_data->auth_config[0]->client_id);
    os_strdup("example_tenant", module_data->auth_config[0]->tenant_id);
    os_strdup("example_secret", module_data->auth_config[0]->secret_value);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_LOGIN_FQDN, module_data->auth_config[0]->login_fqdn);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_QUERY_FQDN, module_data->auth_config[0]->query_fqdn);
    os_strdup("token", module_data->auth_config[0]->access_token);
    module_data->auth_config[0]->token_expiration_time = time(NULL) + 100;
    os_malloc(sizeof(wm_ms_graph_resource), module_data->resources);
    os_strdup("security", module_data->resources[0].name);
    module_data->num_resources = 1;
    os_malloc(sizeof(char*), module_data->resources[0].relationships);
    os_strdup("alerts_v2", module_data->resources[0].relationships[0]);
    module_data->resources[0].num_relationships = 1;
    size_t max_size = OS_SIZE_8192;
    bool initial = false;
    curl_response* response;

    os_calloc(1, sizeof(curl_response), response);
    response->status_code = 200;
    response->max_size_reached = true;
    os_strdup("{\"error\":\"bad_request\"}", response->body);
    os_strdup("test", response->header);

#ifdef TEST_WINAGENT
    will_return_count(__wrap_os_random, 12345, 2);
#else
    will_return(__wrap_os_random, 12345);
#endif

    expect_string(__wrap_wm_state_io, tag, "ms-graph-example_tenant-security-alerts_v2");
    expect_value(__wrap_wm_state_io, op, WM_IO_READ);
    expect_any(__wrap_wm_state_io, state);
    expect_any(__wrap_wm_state_io, size);
    will_return(__wrap_wm_state_io, 0);
    will_return(__wrap_wm_state_io, (void *)&relationship_state_struc);

#ifndef WIN32
    will_return(__wrap_gmtime_r, 1);
#endif
    will_return(__wrap_strftime,"2023-02-08T12:24:56Z");
    will_return(__wrap_strftime, 20);

#ifndef WIN32
    will_return(__wrap_gmtime_r, 1);
#endif
    will_return(__wrap_strftime,"2023-02-08T12:25:56Z");
    will_return(__wrap_strftime, 20);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mtdebug1, formatted_msg, "Microsoft Graph API Log URL: 'https://graph.microsoft.com/v1.0/security/alerts_v2?$top=50&$filter=createdDateTime+ge+2023-02-08T12:24:56Z+and+createdDateTime+lt+2023-02-08T12:25:56Z'");

    expect_any(__wrap_wurl_http_request, method);
    expect_any(__wrap_wurl_http_request, header);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_MS_GRAPH_DEFAULT_TIMEOUT);
    expect_any(__wrap_wurl_http_request, ssl_verify);
    will_return(__wrap_wurl_http_request, response);

    expect_string(__wrap__mtwarn, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mtwarn, formatted_msg, "Reached maximum CURL size when attempting to get relationship 'alerts_v2' logs. Consider increasing the value of 'curl_max_size'.");

    wm_ms_graph_scan_relationships(module_data, module_data->auth_config[0], initial);
}

void test_wm_ms_graph_scan_relationships_single_failed_parse(void **state) {
    /*
    <enabled>yes</enabled>
    <only_future_events>no</only_future_events>
    <curl_max_size>1M</curl_max_size>
    <page_size>25</page_size>
    <time_delay>2</time_delay>
    <run_on_start>yes</run_on_start>
    <version>v1.0</version>
    <api_auth>
      <client_id>example_client</client_id>
      <tenant_id>example_tenant</tenant_id>
      <secret_value>example_secret</secret_value>
      <api_type>global</api_type>
    </api_auth>
    <resource>
      <name>security</name>
      <relationship>alerts_v2</relationship>
    </resource>
    */
    wm_ms_graph* module_data = (wm_ms_graph *)*state;
    wm_ms_graph_state_t relationship_state_struc;
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config);
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config[0]);
    relationship_state_struc.next_time = 10;
    module_data->enabled = true;
    module_data->only_future_events = false;
    module_data->curl_max_size = 1024L;
    module_data->page_size = 25;
    module_data->time_delay = 2;
    module_data->run_on_start = true;
    module_data->scan_config.interval = 60;
    os_strdup("v1.0", module_data->version);
    os_strdup("example_client", module_data->auth_config[0]->client_id);
    os_strdup("example_tenant", module_data->auth_config[0]->tenant_id);
    os_strdup("example_secret", module_data->auth_config[0]->secret_value);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_LOGIN_FQDN, module_data->auth_config[0]->login_fqdn);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_QUERY_FQDN, module_data->auth_config[0]->query_fqdn);
    os_strdup("token", module_data->auth_config[0]->access_token);
    module_data->auth_config[0]->token_expiration_time = time(NULL) + 100;
    os_malloc(sizeof(wm_ms_graph_resource), module_data->resources);
    os_strdup("security", module_data->resources[0].name);
    module_data->num_resources = 1;
    os_malloc(sizeof(char*), module_data->resources[0].relationships);
    os_strdup("alerts_v2", module_data->resources[0].relationships[0]);
    module_data->resources[0].num_relationships = 1;
    size_t max_size = OS_SIZE_8192;
    bool initial = false;
    curl_response* response;

    os_calloc(1, sizeof(curl_response), response);
    response->status_code = 200;
    response->max_size_reached = false;
    os_strdup("no json", response->body);
    os_strdup("test", response->header);

#ifdef TEST_WINAGENT
    will_return_count(__wrap_os_random, 12345, 2);
#else
    will_return(__wrap_os_random, 12345);
#endif

    expect_string(__wrap_wm_state_io, tag, "ms-graph-example_tenant-security-alerts_v2");
    expect_value(__wrap_wm_state_io, op, WM_IO_READ);
    expect_any(__wrap_wm_state_io, state);
    expect_any(__wrap_wm_state_io, size);
    will_return(__wrap_wm_state_io, 0);
    will_return(__wrap_wm_state_io, (void *)&relationship_state_struc);

#ifndef WIN32
    will_return(__wrap_gmtime_r, 1);
#endif
    will_return(__wrap_strftime,"2023-02-08T12:24:56Z");
    will_return(__wrap_strftime, 20);

#ifndef WIN32
    will_return(__wrap_gmtime_r, 1);
#endif
    will_return(__wrap_strftime,"2023-02-08T12:25:56Z");
    will_return(__wrap_strftime, 20);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mtdebug1, formatted_msg, "Microsoft Graph API Log URL: 'https://graph.microsoft.com/v1.0/security/alerts_v2?$top=25&$filter=createdDateTime+ge+2023-02-08T12:24:56Z+and+createdDateTime+lt+2023-02-08T12:25:56Z'");

    expect_any(__wrap_wurl_http_request, method);
    expect_any(__wrap_wurl_http_request, header);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_MS_GRAPH_DEFAULT_TIMEOUT);
    expect_any(__wrap_wurl_http_request, ssl_verify);
    will_return(__wrap_wurl_http_request, response);

    expect_string(__wrap__mtwarn, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mtwarn, formatted_msg, "Failed to parse relationship 'alerts_v2' JSON body.");

    wm_ms_graph_scan_relationships(module_data, module_data->auth_config[0], initial);
}

void test_wm_ms_graph_scan_relationships_single_no_logs(void **state) {
    /*
    <enabled>yes</enabled>
    <only_future_events>no</only_future_events>
    <curl_max_size>1M</curl_max_size>
    <page_size>25</page_size>
    <time_delay>2</time_delay>
    <run_on_start>yes</run_on_start>
    <version>v1.0</version>
    <api_auth>
      <client_id>example_client</client_id>
      <tenant_id>example_tenant</tenant_id>
      <secret_value>example_secret</secret_value>
      <api_type>global</api_type>
    </api_auth>
    <resource>
      <name>security</name>
      <relationship>alerts_v2</relationship>
    </resource>
    */
    wm_ms_graph* module_data = (wm_ms_graph *)*state;
    wm_ms_graph_state_t relationship_state_struc;
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config);
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config[0]);
    relationship_state_struc.next_time = 10;
    module_data->enabled = true;
    module_data->only_future_events = false;
    module_data->curl_max_size = 1024L;
    module_data->page_size = 25;
    module_data->time_delay = 2;
    module_data->run_on_start = true;
    module_data->scan_config.interval = 60;
    os_strdup("v1.0", module_data->version);
    os_strdup("example_client", module_data->auth_config[0]->client_id);
    os_strdup("example_tenant", module_data->auth_config[0]->tenant_id);
    os_strdup("example_secret", module_data->auth_config[0]->secret_value);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_LOGIN_FQDN, module_data->auth_config[0]->login_fqdn);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_QUERY_FQDN, module_data->auth_config[0]->query_fqdn);
    os_strdup("token", module_data->auth_config[0]->access_token);
    module_data->auth_config[0]->token_expiration_time = time(NULL) + 100;
    os_malloc(sizeof(wm_ms_graph_resource), module_data->resources);
    os_strdup("security", module_data->resources[0].name);
    module_data->num_resources = 1;
    os_malloc(sizeof(char*), module_data->resources[0].relationships);
    os_strdup("alerts_v2", module_data->resources[0].relationships[0]);
    module_data->resources[0].num_relationships = 1;
    size_t max_size = OS_SIZE_8192;
    bool initial = false;
    curl_response* response;

    os_calloc(1, sizeof(curl_response), response);
    response->status_code = 200;
    response->max_size_reached = false;
    os_strdup("{\"value\":[]}", response->body);
    os_strdup("test", response->header);

#ifdef TEST_WINAGENT
    will_return_count(__wrap_os_random, 12345, 2);
#else
    will_return(__wrap_os_random, 12345);
#endif

    expect_string(__wrap_wm_state_io, tag, "ms-graph-example_tenant-security-alerts_v2");
    expect_value(__wrap_wm_state_io, op, WM_IO_READ);
    expect_any(__wrap_wm_state_io, state);
    expect_any(__wrap_wm_state_io, size);
    will_return(__wrap_wm_state_io, 0);
    will_return(__wrap_wm_state_io, (void *)&relationship_state_struc);

#ifndef WIN32
    will_return(__wrap_gmtime_r, 1);
#endif
    will_return(__wrap_strftime,"2023-02-08T12:24:56Z");
    will_return(__wrap_strftime, 20);

#ifndef WIN32
    will_return(__wrap_gmtime_r, 1);
#endif
    will_return(__wrap_strftime,"2023-02-08T12:25:56Z");
    will_return(__wrap_strftime, 20);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mtdebug1, formatted_msg, "Microsoft Graph API Log URL: 'https://graph.microsoft.com/v1.0/security/alerts_v2?$top=25&$filter=createdDateTime+ge+2023-02-08T12:24:56Z+and+createdDateTime+lt+2023-02-08T12:25:56Z'");

    expect_any(__wrap_wurl_http_request, method);
    expect_any(__wrap_wurl_http_request, header);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_MS_GRAPH_DEFAULT_TIMEOUT);
    expect_any(__wrap_wurl_http_request, ssl_verify);
    will_return(__wrap_wurl_http_request, response);

    expect_string(__wrap__mtdebug2, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mtdebug2, formatted_msg, "No new logs received.");

    expect_string(__wrap_wm_state_io, tag, "ms-graph-example_tenant-security-alerts_v2");
    expect_value(__wrap_wm_state_io, op, WM_IO_WRITE);
    expect_any(__wrap_wm_state_io, state);
    expect_any(__wrap_wm_state_io, size);
    will_return(__wrap_wm_state_io, 1);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mtdebug1, formatted_msg, "Bookmark updated to '2023-02-08T12:25:56Z' for tenant 'example_tenant' resource 'security' and relationship 'alerts_v2', waiting '60' seconds to run next scan.");

    wm_ms_graph_scan_relationships(module_data, module_data->auth_config[0], initial);
}

void test_wm_ms_graph_scan_relationships_single_success_one_log(void **state) {
    /*
    <enabled>yes</enabled>
    <only_future_events>no</only_future_events>
    <curl_max_size>1M</curl_max_size>
    <page_size>10</page_size>
    <time_delay>1</time_delay>
    <run_on_start>yes</run_on_start>
    <version>v1.0</version>
    <api_auth>
      <client_id>example_client</client_id>
      <tenant_id>example_tenant</tenant_id>
      <secret_value>example_secret</secret_value>
      <api_type>global</api_type>
    </api_auth>
    <resource>
      <name>security</name>
      <relationship>alerts_v2</relationship>
    </resource>
    */
    wm_ms_graph* module_data = (wm_ms_graph *)*state;
    wm_ms_graph_state_t relationship_state_struc;
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config);
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config[0]);
    relationship_state_struc.next_time = 10;
    module_data->enabled = true;
    module_data->only_future_events = false;
    module_data->curl_max_size = 1024L;
    module_data->page_size = 10;
    module_data->time_delay = 1;
    module_data->run_on_start = true;
    module_data->scan_config.interval = 60;
    os_strdup("v1.0", module_data->version);
    os_strdup("example_client", module_data->auth_config[0]->client_id);
    os_strdup("example_tenant", module_data->auth_config[0]->tenant_id);
    os_strdup("example_secret", module_data->auth_config[0]->secret_value);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_LOGIN_FQDN, module_data->auth_config[0]->login_fqdn);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_QUERY_FQDN, module_data->auth_config[0]->query_fqdn);
    os_strdup("token", module_data->auth_config[0]->access_token);
    module_data->auth_config[0]->token_expiration_time = time(NULL) + 100;
    os_malloc(sizeof(wm_ms_graph_resource), module_data->resources);
    os_strdup("security", module_data->resources[0].name);
    module_data->num_resources = 1;
    os_malloc(sizeof(char*), module_data->resources[0].relationships);
    os_strdup("alerts_v2", module_data->resources[0].relationships[0]);
    module_data->resources[0].num_relationships = 1;
    size_t max_size = OS_SIZE_8192;
    bool initial = false;
    curl_response* response;
    wm_max_eps = 1;

    os_calloc(1, sizeof(curl_response), response);
    response->status_code = 200;
    response->max_size_reached = false;
    os_strdup("{\"value\":[{\"full_log\":\"log1\"}]}", response->body);
    os_strdup("test", response->header);

#ifdef TEST_WINAGENT
    will_return_count(__wrap_os_random, 12345, 2);
#else
    will_return(__wrap_os_random, 12345);
#endif

    expect_string(__wrap_wm_state_io, tag, "ms-graph-example_tenant-security-alerts_v2");
    expect_value(__wrap_wm_state_io, op, WM_IO_READ);
    expect_any(__wrap_wm_state_io, state);
    expect_any(__wrap_wm_state_io, size);
    will_return(__wrap_wm_state_io, 0);
    will_return(__wrap_wm_state_io, (void *)&relationship_state_struc);

#ifndef WIN32
    will_return(__wrap_gmtime_r, 1);
#endif
    will_return(__wrap_strftime,"2023-02-08T12:24:56Z");
    will_return(__wrap_strftime, 20);

#ifndef WIN32
    will_return(__wrap_gmtime_r, 1);
#endif
    will_return(__wrap_strftime,"2023-02-08T12:25:56Z");
    will_return(__wrap_strftime, 20);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mtdebug1, formatted_msg, "Microsoft Graph API Log URL: 'https://graph.microsoft.com/v1.0/security/alerts_v2?$top=10&$filter=createdDateTime+ge+2023-02-08T12:24:56Z+and+createdDateTime+lt+2023-02-08T12:25:56Z'");

    expect_any(__wrap_wurl_http_request, method);
    expect_any(__wrap_wurl_http_request, header);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_MS_GRAPH_DEFAULT_TIMEOUT);
    expect_any(__wrap_wurl_http_request, ssl_verify);
    will_return(__wrap_wurl_http_request, response);

    expect_string(__wrap__mtdebug2, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mtdebug2, formatted_msg, "Sending log: '{\"integration\":\"ms-graph\",\"ms-graph\":{\"full_log\":\"log1\",\"resource\":\"security\",\"relationship\":\"alerts_v2\"}}'");

    int result = 1;
    queue_fd = 0;
    expect_value(__wrap_wm_sendmsg, usec, 1000000);
    expect_value(__wrap_wm_sendmsg, queue, queue_fd);
    expect_string(__wrap_wm_sendmsg, message, "{\"integration\":\"ms-graph\",\"ms-graph\":{\"full_log\":\"log1\",\"resource\":\"security\",\"relationship\":\"alerts_v2\"}}");
    expect_string(__wrap_wm_sendmsg, locmsg, "ms-graph");
    expect_value(__wrap_wm_sendmsg, loc, LOCALFILE_MQ);
    will_return(__wrap_wm_sendmsg, result);

    expect_string(__wrap_wm_state_io, tag, "ms-graph-example_tenant-security-alerts_v2");
    expect_value(__wrap_wm_state_io, op, WM_IO_WRITE);
    expect_any(__wrap_wm_state_io, state);
    expect_any(__wrap_wm_state_io, size);
    will_return(__wrap_wm_state_io, 1);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mtdebug1, formatted_msg, "Bookmark updated to '2023-02-08T12:25:56Z' for tenant 'example_tenant' resource 'security' and relationship 'alerts_v2', waiting '60' seconds to run next scan.");

    wm_ms_graph_scan_relationships(module_data, module_data->auth_config[0], initial);
}

void test_wm_ms_graph_scan_relationships_single_success_two_logs(void **state) {
    /*
    <enabled>yes</enabled>
    <only_future_events>no</only_future_events>
    <curl_max_size>1M</curl_max_size>
    <page_size>10</page_size>
    <time_delay>1</time_delay>
    <run_on_start>yes</run_on_start>
    <version>v1.0</version>
    <api_auth>
      <client_id>example_client</client_id>
      <tenant_id>example_tenant</tenant_id>
      <secret_value>example_secret</secret_value>
      <api_type>global</api_type>
    </api_auth>
    <resource>
      <name>deviceManagement</name>
      <relationship>detectedApps</relationship>
    </resource>
    */
    wm_ms_graph* module_data = (wm_ms_graph *)*state;
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config);
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config[0]);
    module_data->enabled = true;
    module_data->only_future_events = false;
    module_data->curl_max_size = 1024L;
    module_data->page_size = 10;
    module_data->time_delay = 1;
    module_data->run_on_start = true;
    module_data->scan_config.interval = 60;
    os_strdup("v1.0", module_data->version);
    os_strdup("example_client", module_data->auth_config[0]->client_id);
    os_strdup("example_tenant", module_data->auth_config[0]->tenant_id);
    os_strdup("example_secret", module_data->auth_config[0]->secret_value);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_LOGIN_FQDN, module_data->auth_config[0]->login_fqdn);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_QUERY_FQDN, module_data->auth_config[0]->query_fqdn);
    os_strdup("token", module_data->auth_config[0]->access_token);
    module_data->auth_config[0]->token_expiration_time = time(NULL) + 100;
    os_malloc(sizeof(wm_ms_graph_resource), module_data->resources);
    os_strdup("deviceManagement", module_data->resources[0].name);
    module_data->num_resources = 1;
    os_malloc(sizeof(char*), module_data->resources[0].relationships);
    os_strdup("detectedApps", module_data->resources[0].relationships[0]);
    module_data->resources[0].num_relationships = 1;
    size_t max_size = OS_SIZE_8192;
    bool initial = false;
    curl_response* response;
    curl_response* response2;
    curl_response* response3;
    wm_max_eps = 1;

    os_calloc(1, sizeof(curl_response), response);
    response->status_code = 200;
    response->max_size_reached = false;
    os_strdup("{\"value\":[{\"full_log\":\"log1\"},{\"full_log\":\"log2\",\"id\":\"12345\"}]}", response->body);
    os_strdup("test", response->header);

    os_calloc(1, sizeof(curl_response), response2);
    response2->status_code = 200;
    response2->max_size_reached = false;
    os_strdup("{\"@odata.nextLink\":\"next_page_url\",\"value\":[{\"id\":\"2345\"},{\"name\":\"test\"}]}", response2->body);
    os_strdup("test2", response2->header);

    os_calloc(1, sizeof(curl_response), response3);
    response3->status_code = 200;
    response3->max_size_reached = false;
    os_strdup("{\"value\":[{\"id\":\"3456\"}]}", response3->body);
    os_strdup("test3", response3->header);

#ifdef TEST_WINAGENT
    will_return_count(__wrap_os_random, 12345, 2);
#else
    will_return(__wrap_os_random, 12345);
#endif

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mtdebug1, formatted_msg, "Microsoft Graph API Log URL: 'https://graph.microsoft.com/v1.0/deviceManagement/detectedApps?$top=10'");

    expect_any(__wrap_wurl_http_request, method);
    expect_any(__wrap_wurl_http_request, header);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_MS_GRAPH_DEFAULT_TIMEOUT);
    expect_any(__wrap_wurl_http_request, ssl_verify);
    will_return(__wrap_wurl_http_request, response);

    expect_string(__wrap__mtdebug2, tag, "wazuh-modulesd:ms-graph");
#ifdef TEST_WINAGENT
    expect_string(__wrap__mtdebug2, formatted_msg, "Sending log: '{\"scan_id\":1234512345,\"integration\":\"ms-graph\",\"ms-graph\":{\"full_log\":\"log1\",\"managedDevices\":[],\"resource\":\"deviceManagement\",\"relationship\":\"detectedApps\"}}'");
#else
    expect_string(__wrap__mtdebug2, formatted_msg, "Sending log: '{\"scan_id\":12345,\"integration\":\"ms-graph\",\"ms-graph\":{\"full_log\":\"log1\",\"managedDevices\":[],\"resource\":\"deviceManagement\",\"relationship\":\"detectedApps\"}}'");
#endif

    queue_fd = 0;
    expect_value(__wrap_wm_sendmsg, usec, 1000000);
    expect_value(__wrap_wm_sendmsg, queue, queue_fd);
#ifdef TEST_WINAGENT
    expect_string(__wrap_wm_sendmsg, message, "{\"scan_id\":1234512345,\"integration\":\"ms-graph\",\"ms-graph\":{\"full_log\":\"log1\",\"managedDevices\":[],\"resource\":\"deviceManagement\",\"relationship\":\"detectedApps\"}}");
#else
    expect_string(__wrap_wm_sendmsg, message, "{\"scan_id\":12345,\"integration\":\"ms-graph\",\"ms-graph\":{\"full_log\":\"log1\",\"managedDevices\":[],\"resource\":\"deviceManagement\",\"relationship\":\"detectedApps\"}}");
#endif
    expect_string(__wrap_wm_sendmsg, locmsg, "ms-graph");
    expect_value(__wrap_wm_sendmsg, loc, LOCALFILE_MQ);
    will_return(__wrap_wm_sendmsg, -1);

    will_return(__wrap_strerror, "Error");

    expect_string(__wrap__mterror, tag, WM_MS_GRAPH_LOGTAG);
    expect_string(__wrap__mterror, formatted_msg, "(1210): Queue 'queue/sockets/queue' not accessible: 'Error'");

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mtdebug1, formatted_msg, "Microsoft Graph API Log URL: 'https://graph.microsoft.com/v1.0/deviceManagement/detectedApps/12345/managedDevices?$top=10&$select=id,deviceName'");

    expect_any(__wrap_wurl_http_request, method);
    expect_any(__wrap_wurl_http_request, header);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_MS_GRAPH_DEFAULT_TIMEOUT);
    expect_any(__wrap_wurl_http_request, ssl_verify);
    will_return(__wrap_wurl_http_request, response2);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mtdebug1, formatted_msg, "Microsoft Graph API Log URL: 'next_page_url'");

    expect_any(__wrap_wurl_http_request, method);
    expect_any(__wrap_wurl_http_request, header);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_MS_GRAPH_DEFAULT_TIMEOUT);
    expect_any(__wrap_wurl_http_request, ssl_verify);
    will_return(__wrap_wurl_http_request, response3);

    expect_string(__wrap__mtdebug2, tag, "wazuh-modulesd:ms-graph");
#ifdef TEST_WINAGENT
    expect_string(__wrap__mtdebug2, formatted_msg, "Sending log: '{\"scan_id\":1234512345,\"integration\":\"ms-graph\",\"ms-graph\":{\"full_log\":\"log2\",\"id\":\"12345\",\"managedDevices\":[{\"id\":\"2345\"},{\"name\":\"test\"},{\"id\":\"3456\"}],\"resource\":\"deviceManagement\",\"relationship\":\"detectedApps\"}}'");
#else
    expect_string(__wrap__mtdebug2, formatted_msg, "Sending log: '{\"scan_id\":12345,\"integration\":\"ms-graph\",\"ms-graph\":{\"full_log\":\"log2\",\"id\":\"12345\",\"managedDevices\":[{\"id\":\"2345\"},{\"name\":\"test\"},{\"id\":\"3456\"}],\"resource\":\"deviceManagement\",\"relationship\":\"detectedApps\"}}'");
#endif

    expect_value(__wrap_wm_sendmsg, usec, 1000000);
    expect_value(__wrap_wm_sendmsg, queue, queue_fd);
#ifdef TEST_WINAGENT
    expect_string(__wrap_wm_sendmsg, message, "{\"scan_id\":1234512345,\"integration\":\"ms-graph\",\"ms-graph\":{\"full_log\":\"log2\",\"id\":\"12345\",\"managedDevices\":[{\"id\":\"2345\"},{\"name\":\"test\"},{\"id\":\"3456\"}],\"resource\":\"deviceManagement\",\"relationship\":\"detectedApps\"}}");
#else
    expect_string(__wrap_wm_sendmsg, message, "{\"scan_id\":12345,\"integration\":\"ms-graph\",\"ms-graph\":{\"full_log\":\"log2\",\"id\":\"12345\",\"managedDevices\":[{\"id\":\"2345\"},{\"name\":\"test\"},{\"id\":\"3456\"}],\"resource\":\"deviceManagement\",\"relationship\":\"detectedApps\"}}");
#endif
    expect_string(__wrap_wm_sendmsg, locmsg, "ms-graph");
    expect_value(__wrap_wm_sendmsg, loc, LOCALFILE_MQ);
    will_return(__wrap_wm_sendmsg, 1);

    wm_ms_graph_scan_relationships(module_data, module_data->auth_config[0], initial);
}

void test_wm_ms_graph_scan_relationships_single_success_two_pages(void **state) {
    /*
    <enabled>yes</enabled>
    <only_future_events>no</only_future_events>
    <curl_max_size>1M</curl_max_size>
    <page_size>200</page_size>
    <time_delay>20</time_delay>
    <run_on_start>yes</run_on_start>
    <version>v1.0</version>
    <api_auth>
      <client_id>example_client</client_id>
      <tenant_id>example_tenant</tenant_id>
      <secret_value>example_secret</secret_value>
      <api_type>global</api_type>
    </api_auth>
    <resource>
      <name>deviceManagement</name>
      <relationship>managedDevices</relationship>
    </resource>
    */
    wm_ms_graph* module_data = (wm_ms_graph *)*state;
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config);
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config[0]);
    module_data->enabled = true;
    module_data->only_future_events = false;
    module_data->curl_max_size = 1024L;
    module_data->page_size = 200;
    module_data->time_delay = 20;
    module_data->run_on_start = true;
    module_data->scan_config.interval = 60;
    os_strdup("v1.0", module_data->version);
    os_strdup("example_client", module_data->auth_config[0]->client_id);
    os_strdup("example_tenant", module_data->auth_config[0]->tenant_id);
    os_strdup("example_secret", module_data->auth_config[0]->secret_value);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_LOGIN_FQDN, module_data->auth_config[0]->login_fqdn);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_QUERY_FQDN, module_data->auth_config[0]->query_fqdn);
    os_strdup("token", module_data->auth_config[0]->access_token);
    module_data->auth_config[0]->token_expiration_time = time(NULL) + 100;
    os_malloc(sizeof(wm_ms_graph_resource), module_data->resources);
    os_strdup("deviceManagement", module_data->resources[0].name);
    module_data->num_resources = 1;
    os_malloc(sizeof(char*), module_data->resources[0].relationships);
    os_strdup("managedDevices", module_data->resources[0].relationships[0]);
    module_data->resources[0].num_relationships = 1;
    size_t max_size = OS_SIZE_8192;
    bool initial = false;
    curl_response* response;
    curl_response* response2;
    wm_max_eps = 1;

    os_calloc(1, sizeof(curl_response), response);
    response->status_code = 200;
    response->max_size_reached = false;
    os_strdup("{\"@odata.nextLink\":\"next_page_url\",\"value\":[{\"full_log\":\"log1\"},{\"full_log\":\"log2\"}]}", response->body);
    os_strdup("test", response->header);

#ifdef TEST_WINAGENT
    will_return_count(__wrap_os_random, 12345, 2);
#else
    will_return(__wrap_os_random, 12345);
#endif

    os_calloc(1, sizeof(curl_response), response2);
    response2->status_code = 200;
    response2->max_size_reached = false;
    os_strdup("{\"value\":[{\"full_log\":\"log3\"}]}", response2->body);
    os_strdup("test2", response2->header);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mtdebug1, formatted_msg, "Microsoft Graph API Log URL: 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$top=200'");

    expect_any(__wrap_wurl_http_request, method);
    expect_any(__wrap_wurl_http_request, header);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_MS_GRAPH_DEFAULT_TIMEOUT);
    expect_any(__wrap_wurl_http_request, ssl_verify);
    will_return(__wrap_wurl_http_request, response);

    expect_string(__wrap__mtdebug2, tag, "wazuh-modulesd:ms-graph");
#ifdef TEST_WINAGENT
    expect_string(__wrap__mtdebug2, formatted_msg, "Sending log: '{\"scan_id\":1234512345,\"integration\":\"ms-graph\",\"ms-graph\":{\"full_log\":\"log1\",\"resource\":\"deviceManagement\",\"relationship\":\"managedDevices\"}}'");
#else
    expect_string(__wrap__mtdebug2, formatted_msg, "Sending log: '{\"scan_id\":12345,\"integration\":\"ms-graph\",\"ms-graph\":{\"full_log\":\"log1\",\"resource\":\"deviceManagement\",\"relationship\":\"managedDevices\"}}'");
#endif

    queue_fd = 0;
    expect_value(__wrap_wm_sendmsg, usec, 1000000);
    expect_value(__wrap_wm_sendmsg, queue, queue_fd);
#ifdef TEST_WINAGENT
    expect_string(__wrap_wm_sendmsg, message, "{\"scan_id\":1234512345,\"integration\":\"ms-graph\",\"ms-graph\":{\"full_log\":\"log1\",\"resource\":\"deviceManagement\",\"relationship\":\"managedDevices\"}}");
#else
    expect_string(__wrap_wm_sendmsg, message, "{\"scan_id\":12345,\"integration\":\"ms-graph\",\"ms-graph\":{\"full_log\":\"log1\",\"resource\":\"deviceManagement\",\"relationship\":\"managedDevices\"}}");
#endif
    expect_string(__wrap_wm_sendmsg, locmsg, "ms-graph");
    expect_value(__wrap_wm_sendmsg, loc, LOCALFILE_MQ);
    will_return(__wrap_wm_sendmsg, -1);

    will_return(__wrap_strerror, "Error");

    expect_string(__wrap__mterror, tag, WM_MS_GRAPH_LOGTAG);
    expect_string(__wrap__mterror, formatted_msg, "(1210): Queue 'queue/sockets/queue' not accessible: 'Error'");

    expect_string(__wrap__mtdebug2, tag, "wazuh-modulesd:ms-graph");
#ifdef TEST_WINAGENT
    expect_string(__wrap__mtdebug2, formatted_msg, "Sending log: '{\"scan_id\":1234512345,\"integration\":\"ms-graph\",\"ms-graph\":{\"full_log\":\"log2\",\"resource\":\"deviceManagement\",\"relationship\":\"managedDevices\"}}'");
#else
    expect_string(__wrap__mtdebug2, formatted_msg, "Sending log: '{\"scan_id\":12345,\"integration\":\"ms-graph\",\"ms-graph\":{\"full_log\":\"log2\",\"resource\":\"deviceManagement\",\"relationship\":\"managedDevices\"}}'");
#endif

    expect_value(__wrap_wm_sendmsg, usec, 1000000);
    expect_value(__wrap_wm_sendmsg, queue, queue_fd);
#ifdef TEST_WINAGENT
    expect_string(__wrap_wm_sendmsg, message, "{\"scan_id\":1234512345,\"integration\":\"ms-graph\",\"ms-graph\":{\"full_log\":\"log2\",\"resource\":\"deviceManagement\",\"relationship\":\"managedDevices\"}}");
#else
    expect_string(__wrap_wm_sendmsg, message, "{\"scan_id\":12345,\"integration\":\"ms-graph\",\"ms-graph\":{\"full_log\":\"log2\",\"resource\":\"deviceManagement\",\"relationship\":\"managedDevices\"}}");
#endif
    expect_string(__wrap_wm_sendmsg, locmsg, "ms-graph");
    expect_value(__wrap_wm_sendmsg, loc, LOCALFILE_MQ);
    will_return(__wrap_wm_sendmsg, 1);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mtdebug1, formatted_msg, "Microsoft Graph API Log URL: 'next_page_url'");

    expect_any(__wrap_wurl_http_request, method);
    expect_any(__wrap_wurl_http_request, header);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_MS_GRAPH_DEFAULT_TIMEOUT);
    expect_any(__wrap_wurl_http_request, ssl_verify);
    will_return(__wrap_wurl_http_request, response2);

    expect_string(__wrap__mtdebug2, tag, "wazuh-modulesd:ms-graph");
#ifdef TEST_WINAGENT
    expect_string(__wrap__mtdebug2, formatted_msg, "Sending log: '{\"scan_id\":1234512345,\"integration\":\"ms-graph\",\"ms-graph\":{\"full_log\":\"log3\",\"resource\":\"deviceManagement\",\"relationship\":\"managedDevices\"}}'");
#else
    expect_string(__wrap__mtdebug2, formatted_msg, "Sending log: '{\"scan_id\":12345,\"integration\":\"ms-graph\",\"ms-graph\":{\"full_log\":\"log3\",\"resource\":\"deviceManagement\",\"relationship\":\"managedDevices\"}}'");
#endif

    queue_fd = 0;
    expect_value(__wrap_wm_sendmsg, usec, 1000000);
    expect_value(__wrap_wm_sendmsg, queue, queue_fd);
#ifdef TEST_WINAGENT
    expect_string(__wrap_wm_sendmsg, message, "{\"scan_id\":1234512345,\"integration\":\"ms-graph\",\"ms-graph\":{\"full_log\":\"log3\",\"resource\":\"deviceManagement\",\"relationship\":\"managedDevices\"}}");
#else
    expect_string(__wrap_wm_sendmsg, message, "{\"scan_id\":12345,\"integration\":\"ms-graph\",\"ms-graph\":{\"full_log\":\"log3\",\"resource\":\"deviceManagement\",\"relationship\":\"managedDevices\"}}");
#endif
    expect_string(__wrap_wm_sendmsg, locmsg, "ms-graph");
    expect_value(__wrap_wm_sendmsg, loc, LOCALFILE_MQ);
    will_return(__wrap_wm_sendmsg, 1);

    wm_ms_graph_scan_relationships(module_data, module_data->auth_config[0], initial);
}

void test_wm_ms_graph_scan_relationships_single_success_two_resources(void **state) {
    /*
    <enabled>yes</enabled>
    <only_future_events>no</only_future_events>
    <curl_max_size>1M</curl_max_size>
    <page_size>200</page_size>
    <time_delay>20</time_delay>
    <run_on_start>yes</run_on_start>
    <version>v1.0</version>
    <api_auth>
      <client_id>example_client</client_id>
      <tenant_id>example_tenant</tenant_id>
      <secret_value>example_secret</secret_value>
      <api_type>global</api_type>
    </api_auth>
    <resource>
      <name>identityProtection</name>
      <relationship>riskDetections</relationship>
    </resource>
    <resource>
      <name>deviceManagement</name>
      <relationship>auditEvents</relationship>
    </resource>
    */
    wm_ms_graph* module_data = (wm_ms_graph *)*state;
    wm_ms_graph_state_t relationship_state_struc;
    wm_ms_graph_state_t relationship_state_struc_2;
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config);
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config[0]);
    relationship_state_struc.next_time = 10;
    relationship_state_struc_2.next_time = 10;
    module_data->enabled = true;
    module_data->only_future_events = false;
    module_data->curl_max_size = 1024L;
    module_data->page_size = 200;
    module_data->time_delay = 20;
    module_data->run_on_start = true;
    module_data->scan_config.interval = 60;
    os_strdup("v1.0", module_data->version);
    os_strdup("example_client", module_data->auth_config[0]->client_id);
    os_strdup("example_tenant", module_data->auth_config[0]->tenant_id);
    os_strdup("example_secret", module_data->auth_config[0]->secret_value);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_LOGIN_FQDN, module_data->auth_config[0]->login_fqdn);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_QUERY_FQDN, module_data->auth_config[0]->query_fqdn);
    os_strdup("token", module_data->auth_config[0]->access_token);
    module_data->auth_config[0]->token_expiration_time = time(NULL) + 100;
    os_malloc(sizeof(wm_ms_graph_resource) * 2, module_data->resources);
    os_strdup("identityProtection", module_data->resources[0].name);
    os_strdup("deviceManagement", module_data->resources[1].name);
    module_data->num_resources = 2;
    os_malloc(sizeof(char*) * 2, module_data->resources[0].relationships);
    os_strdup("riskDetections", module_data->resources[0].relationships[0]);
    module_data->resources[0].num_relationships = 1;
    os_malloc(sizeof(char*) * 2, module_data->resources[1].relationships);
    os_strdup("auditEvents", module_data->resources[1].relationships[0]);
    module_data->resources[1].num_relationships = 1;
    size_t max_size = OS_SIZE_8192;
    bool initial = false;
    curl_response* response;
    wm_max_eps = 1;

    os_calloc(1, sizeof(curl_response), response);
    response->status_code = 200;
    response->max_size_reached = false;
    os_strdup("{\"value\":[{\"full_log\":\"log1\"}]}", response->body);
    os_strdup("test", response->header);

#ifdef TEST_WINAGENT
    will_return_count(__wrap_os_random, 12345, 2);
#else
    will_return(__wrap_os_random, 12345);
#endif

    expect_string(__wrap_wm_state_io, tag, "ms-graph-example_tenant-identityProtection-riskDetections");
    expect_value(__wrap_wm_state_io, op, WM_IO_READ);
    expect_any(__wrap_wm_state_io, state);
    expect_any(__wrap_wm_state_io, size);
    will_return(__wrap_wm_state_io, 0);
    will_return(__wrap_wm_state_io, (void *)&relationship_state_struc);

#ifndef WIN32
    will_return(__wrap_gmtime_r, 1);
#endif
    will_return(__wrap_strftime,"2023-02-08T12:24:56Z");
    will_return(__wrap_strftime, 20);

#ifndef WIN32
    will_return(__wrap_gmtime_r, 1);
#endif
    will_return(__wrap_strftime,"2023-02-08T12:25:56Z");
    will_return(__wrap_strftime, 20);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mtdebug1, formatted_msg, "Microsoft Graph API Log URL: 'https://graph.microsoft.com/v1.0/identityProtection/riskDetections?$top=200&$filter=activityDateTime+ge+2023-02-08T12:24:56Z+and+activityDateTime+lt+2023-02-08T12:25:56Z'");

    expect_any(__wrap_wurl_http_request, method);
    expect_any(__wrap_wurl_http_request, header);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_MS_GRAPH_DEFAULT_TIMEOUT);
    expect_any(__wrap_wurl_http_request, ssl_verify);
    will_return(__wrap_wurl_http_request, response);

    expect_string(__wrap__mtdebug2, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mtdebug2, formatted_msg, "Sending log: '{\"integration\":\"ms-graph\",\"ms-graph\":{\"full_log\":\"log1\",\"resource\":\"identityProtection\",\"relationship\":\"riskDetections\"}}'");

    queue_fd = 0;
    expect_value(__wrap_wm_sendmsg, usec, 1000000);
    expect_value(__wrap_wm_sendmsg, queue, queue_fd);
    expect_string(__wrap_wm_sendmsg, message, "{\"integration\":\"ms-graph\",\"ms-graph\":{\"full_log\":\"log1\",\"resource\":\"identityProtection\",\"relationship\":\"riskDetections\"}}");
    expect_string(__wrap_wm_sendmsg, locmsg, "ms-graph");
    expect_value(__wrap_wm_sendmsg, loc, LOCALFILE_MQ);
    will_return(__wrap_wm_sendmsg, 1);

    expect_string(__wrap_wm_state_io, tag, "ms-graph-example_tenant-identityProtection-riskDetections");
    expect_value(__wrap_wm_state_io, op, WM_IO_WRITE);
    expect_any(__wrap_wm_state_io, state);
    expect_any(__wrap_wm_state_io, size);
    will_return(__wrap_wm_state_io, 1);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mtdebug1, formatted_msg, "Bookmark updated to '2023-02-08T12:25:56Z' for tenant 'example_tenant' resource 'identityProtection' and relationship 'riskDetections', waiting '60' seconds to run next scan.");

    // resource auditlogs
    os_calloc(1, sizeof(curl_response), response);
    response->status_code = 200;
    response->max_size_reached = false;
    os_strdup("{\"value\":[{\"full_log\":\"log1_resource_2\"}]}", response->body);
    os_strdup("test", response->header);

    expect_string(__wrap_wm_state_io, tag, "ms-graph-example_tenant-deviceManagement-auditEvents");
    expect_value(__wrap_wm_state_io, op, WM_IO_READ);
    expect_any(__wrap_wm_state_io, state);
    expect_any(__wrap_wm_state_io, size);
    will_return(__wrap_wm_state_io, 0);
    will_return(__wrap_wm_state_io, (void *)&relationship_state_struc_2);

#ifndef WIN32
    will_return(__wrap_gmtime_r, 1);
#endif
    will_return(__wrap_strftime,"2023-02-08T12:24:56Z");
    will_return(__wrap_strftime, 20);

#ifndef WIN32
    will_return(__wrap_gmtime_r, 1);
#endif
    will_return(__wrap_strftime,"2023-02-08T12:25:56Z");
    will_return(__wrap_strftime, 20);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mtdebug1, formatted_msg, "Microsoft Graph API Log URL: 'https://graph.microsoft.com/v1.0/deviceManagement/auditEvents?$top=200&$filter=activityDateTime+ge+2023-02-08T12:24:56Z+and+activityDateTime+lt+2023-02-08T12:25:56Z'");

    expect_any(__wrap_wurl_http_request, method);
    expect_any(__wrap_wurl_http_request, header);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_MS_GRAPH_DEFAULT_TIMEOUT);
    expect_any(__wrap_wurl_http_request, ssl_verify);
    will_return(__wrap_wurl_http_request, response);

    expect_string(__wrap__mtdebug2, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mtdebug2, formatted_msg, "Sending log: '{\"integration\":\"ms-graph\",\"ms-graph\":{\"full_log\":\"log1_resource_2\",\"resource\":\"deviceManagement\",\"relationship\":\"auditEvents\"}}'");

    queue_fd = 0;
    expect_value(__wrap_wm_sendmsg, usec, 1000000);
    expect_value(__wrap_wm_sendmsg, queue, queue_fd);
    expect_string(__wrap_wm_sendmsg, message, "{\"integration\":\"ms-graph\",\"ms-graph\":{\"full_log\":\"log1_resource_2\",\"resource\":\"deviceManagement\",\"relationship\":\"auditEvents\"}}");
    expect_string(__wrap_wm_sendmsg, locmsg, "ms-graph");
    expect_value(__wrap_wm_sendmsg, loc, LOCALFILE_MQ);
    will_return(__wrap_wm_sendmsg, 1);

    expect_string(__wrap_wm_state_io, tag, "ms-graph-example_tenant-deviceManagement-auditEvents");
    expect_value(__wrap_wm_state_io, op, WM_IO_WRITE);
    expect_any(__wrap_wm_state_io, state);
    expect_any(__wrap_wm_state_io, size);
    will_return(__wrap_wm_state_io, -1);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mterror, formatted_msg, "Couldn't save running state.");

    wm_ms_graph_scan_relationships(module_data, module_data->auth_config[0], initial);
}

void test_wm_ms_graph_scan_relationships_renew_token(void **state) {
    /*
    <enabled>yes</enabled>
    <only_future_events>no</only_future_events>
    <curl_max_size>1M</curl_max_size>
    <page_size>10</page_size>
    <time_delay>1</time_delay>
    <run_on_start>yes</run_on_start>
    <version>v1.0</version>
    <api_auth>
      <client_id>example_client</client_id>
      <tenant_id>example_tenant</tenant_id>
      <secret_value>example_secret</secret_value>
      <api_type>global</api_type>
    </api_auth>
    <resource>
      <name>security</name>
      <relationship>alerts_v2</relationship>
    </resource>
    */
    wm_ms_graph* module_data = (wm_ms_graph *)*state;
    wm_ms_graph_state_t relationship_state_struc;
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config);
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config[0]);
    relationship_state_struc.next_time = 10;
    module_data->enabled = true;
    module_data->only_future_events = false;
    module_data->curl_max_size = 1024L;
    module_data->page_size = 10;
    module_data->time_delay = 1;
    module_data->run_on_start = true;
    module_data->scan_config.interval = 60;
    os_strdup("v1.0", module_data->version);
    os_strdup("example_client", module_data->auth_config[0]->client_id);
    os_strdup("example_tenant", module_data->auth_config[0]->tenant_id);
    os_strdup("example_secret", module_data->auth_config[0]->secret_value);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_LOGIN_FQDN, module_data->auth_config[0]->login_fqdn);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_QUERY_FQDN, module_data->auth_config[0]->query_fqdn);
    os_strdup("token", module_data->auth_config[0]->access_token);
    module_data->auth_config[0]->token_expiration_time = time(NULL) + (WM_MS_GRAPH_DEFAULT_TIMEOUT - 30);
    os_malloc(sizeof(wm_ms_graph_resource), module_data->resources);
    os_strdup("security", module_data->resources[0].name);
    module_data->num_resources = 1;
    os_malloc(sizeof(char*), module_data->resources[0].relationships);
    os_strdup("alerts_v2", module_data->resources[0].relationships[0]);
    module_data->resources[0].num_relationships = 1;
    size_t max_size = OS_SIZE_8192;
    bool initial = false;
    curl_response* response;
    wm_max_eps = 1;

    os_calloc(1, sizeof(curl_response), response);
    response->status_code = 200;
    response->max_size_reached = false;
    os_strdup("{\"value\":[{\"full_log\":\"log1\"}]}", response->body);
    os_strdup("test", response->header);

#ifdef TEST_WINAGENT
    will_return_count(__wrap_os_random, 12345, 2);
#else
    will_return(__wrap_os_random, 12345);
#endif

    expect_string(__wrap_wm_state_io, tag, "ms-graph-example_tenant-security-alerts_v2");
    expect_value(__wrap_wm_state_io, op, WM_IO_READ);
    expect_any(__wrap_wm_state_io, state);
    expect_any(__wrap_wm_state_io, size);
    will_return(__wrap_wm_state_io, 0);
    will_return(__wrap_wm_state_io, (void *)&relationship_state_struc);

#ifndef WIN32
    will_return(__wrap_gmtime_r, 1);
#endif
    will_return(__wrap_strftime,"2023-02-08T12:24:56Z");
    will_return(__wrap_strftime, 20);

#ifndef WIN32
    will_return(__wrap_gmtime_r, 1);
#endif
    will_return(__wrap_strftime,"2023-02-08T12:25:56Z");
    will_return(__wrap_strftime, 20);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mtdebug1, formatted_msg, "Microsoft Graph API Log URL: 'https://graph.microsoft.com/v1.0/security/alerts_v2?$top=10&$filter=createdDateTime+ge+2023-02-08T12:24:56Z+and+createdDateTime+lt+2023-02-08T12:25:56Z'");

    // -----------wm_ms_graph_ensure_valid_token-----------------------
    expect_string(__wrap__mtinfo, tag, WM_MS_GRAPH_LOGTAG);
    expect_string(__wrap__mtinfo, formatted_msg, "Access token expired or missing. Requesting new token.");

    expect_string(__wrap__mtdebug1, tag, WM_MS_GRAPH_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Microsoft Graph API Access Token URL: 'https://login.microsoftonline.com/example_tenant/oauth2/v2.0/token'");

    time_t new_token_expiration_time = time(NULL) + 3600;
    curl_response* response_new_token;
    os_calloc(1, sizeof(curl_response), response_new_token);
    response_new_token->status_code = 200;
    response_new_token->max_size_reached = false;
    char response_new_token_body[256];
    snprintf(response_new_token_body, sizeof(response_new_token_body),
            "{\"access_token\":\"new_token\",\"expires_in\":%ld}", (long)new_token_expiration_time);

    os_strdup(response_new_token_body, response_new_token->body);
    expect_any(__wrap_wurl_http_request, method);
    expect_any(__wrap_wurl_http_request, header);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_MS_GRAPH_DEFAULT_TIMEOUT);
    expect_any(__wrap_wurl_http_request, ssl_verify);
    will_return(__wrap_wurl_http_request, response_new_token);
    // -----------END wm_ms_graph_ensure_valid_token-----------------------

    expect_any(__wrap_wurl_http_request, method);
    // Checking that the Authorization header uses the new token
    expect_string(__wrap_wurl_http_request, header, "Authorization: Bearer new_token");
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_MS_GRAPH_DEFAULT_TIMEOUT);
    expect_any(__wrap_wurl_http_request, ssl_verify);
    will_return(__wrap_wurl_http_request, response);

    expect_string(__wrap__mtdebug2, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mtdebug2, formatted_msg, "Sending log: '{\"integration\":\"ms-graph\",\"ms-graph\":{\"full_log\":\"log1\",\"resource\":\"security\",\"relationship\":\"alerts_v2\"}}'");

    int result = 1;
    queue_fd = 0;
    expect_value(__wrap_wm_sendmsg, usec, 1000000);
    expect_value(__wrap_wm_sendmsg, queue, queue_fd);
    expect_string(__wrap_wm_sendmsg, message, "{\"integration\":\"ms-graph\",\"ms-graph\":{\"full_log\":\"log1\",\"resource\":\"security\",\"relationship\":\"alerts_v2\"}}");
    expect_string(__wrap_wm_sendmsg, locmsg, "ms-graph");
    expect_value(__wrap_wm_sendmsg, loc, LOCALFILE_MQ);
    will_return(__wrap_wm_sendmsg, result);

    expect_string(__wrap_wm_state_io, tag, "ms-graph-example_tenant-security-alerts_v2");
    expect_value(__wrap_wm_state_io, op, WM_IO_WRITE);
    expect_any(__wrap_wm_state_io, state);
    expect_any(__wrap_wm_state_io, size);
    will_return(__wrap_wm_state_io, 1);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mtdebug1, formatted_msg, "Bookmark updated to '2023-02-08T12:25:56Z' for tenant 'example_tenant' resource 'security' and relationship 'alerts_v2', waiting '60' seconds to run next scan.");

    wm_ms_graph_scan_relationships(module_data, module_data->auth_config[0], initial);
}

void test_wm_ms_graph_scan_relationships_renew_token_failed(void **state) {
    /*
    <enabled>yes</enabled>
    <only_future_events>no</only_future_events>
    <curl_max_size>1M</curl_max_size>
    <page_size>50</page_size>
    <time_delay>5</time_delay>
    <run_on_start>yes</run_on_start>
    <version>v1.0</version>
    <api_auth>
      <client_id>example_client</client_id>
      <tenant_id>example_tenant</tenant_id>
      <secret_value>example_secret</secret_value>
      <api_type>global</api_type>
    </api_auth>
    <resource>
      <name>security</name>
      <relationship>alerts_v2</relationship>
    </resource>
    */
    wm_ms_graph* module_data = (wm_ms_graph *)*state;
    wm_ms_graph_state_t relationship_state_struc;
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config);
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config[0]);
    relationship_state_struc.next_time = 10;
    module_data->enabled = true;
    module_data->only_future_events = false;
    module_data->curl_max_size = 1024L;
    module_data->page_size = 50;
    module_data->time_delay = 5;
    module_data->run_on_start = true;
    module_data->scan_config.interval = 60;
    os_strdup("v1.0", module_data->version);
    os_strdup("example_client", module_data->auth_config[0]->client_id);
    os_strdup("example_tenant", module_data->auth_config[0]->tenant_id);
    os_strdup("example_secret", module_data->auth_config[0]->secret_value);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_LOGIN_FQDN, module_data->auth_config[0]->login_fqdn);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_QUERY_FQDN, module_data->auth_config[0]->query_fqdn);
    os_strdup("token", module_data->auth_config[0]->access_token);
    module_data->auth_config[0]->token_expiration_time = time(NULL);
    os_malloc(sizeof(wm_ms_graph_resource), module_data->resources);
    os_strdup("security", module_data->resources[0].name);
    module_data->num_resources = 1;
    os_malloc(sizeof(char*), module_data->resources[0].relationships);
    os_strdup("alerts_v2", module_data->resources[0].relationships[0]);
    module_data->resources[0].num_relationships = 1;
    size_t max_size = OS_SIZE_8192;
    bool initial = true;

#ifdef TEST_WINAGENT
    will_return_count(__wrap_os_random, 12345, 2);
#else
    will_return(__wrap_os_random, 12345);
#endif

    expect_string(__wrap_wm_state_io, tag, "ms-graph-example_tenant-security-alerts_v2");
    expect_value(__wrap_wm_state_io, op, WM_IO_READ);
    expect_any(__wrap_wm_state_io, state);
    expect_any(__wrap_wm_state_io, size);
    will_return(__wrap_wm_state_io, 0);
    will_return(__wrap_wm_state_io, (void *)&relationship_state_struc);

#ifndef WIN32
    will_return(__wrap_gmtime_r, 1);
#endif
    will_return(__wrap_strftime,"2023-02-08T12:24:56Z");
    will_return(__wrap_strftime, 20);

#ifndef WIN32
    will_return(__wrap_gmtime_r, 1);
#endif
    will_return(__wrap_strftime,"2023-02-08T12:25:56Z");
    will_return(__wrap_strftime, 20);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mtdebug1, formatted_msg, "Microsoft Graph API Log URL: 'https://graph.microsoft.com/v1.0/security/alerts_v2?$top=50&$filter=createdDateTime+ge+2023-02-08T12:24:56Z+and+createdDateTime+lt+2023-02-08T12:25:56Z'");

    // -----------wm_ms_graph_ensure_valid_token-----------------------
    expect_string(__wrap__mtinfo, tag, WM_MS_GRAPH_LOGTAG);
    expect_string(__wrap__mtinfo, formatted_msg, "Access token expired or missing. Requesting new token.");

    curl_response* response;

    os_calloc(1, sizeof(curl_response), response);
    response->status_code = 200;
    response->max_size_reached = false;
    os_strdup("no json", response->body);
    os_strdup("test", response->header);

    expect_string(__wrap__mtdebug1, tag, WM_MS_GRAPH_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Microsoft Graph API Access Token URL: 'https://login.microsoftonline.com/example_tenant/oauth2/v2.0/token'");

    expect_any(__wrap_wurl_http_request, method);
    expect_any(__wrap_wurl_http_request, header);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_MS_GRAPH_DEFAULT_TIMEOUT);
    expect_any(__wrap_wurl_http_request, ssl_verify);
    will_return(__wrap_wurl_http_request, response);
    expect_string(__wrap__mtwarn, tag, WM_MS_GRAPH_LOGTAG);
    expect_string(__wrap__mtwarn, formatted_msg, "Failed to parse access token JSON body.");

    expect_string(__wrap__mtwarn, tag, WM_MS_GRAPH_LOGTAG);
    expect_string(__wrap__mtwarn, formatted_msg, "Failed to renew access token.");
    // -----------END wm_ms_graph_ensure_valid_token-----------------------

    expect_string(__wrap__mtwarn, tag, WM_MS_GRAPH_LOGTAG);
    expect_string(__wrap__mtwarn, formatted_msg, "Aborting scan of 'alerts_v2' for tenant 'example_tenant' due to access token error.");

    wm_ms_graph_scan_relationships(module_data, module_data->auth_config[0], initial);
}

static void test_wm_ms_graph_scan_apps_devices_renew_token(void **state) {
    /*
    <enabled>yes</enabled>
    <only_future_events>no</only_future_events>
    <curl_max_size>1M</curl_max_size>
    <page_size>10</page_size>
    <time_delay>1</time_delay>
    <run_on_start>yes</run_on_start>
    <version>v1.0</version>
    <api_auth>
      <client_id>example_client</client_id>
      <tenant_id>example_tenant</tenant_id>
      <secret_value>example_secret</secret_value>
      <api_type>global</api_type>
    </api_auth>
    <resource>
      <name>deviceManagement</name>
      <relationship>detectedApps</relationship>
    </resource>
    */
    wm_ms_graph* module_data = (wm_ms_graph *)*state;
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config);
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config[0]);
    module_data->enabled = true;
    module_data->only_future_events = false;
    module_data->curl_max_size = 1024L;
    module_data->page_size = 10;
    module_data->time_delay = 1;
    module_data->run_on_start = true;
    module_data->scan_config.interval = 60;
    os_strdup("v1.0", module_data->version);
    os_strdup("example_client", module_data->auth_config[0]->client_id);
    os_strdup("example_tenant", module_data->auth_config[0]->tenant_id);
    os_strdup("example_secret", module_data->auth_config[0]->secret_value);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_LOGIN_FQDN, module_data->auth_config[0]->login_fqdn);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_QUERY_FQDN, module_data->auth_config[0]->query_fqdn);
    os_strdup("token", module_data->auth_config[0]->access_token);
    module_data->auth_config[0]->token_expiration_time = time(NULL);
    os_malloc(sizeof(wm_ms_graph_resource), module_data->resources);
    os_strdup("deviceManagement", module_data->resources[0].name);
    module_data->num_resources = 1;
    os_malloc(sizeof(char*), module_data->resources[0].relationships);
    os_strdup("detectedApps", module_data->resources[0].relationships[0]);
    module_data->resources[0].num_relationships = 1;
    size_t max_size = OS_SIZE_8192;
    bool initial = false;
    curl_response* response;
    wm_max_eps = 1;

    os_calloc(1, sizeof(curl_response), response);
    response->status_code = 200;
    response->max_size_reached = false;
    os_strdup("{\"value\":[{\"id\":\"3456\"}]}", response->body);
    os_strdup("test", response->header);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mtdebug1, formatted_msg, "Microsoft Graph API Log URL: 'https://graph.microsoft.com/v1.0/deviceManagement/detectedApps/12345/managedDevices?$top=10&$select=id,deviceName'");

    // -----------wm_ms_graph_ensure_valid_token-----------------------
    expect_string(__wrap__mtinfo, tag, WM_MS_GRAPH_LOGTAG);
    expect_string(__wrap__mtinfo, formatted_msg, "Access token expired or missing. Requesting new token.");

    expect_string(__wrap__mtdebug1, tag, WM_MS_GRAPH_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Microsoft Graph API Access Token URL: 'https://login.microsoftonline.com/example_tenant/oauth2/v2.0/token'");

    time_t new_token_expiration_time = time(NULL) + 3600;
    curl_response* response_new_token;
    os_calloc(1, sizeof(curl_response), response_new_token);
    response_new_token->status_code = 200;
    response_new_token->max_size_reached = false;
    char response_new_token_body[256];
    snprintf(response_new_token_body, sizeof(response_new_token_body),
            "{\"access_token\":\"new_token\",\"expires_in\":%ld}", (long)new_token_expiration_time);

    os_strdup(response_new_token_body, response_new_token->body);
    expect_any(__wrap_wurl_http_request, method);
    expect_any(__wrap_wurl_http_request, header);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_MS_GRAPH_DEFAULT_TIMEOUT);
    expect_any(__wrap_wurl_http_request, ssl_verify);
    will_return(__wrap_wurl_http_request, response_new_token);
    // -----------END wm_ms_graph_ensure_valid_token-----------------------

    expect_any(__wrap_wurl_http_request, method);
    expect_string(__wrap_wurl_http_request, header, "Authorization: Bearer new_token");
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_MS_GRAPH_DEFAULT_TIMEOUT);
    expect_any(__wrap_wurl_http_request, ssl_verify);
    will_return(__wrap_wurl_http_request, response);

    // Prepare headers
    char *headers[] = { NULL, NULL };
    char auth_header[OS_SIZE_8192] = { '\0' };
    snprintf(auth_header, OS_SIZE_8192 - 1, "Authorization: Bearer %s", module_data->auth_config[0]->access_token);
    os_strdup(auth_header, headers[0]);
    cJSON *app_id = cJSON_CreateString("12345");

    cJSON *result = wm_ms_graph_scan_apps_devices(module_data, app_id, module_data->auth_config[0]->query_fqdn, headers, module_data->auth_config[0]);

    assert_non_null(result);
    assert_string_equal(headers[0], "Authorization: Bearer new_token");
    cJSON_Delete(result);
    cJSON_Delete(app_id);
    os_free(headers[0]);
}

static void test_wm_ms_graph_scan_apps_devices_renew_token_failed(void **state) {
    /*
    <enabled>yes</enabled>
    <only_future_events>no</only_future_events>
    <curl_max_size>1M</curl_max_size>
    <page_size>10</page_size>
    <time_delay>1</time_delay>
    <run_on_start>yes</run_on_start>
    <version>v1.0</version>
    <api_auth>
      <client_id>example_client</client_id>
      <tenant_id>example_tenant</tenant_id>
      <secret_value>example_secret</secret_value>
      <api_type>global</api_type>
    </api_auth>
    <resource>
      <name>deviceManagement</name>
      <relationship>detectedApps</relationship>
    </resource>
    */
    wm_ms_graph* module_data = (wm_ms_graph *)*state;
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config);
    os_calloc(1, sizeof(wm_ms_graph_auth), module_data->auth_config[0]);
    module_data->enabled = true;
    module_data->only_future_events = false;
    module_data->curl_max_size = 1024L;
    module_data->page_size = 10;
    module_data->time_delay = 1;
    module_data->run_on_start = true;
    module_data->scan_config.interval = 60;
    os_strdup("v1.0", module_data->version);
    os_strdup("example_client", module_data->auth_config[0]->client_id);
    os_strdup("example_tenant", module_data->auth_config[0]->tenant_id);
    os_strdup("example_secret", module_data->auth_config[0]->secret_value);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_LOGIN_FQDN, module_data->auth_config[0]->login_fqdn);
    os_strdup(WM_MS_GRAPH_GLOBAL_API_QUERY_FQDN, module_data->auth_config[0]->query_fqdn);
    os_strdup("token", module_data->auth_config[0]->access_token);
    module_data->auth_config[0]->token_expiration_time = time(NULL);
    os_malloc(sizeof(wm_ms_graph_resource), module_data->resources);
    os_strdup("deviceManagement", module_data->resources[0].name);
    module_data->num_resources = 1;
    os_malloc(sizeof(char*), module_data->resources[0].relationships);
    os_strdup("detectedApps", module_data->resources[0].relationships[0]);
    module_data->resources[0].num_relationships = 1;
    size_t max_size = OS_SIZE_8192;
    bool initial = false;
    wm_max_eps = 1;

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mtdebug1, formatted_msg, "Microsoft Graph API Log URL: 'https://graph.microsoft.com/v1.0/deviceManagement/detectedApps/12345/managedDevices?$top=10&$select=id,deviceName'");

    // -----------wm_ms_graph_ensure_valid_token-----------------------
    expect_string(__wrap__mtinfo, tag, WM_MS_GRAPH_LOGTAG);
    expect_string(__wrap__mtinfo, formatted_msg, "Access token expired or missing. Requesting new token.");

    curl_response* response;

    os_calloc(1, sizeof(curl_response), response);
    response->status_code = 200;
    response->max_size_reached = false;
    os_strdup("no json", response->body);
    os_strdup("test", response->header);

    expect_string(__wrap__mtdebug1, tag, WM_MS_GRAPH_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Microsoft Graph API Access Token URL: 'https://login.microsoftonline.com/example_tenant/oauth2/v2.0/token'");

    expect_any(__wrap_wurl_http_request, method);
    expect_any(__wrap_wurl_http_request, header);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_MS_GRAPH_DEFAULT_TIMEOUT);
    expect_any(__wrap_wurl_http_request, ssl_verify);
    will_return(__wrap_wurl_http_request, response);
    expect_string(__wrap__mtwarn, tag, WM_MS_GRAPH_LOGTAG);
    expect_string(__wrap__mtwarn, formatted_msg, "Failed to parse access token JSON body.");

    expect_string(__wrap__mtwarn, tag, WM_MS_GRAPH_LOGTAG);
    expect_string(__wrap__mtwarn, formatted_msg, "Failed to renew access token.");
    // -----------END wm_ms_graph_ensure_valid_token-----------------------

    expect_string(__wrap__mtwarn, tag, WM_MS_GRAPH_LOGTAG);
    expect_string(__wrap__mtwarn, formatted_msg, "Aborting app-device scan due to access token error.");

    // Prepare headers
    char *headers[] = { NULL, NULL };
    char auth_header[OS_SIZE_8192] = { '\0' };
    snprintf(auth_header, OS_SIZE_8192 - 1, "Authorization: Bearer %s", module_data->auth_config[0]->access_token);
    os_strdup(auth_header, headers[0]);
    cJSON *app_id = cJSON_CreateString("12345");

    cJSON *result = wm_ms_graph_scan_apps_devices(module_data, app_id, module_data->auth_config[0]->query_fqdn, headers, module_data->auth_config[0]);

    assert_non_null(result);
    assert_int_equal(cJSON_GetArraySize(result), 0);
    cJSON_Delete(result);
    cJSON_Delete(app_id);
    os_free(headers[0]);
}

static void test_wm_ms_graph_ensure_valid_token_token_valid(void **state) {
    wm_ms_graph_auth auth = {0};
    auth.access_token = strdup("valid_token");
    auth.token_expiration_time = time(NULL) + 3600;

    bool token_changed = false;
    assert_true(wm_ms_graph_ensure_valid_token(&auth, 1024, &token_changed));
    assert_false(token_changed);
    os_free(auth.access_token);
}

static void test_wm_ms_graph_ensure_valid_token_token_expired_and_renewed(void **state) {
    wm_ms_graph_auth auth = {0};
    auth.access_token = strdup("expired_token");
    auth.token_expiration_time = time(NULL) - 10;
    auth.login_fqdn = strdup(WM_MS_GRAPH_GLOBAL_API_LOGIN_FQDN);
    auth.tenant_id = strdup("example_tenant");

    time_t new_token_expiration_time = time(NULL) + 3600;

    curl_response* response;
    os_calloc(1, sizeof(curl_response), response);
    response->status_code = 200;
    response->max_size_reached = false;
    char response_body[256];
    snprintf(response_body, sizeof(response_body),
            "{\"access_token\":\"new_token\",\"expires_in\":%ld}", (long)new_token_expiration_time);

    os_strdup(response_body, response->body);

    expect_string(__wrap__mtinfo, tag, WM_MS_GRAPH_LOGTAG);
    expect_string(__wrap__mtinfo, formatted_msg, "Access token expired or missing. Requesting new token.");

    expect_string(__wrap__mtdebug1, tag, WM_MS_GRAPH_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Microsoft Graph API Access Token URL: 'https://login.microsoftonline.com/example_tenant/oauth2/v2.0/token'");

    expect_any(__wrap_wurl_http_request, method);
    expect_any(__wrap_wurl_http_request, header);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_MS_GRAPH_DEFAULT_TIMEOUT);
    expect_any(__wrap_wurl_http_request, ssl_verify);
    will_return(__wrap_wurl_http_request, response);

    bool token_changed = false;
    assert_true(wm_ms_graph_ensure_valid_token(&auth, 1024, &token_changed));
    assert_string_equal(auth.access_token, "new_token");
    assert_true(token_changed);
    os_free(auth.client_id);
    os_free(auth.tenant_id);
    os_free(auth.secret_value);
    os_free(auth.access_token);
    os_free(auth.login_fqdn);
    os_free(auth.query_fqdn);
}

static void test_wm_ms_graph_ensure_valid_token_token_missing_and_renewed(void **state) {
    wm_ms_graph_auth auth = {0};
    auth.token_expiration_time = time(NULL) - 10;
    auth.login_fqdn = strdup(WM_MS_GRAPH_GLOBAL_API_LOGIN_FQDN);
    auth.tenant_id = strdup("example_tenant");

    time_t new_token_expiration_time = time(NULL) + 3600;

    curl_response* response;
    os_calloc(1, sizeof(curl_response), response);
    response->status_code = 200;
    response->max_size_reached = false;
    char response_body[256];
    snprintf(response_body, sizeof(response_body),
            "{\"access_token\":\"new_token\",\"expires_in\":%ld}", (long)new_token_expiration_time);

    os_strdup(response_body, response->body);

    expect_string(__wrap__mtinfo, tag, WM_MS_GRAPH_LOGTAG);
    expect_string(__wrap__mtinfo, formatted_msg, "Access token expired or missing. Requesting new token.");

    expect_string(__wrap__mtdebug1, tag, WM_MS_GRAPH_LOGTAG);
    expect_string(__wrap__mtdebug1, formatted_msg, "Microsoft Graph API Access Token URL: 'https://login.microsoftonline.com/example_tenant/oauth2/v2.0/token'");

    expect_any(__wrap_wurl_http_request, method);
    expect_any(__wrap_wurl_http_request, header);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_MS_GRAPH_DEFAULT_TIMEOUT);
    expect_any(__wrap_wurl_http_request, ssl_verify);
    will_return(__wrap_wurl_http_request, response);

    bool token_changed = false;
    assert_true(wm_ms_graph_ensure_valid_token(&auth, 1024, &token_changed));
    assert_string_equal(auth.access_token, "new_token");
    assert_true(token_changed);
    os_free(auth.client_id);
    os_free(auth.tenant_id);
    os_free(auth.secret_value);
    os_free(auth.access_token);
    os_free(auth.login_fqdn);
    os_free(auth.query_fqdn);
}

static void test_wm_ms_graph_ensure_valid_token_token_renewal_failed(void **state) {
    wm_ms_graph_auth auth = {0};
    auth.access_token = strdup("expired_token");
    auth.token_expiration_time = 0;

    expect_string(__wrap__mtinfo, tag, WM_MS_GRAPH_LOGTAG);
    expect_string(__wrap__mtinfo, formatted_msg, "Access token expired or missing. Requesting new token.");

    curl_response* response;
    os_calloc(1, sizeof(curl_response), response);
    response->status_code = 400;

    expect_any(__wrap_wurl_http_request, method);
    expect_any(__wrap_wurl_http_request, header);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_MS_GRAPH_DEFAULT_TIMEOUT);
    expect_any(__wrap_wurl_http_request, ssl_verify);
    will_return(__wrap_wurl_http_request, response);

    expect_string(__wrap__mtwarn, tag, WM_MS_GRAPH_LOGTAG);
    expect_string(__wrap__mtwarn, formatted_msg, "Failed to renew access token.");

    bool token_changed = false;
    assert_false(wm_ms_graph_ensure_valid_token(&auth, 1024, &token_changed));
    assert_string_equal(auth.access_token, "expired_token");
    assert_false(token_changed);
    os_free(auth.access_token);
}

int main(void) {
    const struct CMUnitTest tests_without_startup[] = {
        cmocka_unit_test(test_cleanup),
        cmocka_unit_test_setup_teardown(test_bad_tag, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_empty_module, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_invalid_enabled, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_enabled_no, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_invalid_only_future_events, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_disabled_only_future_events, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_invalid_curl_max_size, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_invalid_negative_curl_max_size, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_value_curl_max_size, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_invalid_run_on_start, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_disabled_run_on_start, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_invalid_version, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_missing_api_auth, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_empty_api_auth, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_invalid_client_id, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_missing_client_id, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_invalid_tenant_id, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_missing_tenant_id, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_invalid_secret_value, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_missing_secret_value, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_invalid_api_type, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_missing_api_type, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_empty_api_type, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_invalid_attribute_api_type, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_missing_resource, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_empty_resource, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_missing_name, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_empty_name, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_missing_relationship, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_empty_relationship, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_invalid_attribute_resource, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_normal_config, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_normal_config_api_type_gcc, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_normal_config_api_type_dod, setup_test_read, teardown_test_read)
    };
    const struct CMUnitTest tests_with_startup[] = {
        cmocka_unit_test_setup_teardown(test_setup_complete, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_main_token, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_main_relationships, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_disabled, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_no_resources, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_no_relationships, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_dump, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_dump_gcc_configuration, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_dump_dod_configuration, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_ms_graph_get_access_token_no_response, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_ms_graph_get_access_token_unsuccessful_status_code, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_ms_graph_get_access_token_curl_max_size, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_ms_graph_get_access_token_parse_json_fail, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_ms_graph_get_access_token_success, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_ms_graph_get_access_token_no_access_token, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_ms_graph_get_access_token_no_expire_time, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_ms_graph_scan_relationships_single_initial_only_no, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_ms_graph_scan_relationships_single_initial_only_yes_fail_write, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_ms_graph_scan_relationships_single_initial_only_no_next_time_no_response, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_ms_graph_scan_relationships_single_no_initial_no_timestamp, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_ms_graph_scan_relationships_single_unsuccessful_status_code, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_ms_graph_scan_relationships_single_reached_curl_size, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_ms_graph_scan_relationships_single_failed_parse, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_ms_graph_scan_relationships_single_no_logs, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_ms_graph_scan_relationships_single_success_one_log, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_ms_graph_scan_relationships_single_success_two_logs, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_ms_graph_scan_relationships_single_success_two_pages, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_ms_graph_scan_relationships_single_success_two_resources, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_ms_graph_scan_relationships_renew_token, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_ms_graph_scan_relationships_renew_token_failed, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_ms_graph_scan_apps_devices_renew_token, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_ms_graph_scan_apps_devices_renew_token_failed, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_ms_graph_ensure_valid_token_token_valid, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_ms_graph_ensure_valid_token_token_expired_and_renewed, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_ms_graph_ensure_valid_token_token_missing_and_renewed, setup_conf, teardown_conf)
    };
    int result = 0;
    result = cmocka_run_group_tests(tests_without_startup, NULL, NULL);
    result += cmocka_run_group_tests(tests_with_startup, NULL, NULL);
    return result;
}
