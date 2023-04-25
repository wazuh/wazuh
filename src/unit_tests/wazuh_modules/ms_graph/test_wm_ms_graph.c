/*
 * Copyright (C) 2015, Wazuh Inc.
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

#include "shared.h"
#include "wazuh_modules/wmodules.h"
#include "wazuh_modules/wm_ms_graph.h"
#include "wazuh_modules/wm_ms_graph.c"

#include "../scheduling/wmodules_scheduling_helpers.h"
#include "../../wrappers/common.h"

#include "../../wrappers/libc/stdlib_wrappers.h"
#include "../../wrappers/wazuh/shared/mq_op_wrappers.h"
#include "../../wrappers/wazuh/wazuh_modules/wmodules_wrappers.h"
#include "../../wrappers/wazuh/shared/time_op_wrappers.h"
#include "../../wrappers/wazuh/shared/url_wrappers.h"
#include "../../wrappers/libc/time_wrappers.h"

#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../wrappers/wazuh/wazuh_modules/wm_exec_wrappers.h"

#define TEST_MAX_DATES 5

static wmodule *ms_graph_module;
static OS_XML *lxml;

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

        os_free(module_data->auth_config.tenant_id);
        os_free(module_data->auth_config.client_id);
        os_free(module_data->auth_config.secret_value);
        os_free(module_data->auth_config.access_token);

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
        "  <client_id>example_string_with_36_characters___</client_id>\n"
        "  <tenant_id>example_string_with_36_characters___</tenant_id>\n"
        "  <secret_value>example_string_with_40_characters_______</secret_value>\n"
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
    fprintf(stderr, "Got here 1\n");
    test_structure *test = *state;
    fprintf(stderr, "Got here 2\n");
    expect_string(__wrap__merror, formatted_msg, "(1233): Invalid attribute 'invalid' in the configuration: 'ms-graph'.");
    fprintf(stderr, "Got here 3\n");
    test->nodes = string_to_xml_node(config, &(test->xml));
    fprintf(stderr, "Got here 4\n");
    assert_int_equal(wm_ms_graph_read(&(test->xml), test->nodes, test->module), OS_CFGERR);
    fprintf(stderr, "Got here 5\n");
}

void test_empty_module(void **state) {
    const char* config =
        ""
    ;
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
        "  <client_id>example_string_with_36_characters___</client_id>\n"
        "  <tenant_id>example_string_with_36_characters___</tenant_id>\n"
        "  <secret_value>example_string_with_40_characters_______</secret_value>\n"
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
    expect_string(__wrap__merror, formatted_msg, "(1235): Invalid value for element 'enabled': invalid.");
    test->nodes = string_to_xml_node(config, &(test->xml));
    assert_int_equal(wm_ms_graph_read(&(test->xml), test->nodes, test->module), OS_CFGERR);
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
        "  <client_id>example_string_with_36_characters___</client_id>\n"
        "  <tenant_id>example_string_with_36_characters___</tenant_id>\n"
        "  <secret_value>example_string_with_40_characters_______</secret_value>\n"
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
    expect_string(__wrap__merror, formatted_msg, "(1235): Invalid value for element 'only_future_events': invalid.");
    test->nodes = string_to_xml_node(config, &(test->xml));
    assert_int_equal(wm_ms_graph_read(&(test->xml), test->nodes, test->module), OS_CFGERR);
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
        "  <client_id>example_string_with_36_characters___</client_id>\n"
        "  <tenant_id>example_string_with_36_characters___</tenant_id>\n"
        "  <secret_value>example_string_with_40_characters_______</secret_value>\n"
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
    expect_string(__wrap__merror, formatted_msg, "Module 'ms-graph' has invalid content in tag 'curl_max_size': the minimum size is 1KB.");
    test->nodes = string_to_xml_node(config, &(test->xml));
    assert_int_equal(wm_ms_graph_read(&(test->xml), test->nodes, test->module), OS_CFGERR);
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
        "  <client_id>example_string_with_36_characters___</client_id>\n"
        "  <tenant_id>example_string_with_36_characters___</tenant_id>\n"
        "  <secret_value>example_string_with_40_characters_______</secret_value>\n"
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
    expect_string(__wrap__merror, formatted_msg, "(1235): Invalid value for element 'run_on_start': invalid.");
    test->nodes = string_to_xml_node(config, &(test->xml));
    assert_int_equal(wm_ms_graph_read(&(test->xml), test->nodes, test->module), OS_CFGERR);
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
        "  <client_id>example_string_with_36_characters___</client_id>\n"
        "  <tenant_id>example_string_with_36_characters___</tenant_id>\n"
        "  <secret_value>example_string_with_40_characters_______</secret_value>\n"
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
    expect_string(__wrap__merror, formatted_msg, "Unable to read scheduling configuration for module 'ms-graph'.");
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
        "  <client_id>example_string_with_36_characters___</client_id>\n"
        "  <tenant_id>example_string_with_36_characters___</tenant_id>\n"
        "  <secret_value>example_string_with_40_characters_______</secret_value>\n"
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
    expect_string(__wrap__merror, formatted_msg, "(1235): Invalid value for element 'version': invalid.");
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

void test_invalid_client_id(void **state) {
    const char* config =
        "<enabled>yes</enabled>\n"
        "<only_future_events>yes</only_future_events>\n"
        "<curl_max_size>1M</curl_max_size>\n"
        "<run_on_start>yes</run_on_start>\n"
        "<interval>5m</interval>\n"
        "<version>v1.0</version>\n"
        "<api_auth>\n"
        "  <client_id>invalid</client_id>\n"
        "  <tenant_id>example_string_with_36_characters___</tenant_id>\n"
        "  <secret_value>example_string_with_40_characters_______</secret_value>\n"
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
    expect_string(__wrap__merror, formatted_msg, "(1235): Invalid value for element 'client_id': invalid.");
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
        "  <tenant_id>example_string_with_36_characters___</tenant_id>\n"
        "  <secret_value>example_string_with_40_characters_______</secret_value>\n"
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
        "  <client_id>example_string_with_36_characters___</client_id>\n"
        "  <tenant_id>invalid</tenant_id>\n"
        "  <secret_value>example_string_with_40_characters_______</secret_value>\n"
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
    expect_string(__wrap__merror, formatted_msg, "(1235): Invalid value for element 'tenant_id': invalid.");
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
        "  <client_id>example_string_with_36_characters___</client_id>\n"
        "  <secret_value>example_string_with_40_characters_______</secret_value>\n"
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
        "  <client_id>example_string_with_36_characters___</client_id>\n"
        "  <tenant_id>example_string_with_36_characters___</tenant_id>\n"
        "  <secret_value>invalid</secret_value>\n"
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
    expect_string(__wrap__merror, formatted_msg, "(1235): Invalid value for element 'secret_value': invalid.");
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
        "  <client_id>example_string_with_36_characters___</client_id>\n"
        "  <tenant_id>example_string_with_36_characters___</tenant_id>\n"
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

void test_missing_resource(void **state) {
    const char* config =
        "<enabled>yes</enabled>\n"
        "<only_future_events>yes</only_future_events>\n"
        "<curl_max_size>1M</curl_max_size>\n"
        "<run_on_start>yes</run_on_start>\n"
        "<interval>5m</interval>\n"
        "<version>v1.0</version>\n"
        "<api_auth>\n"
        "  <client_id>example_string_with_36_characters___</client_id>\n"
        "  <tenant_id>example_string_with_36_characters___</tenant_id>\n"
        "  <secret_value>example_string_with_40_characters_______</secret_value>\n"
        "</api_auth>\n"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "(1228): Element 'resource' without any option.");
    test->nodes = string_to_xml_node(config, &(test->xml));
    assert_int_equal(wm_ms_graph_read(&(test->xml), test->nodes, test->module), OS_NOTFOUND);
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
        "  <client_id>example_string_with_36_characters___</client_id>\n"
        "  <tenant_id>example_string_with_36_characters___</tenant_id>\n"
        "  <secret_value>example_string_with_40_characters_______</secret_value>\n"
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

void test_missing_relationship(void **state) {
    const char* config =
        "<enabled>yes</enabled>\n"
        "<only_future_events>yes</only_future_events>\n"
        "<curl_max_size>1M</curl_max_size>\n"
        "<run_on_start>yes</run_on_start>\n"
        "<interval>5m</interval>\n"
        "<version>v1.0</version>\n"
        "<api_auth>\n"
        "  <client_id>example_string_with_36_characters___</client_id>\n"
        "  <tenant_id>example_string_with_36_characters___</tenant_id>\n"
        "  <secret_value>example_string_with_40_characters_______</secret_value>\n"
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
        "  <client_id>example_string_with_36_characters___</client_id>\n"
        "  <tenant_id>example_string_with_36_characters___</tenant_id>\n"
        "  <secret_value>example_string_with_40_characters_______</secret_value>\n"
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
    assert_string_equal(module_data->auth_config.tenant_id, "example_string_with_36_characters___");
    assert_string_equal(module_data->auth_config.client_id, "example_string_with_36_characters___");
    assert_string_equal(module_data->auth_config.secret_value, "example_string_with_40_characters_______");
    assert_int_equal(module_data->num_resources, 2);
    assert_string_equal(module_data->resources[0].name, "security");
    assert_int_equal(module_data->resources[0].num_relationships, 2);
    assert_string_equal(module_data->resources[0].relationships[0], "alerts_v2");
    assert_string_equal(module_data->resources[0].relationships[1], "incidents");
    assert_string_equal(module_data->resources[1].name, "identityProtection");
    assert_int_equal(module_data->resources[1].num_relationships, 1);
    assert_string_equal(module_data->resources[1].relationships[0], "riskyUsers");
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
    os_malloc(sizeof(wm_ms_graph_resource) * 2, module_data->resources);
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
    <run_on_start>yes</run_on_start>
    <version>v1.0</version>
    <api_auth>
      <client_id>example_string_with_36_characters___</client_id>
      <tenant_id>example_string_with_36_characters___</tenant_id>
      <secret_value>example_string_with_40_characters_______</secret_value>
    </api_auth>
    <resource>
      <name>security</name>
      <relationship>alerts_v2</relationship>
    </resource>
    */
    wm_ms_graph* module_data = (wm_ms_graph *)*state;
    module_data->enabled = true;
    module_data->only_future_events = false;
    module_data->curl_max_size = 1024L;
    module_data->run_on_start = true;
    os_strdup("v1.0", module_data->version);
    os_strdup("example_string_with_36_characters___", module_data->auth_config.client_id);
    os_strdup("example_string_with_36_characters___", module_data->auth_config.tenant_id);
    os_strdup("example_string_with_40_characters_______", module_data->auth_config.secret_value);
    os_malloc(sizeof(wm_ms_graph_resource) * 2, module_data->resources);
    os_strdup("security", module_data->resources[0].name);
    module_data->num_resources = 1;
    os_malloc(sizeof(char*) * 2, module_data->resources[0].relationships);
    os_strdup("alerts_v2", module_data->resources[0].relationships[0]);
    module_data->resources[0].num_relationships = 1;

    cJSON* dump = wm_ms_graph_dump(module_data);
    char* dump_text = cJSON_PrintUnformatted(dump);

    assert_string_equal(dump_text, "{\"ms_graph\":{\"enabled\":\"yes\",\"only_future_events\":\"no\",\"curl_max_size\":1024,\"run_on_start\":\"yes\",\"version\":\"v1.0\",\"wday\":\"sunday\",\"api_auth\":{\"client_id\":\"example_string_with_36_characters___\",\"tenant_id\":\"example_string_with_36_characters___\",\"secret_value\":\"example_string_with_40_characters_______\",\"name\":\"security\"},\"resources\":[{\"relationship\":\"alerts_v2\"}]}}");

    cJSON_Delete(dump);
    os_free(dump_text);
    os_free(module_data->resources[0].relationships[0]);
    os_free(module_data->resources[0].relationships);
    module_data->resources[0].num_relationships = 0;
    os_free(module_data->resources[0].name);
    os_free(module_data->resources);
    module_data->num_resources = 0;
}

int main(void) {
    const struct CMUnitTest tests_without_startup[] = {
        cmocka_unit_test_setup_teardown(test_bad_tag, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_empty_module, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_invalid_enabled, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_invalid_only_future_events, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_invalid_curl_max_size, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_invalid_run_on_start, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_invalid_version, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_missing_api_auth, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_invalid_client_id, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_missing_client_id, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_invalid_tenant_id, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_missing_tenant_id, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_invalid_secret_value, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_missing_secret_value, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_missing_resource, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_missing_name, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_missing_relationship, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_normal_config, setup_test_read, teardown_test_read)
    };
    const struct CMUnitTest tests_with_startup[] = {
        cmocka_unit_test_setup_teardown(test_disabled, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_no_resources, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_no_relationships, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_dump, setup_conf, teardown_conf)
    };
    int result = 0;
    result = cmocka_run_group_tests(tests_without_startup, NULL, NULL);
    result += cmocka_run_group_tests(tests_with_startup, NULL, NULL);
    return result;
}