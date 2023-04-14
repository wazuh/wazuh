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

static int setup_module() {
    merror("Building module");
    ms_graph_module = calloc(1, sizeof(wmodule));
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
    lxml = malloc(sizeof(OS_XML));
    XML_NODE nodes = string_to_xml_node(config, lxml);
    int ret = wm_ms_graph_read(lxml, nodes, ms_graph_module);
    OS_ClearNode(nodes);
    test_mode = 1;
    return ret;
}

static void wmodule_cleanup(wmodule *module){
    wm_ms_graph* module_data = (wm_ms_graph*)module->data;
    fprintf(stderr, "Got here __1\n");
    if(module_data){
        os_free(module_data->version);
        fprintf(stderr, "Got here __2\n");
        for(unsigned int resource = 0; resource < module_data->num_resources; resource++){
            for(unsigned int relationship = 0; relationship < module_data->resources[resource].num_relationships; relationship++){
                os_free(module_data->resources[resource].relationships[relationship]);
            }
            os_free(module_data->resources[resource].relationships);
            os_free(module_data->resources[resource].name);
        }
        fprintf(stderr, "Got here __3\n");
        os_free(module_data->resources);

        fprintf(stderr, "Got here __4\n");
        os_free(module_data->auth_config.tenant_id);
        fprintf(stderr, "Got here __5\n");
        os_free(module_data->auth_config.client_id);
        fprintf(stderr, "Got here __6\n");
        os_free(module_data->auth_config.secret_value);
        fprintf(stderr, "Got here __7\n");
        os_free(module_data->auth_config.access_token);

        fprintf(stderr, "Got here __8\n");
        os_free(module_data);
    }
    fprintf(stderr, "Got here __9\n");
    os_free(module->tag);
    fprintf(stderr, "Got here __10\n");
    os_free(module);
}

static int teardown_module(){
    test_mode = 0;
    wmodule_cleanup(ms_graph_module);
    OS_ClearXML(lxml);
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
    fprintf(stderr, "Got here _1\n");
    OS_ClearNode(test->nodes);
    fprintf(stderr, "Got here _2\n");
    OS_ClearXML(&(test->xml));
    fprintf(stderr, "Got here _3\n");
    wm_ms_graph* module_data = (wm_ms_graph*)test->module->data;
    fprintf(stderr, "Got here _4\n");
    if(module_data && &(module_data->scan_config)){
        sched_scan_free(&(module_data->scan_config));
    }
    fprintf(stderr, "Got here _5\n");
    wmodule_cleanup(test->module);
    fprintf(stderr, "Got here _6\n");
    os_free(test);
    fprintf(stderr, "Got here _7\n");
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
    assert_int_equal(module_data->curl_max_size, 4096);
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
     wm_ms_graph* module_data = (wm_ms_graph*)ms_graph_module->data;
    *state = module_data;
    module_data->enabled = false;

    expect_string(__wrap__mtinfo, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mtinfo, formatted_msg, "Module disabled. Exiting...");

    wm_ms_graph_main(module_data);
}

void test_no_resources(void **state) {
         wm_ms_graph* module_data = (wm_ms_graph*)ms_graph_module->data;
    *state = module_data;
    module_data->enabled = true;

    expect_string(__wrap__mtinfo, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mtinfo, formatted_msg, "Started module.");

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mterror, formatted_msg, "Invalid module configuration (Missing API info, resources, relationships). Exiting...");

    wm_ms_graph_main(module_data);
}

void test_no_relationships(void **state) {
         wm_ms_graph* module_data = (wm_ms_graph*)ms_graph_module->data;
    *state = module_data;
    module_data->enabled = true;
    os_malloc(sizeof(wm_ms_graph_resource) * 2, module_data->resources);
    module_data->resources[0].num_relationships = 0;
    module_data->num_resources = 1;

    expect_string(__wrap__mtinfo, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mtinfo, formatted_msg, "Started module.");

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:ms-graph");
    expect_string(__wrap__mterror, formatted_msg, "Invalid module configuration (Missing API info, resources, relationships). Exiting...");

    wm_ms_graph_main(module_data);

    os_free(module_data->resources);
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
        //cmocka_unit_test_setup_teardown(test_missing_client_id, setup_test_read, teardown_test_read),
        //cmocka_unit_test_setup_teardown(test_invalid_tenant_id, setup_test_read, teardown_test_read),
        //cmocka_unit_test_setup_teardown(test_missing_tenant_id, setup_test_read, teardown_test_read),
        //cmocka_unit_test_setup_teardown(test_invalid_secret_value, setup_test_read, teardown_test_read),
        //cmocka_unit_test_setup_teardown(test_missing_secret_value, setup_test_read, teardown_test_read),
        //cmocka_unit_test_setup_teardown(test_missing_resource, setup_test_read, teardown_test_read),
        //cmocka_unit_test_setup_teardown(test_missing_name, setup_test_read, teardown_test_read),
        //cmocka_unit_test_setup_teardown(test_missing_relationship, setup_test_read, teardown_test_read)
    };
    return cmocka_run_group_tests(tests_without_startup, NULL, NULL);
}