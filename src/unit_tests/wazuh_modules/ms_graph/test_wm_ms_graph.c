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
#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../wrappers/wazuh/shared/mq_op_wrappers.h"
#include "../../wrappers/wazuh/wazuh_modules/wm_exec_wrappers.h"

#define TEST_MAX_DATES 5

static wmodule *ms_graph_module;
static OS_XML *lxml;

static int setup_module() {
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
    OS_ClearNode(test->nodes);
    OS_ClearXML(&(test->xml));
    wm_ms_graph* module_data = (wm_ms_graph*)test->module->data;
    sched_scan_free(&(module_data->scan_config));
    wmodule_cleanup(test->module);
    os_free(test);
    return 0;
}

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
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "(1233): Invalid attribute 'invalid' in the configuration: 'ms-graph'.");
    test->nodes = string_to_xml_node(config, &(test->xml));
    assert_int_equal(wm_ms_graph_read(&(test->xml), test->nodes, test->module), OS_CFGERR);
}

void test_unclosed_tag(void **state) {
    const char* config =
        "<enabled>yes\n"
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
    expect_string(__wrap__merror, formatted_msg, "(1226): Error reading XML file 'etc/ossec.conf':  (line 0).");
    test->nodes = string_to_xml_node(config, &(test->xml));
    assert_int_equal(wm_ms_graph_read(&(test->xml), test->nodes, test->module), -1);
}

void test_hanging_close_tag(void **state) {
    const char* config =
        "yes</enabled>\n"
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
    expect_string(__wrap__merror, formatted_msg, "(1226): Error reading XML file 'etc/ossec.conf':  (line 0).");
    test->nodes = string_to_xml_node(config, &(test->xml));
    assert_int_equal(wm_ms_graph_read(&(test->xml), test->nodes, test->module), -1);
}

void test_null_tag(void **state) {
    const char* config =
        "<>yes</>\n"
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
    expect_string(__wrap__merror, formatted_msg, XML_ELEMNULL);
    test->nodes = string_to_xml_node(config, &(test->xml));
    assert_int_equal(wm_ms_graph_read(&(test->xml), test->nodes, test->module), OS_CFGERR);
}

void test_null_content(void **state) {
    const char* config =
        "<enabled></enabled>\n"
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
    expect_string(__wrap__merror, formatted_msg, XML_ELEMNULL);
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
        "  <client_id>test_client_secret</client_id>\n"
        "  <tenant_id>test_tenant_id</tenant_id>\n"
        "  <secret_value>test_secret_value</secret_value>\n"
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
        "  <client_id>test_client_secret</client_id>\n"
        "  <tenant_id>test_tenant_id</tenant_id>\n"
        "  <secret_value>test_secret_value</secret_value>\n"
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
        "  <client_id>test_client_secret</client_id>\n"
        "  <tenant_id>test_tenant_id</tenant_id>\n"
        "  <secret_value>test_secret_value</secret_value>\n"
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

int main(void) {
    const struct CMUnitTest tests_without_startup[] = {
        cmocka_unit_test_setup_teardown(test_bad_tag, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_unclosed_tag, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_hanging_close_tag, setup_test_read, teardown_test_read),
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
        cmocka_unit_test_setup_teardown(test_missing_relationship, setup_test_read, teardown_test_read)
    };
    return cmocka_run_group_tests(tests_without_startup, NULL, NULL);
}