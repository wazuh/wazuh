/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Test corresponding to the scheduling capacities
 * for github Module
 * */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <time.h>

#include "shared.h"
#include "wazuh_modules/wmodules.h"
#include "wazuh_modules/wm_office365.h"
#include "wazuh_modules/wm_office365.c"

#include "../scheduling/wmodules_scheduling_helpers.h"
#include "../../wrappers/common.h"
#include "../../wrappers/libc/stdlib_wrappers.h"
#include "../../wrappers/wazuh/os_regex/os_regex_wrappers.c"
#include "../../wrappers/wazuh/shared/mq_op_wrappers.h"
#include "../../wrappers/wazuh/wazuh_modules/wmodules_wrappers.h"
#include "../../wrappers/wazuh/shared/url_wrappers.h"
#include "../../wrappers/libc/time_wrappers.h"


////////////////  test wmodules-office365 /////////////////

static int setup_test_read(void **state) {
    test_structure *test;
    os_calloc(1, sizeof(test_structure), test);
    os_calloc(1, sizeof(wmodule), test->module);
    *state = test;
    return 0;
}

static int teardown_test_read(void **state) {
    test_structure *test = *state;
    OS_ClearNode(test->nodes);
    OS_ClearXML(&(test->xml));
    if((wm_office365*)test->module->data){
        if(((wm_office365*)test->module->data)->auth){
            os_free(((wm_office365*)test->module->data)->auth->tenant_id);
            os_free(((wm_office365*)test->module->data)->auth->client_id);
            os_free(((wm_office365*)test->module->data)->auth->client_secret_path);
            os_free(((wm_office365*)test->module->data)->auth->client_secret);
            if(((wm_office365*)test->module->data)->auth->next) {
                os_free(((wm_office365*)test->module->data)->auth->next->tenant_id);
                os_free(((wm_office365*)test->module->data)->auth->next->client_id);
                os_free(((wm_office365*)test->module->data)->auth->next->client_secret_path);
                os_free(((wm_office365*)test->module->data)->auth->next->client_secret);
                os_free(((wm_office365*)test->module->data)->auth->next->next);
            }
            os_free(((wm_office365*)test->module->data)->auth->next);
            os_free(((wm_office365*)test->module->data)->auth);
        }
    }
    os_free(test->module->data);
    os_free(test->module->tag);
    os_free(test->module);
    os_free(test);
    return 0;
}

void test_read_configuration(void **state) {
    const char *string =
        "<enabled>no</enabled>"
        "<run_on_start>yes</run_on_start>"
        "<skip_on_error>no</skip_on_error>"
        "<interval>10m</interval>"
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
            "<client_id>your_client_id</client_id>"
            "<client_secret_path>/path/to/secret</client_secret_path>"
            "<client_secret>your_secret</client_secret>"
        "</api_auth>"
        "<subscriptions>"
            "<subscription>Audit.AzureActiveDirectory</subscription>"
            "<subscription>Audit.Exchange</subscription>"
            "<subscription>Audit.SharePoint</subscription>"
            "<subscription>Audit.General</subscription>"
            "<subscription>DLP.All</subscription>"
        "</subscriptions>"
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),0);
    wm_office365 *module_data = (wm_office365*)test->module->data;
    assert_int_equal(module_data->enabled, 0);
    assert_int_equal(module_data->run_on_start, 1);
    assert_int_equal(module_data->skip_on_error, 0);
    assert_int_equal(module_data->interval, 600);
    assert_string_equal(module_data->auth->tenant_id, "your_tenant_id");
    assert_string_equal(module_data->auth->client_id, "your_client_id");
    assert_string_equal(module_data->auth->client_secret_path, "/path/to/secret");
    assert_string_equal(module_data->auth->client_secret, "your_secret");
    assert_string_equal(module_data->subscription.azure, "Audit.AzureActiveDirectory");
    assert_string_equal(module_data->subscription.exchange, "Audit.Exchange");
    assert_string_equal(module_data->subscription.sharepoint, "Audit.SharePoint");
    assert_string_equal(module_data->subscription.general, "Audit.General");
    assert_string_equal(module_data->subscription.dlp, "DLP.All");
}

void test_read_configuration_1(void **state) {
    const char *string =
        "<enabled>no</enabled>\n"
        "<run_on_start>yes</run_on_start>\n"
        "<interval>10m</interval>\n"
        "<time_delay>1s</time_delay>"
        "<only_future_events>no</only_future_events>"
        "<api_auth>"
            "<org_name>Wazuh</org_name>"
            "<api_token>Wazuh_token</api_token>"
        "</api_auth>"
        "<api_auth>"
            "<org_name>Wazuh1</org_name>"
            "<api_token>Wazuh_token1</api_token>"
        "</api_auth>"
        "<api_parameters>"
            "<event_type>git</event_type>"
        "</api_parameters>"
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),0);
    wm_office365 *module_data = (wm_office365*)test->module->data;
    assert_int_equal(module_data->enabled, 0);
    assert_int_equal(module_data->run_on_start, 1);
    assert_int_equal(module_data->interval, 600);
    assert_int_equal(module_data->time_delay, 1);
    assert_int_equal(module_data->only_future_events, 0);
    assert_string_equal(module_data->auth->org_name, "Wazuh");
    assert_string_equal(module_data->auth->api_token, "Wazuh_token");
    assert_string_equal(module_data->auth->next->org_name, "Wazuh1");
    assert_string_equal(module_data->auth->next->api_token, "Wazuh_token1");
    assert_string_equal(module_data->event_type, "git");
}

void test_read_default_configuration(void **state) {
    const char *string =
        "<api_auth>"
            "<org_name>Wazuh</org_name>"
            "<api_token>Wazuh_token</api_token>"
        "</api_auth>"
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),0);
    wm_office365 *module_data = (wm_office365*)test->module->data;
    assert_int_equal(module_data->enabled, 1);
    assert_int_equal(module_data->run_on_start, 1);
    assert_int_equal(module_data->interval, 600);
    assert_int_equal(module_data->time_delay, 1);
    assert_int_equal(module_data->only_future_events, 1);
    assert_string_equal(module_data->auth->org_name, "Wazuh");
    assert_string_equal(module_data->auth->api_token, "Wazuh_token");
    assert_string_equal(module_data->event_type, "all");
}

void test_read_interval(void **state) {
    const char *string =
        "<enabled>yes</enabled>\n"
        "<run_on_start>yes</run_on_start>\n"
        "<interval>10</interval>\n"
        "<time_delay>10</time_delay>"
        "<only_future_events>no</only_future_events>"
        "<api_auth>"
            "<org_name>Wazuh</org_name>"
            "<api_token>Wazuh_token</api_token>"
        "</api_auth>"
        "<api_parameters>"
            "<event_type>git</event_type>"
        "</api_parameters>"
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),0);
    wm_office365 *module_data = (wm_office365*)test->module->data;
    assert_int_equal(module_data->interval, 10);
}

void test_read_interval_s(void **state) {
    const char *string =
        "<enabled>no</enabled>\n"
        "<run_on_start>yes</run_on_start>\n"
        "<interval>50s</interval>\n"
        "<time_delay>10</time_delay>"
        "<only_future_events>no</only_future_events>"
        "<api_auth>"
            "<org_name>Wazuh</org_name>"
            "<api_token>Wazuh_token</api_token>"
        "</api_auth>"
        "<api_parameters>"
            "<event_type>git</event_type>"
        "</api_parameters>"
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),0);
    wm_office365 *module_data = (wm_office365*)test->module->data;
    assert_int_equal(module_data->interval, 50);
}

void test_read_interval_m(void **state) {
    const char *string =
        "<enabled>no</enabled>\n"
        "<run_on_start>yes</run_on_start>\n"
        "<interval>1m</interval>\n"
        "<time_delay>10</time_delay>"
        "<only_future_events>no</only_future_events>"
        "<api_auth>"
            "<org_name>Wazuh</org_name>"
            "<api_token>Wazuh_token</api_token>"
        "</api_auth>"
        "<api_parameters>"
            "<event_type>git</event_type>"
        "</api_parameters>"
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),0);
    wm_office365 *module_data = (wm_office365*)test->module->data;
    assert_int_equal(module_data->interval, 60);
}

void test_read_interval_h(void **state) {
    const char *string =
        "<enabled>no</enabled>\n"
        "<run_on_start>yes</run_on_start>\n"
        "<interval>2h</interval>\n"
        "<time_delay>10</time_delay>"
        "<only_future_events>no</only_future_events>"
        "<api_auth>"
            "<org_name>Wazuh</org_name>"
            "<api_token>Wazuh_token</api_token>"
        "</api_auth>"
        "<api_parameters>"
            "<event_type>git</event_type>"
        "</api_parameters>"
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),0);
    wm_office365 *module_data = (wm_office365*)test->module->data;
    assert_int_equal(module_data->interval, 7200);
}

void test_read_interval_d(void **state) {
    const char *string =
        "<enabled>no</enabled>\n"
        "<run_on_start>yes</run_on_start>\n"
        "<interval>3d</interval>\n"
        "<time_delay>10</time_delay>"
        "<only_future_events>no</only_future_events>"
        "<api_auth>"
            "<org_name>Wazuh</org_name>"
            "<api_token>Wazuh_token</api_token>"
        "</api_auth>"
        "<api_parameters>"
            "<event_type>git</event_type>"
        "</api_parameters>"
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),0);
    wm_office365 *module_data = (wm_office365*)test->module->data;
    assert_int_equal(module_data->interval, 259200);
}

void test_repeatd_tag(void **state) {
    const char *string =
        "<enabled>no</enabled>\n"
        "<run_on_start>yes</run_on_start>\n"
        "<interval>10m</interval>\n"
        "<time_delay>1s</time_delay>"
        "<only_future_events>no</only_future_events>"
        "<api_auth>"
            "<org_name>Wazuh</org_name>"
            "<api_token>Wazuh_token</api_token>"
        "</api_auth>"
        "<api_parameters>"
            "<event_type>all</event_type>"
        "</api_parameters>"
        "<api_parameters>"
            "<event_type>git</event_type>"
        "</api_parameters>"
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),0);
    wm_office365 *module_data = (wm_office365*)test->module->data;
    assert_int_equal(module_data->enabled, 0);
    assert_int_equal(module_data->run_on_start, 1);
    assert_int_equal(module_data->interval, 600);
    assert_int_equal(module_data->time_delay, 1);
    assert_int_equal(module_data->only_future_events, 0);
    assert_string_equal(module_data->auth->org_name, "Wazuh");
    assert_string_equal(module_data->auth->api_token, "Wazuh_token");
    assert_string_equal(module_data->event_type, "git");
}

void test_fake_tag(void **state) {
    const char *string =
        "<enabled>no</enabled>\n"
        "<run_on_start>yes</run_on_start>\n"
        "<interval>10m</interval>\n"
        "<time_delay>1s</time_delay>"
        "<only_future_events>no</only_future_events>"
        "<api_auth>"
            "<org_name>Wazuh</org_name>"
            "<api_token>Wazuh_token</api_token>"
        "</api_auth>"
        "<api_parameters>"
            "<event_type>all</event_type>"
        "</api_parameters>"
        "<fake-tag>ASD</fake-tag>"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "No such tag 'fake-tag' at module 'github'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),-1);
}

void test_invalid_content_1(void **state) {
    const char *string =
        "<enabled>no</enabled>\n"
        "<run_on_start>invalid</run_on_start>\n"
        "<interval>10m</interval>\n"
        "<time_delay>1s</time_delay>"
        "<only_future_events>no</only_future_events>"
        "<api_auth>"
            "<org_name>Wazuh</org_name>"
            "<api_token>Wazuh_token</api_token>"
        "</api_auth>"
        "<api_parameters>"
            "<event_type>all</event_type>"
        "</api_parameters>"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'run_on_start' at module 'github'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),-1);
}

void test_invalid_content_2(void **state) {
    const char *string =
        "<enabled>no</enabled>\n"
        "<run_on_start>no</run_on_start>\n"
        "<interval>10m</interval>\n"
        "<time_delay>1s</time_delay>"
        "<only_future_events>yes</only_future_events>"
        "<api_auth>"
            "<org_name>Wazuh</org_name>"
            "<api_token>Wazuh_token</api_token>"
        "</api_auth>"
        "<api_parameters>"
            "<event_type>invalid</event_type>"
        "</api_parameters>"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'event_type' at module 'github'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),-1);
}

void test_invalid_content_3(void **state) {
    const char *string =
        "<enabled>no</enabled>\n"
        "<run_on_start>no</run_on_start>\n"
        "<interval>10m</interval>\n"
        "<time_delay>1s</time_delay>"
        "<only_future_events>invalid</only_future_events>"
        "<api_auth>"
            "<org_name>Wazuh</org_name>"
            "<api_token>Wazuh_token</api_token>"
        "</api_auth>"
        "<api_parameters>"
            "<event_type>all</event_type>"
        "</api_parameters>"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'only_future_events' at module 'github'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),-1);
}

void test_invalid_content_4(void **state) {
    const char *string =
        "<enabled>invalid</enabled>\n"
        "<run_on_start>no</run_on_start>\n"
        "<interval>10m</interval>\n"
        "<time_delay>1s</time_delay>"
        "<only_future_events>yes</only_future_events>"
        "<api_auth>"
            "<org_name>Wazuh</org_name>"
            "<api_token>Wazuh_token</api_token>"
        "</api_auth>"
        "<api_parameters>"
            "<event_type>all</event_type>"
        "</api_parameters>"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'enabled' at module 'github'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),-1);
}

void test_invalid_content_5(void **state) {
    const char *string =
        "<enabled>no</enabled>\n"
        "<run_on_start>no</run_on_start>\n"
        "<interval>invalid</interval>\n"
        "<time_delay>1s</time_delay>"
        "<only_future_events>yes</only_future_events>"
        "<api_auth>"
            "<org_name>Wazuh</org_name>"
            "<api_token>Wazuh_token</api_token>"
        "</api_auth>"
        "<api_parameters>"
            "<event_type>all</event_type>"
        "</api_parameters>"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'interval' at module 'github'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),-1);
}

void test_invalid_time_delay_1(void **state) {
    const char *string =
        "<enabled>no</enabled>\n"
        "<run_on_start>no</run_on_start>\n"
        "<interval>10m</interval>\n"
        "<time_delay>-1</time_delay>"
        "<only_future_events>no</only_future_events>"
        "<api_auth>"
            "<org_name>Wazuh</org_name>"
            "<api_token>Wazuh_token</api_token>"
        "</api_auth>"
        "<api_parameters>"
            "<event_type>invalid</event_type>"
        "</api_parameters>"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'time_delay' at module 'github'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),-1);
}

void test_invalid_time_delay_2(void **state) {
    const char *string =
        "<enabled>no</enabled>\n"
        "<run_on_start>no</run_on_start>\n"
        "<interval>10m</interval>\n"
        "<time_delay>1y</time_delay>"
        "<only_future_events>no</only_future_events>"
        "<api_auth>"
            "<org_name>Wazuh</org_name>"
            "<api_token>Wazuh_token</api_token>"
        "</api_auth>"
        "<api_parameters>"
            "<event_type>invalid</event_type>"
        "</api_parameters>"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'time_delay' at module 'github'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),-1);
}

void test_error_api_auth(void **state) {
    const char *string =
        "<enabled>no</enabled>\n"
        "<run_on_start>no</run_on_start>\n"
        "<interval>10m</interval>\n"
        "<time_delay>1</time_delay>"
        "<only_future_events>no</only_future_events>"
        "<api_parameters>"
            "<event_type>all</event_type>"
        "</api_parameters>"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "Empty content for tag 'api_auth' at module 'github'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),-1);
}

void test_error_api_auth_1(void **state) {
    const char *string =
        "<enabled>no</enabled>\n"
        "<run_on_start>no</run_on_start>\n"
        "<interval>10m</interval>\n"
        "<time_delay>1</time_delay>"
        "<only_future_events>no</only_future_events>"
        "<api_auth>"
            "<invalid>Wazuh</invalid>"
            "<invalid>Wazuh_token</invalid>"
        "</api_auth>"
        "<api_parameters>"
            "<event_type>all</event_type>"
        "</api_parameters>"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "No such tag 'invalid' at module 'github'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),-1);
}

void test_error_org_name(void **state) {
    const char *string =
        "<enabled>no</enabled>\n"
        "<run_on_start>no</run_on_start>\n"
        "<interval>10m</interval>\n"
        "<time_delay>1</time_delay>"
        "<only_future_events>no</only_future_events>"
        "<api_auth>"
            "<org_name></org_name>"
            "<api_token>Wazuh_token</api_token>"
        "</api_auth>"
        "<api_parameters>"
            "<event_type>all</event_type>"
        "</api_parameters>"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "Empty content for tag 'org_name' at module 'github'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),-1);
}

void test_error_org_name_1(void **state) {
    const char *string =
        "<enabled>no</enabled>\n"
        "<run_on_start>no</run_on_start>\n"
        "<interval>10m</interval>\n"
        "<time_delay>1</time_delay>"
        "<only_future_events>no</only_future_events>"
        "<api_auth>"
            "<api_token>Wazuh_token</api_token>"
        "</api_auth>"
        "<api_parameters>"
            "<event_type>all</event_type>"
        "</api_parameters>"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "'org_name' is missing at module 'github'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),-1);
}

void test_error_api_token(void **state) {
    const char *string =
        "<enabled>no</enabled>\n"
        "<run_on_start>no</run_on_start>\n"
        "<interval>10m</interval>\n"
        "<time_delay>1s</time_delay>"
        "<only_future_events>no</only_future_events>"
        "<api_auth>"
            "<org_name>Wazuh</org_name>"
            "<api_token></api_token>"
        "</api_auth>"
        "<api_parameters>"
            "<event_type>all</event_type>"
        "</api_parameters>"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "Empty content for tag 'api_token' at module 'github'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),-1);
}

void test_error_api_token_1(void **state) {
    const char *string =
        "<enabled>no</enabled>\n"
        "<run_on_start>no</run_on_start>\n"
        "<interval>10m</interval>\n"
        "<time_delay>1s</time_delay>"
        "<only_future_events>no</only_future_events>"
        "<api_auth>"
            "<org_name>Wazuh</org_name>"
        "</api_auth>"
        "<api_parameters>"
            "<event_type>all</event_type>"
        "</api_parameters>"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "'api_token' is missing at module 'github'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),-1);
}

void test_error_event_type_1(void **state) {
    const char *string =
        "<enabled>no</enabled>\n"
        "<run_on_start>no</run_on_start>\n"
        "<interval>10m</interval>\n"
        "<time_delay>1s</time_delay>"
        "<only_future_events>no</only_future_events>"
        "<api_auth>"
            "<org_name>Wazuh</org_name>"
            "<api_token>Wazuh_token</api_token>"
        "</api_auth>"
        "<api_parameters>"
            "<invalid>all</invalid>"
        "</api_parameters>"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "No such tag 'invalid' at module 'github'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),-1);
}

int main(void) {
    const struct CMUnitTest tests_without_startup[] = {
        cmocka_unit_test_setup_teardown(test_read_configuration, setup_test_read, teardown_test_read),
        /*cmocka_unit_test_setup_teardown(test_read_configuration_1, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_default_configuration, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_interval, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_interval_s, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_interval_m, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_interval_h, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_interval_d, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_repeatd_tag, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_fake_tag, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_invalid_content_1, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_invalid_content_2, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_invalid_content_3, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_invalid_content_4, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_invalid_content_5, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_invalid_time_delay_1, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_invalid_time_delay_2, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_error_api_auth, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_error_api_auth_1, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_error_org_name, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_error_org_name_1, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_error_api_token, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_error_api_token_1, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_error_event_type_1, setup_test_read, teardown_test_read),*/
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}