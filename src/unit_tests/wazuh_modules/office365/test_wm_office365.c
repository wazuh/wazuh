/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Test corresponding to the scheduling capacities
 * for Office365 Module
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

#include "../../wrappers/libc/stdlib_wrappers.h"
#include "../scheduling/wmodules_scheduling_helpers.h"
#include "../../wrappers/common.h"

int __wrap_access(const char *__name, int __type) {
    check_expected(__name);
    return mock_type(int);
}

////////////////  test wmodules-office365 /////////////////
typedef struct test_struct {
    wm_office365 *office365_config;
    curl_response* response;
    char *root_c;
} test_struct_t;

static int setup_conf(void **state) {
    test_struct_t *init_data = NULL;
    os_calloc(1,sizeof(test_struct_t), init_data);
    os_calloc(1, sizeof(wm_office365), init_data->office365_config);
    test_mode = 1;
    *state = init_data;
    return 0;
}

static int teardown_conf(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    test_mode = 0;
    expect_string(__wrap__mtinfo, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mtinfo, formatted_msg, "Module Office365 finished.");
    wm_office365_destroy(data->office365_config);
    os_free(data->root_c);
    os_free(data);
    return 0;
}

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
    if ((wm_office365*)test->module->data) {
        if (((wm_office365*)test->module->data)->auth) {
            os_free(((wm_office365*)test->module->data)->auth->tenant_id);
            os_free(((wm_office365*)test->module->data)->auth->client_id);
            os_free(((wm_office365*)test->module->data)->auth->client_secret_path);
            os_free(((wm_office365*)test->module->data)->auth->client_secret);
            if (((wm_office365*)test->module->data)->auth->next) {
                os_free(((wm_office365*)test->module->data)->auth->next->tenant_id);
                os_free(((wm_office365*)test->module->data)->auth->next->client_id);
                os_free(((wm_office365*)test->module->data)->auth->next->client_secret_path);
                os_free(((wm_office365*)test->module->data)->auth->next->client_secret);
                os_free(((wm_office365*)test->module->data)->auth->next->next);
            }
            os_free(((wm_office365*)test->module->data)->auth->next);
            os_free(((wm_office365*)test->module->data)->auth);
        }
        if (((wm_office365*)test->module->data)->subscription) {
            os_free(((wm_office365*)test->module->data)->subscription->subscription_name);
            if (((wm_office365*)test->module->data)->subscription->next) {
                os_free(((wm_office365*)test->module->data)->subscription->next->subscription_name);
            }
            if (((wm_office365*)test->module->data)->subscription->next->next) {
                os_free(((wm_office365*)test->module->data)->subscription->next->next->subscription_name);
            }
            if (((wm_office365*)test->module->data)->subscription->next->next->next) {
                os_free(((wm_office365*)test->module->data)->subscription->next->next->next->subscription_name);
            }
            if (((wm_office365*)test->module->data)->subscription->next->next->next->next) {
                os_free(((wm_office365*)test->module->data)->subscription->next->next->next->next->subscription_name);
            }
            os_free(((wm_office365*)test->module->data)->subscription->next->next->next->next);
            os_free(((wm_office365*)test->module->data)->subscription->next->next->next);
            os_free(((wm_office365*)test->module->data)->subscription->next->next);
            os_free(((wm_office365*)test->module->data)->subscription->next);
            os_free(((wm_office365*)test->module->data)->subscription);
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
        "<only_future_events>no</only_future_events>"
        "<interval>10m</interval>"
        "<curl_max_size>2</curl_max_size>"
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
            "<client_id>your_client_id</client_id>"
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
    assert_int_equal(module_data->only_future_events, 0);
    assert_int_equal(module_data->interval, 600);
    assert_int_equal(module_data->curl_max_size, 2048);
    assert_string_equal(module_data->auth->tenant_id, "your_tenant_id");
    assert_string_equal(module_data->auth->client_id, "your_client_id");
    assert_string_equal(module_data->auth->client_secret, "your_secret");
    assert_string_equal(module_data->subscription->subscription_name, "Audit.AzureActiveDirectory");
    assert_string_equal(module_data->subscription->next->subscription_name, "Audit.Exchange");
    assert_string_equal(module_data->subscription->next->next->subscription_name, "Audit.SharePoint");
    assert_string_equal(module_data->subscription->next->next->next->subscription_name, "Audit.General");
    assert_string_equal(module_data->subscription->next->next->next->next->subscription_name, "DLP.All");
}

void test_read_configuration_1(void **state) {
    const char *string =
        "<enabled>no</enabled>"
        "<only_future_events>yes</only_future_events>"
        "<interval>10m</interval>"
        "<curl_max_size>2</curl_max_size>"
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
            "<client_id>your_client_id</client_id>"
            "<client_secret>your_secret</client_secret>"
        "</api_auth>"
        "<api_auth>"
            "<tenant_id>your_tenant_id_1</tenant_id>"
            "<client_id>your_client_id_1</client_id>"
            "<client_secret_path>/path/to/secret</client_secret_path>"
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
    expect_string(__wrap_access, __name, "/path/to/secret");
    will_return(__wrap_access, 0);
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),0);
    wm_office365 *module_data = (wm_office365*)test->module->data;
    assert_int_equal(module_data->enabled, 0);
    assert_int_equal(module_data->only_future_events, 1);
    assert_int_equal(module_data->interval, 600);
    assert_int_equal(module_data->curl_max_size, 2048);
    assert_string_equal(module_data->auth->tenant_id, "your_tenant_id");
    assert_string_equal(module_data->auth->client_id, "your_client_id");
    assert_string_equal(module_data->auth->client_secret, "your_secret");
    assert_string_equal(module_data->auth->next->tenant_id, "your_tenant_id_1");
    assert_string_equal(module_data->auth->next->client_id, "your_client_id_1");
    assert_string_equal(module_data->auth->next->client_secret_path, "/path/to/secret");
    assert_string_equal(module_data->subscription->subscription_name, "Audit.AzureActiveDirectory");
    assert_string_equal(module_data->subscription->next->subscription_name, "Audit.Exchange");
    assert_string_equal(module_data->subscription->next->next->subscription_name, "Audit.SharePoint");
    assert_string_equal(module_data->subscription->next->next->next->subscription_name, "Audit.General");
    assert_string_equal(module_data->subscription->next->next->next->next->subscription_name, "DLP.All");
}

void test_read_default_configuration(void **state) {
    const char *string =
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
            "<client_id>your_client_id</client_id>"
            "<client_secret>your_secret</client_secret>"
        "</api_auth>"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "Empty content for tag 'subscriptions' at module 'office365'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),-1);
}

void test_read_interval(void **state) {
    const char *string =
        "<enabled>no</enabled>"
        "<only_future_events>no</only_future_events>"
        "<interval>10</interval>"
        "<curl_max_size>2</curl_max_size>"
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
            "<client_id>your_client_id</client_id>"
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
    assert_int_equal(module_data->only_future_events, 0);
    assert_int_equal(module_data->interval, 10);
    assert_int_equal(module_data->curl_max_size, 2048);
    assert_string_equal(module_data->auth->tenant_id, "your_tenant_id");
    assert_string_equal(module_data->auth->client_id, "your_client_id");
    assert_string_equal(module_data->auth->client_secret, "your_secret");
    assert_string_equal(module_data->subscription->subscription_name, "Audit.AzureActiveDirectory");
    assert_string_equal(module_data->subscription->next->subscription_name, "Audit.Exchange");
    assert_string_equal(module_data->subscription->next->next->subscription_name, "Audit.SharePoint");
    assert_string_equal(module_data->subscription->next->next->next->subscription_name, "Audit.General");
    assert_string_equal(module_data->subscription->next->next->next->next->subscription_name, "DLP.All");
}

void test_read_interval_s(void **state) {
    const char *string =
        "<enabled>no</enabled>"
        "<only_future_events>no</only_future_events>"
        "<interval>50s</interval>"
        "<curl_max_size>2</curl_max_size>"
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
            "<client_id>your_client_id</client_id>"
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
    assert_int_equal(module_data->interval, 50);
}

void test_read_interval_s_fail(void **state) {
    const char *string =
        "<enabled>no</enabled>"
        "<only_future_events>no</only_future_events>"
        "<interval>90000s</interval>"
        "<curl_max_size>2</curl_max_size>"
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
            "<client_id>your_client_id</client_id>"
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
    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'interval' at module 'office365'. The maximum value allowed is 1 day.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),-1);
}

void test_read_interval_m(void **state) {
    const char *string =
        "<enabled>no</enabled>"
        "<only_future_events>no</only_future_events>"
        "<interval>1m</interval>"
        "<curl_max_size>2</curl_max_size>"
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
            "<client_id>your_client_id</client_id>"
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
    assert_int_equal(module_data->interval, 60);
}

void test_read_interval_m_fail(void **state) {
    const char *string =
        "<enabled>no</enabled>"
        "<only_future_events>no</only_future_events>"
        "<interval>1500m</interval>"
        "<curl_max_size>2</curl_max_size>"
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
            "<client_id>your_client_id</client_id>"
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
    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'interval' at module 'office365'. The maximum value allowed is 1 day.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),-1);
}

void test_read_interval_h(void **state) {
    const char *string =
        "<enabled>no</enabled>"
        "<only_future_events>no</only_future_events>"
        "<interval>2h</interval>"
        "<curl_max_size>2</curl_max_size>"
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
            "<client_id>your_client_id</client_id>"
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
    assert_int_equal(module_data->interval, 7200);
}

void test_read_interval_h_fail(void **state) {
    const char *string =
        "<enabled>no</enabled>"
        "<only_future_events>no</only_future_events>"
        "<interval>30h</interval>"
        "<curl_max_size>2</curl_max_size>"
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
            "<client_id>your_client_id</client_id>"
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
    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'interval' at module 'office365'. The maximum value allowed is 1 day.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),-1);
}

void test_read_interval_d(void **state) {
    const char *string =
        "<enabled>no</enabled>"
        "<only_future_events>no</only_future_events>"
        "<interval>1d</interval>"
        "<curl_max_size>2</curl_max_size>"
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
            "<client_id>your_client_id</client_id>"
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
    assert_int_equal(module_data->interval, 86400);
}

void test_read_interval_d_fail(void **state) {
    const char *string =
        "<enabled>no</enabled>"
        "<only_future_events>no</only_future_events>"
        "<interval>2d</interval>"
        "<curl_max_size>2</curl_max_size>"
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
            "<client_id>your_client_id</client_id>"
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
    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'interval' at module 'office365'. The maximum value allowed is 1 day.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),-1);
}

void test_read_curl_max_size(void **state) {
    const char *string =
        "<enabled>no</enabled>"
        "<only_future_events>no</only_future_events>"
        "<interval>10</interval>"
        "<curl_max_size>4</curl_max_size>"
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
            "<client_id>your_client_id</client_id>"
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
    assert_int_equal(module_data->only_future_events, 0);
    assert_int_equal(module_data->interval, 10);
    assert_int_equal(module_data->curl_max_size, 4096);
    assert_string_equal(module_data->auth->tenant_id, "your_tenant_id");
    assert_string_equal(module_data->auth->client_id, "your_client_id");
    assert_string_equal(module_data->auth->client_secret, "your_secret");
    assert_string_equal(module_data->subscription->subscription_name, "Audit.AzureActiveDirectory");
    assert_string_equal(module_data->subscription->next->subscription_name, "Audit.Exchange");
    assert_string_equal(module_data->subscription->next->next->subscription_name, "Audit.SharePoint");
    assert_string_equal(module_data->subscription->next->next->next->subscription_name, "Audit.General");
    assert_string_equal(module_data->subscription->next->next->next->next->subscription_name, "DLP.All");
}

void test_read_curl_max_size_invalid_1(void **state) {
    const char *string =
        "<enabled>no</enabled>"
        "<only_future_events>no</only_future_events>"
        "<interval>10</interval>"
        "<curl_max_size>0</curl_max_size>"
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
            "<client_id>your_client_id</client_id>"
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
    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'curl_max_size' at module 'office365'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),-1);
}

void test_read_curl_max_size_invalid_2(void **state) {
    const char *string =
        "<enabled>no</enabled>"
        "<only_future_events>no</only_future_events>"
        "<interval>10</interval>"
        "<curl_max_size>-1</curl_max_size>"
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
            "<client_id>your_client_id</client_id>"
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
    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'curl_max_size' at module 'office365'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),-1);
}

void test_read_curl_max_size_invalid_3(void **state) {
    const char *string =
        "<enabled>no</enabled>"
        "<only_future_events>no</only_future_events>"
        "<interval>10</interval>"
        "<curl_max_size>invalid</curl_max_size>"
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
            "<client_id>your_client_id</client_id>"
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
    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'curl_max_size' at module 'office365'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),-1);
}

void test_secret_path_and_secret(void **state) {
    const char *string =
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
            "<client_id>your_client_id</client_id>"
            "<client_secret_path>/path/to/secret</client_secret_path>"
            "<client_secret>your_secret</client_secret>"
        "</api_auth>"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "It is not allowed to set 'client_secret' and 'client_secret_path' at module 'office365'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),-1);
}

void test_fake_tag(void **state) {
    const char *string =
        "<enabled>no</enabled>"
        "<only_future_events>no</only_future_events>"
        "<interval>1d</interval>"
        "<curl_max_size>2</curl_max_size>"
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
            "<client_id>your_client_id</client_id>"
            "<client_secret>your_secret</client_secret>"
        "</api_auth>"
        "<subscriptions>"
            "<subscription>Audit.AzureActiveDirectory</subscription>"
            "<subscription>Audit.Exchange</subscription>"
            "<subscription>Audit.SharePoint</subscription>"
            "<subscription>Audit.General</subscription>"
            "<subscription>DLP.All</subscription>"
        "</subscriptions>"
        "<fake-tag>ASD</fake-tag>"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "No such tag 'fake-tag' at module 'office365'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),-1);
}

void test_fake_tag_1(void **state) {
    const char *string =
        "<enabled>no</enabled>"
        "<only_future_events>no</only_future_events>"
        "<interval>1d</interval>"
        "<curl_max_size>2</curl_max_size>"
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
            "<client_id>your_client_id</client_id>"
            "<client_secret>your_secret</client_secret>"
        "</api_auth>"
        "<subscriptions>"
            "<subscription>Audit.AzureActiveDirectory</subscription>"
            "<subscription>Audit.Exchange</subscription>"
            "<subscription>Audit.SharePoint</subscription>"
            "<subscription>Audit.General</subscription>"
            "<subscription>DLP.All</subscription>"
            "<fake-tag>ASD</fake-tag>"
        "</subscriptions>"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "No such tag 'fake-tag' at module 'office365'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),-1);
}

void test_invalid_content_1(void **state) {
    const char *string =
        "<enabled>no</enabled>"
        "<only_future_events>no</only_future_events>"
        "<interval>1d</interval>"
        "<curl_max_size>2</curl_max_size>"
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
            "<client_id>your_client_id</client_id>"
            "<client_secret>your_secret</client_secret>"
        "</api_auth>"
        "<subscriptions>"
            "<subscription></subscription>"
            "<subscription>Audit.Exchange</subscription>"
            "<subscription>Audit.SharePoint</subscription>"
            "<subscription>Audit.General</subscription>"
            "<subscription>DLP.All</subscription>"
        "</subscriptions>"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "Empty content for tag 'subscription' at module 'office365'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),-1);
}

void test_invalid_content_2(void **state) {
    const char *string =
        "<enabled>invalid</enabled>\n"
        "<only_future_events>no</only_future_events>"
        "<interval>1d</interval>"
        "<curl_max_size>2</curl_max_size>"
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
            "<client_id>your_client_id</client_id>"
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
    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'enabled' at module 'office365'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),-1);
}

void test_invalid_content_3(void **state) {
    const char *string =
        "<enabled>yes</enabled>\n"
        "<only_future_events>no</only_future_events>"
        "<interval>invalid</interval>"
        "<curl_max_size>2</curl_max_size>"
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
            "<client_id>your_client_id</client_id>"
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
    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'interval' at module 'office365'. The maximum value allowed is 1 day.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),-1);
}

void test_invalid_content_4(void **state) {
    const char *string =
        "<enabled>yes</enabled>\n"
        "<only_future_events>invalid</only_future_events>"
        "<interval>yes</interval>"
        "<curl_max_size>2</curl_max_size>"
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
            "<client_id>your_client_id</client_id>"
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
    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'only_future_events' at module 'office365'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),-1);
}

void test_invalid_interval(void **state) {
    const char *string =
        "<enabled>yes</enabled>\n"
        "<interval>-10</interval>"
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
            "<client_id>your_client_id</client_id>"
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
    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'interval' at module 'office365'. The maximum value allowed is 1 day.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),-1);
}

void test_error_api_auth(void **state) {
    const char *string =
        "<enabled>yes</enabled>\n"
        "<interval>10</interval>"
        "<subscriptions>"
            "<subscription>Audit.AzureActiveDirectory</subscription>"
            "<subscription>Audit.Exchange</subscription>"
            "<subscription>Audit.SharePoint</subscription>"
            "<subscription>Audit.General</subscription>"
            "<subscription>DLP.All</subscription>"
        "</subscriptions>"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "Empty content for tag 'api_auth' at module 'office365'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),-1);
}

void test_error_api_auth_1(void **state) {
    const char *string =
        "<enabled>yes</enabled>\n"
        "<interval>10</interval>"
        "<api_auth>"
            "<invalid>your_tenant_id</invalid>"
            "<invalid>your_client_id</invalid>"
            "<invalid>your_secret</invalid>"
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
    expect_string(__wrap__merror, formatted_msg, "No such tag 'invalid' at module 'office365'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),-1);
}

void test_error_tenant_id(void **state) {
    const char *string =
        "<enabled>yes</enabled>\n"
        "<interval>10</interval>"
        "<api_auth>"
            "<tenant_id></tenant_id>"
            "<client_id>your_client_id</client_id>"
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
    expect_string(__wrap__merror, formatted_msg, "Empty content for tag 'tenant_id' at module 'office365'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),-1);
}

void test_error_tenant_id_1(void **state) {
    const char *string =
        "<enabled>yes</enabled>\n"
        "<interval>10</interval>"
        "<api_auth>"
            "<client_id>your_client_id</client_id>"
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
    expect_string(__wrap__merror, formatted_msg, "'tenant_id' is missing at module 'office365'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),-1);
}

void test_error_client_id(void **state) {
    const char *string =
        "<enabled>yes</enabled>\n"
        "<interval>10</interval>"
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
            "<client_id></client_id>"
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
    expect_string(__wrap__merror, formatted_msg, "Empty content for tag 'client_id' at module 'office365'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),-1);
}

void test_error_client_id_1(void **state) {
    const char *string =
        "<enabled>yes</enabled>\n"
        "<interval>10</interval>"
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
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
    expect_string(__wrap__merror, formatted_msg, "'client_id' is missing at module 'office365'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),-1);
}

void test_error_client_secret(void **state) {
    const char *string =
        "<enabled>yes</enabled>\n"
        "<interval>10</interval>"
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
            "<client_id>your_client_id</client_id>"
            "<client_secret></client_secret>"
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
    expect_string(__wrap__merror, formatted_msg, "Empty content for tag 'client_secret' at module 'office365'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),-1);
}

void test_error_client_secret_1(void **state) {
    const char *string =
        "<enabled>yes</enabled>\n"
        "<interval>10</interval>"
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
            "<client_id>your_client_id</client_id>"
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
    expect_string(__wrap__merror, formatted_msg, "'client_secret' is missing at module 'office365'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),-1);
}

void test_error_client_secret_path (void **state) {
    const char *string =
        "<enabled>yes</enabled>\n"
        "<interval>10</interval>"
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
            "<client_id>your_client_id</client_id>"
            "<client_secret_path>/path/to/secret</client_secret_path>"
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
    expect_string(__wrap_access, __name, "/path/to/secret");
    will_return(__wrap_access, -1);
    expect_string(__wrap__merror, formatted_msg, "At module 'office365': The path cannot be opened.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),-1);
}

void test_error_client_secret_path_1(void **state) {
    const char *string =
        "<enabled>yes</enabled>\n"
        "<interval>10</interval>"
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
            "<client_id>your_client_id</client_id>"
            "<client_secret_path></client_secret_path>"
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
    expect_string(__wrap__merror, formatted_msg, "Empty content for tag 'client_secret_path' at module 'office365'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),-1);
}

void test_wm_office365_dump_no_options(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    char *test = "{\"office365\":{\"enabled\":\"no\",\"only_future_events\":\"no\"}}";

    cJSON *root = wm_office365_dump(data->office365_config);
    data->root_c = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    assert_string_equal(data->root_c, test);
}

void test_wm_office365_dump_yes_options_empty_arrays(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    data->office365_config->enabled = 1;
    data->office365_config->only_future_events = 1;
    data->office365_config->interval = 10;
    data->office365_config->queue_fd = 1;

    os_calloc(1, sizeof(wm_office365_auth), data->office365_config->auth);
    
    os_calloc(1, sizeof(wm_office365_subscription), data->office365_config->subscription);
    os_strdup("", data->office365_config->subscription->subscription_name);

    char *test = "{\"office365\":{\"enabled\":\"yes\",\"only_future_events\":\"yes\",\"interval\":10,\"api_auth\":[{}],\"subscriptions\":[\"\"]}}";
    
    cJSON *root = wm_office365_dump(data->office365_config);
    data->root_c = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    assert_string_equal(data->root_c, test);
}

void test_wm_office365_dump_yes_options(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    data->office365_config->enabled = 1;
    data->office365_config->only_future_events = 1;
    data->office365_config->interval = 10;
    data->office365_config->queue_fd = 1;

    os_calloc(1, sizeof(wm_office365_auth), data->office365_config->auth);
    os_strdup("test_tenant_id", data->office365_config->auth->tenant_id);
    os_strdup("test_client_id", data->office365_config->auth->client_id);
    os_strdup("test_client_secret_path", data->office365_config->auth->client_secret_path);
    os_strdup("test_client_secret", data->office365_config->auth->client_secret);
    
    os_calloc(1, sizeof(wm_office365_subscription), data->office365_config->subscription);
    os_strdup("test_subscription_name", data->office365_config->subscription->subscription_name);

    char *test = "{\"office365\":{\"enabled\":\"yes\",\"only_future_events\":\"yes\",\"interval\":10,\"api_auth\":[{\"tenant_id\":\"test_tenant_id\",\"client_id\":\"test_client_id\",\"client_secret_path\":\"test_client_secret_path\",\"client_secret\":\"test_client_secret\"}],\"subscriptions\":[\"test_subscription_name\"]}}";
    
    cJSON *root = wm_office365_dump(data->office365_config);
    data->root_c = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    assert_string_equal(data->root_c, test);
}


void test_wm_office365_get_access_token_with_auth_secret(void **state) {
    size_t max_size = OS_SIZE_8192;
    test_struct_t *data  = (test_struct_t *)*state;
    data->response = NULL;
    char *access_token = NULL;

    os_calloc(1, sizeof(wm_office365_auth), data->office365_config->auth);
    os_strdup("test_tenant_id", data->office365_config->auth->tenant_id);
    os_strdup("test_client_id", data->office365_config->auth->client_id);
    os_strdup("test_client_secret", data->office365_config->auth->client_secret);

    expect_any(__wrap_wurl_http_request, method);
    expect_any(__wrap_wurl_http_request, header);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    will_return(__wrap_wurl_http_request, data->response);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_any(__wrap__mtdebug1, formatted_msg);
    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mtdebug1, formatted_msg, "Unknown error while getting access token.");

    access_token = wm_office365_get_access_token(data->office365_config->auth, max_size);

    assert_null(access_token);
}

void test_wm_office365_get_access_token_with_auth_secret_path(void **state) {
    size_t max_size = OS_SIZE_8192;
    test_struct_t *data  = (test_struct_t *)*state;
    data->response = NULL;
    char *access_token = NULL;

    const char *filename = "test_client_secret_path";
    FILE *outfile;
    outfile = fopen(filename, "wb");

    os_calloc(1, sizeof(wm_office365_auth), data->office365_config->auth);
    os_strdup("test_tenant_id", data->office365_config->auth->tenant_id);
    os_strdup("test_client_id", data->office365_config->auth->client_id);
    os_strdup("test_client_secret_path", data->office365_config->auth->client_secret_path);

    expect_any(__wrap_wurl_http_request, method);
    expect_any(__wrap_wurl_http_request, header);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    will_return(__wrap_wurl_http_request, data->response);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_any(__wrap__mtdebug1, formatted_msg);
    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mtdebug1, formatted_msg, "Unknown error while getting access token.");

    access_token = wm_office365_get_access_token(data->office365_config->auth, max_size);

    fclose(outfile);

    assert_null(access_token);
}

void test_wm_office365_get_access_token_with_auth_secret_response_fail(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    char *access_token = NULL;
    size_t max_size = OS_SIZE_8192;

    os_calloc(1, sizeof(wm_office365_auth), data->office365_config->auth);
    os_strdup("test_tenant_id", data->office365_config->auth->tenant_id);
    os_strdup("test_client_id", data->office365_config->auth->client_id);
    os_strdup("test_client_secret", data->office365_config->auth->client_secret);

    os_calloc(1, sizeof(curl_response), data->response);
    data->response->status_code = 400;
    os_strdup("{\"error\":\"bad_request\"}", data->response->body);
    os_strdup("test", data->response->header);

    expect_any(__wrap_wurl_http_request, method);
    expect_any(__wrap_wurl_http_request, header);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    will_return(__wrap_wurl_http_request, data->response);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_any(__wrap__mtdebug1, formatted_msg);
    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mtdebug1, formatted_msg, "Error while getting access token: '{\"error\":\"bad_request\"}'");

    expect_value(__wrap_wurl_free_response, response, data->response);

    access_token = wm_office365_get_access_token(data->office365_config->auth, max_size);

    assert_null(access_token);
}

void test_wm_office365_get_access_token_with_auth_secret_response_200(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    char *access_token = NULL;
    size_t max_size = OS_SIZE_8192;

    os_calloc(1, sizeof(wm_office365_auth), data->office365_config->auth);
    os_strdup("test_tenant_id", data->office365_config->auth->tenant_id);
    os_strdup("test_client_id", data->office365_config->auth->client_id);
    os_strdup("test_client_secret", data->office365_config->auth->client_secret);

    os_calloc(1, sizeof(curl_response), data->response);
    data->response->status_code = 200;
    os_strdup("{\"access_token\":\"wazuh\"}", data->response->body);
    os_strdup("test", data->response->header);

    expect_any(__wrap_wurl_http_request, method);
    expect_any(__wrap_wurl_http_request, header);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    will_return(__wrap_wurl_http_request, data->response);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_any(__wrap__mtdebug1, formatted_msg);

    expect_value(__wrap_wurl_free_response, response, data->response);

    access_token = wm_office365_get_access_token(data->office365_config->auth, max_size);

    assert_string_equal(access_token, "wazuh");
}


void test_wm_office365_manage_subscription_start_code_200(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int value = 0;
    size_t max_size = OS_SIZE_8192;

    char *token = "test_token";
    char* client_id = "test_client_id";
    int start = 1;

    os_calloc(1, sizeof(wm_office365_auth), data->office365_config->auth);
    os_strdup("test_tenant_id", data->office365_config->auth->tenant_id);
    os_strdup("test_client_id", data->office365_config->auth->client_id);
    os_strdup("test_client_secret", data->office365_config->auth->client_secret);

    os_calloc(1, sizeof(wm_office365_subscription), data->office365_config->subscription);
    os_strdup("test_subscription_name", data->office365_config->subscription->subscription_name);

    os_calloc(1, sizeof(curl_response), data->response);
    data->response->status_code = 200;
    os_strdup("{\"access_token\":\"wazuh\"}", data->response->body);
    os_strdup("test", data->response->header);

    expect_any(__wrap_wurl_http_request, method);
    expect_string(__wrap_wurl_http_request, header, "Content-Type: application/json");

    char expHeader[OS_SIZE_8192];
    snprintf(expHeader, OS_SIZE_8192 -1, "Authorization: Bearer %s", token);

    expect_string(__wrap_wurl_http_request, header, expHeader);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    will_return(__wrap_wurl_http_request, data->response);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_any(__wrap__mtdebug1, formatted_msg);

    expect_value(__wrap_wurl_free_response, response, data->response);

    value = wm_office365_manage_subscription(data->office365_config->subscription, client_id, token, max_size, start);

    assert_int_equal(value, OS_SUCCESS);
}

void test_wm_office365_manage_subscription_stop_code_400_error_AF20024(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int value = 0;
    size_t max_size = OS_SIZE_8192;

    char *token = "test_token";
    char* client_id = "test_client_id";
    int start = 0;

    os_calloc(1, sizeof(wm_office365_auth), data->office365_config->auth);
    os_strdup("test_tenant_id", data->office365_config->auth->tenant_id);
    os_strdup("test_client_id", data->office365_config->auth->client_id);
    os_strdup("test_client_secret", data->office365_config->auth->client_secret);

    os_calloc(1, sizeof(wm_office365_subscription), data->office365_config->subscription);
    os_strdup("test_subscription_name", data->office365_config->subscription->subscription_name);

    os_calloc(1, sizeof(curl_response), data->response);
    data->response->status_code = 400;
    os_strdup("{\"error\":{\"code\":\"AF20024\"}}", data->response->body);
    os_strdup("test", data->response->header);

    expect_any(__wrap_wurl_http_request, method);
    expect_string(__wrap_wurl_http_request, header, "Content-Type: application/json");

    char expHeader[OS_SIZE_8192];
    snprintf(expHeader, OS_SIZE_8192 -1, "Authorization: Bearer %s", token);

    expect_string(__wrap_wurl_http_request, header, expHeader);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    will_return(__wrap_wurl_http_request, data->response);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_any(__wrap__mtdebug1, formatted_msg);

    expect_value(__wrap_wurl_free_response, response, data->response);

    value = wm_office365_manage_subscription(data->office365_config->subscription, client_id, token, max_size, start);

    assert_int_equal(value, OS_SUCCESS);
}

void test_wm_office365_manage_subscription_stop_code_400_error_different_AF20024(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int value = 0;
    size_t max_size = OS_SIZE_8192;

    char *token = "test_token";
    char* client_id = "test_client_id";
    int start = 0;

    os_calloc(1, sizeof(wm_office365_auth), data->office365_config->auth);
    os_strdup("test_tenant_id", data->office365_config->auth->tenant_id);
    os_strdup("test_client_id", data->office365_config->auth->client_id);
    os_strdup("test_client_secret", data->office365_config->auth->client_secret);

    os_calloc(1, sizeof(wm_office365_subscription), data->office365_config->subscription);
    os_strdup("test_subscription_name", data->office365_config->subscription->subscription_name);

    os_calloc(1, sizeof(curl_response), data->response);
    data->response->status_code = 400;
    os_strdup("{\"error\":{\"code\":\"AF20023\"}}", data->response->body);
    os_strdup("test", data->response->header);

    expect_any(__wrap_wurl_http_request, method);
    expect_string(__wrap_wurl_http_request, header, "Content-Type: application/json");

    char expHeader[OS_SIZE_8192];
    snprintf(expHeader, OS_SIZE_8192 -1, "Authorization: Bearer %s", token);

    expect_string(__wrap_wurl_http_request, header, expHeader);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    will_return(__wrap_wurl_http_request, data->response);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_any(__wrap__mtdebug1, formatted_msg);
    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mtdebug1, formatted_msg, "Error while managing subscription: '{\"error\":{\"code\":\"AF20023\"}}'");

    expect_value(__wrap_wurl_free_response, response, data->response);

    value = wm_office365_manage_subscription(data->office365_config->subscription, client_id, token, max_size, start);

    assert_int_equal(value, OS_INVALID);
    //assert_string_equal(*error_msg, data->response->body);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_read_configuration, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_configuration_1, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_default_configuration, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_interval, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_interval_s, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_interval_s_fail, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_interval_m, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_interval_m_fail, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_interval_h, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_interval_h_fail, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_interval_d, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_interval_d_fail, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_curl_max_size, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_curl_max_size_invalid_1, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_curl_max_size_invalid_2, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_curl_max_size_invalid_3, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_secret_path_and_secret, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_fake_tag, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_fake_tag_1, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_invalid_content_1, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_invalid_content_2, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_invalid_content_3, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_invalid_content_4, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_invalid_interval, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_error_api_auth, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_error_api_auth_1, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_error_tenant_id, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_error_tenant_id_1, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_error_client_id, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_error_client_id_1, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_error_client_secret, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_error_client_secret_1, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_error_client_secret_path, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_error_client_secret_path_1, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_wm_office365_dump_no_options, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_office365_dump_yes_options_empty_arrays, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_office365_dump_yes_options, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_office365_get_access_token_with_auth_secret, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_office365_get_access_token_with_auth_secret_path, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_office365_get_access_token_with_auth_secret_response_fail, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_office365_get_access_token_with_auth_secret_response_200, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_office365_manage_subscription_start_code_200, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_office365_manage_subscription_stop_code_400_error_AF20024, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_office365_manage_subscription_stop_code_400_error_different_AF20024, setup_conf, teardown_conf),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

