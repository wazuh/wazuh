/*
 * Copyright (C) 2015, Wazuh Inc.
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
#include "../wazuh_modules/wmodules.h"
#include "../wazuh_modules/wm_office365.h"
#include "../wazuh_modules/wm_office365.c"

#include "../scheduling/wmodules_scheduling_helpers.h"
#include "../../wrappers/common.h"
#include "../../wrappers/libc/stdlib_wrappers.h"
#include "../../wrappers/wazuh/shared/mq_op_wrappers.h"
#include "../../wrappers/wazuh/wazuh_modules/wmodules_wrappers.h"
#include "../../wrappers/wazuh/shared/time_op_wrappers.h"
#include "../../wrappers/wazuh/shared/url_wrappers.h"
#include "../../wrappers/libc/time_wrappers.h"
#ifdef WIN32
#include "../../wrappers/wazuh/shared/file_op_wrappers.h"
#endif

int __wrap_access(const char *__name, int __type) {
    check_expected(__name);
    return mock_type(int);
}

unsigned int __wrap_sleep(unsigned int __seconds) {
    check_expected(__seconds);
    return mock_type(unsigned int);
}

unsigned int __wrap_gmtime_r(__attribute__ ((__unused__)) const time_t *t, __attribute__ ((__unused__)) struct tm *tm) {
    return mock_type(unsigned int);
}

int __wrap_isDebug() {
    return mock();
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
            os_free(((wm_office365*)test->module->data)->auth->login_fqdn);
            os_free(((wm_office365*)test->module->data)->auth->management_fqdn);
            if (((wm_office365*)test->module->data)->auth->next) {
                os_free(((wm_office365*)test->module->data)->auth->next->tenant_id);
                os_free(((wm_office365*)test->module->data)->auth->next->client_id);
                os_free(((wm_office365*)test->module->data)->auth->next->client_secret_path);
                os_free(((wm_office365*)test->module->data)->auth->next->client_secret);
                os_free(((wm_office365*)test->module->data)->auth->next->login_fqdn);
                os_free(((wm_office365*)test->module->data)->auth->next->management_fqdn);
                if (((wm_office365*)test->module->data)->auth->next->next) {
                    os_free(((wm_office365*)test->module->data)->auth->next->next->tenant_id);
                    os_free(((wm_office365*)test->module->data)->auth->next->next->client_id);
                    os_free(((wm_office365*)test->module->data)->auth->next->next->client_secret_path);
                    os_free(((wm_office365*)test->module->data)->auth->next->next->client_secret);
                    os_free(((wm_office365*)test->module->data)->auth->next->next->login_fqdn);
                    os_free(((wm_office365*)test->module->data)->auth->next->next->management_fqdn);
                    os_free(((wm_office365*)test->module->data)->auth->next->next->next);
                }
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
        "<curl_max_size>2048</curl_max_size>"
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
    assert_string_equal(module_data->auth->login_fqdn, WM_OFFICE365_DEFAULT_API_LOGIN_FQDN); // retrocompatability test
    assert_string_equal(module_data->auth->management_fqdn, WM_OFFICE365_DEFAULT_API_MANAGEMENT_FQDN); // retrocompatability test
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
        "<curl_max_size>2k</curl_max_size>"
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
            "<client_id>your_client_id</client_id>"
            "<client_secret>your_secret</client_secret>"
            "<api_type>commercial</api_type>"
        "</api_auth>"
        "<api_auth>"
            "<tenant_id>your_tenant_id_1</tenant_id>"
            "<client_id>your_client_id_1</client_id>"
            "<client_secret>your_secret_1</client_secret>"
            "<api_type>gcc</api_type>"
        "</api_auth>"
        "<api_auth>"
            "<tenant_id>your_tenant_id_2</tenant_id>"
            "<client_id>your_client_id_2</client_id>"
            "<client_secret_path>/path/to/secret</client_secret_path>"
            "<api_type>gcc-high</api_type>"
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
    assert_string_equal(module_data->auth->login_fqdn, WM_OFFICE365_DEFAULT_API_LOGIN_FQDN);
    assert_string_equal(module_data->auth->management_fqdn, WM_OFFICE365_DEFAULT_API_MANAGEMENT_FQDN);
    assert_string_equal(module_data->auth->next->tenant_id, "your_tenant_id_1");
    assert_string_equal(module_data->auth->next->client_id, "your_client_id_1");
    assert_string_equal(module_data->auth->next->client_secret, "your_secret_1");
    assert_string_equal(module_data->auth->next->login_fqdn, WM_OFFICE365_GCC_API_LOGIN_FQDN);
    assert_string_equal(module_data->auth->next->management_fqdn, WM_OFFICE365_GCC_API_MANAGEMENT_FQDN);
    assert_string_equal(module_data->auth->next->next->tenant_id, "your_tenant_id_2");
    assert_string_equal(module_data->auth->next->next->client_id, "your_client_id_2");
    assert_string_equal(module_data->auth->next->next->client_secret_path, "/path/to/secret");
    assert_string_equal(module_data->auth->next->next->login_fqdn, WM_OFFICE365_GCC_HIGH_API_LOGIN_FQDN);
    assert_string_equal(module_data->auth->next->next->management_fqdn, WM_OFFICE365_GCC_HIGH_API_MANAGEMENT_FQDN);
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
            "<api_type>commercial</api_type>"
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
        "<curl_max_size>2k</curl_max_size>"
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
            "<client_id>your_client_id</client_id>"
            "<client_secret>your_secret</client_secret>"
            "<api_type>commercial</api_type>"
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
    assert_string_equal(module_data->auth->login_fqdn, WM_OFFICE365_DEFAULT_API_LOGIN_FQDN);
    assert_string_equal(module_data->auth->management_fqdn, WM_OFFICE365_DEFAULT_API_MANAGEMENT_FQDN);
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
        "<curl_max_size>2k</curl_max_size>"
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
            "<client_id>your_client_id</client_id>"
            "<client_secret>your_secret</client_secret>"
            "<api_type>commercial</api_type>"
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
        "<curl_max_size>2k</curl_max_size>"
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
            "<client_id>your_client_id</client_id>"
            "<client_secret>your_secret</client_secret>"
            "<api_type>commercial</api_type>"
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
        "<curl_max_size>2k</curl_max_size>"
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
            "<client_id>your_client_id</client_id>"
            "<client_secret>your_secret</client_secret>"
            "<api_type>commercial</api_type>"
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
        "<curl_max_size>2k</curl_max_size>"
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
            "<client_id>your_client_id</client_id>"
            "<client_secret>your_secret</client_secret>"
            "<api_type>commercial</api_type>"
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
        "<curl_max_size>2k</curl_max_size>"
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
            "<client_id>your_client_id</client_id>"
            "<client_secret>your_secret</client_secret>"
            "<api_type>commercial</api_type>"
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
        "<curl_max_size>2k</curl_max_size>"
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
            "<client_id>your_client_id</client_id>"
            "<client_secret>your_secret</client_secret>"
            "<api_type>commercial</api_type>"
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
        "<curl_max_size>2k</curl_max_size>"
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
            "<client_id>your_client_id</client_id>"
            "<client_secret>your_secret</client_secret>"
            "<api_type>commercial</api_type>"
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
        "<curl_max_size>2k</curl_max_size>"
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
            "<client_id>your_client_id</client_id>"
            "<client_secret>your_secret</client_secret>"
            "<api_type>commercial</api_type>"
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
        "<curl_max_size>4k</curl_max_size>"
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
            "<client_id>your_client_id</client_id>"
            "<client_secret>your_secret</client_secret>"
            "<api_type>commercial</api_type>"
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
    assert_string_equal(module_data->auth->login_fqdn, WM_OFFICE365_DEFAULT_API_LOGIN_FQDN);
    assert_string_equal(module_data->auth->management_fqdn, WM_OFFICE365_DEFAULT_API_MANAGEMENT_FQDN);
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
            "<api_type>commercial</api_type>"
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
    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'curl_max_size' at module 'office365'. The minimum value allowed is 1KB.");
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
            "<api_type>commercial</api_type>"
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
    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'curl_max_size' at module 'office365'. The minimum value allowed is 1KB.");
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
            "<api_type>commercial</api_type>"
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
    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'curl_max_size' at module 'office365'. The minimum value allowed is 1KB.");
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
            "<api_type>commercial</api_type>"
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
        "<curl_max_size>2k</curl_max_size>"
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
            "<client_id>your_client_id</client_id>"
            "<client_secret>your_secret</client_secret>"
            "<api_type>commercial</api_type>"
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
        "<curl_max_size>2k</curl_max_size>"
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
            "<client_id>your_client_id</client_id>"
            "<client_secret>your_secret</client_secret>"
            "<api_type>commercial</api_type>"
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
        "<curl_max_size>2k</curl_max_size>"
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
            "<client_id>your_client_id</client_id>"
            "<client_secret>your_secret</client_secret>"
            "<api_type>commercial</api_type>"
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
        "<curl_max_size>2k</curl_max_size>"
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
            "<client_id>your_client_id</client_id>"
            "<client_secret>your_secret</client_secret>"
            "<api_type>commercial</api_type>"
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
        "<curl_max_size>2k</curl_max_size>"
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
            "<client_id>your_client_id</client_id>"
            "<client_secret>your_secret</client_secret>"
            "<api_type>commercial</api_type>"
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
        "<curl_max_size>2k</curl_max_size>"
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
            "<client_id>your_client_id</client_id>"
            "<client_secret>your_secret</client_secret>"
            "<api_type>commercial</api_type>"
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
            "<api_type>commercial</api_type>"
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
            "<invalid>commercial</invalid>"
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
            "<api_type>commercial</api_type>"
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
            "<api_type>commercial</api_type>"
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
            "<api_type>commercial</api_type>"
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
            "<api_type>commercial</api_type>"
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
            "<api_type>commercial</api_type>"
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
            "<api_type>commercial</api_type>"
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

void test_error_client_secret_path(void **state) {
    const char *string =
        "<enabled>yes</enabled>\n"
        "<interval>10</interval>"
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
            "<client_id>your_client_id</client_id>"
            "<client_secret_path>/path/to/secret</client_secret_path>"
            "<api_type>commercial</api_type>"
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
    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'client_secret_path' at module 'office365': The path cannot be opened.");
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
            "<api_type>commercial</api_type>"
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

void test_error_api_type(void **state) {
    const char *string =
        "<enabled>yes</enabled>\n"
        "<interval>10</interval>"
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
            "<client_id>your_client_id</client_id>"
            "<client_secret>your_secret</client_secret>"
            "<api_type>invalid</api_type>"
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
    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'api_type' at module 'office365'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),-1);
}

void test_error_api_type_1(void **state) {
    const char *string =
        "<enabled>yes</enabled>\n"
        "<interval>10</interval>"
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
            "<client_id>your_client_id</client_id>"
            "<client_secret>your_secret</client_secret>"
            "<api_type></api_type>"
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
    expect_string(__wrap__merror, formatted_msg, "Empty content for tag 'api_type' at module 'office365'.");
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
    data->office365_config->curl_max_size = 1024;
    data->office365_config->queue_fd = 1;

    os_calloc(1, sizeof(wm_office365_auth), data->office365_config->auth);

    os_calloc(1, sizeof(wm_office365_subscription), data->office365_config->subscription);
    os_strdup("", data->office365_config->subscription->subscription_name);

    char *test = "{\"office365\":{\"enabled\":\"yes\",\"only_future_events\":\"yes\",\"interval\":10,\"curl_max_size\":1024,\"api_auth\":[{}],\"subscriptions\":[\"\"]}}";

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
    os_strdup(WM_OFFICE365_DEFAULT_API_LOGIN_FQDN, data->office365_config->auth->login_fqdn);
    os_strdup(WM_OFFICE365_DEFAULT_API_MANAGEMENT_FQDN, data->office365_config->auth->management_fqdn);

    os_calloc(1, sizeof(wm_office365_subscription), data->office365_config->subscription);
    os_strdup("test_subscription_name", data->office365_config->subscription->subscription_name);

    char *test = "{\"office365\":{\"enabled\":\"yes\",\"only_future_events\":\"yes\",\"interval\":10,\"api_auth\":[{\"tenant_id\":\"test_tenant_id\",\"client_id\":\"test_client_id\",\"client_secret_path\":\"test_client_secret_path\",\"client_secret\":\"test_client_secret\",\"api_type\":\"commercial\"}],\"subscriptions\":[\"test_subscription_name\"]}}";

    cJSON *root = wm_office365_dump(data->office365_config);
    data->root_c = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    assert_string_equal(data->root_c, test);
}

void test_wm_office365_main_disabled(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    data->office365_config->enabled = 0;

    expect_string(__wrap__mtinfo, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mtinfo, formatted_msg, "Module Office365 disabled.");

    wm_office365_main(data->office365_config);
}

void test_wm_office365_main_fail_StartMQ(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    data->office365_config->enabled = 1;

    expect_string(__wrap__mtinfo, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mtinfo, formatted_msg, "Module Office365 started.");

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mterror, formatted_msg, "Can't connect to queue. Closing module.");

    expect_string(__wrap_StartMQ, path, DEFAULTQUEUE);
    expect_value(__wrap_StartMQ, type, WRITE);
    will_return(__wrap_StartMQ, -1);

    wm_office365_main(data->office365_config);
}

void test_wm_office365_main_enable(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    size_t max_size = OS_SIZE_8192;

    data->office365_config->enabled = 1;
    os_calloc(1, sizeof(wm_office365_auth), data->office365_config->auth);
    os_strdup("test_tenant_id", data->office365_config->auth->tenant_id);
    os_strdup("test_client_id", data->office365_config->auth->client_id);
    os_strdup("test_client_secret", data->office365_config->auth->client_secret);
    os_strdup(WM_OFFICE365_DEFAULT_API_LOGIN_FQDN, data->office365_config->auth->login_fqdn);
    os_strdup(WM_OFFICE365_DEFAULT_API_MANAGEMENT_FQDN, data->office365_config->auth->management_fqdn);
    os_calloc(1, sizeof(wm_office365_subscription), data->office365_config->subscription);
    os_strdup("test_subscription_name", data->office365_config->subscription->subscription_name);
    data->office365_config->only_future_events = 1;

    expect_string(__wrap_StartMQ, path, DEFAULTQUEUE);
    expect_value(__wrap_StartMQ, type, WRITE);
    will_return(__wrap_StartMQ, 1);

    expect_string(__wrap__mtinfo, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mtinfo, formatted_msg, "Module Office365 started.");

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mtdebug1, formatted_msg, "Scanning tenant: 'test_tenant_id'");

    expect_string(__wrap_wm_state_io, tag, "office365-test_tenant_id-test_subscription_name");
    expect_value(__wrap_wm_state_io, op, WM_IO_READ);
    expect_any(__wrap_wm_state_io, state);
    expect_any(__wrap_wm_state_io, size);
    will_return(__wrap_wm_state_io, 1);

    will_return(__wrap_isDebug, 0);

    expect_string(__wrap_wm_state_io, tag, "office365-test_tenant_id-test_subscription_name");
    expect_value(__wrap_wm_state_io, op, WM_IO_WRITE);
    expect_any(__wrap_wm_state_io, state);
    expect_any(__wrap_wm_state_io, size);
    will_return(__wrap_wm_state_io, 1);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mtdebug1, formatted_msg, "Scanning tenant: 'test_tenant_id'");

    expect_any(__wrap_wurl_http_request, method);
    expect_any(__wrap_wurl_http_request, header);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_OFFICE365_DEFAULT_CURL_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_request, NULL);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_any(__wrap__mtdebug1, formatted_msg);
    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mtdebug1, formatted_msg, "Unknown error while getting access token.");

    wm_office365_main(data->office365_config);
}

void test_wm_office365_get_access_token_with_auth_secret(void **state) {
    size_t max_size = OS_SIZE_8192;
    test_struct_t *data  = (test_struct_t *)*state;
    data->response = NULL;
    char *access_token = NULL;
    char *error_msg = NULL;

    os_calloc(1, sizeof(wm_office365_auth), data->office365_config->auth);
    os_strdup("test_tenant_id", data->office365_config->auth->tenant_id);
    os_strdup("test_client_id", data->office365_config->auth->client_id);
    os_strdup("test_client_secret", data->office365_config->auth->client_secret);
    os_strdup(WM_OFFICE365_DEFAULT_API_LOGIN_FQDN, data->office365_config->auth->login_fqdn);
    os_strdup(WM_OFFICE365_DEFAULT_API_MANAGEMENT_FQDN, data->office365_config->auth->management_fqdn);

    expect_any(__wrap_wurl_http_request, method);
    expect_any(__wrap_wurl_http_request, header);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_OFFICE365_DEFAULT_CURL_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_request, data->response);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_any(__wrap__mtdebug1, formatted_msg);
    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mtdebug1, formatted_msg, "Unknown error while getting access token.");

    access_token = wm_office365_get_access_token(data->office365_config->auth, max_size, &error_msg);

    assert_null(access_token);
    assert_null(error_msg);
}

void test_wm_office365_get_access_token_with_auth_secret_path(void **state) {
    size_t max_size = OS_SIZE_8192;
    test_struct_t *data  = (test_struct_t *)*state;
    data->response = NULL;
    char *access_token = NULL;
    char *error_msg = NULL;

    const char *filename = "test_client_secret_path";
    FILE *outfile;
    outfile = fopen(filename, "wb");

    os_calloc(1, sizeof(wm_office365_auth), data->office365_config->auth);
    os_strdup("test_tenant_id", data->office365_config->auth->tenant_id);
    os_strdup("test_client_id", data->office365_config->auth->client_id);
    os_strdup("test_client_secret_path", data->office365_config->auth->client_secret_path);
    os_strdup(WM_OFFICE365_DEFAULT_API_LOGIN_FQDN, data->office365_config->auth->login_fqdn);
    os_strdup(WM_OFFICE365_DEFAULT_API_MANAGEMENT_FQDN, data->office365_config->auth->management_fqdn);

    expect_any(__wrap_wurl_http_request, method);
    expect_any(__wrap_wurl_http_request, header);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_OFFICE365_DEFAULT_CURL_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_request, data->response);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_any(__wrap__mtdebug1, formatted_msg);
    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mtdebug1, formatted_msg, "Unknown error while getting access token.");

    test_mode = 0;
    access_token = wm_office365_get_access_token(data->office365_config->auth, max_size, &error_msg);
    test_mode = 1;

    fclose(outfile);

    assert_null(access_token);
    assert_null(error_msg);
}

void test_wm_office365_get_access_token_with_auth_secret_response_400(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    char *access_token = NULL;
    size_t max_size = OS_SIZE_8192;
    char *error_msg = NULL;

    os_calloc(1, sizeof(wm_office365_auth), data->office365_config->auth);
    os_strdup("test_tenant_id", data->office365_config->auth->tenant_id);
    os_strdup("test_client_id", data->office365_config->auth->client_id);
    os_strdup("test_client_secret", data->office365_config->auth->client_secret);
    os_strdup(WM_OFFICE365_DEFAULT_API_LOGIN_FQDN, data->office365_config->auth->login_fqdn);
    os_strdup(WM_OFFICE365_DEFAULT_API_MANAGEMENT_FQDN, data->office365_config->auth->management_fqdn);

    os_calloc(1, sizeof(curl_response), data->response);
    data->response->status_code = 400;
    os_strdup("{\"error\":\"bad_request\"}", data->response->body);
    os_strdup("test", data->response->header);

    expect_any(__wrap_wurl_http_request, method);
    expect_any(__wrap_wurl_http_request, header);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_OFFICE365_DEFAULT_CURL_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_request, data->response);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_any(__wrap__mtdebug1, formatted_msg);
    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mtdebug1, formatted_msg, "Error while getting access token: '{\"error\":\"bad_request\"}'");

    expect_value(__wrap_wurl_free_response, response, data->response);

    access_token = wm_office365_get_access_token(data->office365_config->auth, max_size, &error_msg);

    assert_null(access_token);
    assert_string_equal(error_msg, data->response->body);

    os_free(data->response->body);
    os_free(data->response->header);
    os_free(data->response);
    os_free(error_msg);
}

void test_wm_office365_get_access_token_with_auth_secret_response_null(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    char *access_token = NULL;
    size_t max_size = OS_SIZE_8192;
    char *error_msg = NULL;

    os_calloc(1, sizeof(wm_office365_auth), data->office365_config->auth);
    os_strdup("test_tenant_id", data->office365_config->auth->tenant_id);
    os_strdup("test_client_id", data->office365_config->auth->client_id);
    os_strdup("test_client_secret", data->office365_config->auth->client_secret);
    os_strdup(WM_OFFICE365_DEFAULT_API_LOGIN_FQDN, data->office365_config->auth->login_fqdn);
    os_strdup(WM_OFFICE365_DEFAULT_API_MANAGEMENT_FQDN, data->office365_config->auth->management_fqdn);

    os_calloc(1, sizeof(curl_response), data->response);
    data->response->status_code = 400;
    os_strdup("{\"error\":\"bad_request\"}", data->response->body);
    os_strdup("test", data->response->header);

    expect_any(__wrap_wurl_http_request, method);
    expect_any(__wrap_wurl_http_request, header);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_OFFICE365_DEFAULT_CURL_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_request, NULL);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_any(__wrap__mtdebug1, formatted_msg);
    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mtdebug1, formatted_msg, "Unknown error while getting access token.");

    access_token = wm_office365_get_access_token(data->office365_config->auth, max_size, &error_msg);

    assert_null(access_token);
    assert_null(error_msg);

    os_free(data->response->body);
    os_free(data->response->header);
    os_free(data->response);
}

void test_wm_office365_get_access_token_with_auth_secret_response_max_size_reached(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    char *access_token = NULL;
    size_t max_size = OS_SIZE_8192;
    char *error_msg = NULL;

    os_calloc(1, sizeof(wm_office365_auth), data->office365_config->auth);
    os_strdup("test_tenant_id", data->office365_config->auth->tenant_id);
    os_strdup("test_client_id", data->office365_config->auth->client_id);
    os_strdup("test_client_secret", data->office365_config->auth->client_secret);
    os_strdup(WM_OFFICE365_DEFAULT_API_LOGIN_FQDN, data->office365_config->auth->login_fqdn);
    os_strdup(WM_OFFICE365_DEFAULT_API_MANAGEMENT_FQDN, data->office365_config->auth->management_fqdn);

    os_calloc(1, sizeof(curl_response), data->response);
    data->response->status_code = 400;
    os_strdup("{\"error\":\"bad_request\"}", data->response->body);
    os_strdup("test", data->response->header);
    data->response->max_size_reached = 1;

    expect_any(__wrap_wurl_http_request, method);
    expect_any(__wrap_wurl_http_request, header);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_OFFICE365_DEFAULT_CURL_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_request, data->response);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_any(__wrap__mtdebug1, formatted_msg);
    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mtdebug1, formatted_msg, "Libcurl error, reached maximum response size.");

    expect_value(__wrap_wurl_free_response, response, data->response);

    access_token = wm_office365_get_access_token(data->office365_config->auth, max_size, &error_msg);

    assert_null(access_token);
    assert_null(error_msg);

    os_free(data->response->body);
    os_free(data->response->header);
    os_free(data->response);
}

void test_wm_office365_get_access_token_with_auth_secret_error_json_response(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    char *access_token = NULL;
    size_t max_size = OS_SIZE_8192;
    char *error_msg = NULL;

    os_calloc(1, sizeof(wm_office365_auth), data->office365_config->auth);
    os_strdup("test_tenant_id", data->office365_config->auth->tenant_id);
    os_strdup("test_client_id", data->office365_config->auth->client_id);
    os_strdup("test_client_secret", data->office365_config->auth->client_secret);
    os_strdup(WM_OFFICE365_DEFAULT_API_LOGIN_FQDN, data->office365_config->auth->login_fqdn);
    os_strdup(WM_OFFICE365_DEFAULT_API_MANAGEMENT_FQDN, data->office365_config->auth->management_fqdn);

    os_calloc(1, sizeof(curl_response), data->response);
    data->response->status_code = 400;
    os_strdup("{\"error\":\"bad_requ", data->response->body);
    os_strdup("test", data->response->header);

    expect_any(__wrap_wurl_http_request, method);
    expect_any(__wrap_wurl_http_request, header);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_OFFICE365_DEFAULT_CURL_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_request, data->response);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_any(__wrap__mtdebug1, formatted_msg);
    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mtdebug1, formatted_msg, "Error while parsing access token JSON response.");

    expect_value(__wrap_wurl_free_response, response, data->response);

    access_token = wm_office365_get_access_token(data->office365_config->auth, max_size, &error_msg);

    assert_null(access_token);
    assert_null(error_msg);

    os_free(data->response->body);
    os_free(data->response->header);
    os_free(data->response);
}

void test_wm_office365_get_access_token_with_auth_secret_response_200(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    char *access_token = NULL;
    size_t max_size = OS_SIZE_8192;
    char *error_msg = NULL;

    os_calloc(1, sizeof(wm_office365_auth), data->office365_config->auth);
    os_strdup("test_tenant_id", data->office365_config->auth->tenant_id);
    os_strdup("test_client_id", data->office365_config->auth->client_id);
    os_strdup("test_client_secret", data->office365_config->auth->client_secret);
    os_strdup(WM_OFFICE365_DEFAULT_API_LOGIN_FQDN, data->office365_config->auth->login_fqdn);
    os_strdup(WM_OFFICE365_DEFAULT_API_MANAGEMENT_FQDN, data->office365_config->auth->management_fqdn);

    os_calloc(1, sizeof(curl_response), data->response);
    data->response->status_code = 200;
    os_strdup("{\"access_token\":\"wazuh\"}", data->response->body);
    os_strdup("test", data->response->header);

    expect_any(__wrap_wurl_http_request, method);
    expect_any(__wrap_wurl_http_request, header);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_OFFICE365_DEFAULT_CURL_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_request, data->response);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_any(__wrap__mtdebug1, formatted_msg);

    expect_value(__wrap_wurl_free_response, response, data->response);

    access_token = wm_office365_get_access_token(data->office365_config->auth, max_size, &error_msg);

    assert_string_equal(access_token, "wazuh");
    assert_null(error_msg);

    os_free(data->response->body);
    os_free(data->response->header);
    os_free(data->response);
    os_free(access_token);
}

void test_wm_office365_manage_subscription_start_response_null(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int value = 0;
    size_t max_size = OS_SIZE_8192;
    char *error_msg = NULL;

    char *token = "test_token";
    char* client_id = "test_client_id";
    char* management_fqdn = WM_OFFICE365_DEFAULT_API_MANAGEMENT_FQDN;
    int start = 1;

    os_calloc(1, sizeof(wm_office365_auth), data->office365_config->auth);
    os_strdup("test_tenant_id", data->office365_config->auth->tenant_id);
    os_strdup("test_client_id", data->office365_config->auth->client_id);
    os_strdup("test_client_secret", data->office365_config->auth->client_secret);
    os_strdup(WM_OFFICE365_DEFAULT_API_LOGIN_FQDN, data->office365_config->auth->login_fqdn);
    os_strdup(WM_OFFICE365_DEFAULT_API_MANAGEMENT_FQDN, data->office365_config->auth->management_fqdn);

    os_calloc(1, sizeof(wm_office365_subscription), data->office365_config->subscription);
    os_strdup("test_subscription_name", data->office365_config->subscription->subscription_name);

    os_calloc(1, sizeof(curl_response), data->response);
    data->response->status_code = 200;
    os_strdup("{\"access_token\":\"wazuh\"}", data->response->body);
    os_strdup("test", data->response->header);

    expect_string(__wrap_wurl_http_request, header, "Content-Type: application/json");
    expect_any(__wrap_wurl_http_request, method);

    char expHeader[OS_SIZE_8192];
    snprintf(expHeader, OS_SIZE_8192 -1, "Authorization: Bearer %s", token);

    expect_string(__wrap_wurl_http_request, header, expHeader);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_OFFICE365_DEFAULT_CURL_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_request, NULL);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_any(__wrap__mtdebug1, formatted_msg);
    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mtdebug1, formatted_msg, "Unknown error while managing subscription.");

    value = wm_office365_manage_subscription(data->office365_config->subscription, management_fqdn, client_id, token, start, max_size, &error_msg);

    assert_int_equal(value, OS_INVALID);
    assert_null(error_msg);

    os_free(data->response->body);
    os_free(data->response->header);
    os_free(data->response);
}

void test_wm_office365_manage_subscription_start_code_200(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int value = 0;
    size_t max_size = OS_SIZE_8192;
    char *error_msg = NULL;

    char *token = "test_token";
    char* client_id = "test_client_id";
    char* management_fqdn = WM_OFFICE365_DEFAULT_API_MANAGEMENT_FQDN;
    int start = 1;

    os_calloc(1, sizeof(wm_office365_auth), data->office365_config->auth);
    os_strdup("test_tenant_id", data->office365_config->auth->tenant_id);
    os_strdup("test_client_id", data->office365_config->auth->client_id);
    os_strdup("test_client_secret", data->office365_config->auth->client_secret);
    os_strdup(WM_OFFICE365_DEFAULT_API_LOGIN_FQDN, data->office365_config->auth->login_fqdn);
    os_strdup(WM_OFFICE365_DEFAULT_API_MANAGEMENT_FQDN, data->office365_config->auth->management_fqdn);

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
    expect_value(__wrap_wurl_http_request, timeout, WM_OFFICE365_DEFAULT_CURL_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_request, data->response);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_any(__wrap__mtdebug1, formatted_msg);

    expect_value(__wrap_wurl_free_response, response, data->response);

    value = wm_office365_manage_subscription(data->office365_config->subscription, management_fqdn, client_id, token, start, max_size, &error_msg);

    assert_int_equal(value, OS_SUCCESS);
    assert_null(error_msg);

    os_free(data->response->body);
    os_free(data->response->header);
    os_free(data->response);
}

void test_wm_office365_manage_subscription_stop_error_json_response(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int value = 0;
    size_t max_size = OS_SIZE_8192;
    char *error_msg = NULL;

    char *token = "test_token";
    char* client_id = "test_client_id";
    char* management_fqdn = WM_OFFICE365_DEFAULT_API_MANAGEMENT_FQDN;
    int start = 0;

    os_calloc(1, sizeof(wm_office365_auth), data->office365_config->auth);
    os_strdup("test_tenant_id", data->office365_config->auth->tenant_id);
    os_strdup("test_client_id", data->office365_config->auth->client_id);
    os_strdup("test_client_secret", data->office365_config->auth->client_secret);
    os_strdup(WM_OFFICE365_DEFAULT_API_LOGIN_FQDN, data->office365_config->auth->login_fqdn);
    os_strdup(WM_OFFICE365_DEFAULT_API_MANAGEMENT_FQDN, data->office365_config->auth->management_fqdn);

    os_calloc(1, sizeof(wm_office365_subscription), data->office365_config->subscription);
    os_strdup("test_subscription_name", data->office365_config->subscription->subscription_name);

    os_calloc(1, sizeof(curl_response), data->response);
    data->response->status_code = 400;
    os_strdup("{\"error\":{\"code\":", data->response->body);
    os_strdup("test", data->response->header);

    expect_any(__wrap_wurl_http_request, method);
    expect_string(__wrap_wurl_http_request, header, "Content-Type: application/json");

    char expHeader[OS_SIZE_8192];
    snprintf(expHeader, OS_SIZE_8192 -1, "Authorization: Bearer %s", token);

    expect_string(__wrap_wurl_http_request, header, expHeader);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_OFFICE365_DEFAULT_CURL_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_request, data->response);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_any(__wrap__mtdebug1, formatted_msg);
    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mtdebug1, formatted_msg, "Error while parsing managing subscription JSON response.");

    expect_value(__wrap_wurl_free_response, response, data->response);

    value = wm_office365_manage_subscription(data->office365_config->subscription, management_fqdn, client_id, token, start, max_size, &error_msg);

    assert_int_equal(value, OS_INVALID);
    assert_null(error_msg);

    os_free(data->response->body);
    os_free(data->response->header);
    os_free(data->response);
}

void test_wm_office365_manage_subscription_stop_error_max_size_reached(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int value = 0;
    size_t max_size = OS_SIZE_8192;
    char *error_msg = NULL;

    char *token = "test_token";
    char* client_id = "test_client_id";
    char* management_fqdn = WM_OFFICE365_DEFAULT_API_MANAGEMENT_FQDN;
    int start = 0;

    os_calloc(1, sizeof(wm_office365_auth), data->office365_config->auth);
    os_strdup("test_tenant_id", data->office365_config->auth->tenant_id);
    os_strdup("test_client_id", data->office365_config->auth->client_id);
    os_strdup("test_client_secret", data->office365_config->auth->client_secret);
    os_strdup(WM_OFFICE365_DEFAULT_API_LOGIN_FQDN, data->office365_config->auth->login_fqdn);
    os_strdup(WM_OFFICE365_DEFAULT_API_MANAGEMENT_FQDN, data->office365_config->auth->management_fqdn);

    os_calloc(1, sizeof(wm_office365_subscription), data->office365_config->subscription);
    os_strdup("test_subscription_name", data->office365_config->subscription->subscription_name);

    os_calloc(1, sizeof(curl_response), data->response);
    data->response->status_code = 400;
    os_strdup("{\"error\":{\"code\":", data->response->body);
    os_strdup("test", data->response->header);
    data->response->max_size_reached = 1;

    expect_any(__wrap_wurl_http_request, method);
    expect_string(__wrap_wurl_http_request, header, "Content-Type: application/json");

    char expHeader[OS_SIZE_8192];
    snprintf(expHeader, OS_SIZE_8192 -1, "Authorization: Bearer %s", token);

    expect_string(__wrap_wurl_http_request, header, expHeader);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_OFFICE365_DEFAULT_CURL_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_request, data->response);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_any(__wrap__mtdebug1, formatted_msg);
    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mtdebug1, formatted_msg, "Libcurl error, reached maximum response size.");

    expect_value(__wrap_wurl_free_response, response, data->response);

    value = wm_office365_manage_subscription(data->office365_config->subscription, management_fqdn, client_id, token, start, max_size, &error_msg);

    assert_int_equal(value, OS_INVALID);
    assert_null(error_msg);

    os_free(data->response->body);
    os_free(data->response->header);
    os_free(data->response);
}

void test_wm_office365_manage_subscription_stop_code_400_error_AF20024(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int value = 0;
    size_t max_size = OS_SIZE_8192;
    char *error_msg = NULL;

    char *token = "test_token";
    char* client_id = "test_client_id";
    char* management_fqdn = WM_OFFICE365_DEFAULT_API_MANAGEMENT_FQDN;
    int start = 0;

    os_calloc(1, sizeof(wm_office365_auth), data->office365_config->auth);
    os_strdup("test_tenant_id", data->office365_config->auth->tenant_id);
    os_strdup("test_client_id", data->office365_config->auth->client_id);
    os_strdup("test_client_secret", data->office365_config->auth->client_secret);
    os_strdup(WM_OFFICE365_DEFAULT_API_LOGIN_FQDN, data->office365_config->auth->login_fqdn);
    os_strdup(WM_OFFICE365_DEFAULT_API_MANAGEMENT_FQDN, data->office365_config->auth->management_fqdn);

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
    expect_value(__wrap_wurl_http_request, timeout, WM_OFFICE365_DEFAULT_CURL_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_request, data->response);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_any(__wrap__mtdebug1, formatted_msg);

    expect_value(__wrap_wurl_free_response, response, data->response);

    value = wm_office365_manage_subscription(data->office365_config->subscription, management_fqdn, client_id, token, start, max_size, &error_msg);

    assert_int_equal(value, OS_SUCCESS);
    assert_null(error_msg);

    os_free(data->response->body);
    os_free(data->response->header);
    os_free(data->response);
}

void test_wm_office365_manage_subscription_stop_code_400_error_different_AF20024(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int value = 0;
    size_t max_size = OS_SIZE_8192;
    char *error_msg = NULL;

    char *token = "test_token";
    char* client_id = "test_client_id";
    char* management_fqdn = WM_OFFICE365_DEFAULT_API_MANAGEMENT_FQDN;
    int start = 0;

    os_calloc(1, sizeof(wm_office365_auth), data->office365_config->auth);
    os_strdup("test_tenant_id", data->office365_config->auth->tenant_id);
    os_strdup("test_client_id", data->office365_config->auth->client_id);
    os_strdup("test_client_secret", data->office365_config->auth->client_secret);
    os_strdup(WM_OFFICE365_DEFAULT_API_LOGIN_FQDN, data->office365_config->auth->login_fqdn);
    os_strdup(WM_OFFICE365_DEFAULT_API_MANAGEMENT_FQDN, data->office365_config->auth->management_fqdn);

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
    expect_value(__wrap_wurl_http_request, timeout, WM_OFFICE365_DEFAULT_CURL_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_request, data->response);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_any(__wrap__mtdebug1, formatted_msg);
    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mtdebug1, formatted_msg, "Error while managing subscription: '{\"error\":{\"code\":\"AF20023\"}}'");

    expect_value(__wrap_wurl_free_response, response, data->response);

    value = wm_office365_manage_subscription(data->office365_config->subscription, management_fqdn, client_id, token, start, max_size, &error_msg);

    assert_int_equal(value, OS_INVALID);
    assert_string_equal(error_msg, data->response->body);

    os_free(data->response->body);
    os_free(data->response->header);
    os_free(data->response);
    os_free(error_msg);
}

void test_wm_office365_get_fail_by_tenant_and_subscription_null(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    wm_office365_fail *result = NULL;
    wm_office365_fail *fails = NULL;
    os_calloc(1, sizeof(wm_office365_fail), fails);
    fails->subscription_name = "subscription";
    fails->tenant_id = "tenant";

    char* subscription_name = "subscription_name";
    char* tenant_id = "tenant_id";

    result = wm_office365_get_fail_by_tenant_and_subscription(fails, tenant_id, subscription_name);
    assert_null(result);
    os_free(fails);
}

void test_wm_office365_get_fail_by_tenant_and_subscription_not_null(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    wm_office365_fail *result = NULL;
    wm_office365_fail *fails = NULL;
    os_calloc(1, sizeof(wm_office365_fail), fails);
    fails->subscription_name = "subscription_name";
    fails->tenant_id = "tenant_id";

    char* subscription_name = "subscription_name";
    char* tenant_id = "tenant_id";

    result = wm_office365_get_fail_by_tenant_and_subscription(fails, tenant_id, subscription_name);
    assert_string_equal(result->tenant_id, tenant_id);
    assert_string_equal(result->subscription_name, subscription_name);

    os_free(fails);
}

void test_wm_office365_get_content_blobs_response_null(void **state) {
    size_t max_size = OS_SIZE_8192;
    char* client_id = "test_client_id";
    const char* url = "test_url";
    const char* token = "test_token";
    char** next_page;
    bool buffer_size_reached = 0;
    char *error_msg = NULL;

    expect_any(__wrap_wurl_http_request, method);
    expect_string(__wrap_wurl_http_request, header, "Content-Type: application/json");

    char expHeader[OS_SIZE_8192];
    snprintf(expHeader, OS_SIZE_8192 -1, "Authorization: Bearer %s", token);

    expect_string(__wrap_wurl_http_request, header, expHeader);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_OFFICE365_DEFAULT_CURL_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_request, NULL);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_any(__wrap__mtdebug1, formatted_msg);
    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mtdebug1, formatted_msg, "Unknown error while getting content blobs.");

    cJSON *blob = wm_office365_get_content_blobs(url, token, next_page, max_size, &buffer_size_reached, &error_msg);
    assert_null(blob);
    assert_null(error_msg);
    cJSON_Delete(blob);
}

void test_wm_office365_get_content_blobs_response_max_size_reached(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    size_t max_size = OS_SIZE_8192;

    char* client_id = "test_client_id";
    const char* url = "test_url";
    const char* token = "test_token";
    char** next_page;
    bool buffer_size_reached = 0;
    char *error_msg = NULL;

    os_calloc(1, sizeof(curl_response), data->response);
    data->response->status_code = 200;
    os_strdup("{\"access_token\":\"wazuh\"}", data->response->body);
    os_strdup("test", data->response->header);
    data->response->max_size_reached = 1;

    expect_any(__wrap_wurl_http_request, method);
    expect_string(__wrap_wurl_http_request, header, "Content-Type: application/json");

    char expHeader[OS_SIZE_8192];
    snprintf(expHeader, OS_SIZE_8192 -1, "Authorization: Bearer %s", token);

    expect_string(__wrap_wurl_http_request, header, expHeader);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_OFFICE365_DEFAULT_CURL_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_request, data->response);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_any(__wrap__mtdebug1, formatted_msg);
    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mtdebug1, formatted_msg, "Libcurl error, reached maximum response size.");

    expect_value(__wrap_wurl_free_response, response, data->response);

    cJSON *blob = wm_office365_get_content_blobs(url, token, next_page, max_size, &buffer_size_reached, &error_msg);
    assert_null(blob);
    assert_null(error_msg);
    assert_int_equal(buffer_size_reached, 1);
    cJSON_Delete(blob);

    os_free(data->response->body);
    os_free(data->response->header);
    os_free(data->response);
}

void test_wm_office365_get_content_blobs_error_json_response(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    size_t max_size = OS_SIZE_8192;

    char* client_id = "test_client_id";
    const char* url = "test_url";
    const char* token = "test_token";
    char** next_page;
    bool buffer_size_reached = 0;
    char *error_msg = NULL;

    os_calloc(1, sizeof(curl_response), data->response);
    data->response->status_code = 200;
    os_strdup("{\"access_token\":\"", data->response->body);
    os_strdup("test", data->response->header);

    expect_any(__wrap_wurl_http_request, method);
    expect_string(__wrap_wurl_http_request, header, "Content-Type: application/json");

    char expHeader[OS_SIZE_8192];
    snprintf(expHeader, OS_SIZE_8192 -1, "Authorization: Bearer %s", token);

    expect_string(__wrap_wurl_http_request, header, expHeader);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_OFFICE365_DEFAULT_CURL_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_request, data->response);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_any(__wrap__mtdebug1, formatted_msg);
    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mtdebug1, formatted_msg, "Error while parsing content blobs JSON response.");

    expect_value(__wrap_wurl_free_response, response, data->response);

    cJSON *blob = wm_office365_get_content_blobs(url, token, next_page, max_size, &buffer_size_reached, &error_msg);
    assert_null(blob);
    assert_null(error_msg);
    cJSON_Delete(blob);

    os_free(data->response->body);
    os_free(data->response->header);
    os_free(data->response);
}

void test_wm_office365_get_content_blobs_bad_response(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    size_t max_size = OS_SIZE_8192;

    char* client_id = "test_client_id";
    const char* url = "test_url";
    const char* token = "test_token";
    char** next_page;
    bool buffer_size_reached = 0;
    char *error_msg = NULL;

    os_calloc(1, sizeof(curl_response), data->response);
    data->response->status_code = 400;
    os_strdup("{\"response\":\"test\"}", data->response->body);
    os_strdup("test", data->response->header);

    expect_any(__wrap_wurl_http_request, method);
    expect_string(__wrap_wurl_http_request, header, "Content-Type: application/json");

    char expHeader[OS_SIZE_8192];
    snprintf(expHeader, OS_SIZE_8192 -1, "Authorization: Bearer %s", token);

    expect_string(__wrap_wurl_http_request, header, expHeader);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_OFFICE365_DEFAULT_CURL_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_request, data->response);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_any(__wrap__mtdebug1, formatted_msg);
    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mtdebug1, formatted_msg, "Error while getting content blobs: '{\"response\":\"test\"}'");

    expect_value(__wrap_wurl_free_response, response, data->response);

    cJSON *blob = wm_office365_get_content_blobs(url, token, next_page, max_size, &buffer_size_reached, &error_msg);
    assert_null(blob);
    assert_string_equal(error_msg, data->response->body);
    cJSON_Delete(blob);

    os_free(data->response->body);
    os_free(data->response->header);
    os_free(data->response);
    os_free(error_msg);
}

void test_wm_office365_get_content_blobs_400_code_AF20055(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    size_t max_size = OS_SIZE_8192;

    char* client_id = "test_client_id";
    const char* url = "test_url";
    const char* token = "test_token";
    char** next_page;
    bool buffer_size_reached = 0;
    char *error_msg = NULL;

    os_calloc(1, sizeof(curl_response), data->response);
    data->response->status_code = 400;
    os_strdup("{\"error\":{\"code\":\"AF20055\"}}", data->response->body);
    os_strdup("NextPageUri: valueNextPageUri", data->response->header);

    expect_any(__wrap_wurl_http_request, method);
    expect_string(__wrap_wurl_http_request, header, "Content-Type: application/json");

    char expHeader[OS_SIZE_8192];
    snprintf(expHeader, OS_SIZE_8192 -1, "Authorization: Bearer %s", token);

    expect_string(__wrap_wurl_http_request, header, expHeader);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_OFFICE365_DEFAULT_CURL_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_request, data->response);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_any(__wrap__mtdebug1, formatted_msg);

    expect_value(__wrap_wurl_free_response, response, data->response);

    cJSON *blob = wm_office365_get_content_blobs(url, token, next_page, max_size, &buffer_size_reached, &error_msg);
    assert_non_null(blob);
    assert_null(error_msg);
    cJSON_Delete(blob);

    os_free(data->response->body);
    os_free(data->response->header);
    os_free(data->response);
}

void test_wm_office365_scan_failure_action_null(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    wm_office365_fail *fails = NULL;
    os_calloc(1, sizeof(wm_office365_fail), fails);
    fails->subscription_name = "subscription";
    fails->tenant_id = "tenant";

    char* subscription_name = "subscription_name";
    char* tenant_id = "tenant_id";
    int queue_fd = 0;
    char *error_msg = NULL;

    wm_office365_scan_failure_action(&fails, tenant_id, subscription_name, error_msg, queue_fd);
    assert_string_equal(fails->next->tenant_id, tenant_id);
    assert_string_equal(fails->next->subscription_name, subscription_name);

    os_free(fails->next->tenant_id);
    os_free(fails->next->subscription_name);
    os_free(fails->next);
    os_free(fails);
}

void test_wm_office365_scan_failure_action_no_fail(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    wm_office365_fail *fails = NULL;

    char* subscription_name = "subscription_name";
    char* tenant_id = "tenant_id";
    int queue_fd = 0;
    char *error_msg = NULL;

    wm_office365_scan_failure_action(&fails, tenant_id, subscription_name, error_msg, queue_fd);
    assert_string_equal(fails->tenant_id, tenant_id);
    assert_string_equal(fails->subscription_name, subscription_name);

    os_free(fails->tenant_id);
    os_free(fails->subscription_name);
    os_free(fails);
}

void test_wm_office365_scan_failure_action_null_mult_next(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    wm_office365_fail *fails = NULL;
    os_calloc(1, sizeof(wm_office365_fail), fails);
    fails->subscription_name = "subscription";
    fails->tenant_id = "tenant";
    os_calloc(1, sizeof(wm_office365_fail), fails->next);
    fails->next->subscription_name = "subscription1";
    fails->next->tenant_id = "tenant1";

    char* subscription_name = "subscription_name";
    char* tenant_id = "tenant_id";
    int queue_fd = 0;
    char *error_msg = NULL;

    wm_office365_scan_failure_action(&fails, tenant_id, subscription_name, error_msg, queue_fd);
    assert_string_equal(fails->next->next->tenant_id, tenant_id);
    assert_string_equal(fails->next->next->subscription_name, subscription_name);

    os_free(fails->next->next->tenant_id);
    os_free(fails->next->next->subscription_name);
    os_free(fails->next->next);
    os_free(fails->next);
    os_free(fails);
}

void test_wm_office365_scan_failure_action_not_null(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    wm_office365_fail *fails = NULL;
    os_calloc(1, sizeof(wm_office365_fail), fails);
    fails->subscription_name = "subscription_name";
    fails->tenant_id = "tenant_id";
    fails->fails = 2;
    wm_max_eps = 1;

    char* subscription_name = "subscription_name";
    char* tenant_id = "tenant_id";
    int queue_fd = 1;
    char *error_msg = NULL;

    expect_string(__wrap__mtwarn, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mtwarn, formatted_msg, "Sending Office365 internal message: '{\"integration\":\"office365\",\"office365\":{\"actor\":\"wazuh\",\"tenant_id\":\"tenant_id\",\"subscription_name\":\"subscription_name\",\"response\":\"Unknown error\"}}'");

    int result = -1;
    expect_value(__wrap_wm_sendmsg, usec, 1000000);
    expect_value(__wrap_wm_sendmsg, queue, queue_fd);
    expect_string(__wrap_wm_sendmsg, message, "{\"integration\":\"office365\",\"office365\":{\"actor\":\"wazuh\",\"tenant_id\":\"tenant_id\",\"subscription_name\":\"subscription_name\",\"response\":\"Unknown error\"}}");
    expect_string(__wrap_wm_sendmsg, locmsg, "office365");
    expect_value(__wrap_wm_sendmsg, loc, LOCALFILE_MQ);
    will_return(__wrap_wm_sendmsg, result);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mterror, formatted_msg, "(1210): Queue 'queue/sockets/queue' not accessible: 'Success'");

    wm_office365_scan_failure_action(&fails, tenant_id, subscription_name, error_msg, queue_fd);

    os_free(fails);
}

void test_wm_office365_scan_failure_action_not_null_error_msg(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    wm_office365_fail *fails = NULL;
    os_calloc(1, sizeof(wm_office365_fail), fails);
    fails->subscription_name = "subscription_name";
    fails->tenant_id = "tenant_id";
    fails->fails = 2;
    wm_max_eps = 1;

    char* subscription_name = "subscription_name";
    char* tenant_id = "tenant_id";
    int queue_fd = 1;
    char *error_msg = "{\"response\":\"test\"}";

    expect_string(__wrap__mtwarn, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mtwarn, formatted_msg, "Sending Office365 internal message: '{\"integration\":\"office365\",\"office365\":{\"actor\":\"wazuh\",\"tenant_id\":\"tenant_id\",\"subscription_name\":\"subscription_name\",\"response\":\"{\\\"response\\\":\\\"test\\\"}\"}}'");

    int result = -1;
    expect_value(__wrap_wm_sendmsg, usec, 1000000);
    expect_value(__wrap_wm_sendmsg, queue, queue_fd);
    expect_string(__wrap_wm_sendmsg, message, "{\"integration\":\"office365\",\"office365\":{\"actor\":\"wazuh\",\"tenant_id\":\"tenant_id\",\"subscription_name\":\"subscription_name\",\"response\":\"{\\\"response\\\":\\\"test\\\"}\"}}");
    expect_string(__wrap_wm_sendmsg, locmsg, "office365");
    expect_value(__wrap_wm_sendmsg, loc, LOCALFILE_MQ);
    will_return(__wrap_wm_sendmsg, result);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mterror, formatted_msg, "(1210): Queue 'queue/sockets/queue' not accessible: 'Success'");

    wm_office365_scan_failure_action(&fails, tenant_id, subscription_name, error_msg, queue_fd);

    os_free(fails);
}

void test_wm_office365_get_logs_from_blob_response_null(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int value = 0;
    cJSON *logs_array = NULL;

    size_t max_size = OS_SIZE_8192;
    char *token = "test_token";
    char *url = "https://test_url.com";
    bool buffer_size_reached = false;
    char *error_msg = NULL;

    expect_string(__wrap_wurl_http_request, header, "Content-Type: application/json");
    expect_any(__wrap_wurl_http_request, method);

    char expHeader[OS_SIZE_8192];
    snprintf(expHeader, OS_SIZE_8192 -1, "Authorization: Bearer %s", token);

    expect_string(__wrap_wurl_http_request, header, expHeader);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_OFFICE365_DEFAULT_CURL_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_request, NULL);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_any(__wrap__mtdebug1, formatted_msg);
    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mtdebug1, formatted_msg, "Unknown error while getting logs from blob.");

    logs_array = wm_office365_get_logs_from_blob(url, token, max_size, &buffer_size_reached, &error_msg);

    assert_null(logs_array);
    assert_null(error_msg);

}

void test_wm_office365_get_logs_from_blob_response_max_size_reached(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int value = 0;
    cJSON *logs_array = NULL;

    size_t max_size = OS_SIZE_8192;
    char *token = "test_token";
    char *url = "https://test_url.com";
    bool buffer_size_reached = false;
    char *error_msg = NULL;

    os_calloc(1, sizeof(curl_response), data->response);
    data->response->status_code = 200;
    data->response->max_size_reached = true;
    os_strdup("[{\"test\":{\"code\":\"test\"", data->response->body);
    os_strdup("test", data->response->header);

    expect_string(__wrap_wurl_http_request, header, "Content-Type: application/json");
    expect_any(__wrap_wurl_http_request, method);

    char expHeader[OS_SIZE_8192];
    snprintf(expHeader, OS_SIZE_8192 -1, "Authorization: Bearer %s", token);

    expect_string(__wrap_wurl_http_request, header, expHeader);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_OFFICE365_DEFAULT_CURL_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_request, data->response);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_any(__wrap__mtdebug1, formatted_msg);
    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mtdebug1, formatted_msg, "Libcurl error, reached maximum response size.");

    expect_value(__wrap_wurl_free_response, response, data->response);

    logs_array = wm_office365_get_logs_from_blob(url, token, max_size, &buffer_size_reached, &error_msg);

    assert_null(logs_array);
    assert_null(error_msg);

    os_free(data->response->body);
    os_free(data->response->header);
    os_free(data->response);

}

void test_wm_office365_get_logs_from_blob_response_parsing_error(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int value = 0;
    cJSON *logs_array = NULL;

    size_t max_size = OS_SIZE_8192;
    char *token = "test_token";
    char *url = "https://test_url.com";
    bool buffer_size_reached = false;
    char *error_msg = NULL;

    os_calloc(1, sizeof(curl_response), data->response);
    data->response->status_code = 200;
    data->response->max_size_reached = false;
    os_strdup("[{\"test\":{\"code\":\"test\"", data->response->body);
    os_strdup("test", data->response->header);

    expect_string(__wrap_wurl_http_request, header, "Content-Type: application/json");
    expect_any(__wrap_wurl_http_request, method);

    char expHeader[OS_SIZE_8192];
    snprintf(expHeader, OS_SIZE_8192 -1, "Authorization: Bearer %s", token);

    expect_string(__wrap_wurl_http_request, header, expHeader);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_OFFICE365_DEFAULT_CURL_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_request, data->response);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_any(__wrap__mtdebug1, formatted_msg);
    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mtdebug1, formatted_msg, "Error while parsing logs from blob JSON response.");

    expect_value(__wrap_wurl_free_response, response, data->response);

    logs_array = wm_office365_get_logs_from_blob(url, token, max_size, &buffer_size_reached, &error_msg);

    assert_null(logs_array);
    assert_null(error_msg);

    os_free(data->response->body);
    os_free(data->response->header);
    os_free(data->response);

}

void test_wm_office365_get_logs_from_blob_response_code_400(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int value = 0;
    cJSON *logs_array = NULL;

    size_t max_size = OS_SIZE_8192;
    char *token = "test_token";
    char *url = "https://test_url.com";
    bool buffer_size_reached = false;
    char *error_msg = NULL;

    os_calloc(1, sizeof(curl_response), data->response);
    data->response->status_code = 400;
    data->response->max_size_reached = false;
    os_strdup("[{\"test\":{\"code\":\"test\"}}]", data->response->body);
    os_strdup("test", data->response->header);

    expect_string(__wrap_wurl_http_request, header, "Content-Type: application/json");
    expect_any(__wrap_wurl_http_request, method);

    char expHeader[OS_SIZE_8192];
    snprintf(expHeader, OS_SIZE_8192 -1, "Authorization: Bearer %s", token);

    expect_string(__wrap_wurl_http_request, header, expHeader);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_OFFICE365_DEFAULT_CURL_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_request, data->response);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_any(__wrap__mtdebug1, formatted_msg);
    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mtdebug1, formatted_msg, "Error while getting logs from blob: '[{\"test\":{\"code\":\"test\"}}]'");

    expect_value(__wrap_wurl_free_response, response, data->response);

    logs_array = wm_office365_get_logs_from_blob(url, token, max_size, &buffer_size_reached, &error_msg);

    assert_null(logs_array);
    assert_string_equal(error_msg, data->response->body);

    os_free(data->response->body);
    os_free(data->response->header);
    os_free(data->response);
    os_free(error_msg);

}

void test_wm_office365_get_logs_from_blob_response_no_array(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int value = 0;
    cJSON *logs_array = NULL;

    size_t max_size = OS_SIZE_8192;
    char *token = "test_token";
    char *url = "https://test_url.com";
    bool buffer_size_reached = false;
    char *error_msg = NULL;

    os_calloc(1, sizeof(curl_response), data->response);
    data->response->status_code = 200;
    data->response->max_size_reached = false;
    os_strdup("{\"test\":{\"code\":\"test\"}}", data->response->body);
    os_strdup("test", data->response->header);

    expect_string(__wrap_wurl_http_request, header, "Content-Type: application/json");
    expect_any(__wrap_wurl_http_request, method);

    char expHeader[OS_SIZE_8192];
    snprintf(expHeader, OS_SIZE_8192 -1, "Authorization: Bearer %s", token);

    expect_string(__wrap_wurl_http_request, header, expHeader);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_OFFICE365_DEFAULT_CURL_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_request, data->response);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_any(__wrap__mtdebug1, formatted_msg);
    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mtdebug1, formatted_msg, "Error while getting logs from blob: '{\"test\":{\"code\":\"test\"}}'");

    expect_value(__wrap_wurl_free_response, response, data->response);

    logs_array = wm_office365_get_logs_from_blob(url, token, max_size, &buffer_size_reached, &error_msg);

    assert_null(logs_array);
    assert_string_equal(error_msg, data->response->body);

    os_free(data->response->body);
    os_free(data->response->header);
    os_free(data->response);
    os_free(error_msg);

}

void test_wm_office365_get_logs_from_blob_ok(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int value = 0;
    cJSON *logs_array = NULL;

    size_t max_size = OS_SIZE_8192;
    char *token = "test_token";
    char *url = "https://test_url.com";
    bool buffer_size_reached = false;
    char *error_msg = NULL;

    os_calloc(1, sizeof(curl_response), data->response);
    data->response->status_code = 200;
    data->response->max_size_reached = false;
    os_strdup("[{\"test\":{\"code\":\"test\"}}]", data->response->body);
    os_strdup("test", data->response->header);

    expect_string(__wrap_wurl_http_request, header, "Content-Type: application/json");
    expect_any(__wrap_wurl_http_request, method);

    char expHeader[OS_SIZE_8192];
    snprintf(expHeader, OS_SIZE_8192 -1, "Authorization: Bearer %s", token);

    expect_string(__wrap_wurl_http_request, header, expHeader);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_OFFICE365_DEFAULT_CURL_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_request, data->response);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_any(__wrap__mtdebug1, formatted_msg);

    expect_value(__wrap_wurl_free_response, response, data->response);

    logs_array = wm_office365_get_logs_from_blob(url, token, max_size, &buffer_size_reached, &error_msg);

    assert_non_null(logs_array);
    assert_null(error_msg);

    os_free(data->response->body);
    os_free(data->response->header);
    os_free(data->response);
    cJSON_Delete(logs_array);

}

void test_wm_office365_execute_scan_all(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    wm_office365_state tenant_state_struc;
    tenant_state_struc.last_log_time = 160;
    current_time = 161;
    wm_max_eps = 1;

    os_calloc(1, sizeof(wm_office365_auth), data->office365_config->auth);
    os_strdup("test_tenant_id", data->office365_config->auth->tenant_id);
    os_strdup("test_client_id", data->office365_config->auth->client_id);
    os_strdup("test_client_secret", data->office365_config->auth->client_secret);
    os_strdup(WM_OFFICE365_DEFAULT_API_LOGIN_FQDN, data->office365_config->auth->login_fqdn);
    os_strdup(WM_OFFICE365_DEFAULT_API_MANAGEMENT_FQDN, data->office365_config->auth->management_fqdn);
    data->office365_config->auth->next = NULL;

    os_calloc(1, sizeof(wm_office365_subscription), data->office365_config->subscription);
    os_strdup("test_subscription_name", data->office365_config->subscription->subscription_name);
    data->office365_config->subscription->next = NULL;

    os_calloc(1, sizeof(wm_office365_fail), data->office365_config->fails);
    os_strdup("subscription_name", data->office365_config->fails->subscription_name);
    os_strdup("tenant_id", data->office365_config->fails->tenant_id);
    data->office365_config->interval = 10;

    int initial_scan = 1;

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mtdebug1, formatted_msg, "Scanning tenant: 'test_tenant_id'");

    os_calloc(1, sizeof(curl_response), data->response);
    data->response->status_code = 200;
    os_strdup("{\"access_token\":\"wazuh\"}", data->response->body);
    os_strdup("test", data->response->header);

    // wm_office365_get_content_blobs
    curl_response *get_content_blobs_response;
    os_calloc(1, sizeof(curl_response), get_content_blobs_response);
    get_content_blobs_response->status_code = 200;
    get_content_blobs_response->max_size_reached = false;
    os_strdup("[{\"contentUri\":\"https://contentUri1.com\"}]", get_content_blobs_response->body);
    os_strdup("test", get_content_blobs_response->header);

    expect_any(__wrap_wurl_http_request, method);
    expect_any(__wrap_wurl_http_request, header);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_OFFICE365_DEFAULT_CURL_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_request, data->response);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    const char expected_token_url[] = "Office 365 API access token URL: 'https://" WM_OFFICE365_DEFAULT_API_LOGIN_FQDN "/test_tenant_id/oauth2/v2.0/token'";
    expect_string(__wrap__mtdebug1, formatted_msg, expected_token_url);

    expect_value(__wrap_wurl_free_response, response, data->response);

    expect_string(__wrap_wm_state_io, tag, "office365-test_tenant_id-test_subscription_name");
    expect_value(__wrap_wm_state_io, op, WM_IO_READ);
    expect_any(__wrap_wm_state_io, state);
    expect_any(__wrap_wm_state_io, size);
    will_return(__wrap_wm_state_io, 0);
    will_return(__wrap_wm_state_io, (void *)&tenant_state_struc);

    expect_any(__wrap_wurl_http_request, method);
    expect_string(__wrap_wurl_http_request, header, "Content-Type: application/json");

    char expHeader[OS_SIZE_8192];
    snprintf(expHeader, OS_SIZE_8192 -1, "Authorization: Bearer wazuh");

    expect_string(__wrap_wurl_http_request, header, expHeader);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_OFFICE365_DEFAULT_CURL_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_request, data->response);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    const char expected_subscription_url[] = "Office 365 API subscription URL: 'https://" WM_OFFICE365_DEFAULT_API_MANAGEMENT_FQDN "/api/v1.0/test_client_id/activity/feed/subscriptions/start?contentType=test_subscription_name'";
    expect_string(__wrap__mtdebug1, formatted_msg, expected_subscription_url);

    #ifndef WIN32
        will_return(__wrap_gmtime_r, 1);
        will_return(__wrap_gmtime_r, 1);
    #endif

    will_return(__wrap_strftime,"2021-05-07 12:24:56");
    will_return(__wrap_strftime, 20);
    will_return(__wrap_strftime,"2021-05-07 12:24:56");
    will_return(__wrap_strftime, 20);

    expect_value(__wrap_wurl_free_response, response, data->response);

    expect_any(__wrap_wurl_http_request, method);
    expect_string(__wrap_wurl_http_request, header, "Content-Type: application/json");

    snprintf(expHeader, OS_SIZE_8192 -1, "Authorization: Bearer wazuh");

    expect_string(__wrap_wurl_http_request, header, expHeader);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_OFFICE365_DEFAULT_CURL_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_request, get_content_blobs_response);

    expect_any(__wrap__mdebug1, formatted_msg);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    const char expected_blob_url[] = "Office 365 API content blobs URL: 'https://" WM_OFFICE365_DEFAULT_API_MANAGEMENT_FQDN "/api/v1.0/test_client_id/activity/feed/subscriptions/content?contentType=test_subscription_name&startTime=2021-05-07 12:24:56&endTime=2021-05-07 12:24:56'";
    expect_string(__wrap__mtdebug1, formatted_msg, expected_blob_url);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mtdebug1, formatted_msg, "Office 365 API content URI: 'https://contentUri1.com'");

    expect_value(__wrap_wurl_free_response, response, get_content_blobs_response);

    expect_string(__wrap_wurl_http_request, header, "Content-Type: application/json");
    expect_any(__wrap_wurl_http_request, method);

    snprintf(expHeader, OS_SIZE_8192 -1, "Authorization: Bearer wazuh");

    expect_string(__wrap_wurl_http_request, header, expHeader);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_OFFICE365_DEFAULT_CURL_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_request, get_content_blobs_response);

    expect_value(__wrap_wurl_free_response, response, get_content_blobs_response);

    expect_string(__wrap__mtdebug2, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mtdebug2, formatted_msg, "Sending Office365 log: '{\"integration\":\"office365\",\"office365\":{\"contentUri\":\"https://contentUri1.com\",\"Subscription\":\"test_subscription_name\"}}'");

    int result = 1;
    int queue_fd = 0;
    expect_value(__wrap_wm_sendmsg, usec, 1000000);
    expect_value(__wrap_wm_sendmsg, queue, queue_fd);
    expect_string(__wrap_wm_sendmsg, message, "{\"integration\":\"office365\",\"office365\":{\"contentUri\":\"https://contentUri1.com\",\"Subscription\":\"test_subscription_name\"}}");
    expect_string(__wrap_wm_sendmsg, locmsg, "office365");
    expect_value(__wrap_wm_sendmsg, loc, LOCALFILE_MQ);
    will_return(__wrap_wm_sendmsg, result);

    expect_string(__wrap_wm_state_io, tag, "office365-test_tenant_id-test_subscription_name");
    expect_value(__wrap_wm_state_io, op, WM_IO_WRITE);
    expect_any(__wrap_wm_state_io, state);
    expect_any(__wrap_wm_state_io, size);
    will_return(__wrap_wm_state_io, 1);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mtdebug1, formatted_msg, "Bookmark updated to '2021-05-07 12:24:56' for tenant 'test_tenant_id' and subscription 'test_subscription_name', waiting '10' seconds to run next scan.");

    wm_office365_execute_scan(data->office365_config, initial_scan);

    os_free(data->response->body);
    os_free(data->response->header);
    os_free(data->response);

    os_free(get_content_blobs_response->body);
    os_free(get_content_blobs_response->header);
    os_free(get_content_blobs_response);
}

void test_wm_office365_execute_scan_initial_scan_only_future_events(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    os_calloc(1, sizeof(wm_office365_auth), data->office365_config->auth);
    os_strdup("test_tenant_id", data->office365_config->auth->tenant_id);
    os_strdup("test_client_id", data->office365_config->auth->client_id);
    os_strdup("test_client_secret", data->office365_config->auth->client_secret);
    os_strdup(WM_OFFICE365_DEFAULT_API_LOGIN_FQDN, data->office365_config->auth->login_fqdn);
    os_strdup(WM_OFFICE365_DEFAULT_API_MANAGEMENT_FQDN, data->office365_config->auth->management_fqdn);
    os_calloc(1, sizeof(wm_office365_subscription), data->office365_config->subscription);
    os_strdup("test_subscription_name", data->office365_config->subscription->subscription_name);
    data->office365_config->only_future_events = 1;
    data->office365_config->interval = 10;

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mtdebug1, formatted_msg, "Scanning tenant: 'test_tenant_id'");

    expect_string(__wrap_wm_state_io, tag, "office365-test_tenant_id-test_subscription_name");
    expect_value(__wrap_wm_state_io, op, WM_IO_READ);
    expect_any(__wrap_wm_state_io, state);
    expect_any(__wrap_wm_state_io, size);
    will_return(__wrap_wm_state_io, 1);

    expect_string(__wrap_wm_state_io, tag, "office365-test_tenant_id-test_subscription_name");
    expect_value(__wrap_wm_state_io, op, WM_IO_WRITE);
    expect_any(__wrap_wm_state_io, state);
    expect_any(__wrap_wm_state_io, size);
    will_return(__wrap_wm_state_io, 1);

    will_return(__wrap_isDebug, 1);

#ifndef WIN32
    will_return(__wrap_gmtime_r, 1);
#endif
    will_return(__wrap_strftime,"2021-05-07 12:24:56");
    will_return(__wrap_strftime, 20);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mtdebug1, formatted_msg, "Bookmark updated to '2021-05-07 12:24:56' for tenant 'test_tenant_id' and subscription 'test_subscription_name', waiting '10' seconds to run first scan.");

    wm_office365_execute_scan(data->office365_config, 1);
}

void test_wm_office365_execute_scan_access_token_null(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    size_t max_size = OS_SIZE_8192;

    os_calloc(1, sizeof(wm_office365_auth), data->office365_config->auth);
    os_strdup("test_tenant_id", data->office365_config->auth->tenant_id);
    os_strdup("test_client_id", data->office365_config->auth->client_id);
    os_strdup("test_client_secret", data->office365_config->auth->client_secret);
    os_strdup(WM_OFFICE365_DEFAULT_API_LOGIN_FQDN, data->office365_config->auth->login_fqdn);
    os_strdup(WM_OFFICE365_DEFAULT_API_MANAGEMENT_FQDN, data->office365_config->auth->management_fqdn);
    os_calloc(1, sizeof(wm_office365_subscription), data->office365_config->subscription);
    os_strdup("test_subscription_name", data->office365_config->subscription->subscription_name);
    data->office365_config->only_future_events = 1;

    os_calloc(1, sizeof(curl_response), data->response);
    data->response->status_code = 400;
    os_strdup("{\"error\":\"bad_request\"}", data->response->body);
    os_strdup("test", data->response->header);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mtdebug1, formatted_msg, "Scanning tenant: 'test_tenant_id'");

    expect_any(__wrap_wurl_http_request, method);
    expect_any(__wrap_wurl_http_request, header);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_OFFICE365_DEFAULT_CURL_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_request, data->response);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_any(__wrap__mtdebug1, formatted_msg);
    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mtdebug1, formatted_msg, "Error while getting access token: '{\"error\":\"bad_request\"}'");

    expect_value(__wrap_wurl_free_response, response, data->response);

    wm_office365_execute_scan(data->office365_config, 0);

    os_free(data->response->body);
    os_free(data->response->header);
    os_free(data->response);
}

void test_wm_office365_execute_scan_manage_subscription_error(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    size_t max_size = OS_SIZE_8192;
    wm_office365_state tenant_state_struc;

    tenant_state_struc.last_log_time = 123456789;

    os_calloc(1, sizeof(wm_office365_auth), data->office365_config->auth);
    os_strdup("test_tenant_id", data->office365_config->auth->tenant_id);
    os_strdup("test_client_id", data->office365_config->auth->client_id);
    os_strdup("test_client_secret", data->office365_config->auth->client_secret);
    os_strdup(WM_OFFICE365_DEFAULT_API_LOGIN_FQDN, data->office365_config->auth->login_fqdn);
    os_strdup(WM_OFFICE365_DEFAULT_API_MANAGEMENT_FQDN, data->office365_config->auth->management_fqdn);
    os_calloc(1, sizeof(wm_office365_subscription), data->office365_config->subscription);
    os_strdup("test_subscription_name", data->office365_config->subscription->subscription_name);
    data->office365_config->only_future_events = 0;

    os_calloc(1, sizeof(curl_response), data->response);
    data->response->status_code = 200;
    os_strdup("{\"access_token\":\"wazuh\"}", data->response->body);
    os_strdup("test", data->response->header);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mtdebug1, formatted_msg, "Scanning tenant: 'test_tenant_id'");

    expect_any(__wrap_wurl_http_request, method);
    expect_any(__wrap_wurl_http_request, header);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_OFFICE365_DEFAULT_CURL_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_request, data->response);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_any(__wrap__mtdebug1, formatted_msg);

    expect_value(__wrap_wurl_free_response, response, data->response);

    expect_string(__wrap_wm_state_io, tag, "office365-test_tenant_id-test_subscription_name");
    expect_value(__wrap_wm_state_io, op, WM_IO_READ);
    expect_any(__wrap_wm_state_io, state);
    expect_any(__wrap_wm_state_io, size);
    will_return(__wrap_wm_state_io, 0);
    will_return(__wrap_wm_state_io, (void *)&tenant_state_struc);

    expect_string(__wrap_wurl_http_request, header, "Content-Type: application/json");
    expect_any(__wrap_wurl_http_request, method);

    char expHeader[OS_SIZE_8192];
    snprintf(expHeader, OS_SIZE_8192 -1, "Authorization: Bearer %s", "wazuh");

    expect_string(__wrap_wurl_http_request, header, expHeader);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_OFFICE365_DEFAULT_CURL_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_request, NULL);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_any(__wrap__mtdebug1, formatted_msg);
    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mtdebug1, formatted_msg, "Unknown error while managing subscription.");

    wm_office365_execute_scan(data->office365_config, 0);

    os_free(data->response->body);
    os_free(data->response->header);
    os_free(data->response);
}

void test_wm_office365_execute_scan_saving_running_state_error(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int initial_scan = 0;

    os_calloc(1, sizeof(wm_office365_auth), data->office365_config->auth);
    os_strdup("test_tenant_id", data->office365_config->auth->tenant_id);
    os_strdup("test_client_id", data->office365_config->auth->client_id);
    os_strdup("test_client_secret", data->office365_config->auth->client_secret);
    os_strdup(WM_OFFICE365_DEFAULT_API_LOGIN_FQDN, data->office365_config->auth->login_fqdn);
    os_strdup(WM_OFFICE365_DEFAULT_API_MANAGEMENT_FQDN, data->office365_config->auth->management_fqdn);

    os_calloc(1, sizeof(wm_office365_subscription), data->office365_config->subscription);
    os_strdup("test_subscription_name", data->office365_config->subscription->subscription_name);

    os_calloc(1, sizeof(curl_response), data->response);
    data->response->status_code = 200;
    os_strdup("{\"access_token\":\"access_token_value\"}", data->response->body);
    os_strdup("test", data->response->header);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mtdebug1, formatted_msg, "Scanning tenant: 'test_tenant_id'");

    /* wm_office365_get_access_token */
    expect_any(__wrap_wurl_http_request, method);
    expect_any(__wrap_wurl_http_request, header);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_OFFICE365_DEFAULT_CURL_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_request, data->response);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_any(__wrap__mtdebug1, formatted_msg);

    expect_string(__wrap_wm_state_io, tag, "office365-test_tenant_id-test_subscription_name");
    expect_value(__wrap_wm_state_io, op, WM_IO_READ);
    expect_any(__wrap_wm_state_io, state);
    expect_any(__wrap_wm_state_io, size);
    will_return(__wrap_wm_state_io, -1);

    expect_string(__wrap_wm_state_io, tag, "office365-test_tenant_id-test_subscription_name");
    expect_value(__wrap_wm_state_io, op, WM_IO_WRITE);
    expect_any(__wrap_wm_state_io, state);
    expect_any(__wrap_wm_state_io, size);
    will_return(__wrap_wm_state_io, -1);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mterror, formatted_msg, "Couldn't save running state.");

    expect_value(__wrap_wurl_free_response, response, data->response);

    wm_office365_execute_scan(data->office365_config, initial_scan);

    os_free(data->response->body);
    os_free(data->response->header);
    os_free(data->response);
}

void test_wm_office365_execute_scan_content_blobs_fail(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int initial_scan = 1;

    wm_office365_state tenant_state_struc;
    tenant_state_struc.last_log_time = 123456789;

    os_calloc(1, sizeof(wm_office365_auth), data->office365_config->auth);
    os_strdup("test_tenant_id", data->office365_config->auth->tenant_id);
    os_strdup("test_client_id", data->office365_config->auth->client_id);
    os_strdup("test_client_secret", data->office365_config->auth->client_secret);
    os_strdup(WM_OFFICE365_DEFAULT_API_LOGIN_FQDN, data->office365_config->auth->login_fqdn);
    os_strdup(WM_OFFICE365_DEFAULT_API_MANAGEMENT_FQDN, data->office365_config->auth->management_fqdn);
    data->office365_config->only_future_events = 0;

    os_calloc(1, sizeof(wm_office365_subscription), data->office365_config->subscription);
    os_strdup("test_subscription_name", data->office365_config->subscription->subscription_name);

    os_calloc(1, sizeof(curl_response), data->response);
    data->response->status_code = 200;
    os_strdup("{\"access_token\":\"access_token_value\"}", data->response->body);
    os_strdup("test", data->response->header);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mtdebug1, formatted_msg, "Scanning tenant: 'test_tenant_id'");

    /* wm_office365_get_access_token */
    expect_any(__wrap_wurl_http_request, method);
    expect_any(__wrap_wurl_http_request, header);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_OFFICE365_DEFAULT_CURL_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_request, data->response);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_any(__wrap__mtdebug1, formatted_msg);
    /* wm_office365_get_access_token */

    expect_string(__wrap_wm_state_io, tag, "office365-test_tenant_id-test_subscription_name");
    expect_value(__wrap_wm_state_io, op, WM_IO_READ);
    expect_any(__wrap_wm_state_io, state);
    expect_any(__wrap_wm_state_io, size);
    will_return(__wrap_wm_state_io, 0);
    will_return(__wrap_wm_state_io, (void *)&tenant_state_struc);

    /* wm_office365_manage_subscription */
    expect_any(__wrap_wurl_http_request, method);
    expect_string(__wrap_wurl_http_request, header, "Content-Type: application/json");

    expect_string(__wrap_wurl_http_request, header, "Authorization: Bearer access_token_value");
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_OFFICE365_DEFAULT_CURL_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_request, data->response);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_any(__wrap__mtdebug1, formatted_msg);

    expect_value(__wrap_wurl_free_response, response, data->response);
    /* wm_office365_manage_subscription */

#ifndef WIN32
    will_return(__wrap_gmtime_r, 1);
#endif

    will_return(__wrap_strftime,"2021-05-07 12:24:56");
    will_return(__wrap_strftime, 20);

#ifndef WIN32
    will_return(__wrap_gmtime_r, 1);
#endif

    will_return(__wrap_strftime,"2021-05-08 12:24:55");
    will_return(__wrap_strftime, 20);

    /* wm_office365_get_content_blobs */
    expect_any(__wrap_wurl_http_request, method);
    expect_string(__wrap_wurl_http_request, header, "Content-Type: application/json");

    expect_string(__wrap_wurl_http_request, header, "Authorization: Bearer access_token_value");
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_OFFICE365_DEFAULT_CURL_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_request, NULL);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_any(__wrap__mtdebug1, formatted_msg);
    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mtdebug1, formatted_msg, "Unknown error while getting content blobs.");
    /* wm_office365_get_content_blobs */

    expect_value(__wrap_wurl_free_response, response, data->response);

    wm_office365_execute_scan(data->office365_config, initial_scan);

    os_free(data->response->body);
    os_free(data->response->header);
    os_free(data->response);
}

void test_wm_office365_execute_scan_get_logs_from_blob_response_null(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    size_t max_size = OS_SIZE_8192;
    wm_office365_state tenant_state_struc;

    tenant_state_struc.last_log_time = 123456789;

    os_calloc(1, sizeof(wm_office365_auth), data->office365_config->auth);
    os_strdup("test_tenant_id", data->office365_config->auth->tenant_id);
    os_strdup("test_client_id", data->office365_config->auth->client_id);
    os_strdup("test_client_secret", data->office365_config->auth->client_secret);
    os_strdup(WM_OFFICE365_DEFAULT_API_LOGIN_FQDN, data->office365_config->auth->login_fqdn);
    os_strdup(WM_OFFICE365_DEFAULT_API_MANAGEMENT_FQDN, data->office365_config->auth->management_fqdn);
    os_calloc(1, sizeof(wm_office365_subscription), data->office365_config->subscription);
    os_strdup("test_subscription_name", data->office365_config->subscription->subscription_name);
    data->office365_config->only_future_events = 0;

    os_calloc(1, sizeof(curl_response), data->response);
    data->response->status_code = 200;
    os_strdup("{\"access_token\":\"wazuh\"}", data->response->body);
    os_strdup("test", data->response->header);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mtdebug1, formatted_msg, "Scanning tenant: 'test_tenant_id'");

    expect_any(__wrap_wurl_http_request, method);
    expect_any(__wrap_wurl_http_request, header);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_OFFICE365_DEFAULT_CURL_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_request, data->response);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_any(__wrap__mtdebug1, formatted_msg);

    expect_value(__wrap_wurl_free_response, response, data->response);

    expect_string(__wrap_wm_state_io, tag, "office365-test_tenant_id-test_subscription_name");
    expect_value(__wrap_wm_state_io, op, WM_IO_READ);
    expect_any(__wrap_wm_state_io, state);
    expect_any(__wrap_wm_state_io, size);
    will_return(__wrap_wm_state_io, 0);
    will_return(__wrap_wm_state_io, (void *)&tenant_state_struc);

    curl_response *manage_subscription_response;
    os_calloc(1, sizeof(curl_response), manage_subscription_response);
    manage_subscription_response->status_code = 200;
    manage_subscription_response->max_size_reached = false;
    os_strdup("{\"test\":\"wazuh\"}", manage_subscription_response->body);
    os_strdup("test", manage_subscription_response->header);


    expect_any(__wrap_wurl_http_request, method);
    expect_any(__wrap_wurl_http_request, header);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_OFFICE365_DEFAULT_CURL_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_request, manage_subscription_response);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_any(__wrap__mtdebug1, formatted_msg);

    expect_value(__wrap_wurl_free_response, response, manage_subscription_response);

    // while ((end_time - start_time) > 0)
#ifndef WIN32
    will_return(__wrap_gmtime_r, 1);
#endif

    will_return(__wrap_strftime,"2021-06-11T12:24:56Z");
    will_return(__wrap_strftime, 20);

#ifndef WIN32
    will_return(__wrap_gmtime_r, 1);
#endif

    will_return(__wrap_strftime,"2021-06-11T12:34:56Z");
    will_return(__wrap_strftime, 20);

    // wm_office365_get_content_blobs
    curl_response *get_content_blobs_response;
    os_calloc(1, sizeof(curl_response), get_content_blobs_response);
    get_content_blobs_response->status_code = 200;
    get_content_blobs_response->max_size_reached = false;
    os_strdup("[{\"contentUri\":\"https://contentUri1.com\"}]", get_content_blobs_response->body);
    os_strdup("test", get_content_blobs_response->header);

    expect_any(__wrap__mdebug1, formatted_msg);

    expect_any(__wrap_wurl_http_request, method);
    expect_any(__wrap_wurl_http_request, header);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_OFFICE365_DEFAULT_CURL_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_request, get_content_blobs_response);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_any(__wrap__mtdebug1, formatted_msg);

    expect_value(__wrap_wurl_free_response, response, get_content_blobs_response);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mtdebug1, formatted_msg, "Office 365 API content URI: 'https://contentUri1.com'");

    expect_string(__wrap_wurl_http_request, header, "Content-Type: application/json");
    expect_string(__wrap_wurl_http_request, header, "Authorization: Bearer wazuh");
    expect_any(__wrap_wurl_http_request, header);
    expect_any(__wrap_wurl_http_request, method);
    expect_any(__wrap_wurl_http_request, header);
    expect_any(__wrap_wurl_http_request, url);
    expect_any(__wrap_wurl_http_request, payload);
    expect_any(__wrap_wurl_http_request, max_size);
    expect_value(__wrap_wurl_http_request, timeout, WM_OFFICE365_DEFAULT_CURL_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_request, NULL);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:office365");
    expect_string(__wrap__mtdebug1, formatted_msg, "Unknown error while getting logs from blob.");

    wm_office365_execute_scan(data->office365_config, 0);

    os_free(data->response->body);
    os_free(data->response->header);
    os_free(data->response);

    os_free(manage_subscription_response->body);
    os_free(manage_subscription_response->header);
    os_free(manage_subscription_response);

    os_free(get_content_blobs_response->body);
    os_free(get_content_blobs_response->header);
    os_free(get_content_blobs_response);
}

int main(void) {
    const struct CMUnitTest tests_configuration[] = {
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
        cmocka_unit_test_setup_teardown(test_error_api_type, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_error_api_type_1, setup_test_read, teardown_test_read),
    };
    const struct CMUnitTest tests_functionality[] = {
        cmocka_unit_test_setup_teardown(test_wm_office365_main_disabled, setup_conf, teardown_conf),
        #ifndef WIN32
            cmocka_unit_test_setup_teardown(test_wm_office365_main_fail_StartMQ, setup_conf, teardown_conf),
            cmocka_unit_test_setup_teardown(test_wm_office365_main_enable, setup_conf, teardown_conf),
        #endif
        cmocka_unit_test_setup_teardown(test_wm_office365_dump_no_options, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_office365_dump_yes_options_empty_arrays, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_office365_dump_yes_options, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_office365_get_access_token_with_auth_secret, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_office365_get_access_token_with_auth_secret_path, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_office365_get_access_token_with_auth_secret_response_400, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_office365_get_access_token_with_auth_secret_response_null, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_office365_get_access_token_with_auth_secret_response_max_size_reached, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_office365_get_access_token_with_auth_secret_error_json_response, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_office365_get_access_token_with_auth_secret_response_200, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_office365_manage_subscription_stop_error_json_response, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_office365_manage_subscription_stop_error_max_size_reached, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_office365_manage_subscription_start_code_200, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_office365_manage_subscription_start_response_null, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_office365_manage_subscription_stop_code_400_error_AF20024, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_office365_manage_subscription_stop_code_400_error_different_AF20024, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_office365_get_fail_by_tenant_and_subscription_null, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_office365_get_fail_by_tenant_and_subscription_not_null, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_office365_get_content_blobs_response_null, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_office365_get_content_blobs_response_max_size_reached, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_office365_get_content_blobs_error_json_response, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_office365_get_content_blobs_bad_response, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_office365_get_content_blobs_400_code_AF20055, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_office365_scan_failure_action_null, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_office365_scan_failure_action_no_fail, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_office365_scan_failure_action_null_mult_next, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_office365_scan_failure_action_not_null, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_office365_scan_failure_action_not_null_error_msg, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_office365_get_logs_from_blob_response_null, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_office365_get_logs_from_blob_response_max_size_reached, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_office365_get_logs_from_blob_response_parsing_error, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_office365_get_logs_from_blob_response_code_400, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_office365_get_logs_from_blob_response_no_array, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_office365_get_logs_from_blob_ok, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_office365_execute_scan_initial_scan_only_future_events, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_office365_execute_scan_access_token_null, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_office365_execute_scan_manage_subscription_error, setup_conf, teardown_conf),
        cmocka_unit_test_setup_teardown(test_wm_office365_execute_scan_saving_running_state_error, setup_conf, teardown_conf),
        #ifndef WIN32
            cmocka_unit_test_setup_teardown(test_wm_office365_execute_scan_content_blobs_fail, setup_conf, teardown_conf),
            cmocka_unit_test_setup_teardown(test_wm_office365_execute_scan_get_logs_from_blob_response_null, setup_conf, teardown_conf),
            cmocka_unit_test_setup_teardown(test_wm_office365_execute_scan_all, setup_conf, teardown_conf),
        #endif
    };

    int result;
    result = cmocka_run_group_tests(tests_configuration, NULL, NULL);
    result += cmocka_run_group_tests(tests_functionality, NULL, NULL);
    return result;
}
