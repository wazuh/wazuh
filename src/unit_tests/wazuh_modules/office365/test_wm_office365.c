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

#include "../../wrappers/libc/stdlib_wrappers.h"
#include "../scheduling/wmodules_scheduling_helpers.h"
#include "../../wrappers/common.h"

int __wrap_access(const char *__name, int __type) {
    check_expected(__name);
    return mock_type(int);
}

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
        "<run_on_start>no</run_on_start>"
        "<skip_on_error>no</skip_on_error>"
        "<interval>10m</interval>"
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
    assert_int_equal(module_data->run_on_start, 0);
    assert_int_equal(module_data->skip_on_error, 0);
    assert_int_equal(module_data->interval, 600);
    assert_string_equal(module_data->auth->tenant_id, "your_tenant_id");
    assert_string_equal(module_data->auth->client_id, "your_client_id");
    assert_string_equal(module_data->auth->client_secret, "your_secret");
    assert_int_equal(module_data->subscription.azure, 1);
    assert_int_equal(module_data->subscription.exchange, 1);
    assert_int_equal(module_data->subscription.sharepoint, 1);
    assert_int_equal(module_data->subscription.general, 1);
    assert_int_equal(module_data->subscription.dlp, 1);
}

void test_read_configuration_1(void **state) {
    const char *string =
        "<enabled>no</enabled>"
        "<run_on_start>yes</run_on_start>"
        "<skip_on_error>no</skip_on_error>"
        "<interval>10m</interval>"
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
    assert_int_equal(module_data->run_on_start, 1);
    assert_int_equal(module_data->skip_on_error, 0);
    assert_int_equal(module_data->interval, 600);
    assert_string_equal(module_data->auth->tenant_id, "your_tenant_id");
    assert_string_equal(module_data->auth->client_id, "your_client_id");
    assert_string_equal(module_data->auth->client_secret, "your_secret");
    assert_string_equal(module_data->auth->next->tenant_id, "your_tenant_id_1");
    assert_string_equal(module_data->auth->next->client_id, "your_client_id_1");
    assert_string_equal(module_data->auth->next->client_secret_path, "/path/to/secret");
    assert_int_equal(module_data->subscription.azure, 1);
    assert_int_equal(module_data->subscription.exchange, 1);
    assert_int_equal(module_data->subscription.sharepoint, 1);
    assert_int_equal(module_data->subscription.general, 1);
    assert_int_equal(module_data->subscription.dlp, 1);
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
    expect_string(__wrap__mwarn, formatted_msg, "At module 'office365': No subscription was provided, everything will be monitored by default.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),0);
    wm_office365 *module_data = (wm_office365*)test->module->data;
    assert_int_equal(module_data->enabled, 1);
    assert_int_equal(module_data->run_on_start, 1);
    assert_int_equal(module_data->skip_on_error, 0);
    assert_int_equal(module_data->interval, 20);
    assert_string_equal(module_data->auth->tenant_id, "your_tenant_id");
    assert_string_equal(module_data->auth->client_id, "your_client_id");
    assert_string_equal(module_data->auth->client_secret, "your_secret");
    assert_int_equal(module_data->subscription.azure, 1);
    assert_int_equal(module_data->subscription.exchange, 1);
    assert_int_equal(module_data->subscription.sharepoint, 1);
    assert_int_equal(module_data->subscription.general, 1);
    assert_int_equal(module_data->subscription.dlp, 1);
}

void test_read_interval(void **state) {
    const char *string =
        "<enabled>no</enabled>"
        "<run_on_start>yes</run_on_start>"
        "<skip_on_error>no</skip_on_error>"
        "<interval>10</interval>"
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
    assert_int_equal(module_data->run_on_start, 1);
    assert_int_equal(module_data->skip_on_error, 0);
    assert_int_equal(module_data->interval, 10);
    assert_string_equal(module_data->auth->tenant_id, "your_tenant_id");
    assert_string_equal(module_data->auth->client_id, "your_client_id");
    assert_string_equal(module_data->auth->client_secret, "your_secret");
    assert_int_equal(module_data->subscription.azure, 1);
    assert_int_equal(module_data->subscription.exchange, 1);
    assert_int_equal(module_data->subscription.sharepoint, 1);
    assert_int_equal(module_data->subscription.general, 1);
    assert_int_equal(module_data->subscription.dlp, 1);
}

void test_read_interval_s(void **state) {
    const char *string =
        "<enabled>no</enabled>"
        "<run_on_start>yes</run_on_start>"
        "<skip_on_error>no</skip_on_error>"
        "<interval>50s</interval>"
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
        "<run_on_start>yes</run_on_start>"
        "<skip_on_error>no</skip_on_error>"
        "<interval>90000s</interval>"
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
    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'interval' at module 'office365'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),-1);
}

void test_read_interval_m(void **state) {
    const char *string =
        "<enabled>no</enabled>"
        "<run_on_start>yes</run_on_start>"
        "<skip_on_error>no</skip_on_error>"
        "<interval>1m</interval>"
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
        "<run_on_start>yes</run_on_start>"
        "<skip_on_error>no</skip_on_error>"
        "<interval>1500m</interval>"
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
    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'interval' at module 'office365'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),-1);
}

void test_read_interval_h(void **state) {
    const char *string =
        "<enabled>no</enabled>"
        "<run_on_start>yes</run_on_start>"
        "<skip_on_error>no</skip_on_error>"
        "<interval>2h</interval>"
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
        "<run_on_start>yes</run_on_start>"
        "<skip_on_error>no</skip_on_error>"
        "<interval>30h</interval>"
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
    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'interval' at module 'office365'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),-1);
}

void test_read_interval_d(void **state) {
    const char *string =
        "<enabled>no</enabled>"
        "<run_on_start>yes</run_on_start>"
        "<skip_on_error>no</skip_on_error>"
        "<interval>1d</interval>"
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
        "<run_on_start>yes</run_on_start>"
        "<skip_on_error>no</skip_on_error>"
        "<interval>2d</interval>"
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
    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'interval' at module 'office365'.");
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
        "<run_on_start>yes</run_on_start>"
        "<skip_on_error>no</skip_on_error>"
        "<interval>1d</interval>"
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
        "<run_on_start>yes</run_on_start>"
        "<skip_on_error>no</skip_on_error>"
        "<interval>1d</interval>"
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
        "<run_on_start>invalid</run_on_start>"
        "<skip_on_error>no</skip_on_error>"
        "<interval>1d</interval>"
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
    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'run_on_start' at module 'office365'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),-1);
}

void test_invalid_content_2(void **state) {
    const char *string =
        "<enabled>no</enabled>"
        "<run_on_start>yes</run_on_start>"
        "<skip_on_error>no</skip_on_error>"
        "<interval>1d</interval>"
        "<api_auth>"
            "<tenant_id>your_tenant_id</tenant_id>"
            "<client_id>your_client_id</client_id>"
            "<client_secret>your_secret</client_secret>"
        "</api_auth>"
        "<subscriptions>"
            "<subscription>invalid</subscription>"
            "<subscription>Audit.Exchange</subscription>"
            "<subscription>Audit.SharePoint</subscription>"
            "<subscription>Audit.General</subscription>"
            "<subscription>DLP.All</subscription>"
        "</subscriptions>"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'subscription' at module 'office365'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),-1);
}

void test_invalid_content_3(void **state) {
    const char *string =
        "<enabled>no</enabled>"
        "<run_on_start>yes</run_on_start>"
        "<skip_on_error>invalid</skip_on_error>"
        "<interval>1d</interval>"
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
    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'skip_on_error' at module 'office365'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),-1);
}

void test_invalid_content_4(void **state) {
    const char *string =
        "<enabled>invalid</enabled>\n"
        "<run_on_start>yes</run_on_start>"
        "<skip_on_error>invalid</skip_on_error>"
        "<interval>1d</interval>"
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

void test_invalid_content_5(void **state) {
    const char *string =
        "<enabled>yes</enabled>\n"
        "<run_on_start>yes</run_on_start>"
        "<skip_on_error>yes</skip_on_error>"
        "<interval>invalid</interval>"
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
    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'interval' at module 'office365'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),-1);
}

void test_invalid_interval(void **state) {
    const char *string =
        "<enabled>yes</enabled>\n"
        "<run_on_start>yes</run_on_start>"
        "<skip_on_error>yes</skip_on_error>"
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
    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'interval' at module 'office365'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),-1);
}

void test_error_api_auth(void **state) {
    const char *string =
        "<enabled>yes</enabled>\n"
        "<run_on_start>yes</run_on_start>"
        "<skip_on_error>yes</skip_on_error>"
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
        "<run_on_start>yes</run_on_start>"
        "<skip_on_error>yes</skip_on_error>"
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
        "<run_on_start>yes</run_on_start>"
        "<skip_on_error>yes</skip_on_error>"
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
        "<run_on_start>yes</run_on_start>"
        "<skip_on_error>yes</skip_on_error>"
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
        "<run_on_start>yes</run_on_start>"
        "<skip_on_error>yes</skip_on_error>"
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
        "<run_on_start>yes</run_on_start>"
        "<skip_on_error>yes</skip_on_error>"
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
        "<run_on_start>yes</run_on_start>"
        "<skip_on_error>yes</skip_on_error>"
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
        "<run_on_start>yes</run_on_start>"
        "<skip_on_error>yes</skip_on_error>"
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
        "<run_on_start>yes</run_on_start>"
        "<skip_on_error>yes</skip_on_error>"
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
    expect_string(__wrap__merror, formatted_msg, "At module 'office365': The path cannot be opened. Skipping block...");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_office365_read(&(test->xml), test->nodes, test->module),-1);
}

void test_error_client_secret_path_1(void **state) {
    const char *string =
        "<enabled>yes</enabled>\n"
        "<run_on_start>yes</run_on_start>"
        "<skip_on_error>yes</skip_on_error>"
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
        cmocka_unit_test_setup_teardown(test_secret_path_and_secret, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_fake_tag, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_fake_tag_1, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_invalid_content_1, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_invalid_content_2, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_invalid_content_3, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_invalid_content_4, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_invalid_content_5, setup_test_read, teardown_test_read),
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
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
