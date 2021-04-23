/*
 * Copyright (C) 2015-2020, Wazuh Inc.
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
#include "wazuh_modules/wmodules.h"
#include "wazuh_modules/wm_github.h"

#include "../scheduling/wmodules_scheduling_helpers.h"
#include "../../wrappers/common.h"
#include "../../wrappers/libc/stdlib_wrappers.h"

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
    if((wm_github*)test->module->data){
        os_free(((wm_github*)test->module->data)->org_name);
        os_free(((wm_github*)test->module->data)->api_token);
        os_free(((wm_github*)test->module->data)->event_type);
    }
    os_free(test->module->data);
    os_free(test->module->tag);
    os_free(test->module);
    os_free(test);
    return 0;
}

void test_read_configuration(void **state) {
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
            "<event_type>git</event_type>"
        "</api_parameters>"
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_github_read(&(test->xml), test->nodes, test->module),0);
    wm_github *module_data = (wm_github*)test->module->data;
    assert_int_equal(module_data->enabled, 0);
    assert_int_equal(module_data->run_on_start, 1);
    assert_int_equal(module_data->interval, 600);
    assert_int_equal(module_data->time_delay, 1);
    assert_int_equal(module_data->only_future_events, 0);
    assert_string_equal(module_data->org_name, "Wazuh");
    assert_string_equal(module_data->api_token, "Wazuh_token");
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
    assert_int_equal(wm_github_read(&(test->xml), test->nodes, test->module),0);
    wm_github *module_data = (wm_github*)test->module->data;
    assert_int_equal(module_data->enabled, 0);
    assert_int_equal(module_data->run_on_start, 1);
    assert_int_equal(module_data->interval, 600);
    assert_int_equal(module_data->time_delay, 1);
    assert_int_equal(module_data->only_future_events, 0);
    assert_string_equal(module_data->org_name, "Wazuh");
    assert_string_equal(module_data->api_token, "Wazuh_token");
    assert_string_equal(module_data->event_type, "all");
}

void test_read_interval(void **state) {
    const char *string =
        "<interval>10</interval>\n"
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_github_read(&(test->xml), test->nodes, test->module),0);
    wm_github *module_data = (wm_github*)test->module->data;
    assert_int_equal(module_data->interval, 10);
}

void test_read_interval_s(void **state) {
    const char *string =
        "<interval>50s</interval>\n"
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_github_read(&(test->xml), test->nodes, test->module),0);
    wm_github *module_data = (wm_github*)test->module->data;
    assert_int_equal(module_data->interval, 50);
}

void test_read_interval_m(void **state) {
    const char *string =
        "<interval>1m</interval>\n"
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_github_read(&(test->xml), test->nodes, test->module),0);
    wm_github *module_data = (wm_github*)test->module->data;
    assert_int_equal(module_data->interval, 60);
}

void test_read_interval_h(void **state) {
    const char *string =
        "<interval>2h</interval>\n"
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_github_read(&(test->xml), test->nodes, test->module),0);
    wm_github *module_data = (wm_github*)test->module->data;
    assert_int_equal(module_data->interval, 7200);
}

void test_read_interval_d(void **state) {
    const char *string =
        "<interval>3d</interval>\n"
    ;
    test_structure *test = *state;
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_github_read(&(test->xml), test->nodes, test->module),0);
    wm_github *module_data = (wm_github*)test->module->data;
    assert_int_equal(module_data->interval, 259200);
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
    assert_int_equal(wm_github_read(&(test->xml), test->nodes, test->module),-1);
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
    assert_int_equal(wm_github_read(&(test->xml), test->nodes, test->module),-1);
}

void test_invalid_content_2(void **state) {
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
            "<event_type>invalid</event_type>"
        "</api_parameters>"
    ;
    test_structure *test = *state;
    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'event_type' at module 'github'.");
    test->nodes = string_to_xml_node(string, &(test->xml));
    assert_int_equal(wm_github_read(&(test->xml), test->nodes, test->module),-1);
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
    assert_int_equal(wm_github_read(&(test->xml), test->nodes, test->module),-1);
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
    assert_int_equal(wm_github_read(&(test->xml), test->nodes, test->module),-1);
}



int main(void) {

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_read_configuration, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_default_configuration, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_interval, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_interval_s, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_interval_m, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_interval_h, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_read_interval_d, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_fake_tag, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_invalid_content_1, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_invalid_content_2, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_invalid_time_delay_1, setup_test_read, teardown_test_read),
        cmocka_unit_test_setup_teardown(test_invalid_time_delay_2, setup_test_read, teardown_test_read),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
