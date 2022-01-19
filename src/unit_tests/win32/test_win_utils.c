/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include "../../client-agent/agentd.h"
#include "../wrappers/externals/cJSON/cJSON_wrappers.h"
#include "../wrappers/common.h"
#include "../../data_provider/include/sysInfo.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"


#ifdef TEST_WINAGENT

#define TIME_INCREMENT ((time_t)(60))

extern sysinfo_networks_func sysinfo_network_ptr;
extern sysinfo_free_result_func sysinfo_free_result_ptr;

static agent global_config = { .main_ip_update_interval = (int)TIME_INCREMENT };
static int test_case_selector = 0;
static int error_code_sysinfo_network = 0;

int mock_sysinfo_networks_func(cJSON **object) {

    static const char *ip_update_success =
    "{ \"iface\": [ { \"gateway\":\"mock_gateway\", \"IPv4\": [ { \"address\":\"111.222.333.444\" } ] } ] }";
    static const char *iface_bad_name = "{\"iface_fail\":[]}";
    static const char *iface_no_elements = "{\"iface\":[]";
    static const char *gateway_unknown = "{ \"iface\": [ { \"gateway\":\"unknown\" } ] }";
    const char *json_string = NULL;

    switch (test_case_selector) {
    case 1:
        json_string = ip_update_success;
        break;
    case 2:
        json_string = iface_bad_name;
        break;
    case 3:
        json_string = iface_no_elements;
        break;
    case 4:
        json_string = gateway_unknown;
        break;
    }

    *object = cJSON_Parse(json_string);

    return error_code_sysinfo_network;
}

void mock_sysinfo_free_result_func(cJSON **object) {
    cJSON_free(*object);
    return;
}

static int setup_group(void **state) {
    agt = &global_config;
    time_mock_value = 0;
    sysinfo_network_ptr = mock_sysinfo_networks_func;
    sysinfo_free_result_ptr = mock_sysinfo_free_result_func;

    return 0;
}

static void test_get_agent_ip_update_ip_success(void **state) {

    char *agent_ip = { "\0" };
    char *address = { "111.222.333.444" };
    time_mock_value += TIME_INCREMENT + 1;
    error_code_sysinfo_network = 0;
    test_case_selector = 1;

    agent_ip = get_agent_ip();

    assert_string_equal(agent_ip, address);
}

static void test_get_agent_ip_sysinfo_error(void **state) {

    char *agent_ip = { "\0" };
    char *address = { "\0" };
    time_mock_value += TIME_INCREMENT + 1;
    error_code_sysinfo_network = 2;
    test_case_selector = 1;
    expect_string(__wrap__merror, formatted_msg, "Unable to get system network information. Error code: 2.");
    agent_ip = get_agent_ip();

    assert_string_equal(agent_ip, address);
}

static void test_get_agent_ip_iface_bad_name(void **state) {

    char *agent_ip = { "\0" };
    char *address = { "\0" };
    time_mock_value += TIME_INCREMENT + 1;
    error_code_sysinfo_network = 0;
    test_case_selector = 2;

    agent_ip = get_agent_ip();

    assert_string_equal(agent_ip, address);
}

static void test_get_agent_ip_iface_no_elements(void **state) {

    char *agent_ip = { "\0" };
    char *address = { "\0" };
    time_mock_value += TIME_INCREMENT + 1;
    error_code_sysinfo_network = 0;
    test_case_selector = 3;

    agent_ip = get_agent_ip();

    assert_string_equal(agent_ip, address);
}

static void test_get_agent_ip_gateway_unknown(void **state) {

    char *agent_ip = { "\0" };
    char *address = { "\0" };
    time_mock_value += TIME_INCREMENT + 1;
    error_code_sysinfo_network = 0;
    test_case_selector = 4;

    agent_ip = get_agent_ip();

    assert_string_equal(agent_ip, address);
}

static void test_get_agent_ip_no_update(void **state) {

    char *agent_ip = { "\0" };
    char *address = { "\0" };
    time_mock_value += TIME_INCREMENT;

    agent_ip = get_agent_ip();

    assert_string_equal(agent_ip, address);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_get_agent_ip_update_ip_success), cmocka_unit_test(test_get_agent_ip_sysinfo_error),
        cmocka_unit_test(test_get_agent_ip_iface_bad_name),    cmocka_unit_test(test_get_agent_ip_iface_no_elements),
        cmocka_unit_test(test_get_agent_ip_gateway_unknown),   cmocka_unit_test(test_get_agent_ip_no_update),
    };

    return cmocka_run_group_tests(tests, setup_group, NULL);
}

#endif
