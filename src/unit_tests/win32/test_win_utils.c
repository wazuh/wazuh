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

int __wrap_send_msg(const char *msg, ssize_t msg_length) {
    check_expected(msg);
    return mock();
}

int mock_sysinfo_networks_func(cJSON **object) {

    static const char *ip_update_success =
    "{ \"iface\": [ { \"gateway\":\"mock_gateway\", \"IPv4\": [ { \"address\":\"111.222.333.444\" } ] } ] }";
    static const char *ipv6_gw_ipv4_addr_update_success =
    "{ \"iface\": [ { \"gateway\":\"fe80::\", \"IPv4\": [ { \"address\":\"111.222.333.444\" } ] } ] }";
    static const char *ipv6_gw_ipv6_addr_update_success =
    "{ \"iface\": [ { \"gateway\":\"fe80::\", \"IPv6\": [ { \"address\":\"fe80::a00:27ff:fee0:d046\" } ] } ] }";
    static const char *ipv4_gw_ipv4_addr_update_success =
    "{ \"iface\": [ { \"gateway\":\"192.168.1.1\", \"IPv4\": [ { \"address\":\"111.222.333.444\" } ] } ] }";
    static const char *ipv4_gw_ipv6_addr_update_success =
    "{ \"iface\": [ { \"gateway\":\"192.168.1.1\", \"IPv6\": [ { \"address\":\"fe80::a00:27ff:fee0:d046\" } ] } ] }";
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
    case 5:
        json_string = ipv6_gw_ipv4_addr_update_success;
        break;
    case 6:
        json_string = ipv6_gw_ipv6_addr_update_success;
        break;
    case 7:
        json_string = ipv4_gw_ipv4_addr_update_success;
        break;
    case  8:
        json_string = ipv4_gw_ipv6_addr_update_success;
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

static void test_get_agent_ip_legacy_win32_update_ip_success(void **state) {

    char *agent_ip = { "\0" };
    char *address = { "111.222.333.444" };
    time_mock_value += TIME_INCREMENT + 1;
    error_code_sysinfo_network = 0;
    test_case_selector = 1;

    agent_ip = get_agent_ip_legacy_win32();

    assert_string_equal(agent_ip, address);
}

static void test_get_agent_ip_legacy_win32_update_ipv6_gateway_ipv6_success(void ** state) {

    const char * address = {"FE80:0000:0000:0000:0A00:27FF:FEE0:D046"};
    time_mock_value += TIME_INCREMENT + 1;
    error_code_sysinfo_network = 0;
    test_case_selector = 6;

    char * agent_ip = get_agent_ip_legacy_win32();

    assert_string_equal(agent_ip, address);
    os_free(agent_ip);
}

static void test_get_agent_ip_legacy_win32_update_ipv6_gateway_ipv4_success(void ** state) {

    const char * address = {"111.222.333.444"};
    time_mock_value += TIME_INCREMENT + 1;
    error_code_sysinfo_network = 0;
    test_case_selector = 5;

    char * agent_ip = get_agent_ip_legacy_win32();

    assert_string_equal(agent_ip, address);
    os_free(agent_ip);
}

static void test_get_agent_ip_legacy_win32_update_ipv4_gateway_ipv4_success(void ** state) {

    const char * address = {"111.222.333.444"};
    time_mock_value += TIME_INCREMENT + 1;
    error_code_sysinfo_network = 0;
    test_case_selector = 7;

    char * agent_ip = get_agent_ip_legacy_win32();

    assert_string_equal(agent_ip, address);
    os_free(agent_ip);
}

static void test_get_agent_ip_legacy_win32_update_ipv4_gateway_ipv6_success(void ** state) {

    const char * address = {"FE80:0000:0000:0000:0A00:27FF:FEE0:D046"};
    time_mock_value += TIME_INCREMENT + 1;
    error_code_sysinfo_network = 0;
    test_case_selector = 8;

    char * agent_ip = get_agent_ip_legacy_win32();

    assert_string_equal(agent_ip, address);
    os_free(agent_ip);
}

static void test_get_agent_ip_legacy_win32_sysinfo_error(void **state) {

    char *agent_ip = { "\0" };
    char *address = { "\0" };
    time_mock_value += TIME_INCREMENT + 1;
    error_code_sysinfo_network = 2;
    test_case_selector = 1;
    expect_string(__wrap__merror, formatted_msg, "Unable to get system network information. Error code: 2.");
    agent_ip = get_agent_ip_legacy_win32();

    assert_string_equal(agent_ip, address);
}

static void test_get_agent_ip_legacy_win32_iface_bad_name(void **state) {

    char *agent_ip = { "\0" };
    char *address = { "\0" };
    time_mock_value += TIME_INCREMENT + 1;
    error_code_sysinfo_network = 0;
    test_case_selector = 2;

    agent_ip = get_agent_ip_legacy_win32();

    assert_string_equal(agent_ip, address);
}

static void test_get_agent_ip_legacy_win32_iface_no_elements(void **state) {

    char *agent_ip = { "\0" };
    char *address = { "\0" };
    time_mock_value += TIME_INCREMENT + 1;
    error_code_sysinfo_network = 0;
    test_case_selector = 3;

    agent_ip = get_agent_ip_legacy_win32();

    assert_string_equal(agent_ip, address);
}

static void test_get_agent_ip_legacy_win32_gateway_unknown(void **state) {

    char *agent_ip = { "\0" };
    char *address = { "\0" };
    time_mock_value += TIME_INCREMENT + 1;
    error_code_sysinfo_network = 0;
    test_case_selector = 4;

    agent_ip = get_agent_ip_legacy_win32();

    assert_string_equal(agent_ip, address);
}

static void test_get_agent_ip_legacy_win32_no_update(void **state) {

    char *agent_ip = { "\0" };
    char *address = { "\0" };
    time_mock_value += TIME_INCREMENT;

    agent_ip = get_agent_ip_legacy_win32();

    assert_string_equal(agent_ip, address);
}

static void test_SendMSGAction_mutex_abandoned(void **state) {

    expect_any(wrap_WaitForSingleObject, hMutex);
    expect_value(wrap_WaitForSingleObject, value, 1000000L);
    will_return(wrap_WaitForSingleObject, WAIT_ABANDONED);

    expect_string(__wrap__merror, formatted_msg, "Error waiting mutex (abandoned).");

    int ret = SendMSG(0, "message", "locmsg", LOCALFILE_MQ);

    assert_int_equal(ret, -1);
}

static void test_SendMSGAction_mutex_error(void **state) {

    expect_any(wrap_WaitForSingleObject, hMutex);
    expect_value(wrap_WaitForSingleObject, value, 1000000L);
    will_return(wrap_WaitForSingleObject, -8);

    expect_string(__wrap__merror, formatted_msg, "Error waiting mutex.");

    int ret = SendMSG(0, "message", "locmsg", LOCALFILE_MQ);

    assert_int_equal(ret, -1);
}

static void test_SendMSGAction_non_escape(void **state) {

    agt->buffer = 0;

    expect_any(wrap_WaitForSingleObject, hMutex);
    expect_value(wrap_WaitForSingleObject, value, 1000000L);
    will_return(wrap_WaitForSingleObject, WAIT_OBJECT_0);

    expect_string(__wrap_send_msg, msg, "1:locmsg:message");
    will_return(__wrap_send_msg, 0);

    expect_any_always(wrap_ReleaseMutex, hMutex);
    will_return(wrap_ReleaseMutex, 1);

    int ret = SendMSG(0, "message", "locmsg", LOCALFILE_MQ);

    assert_int_equal(ret, 0);
}

static void test_SendMSGAction_escape(void **state) {

    agt->buffer = 0;

    expect_any(wrap_WaitForSingleObject, hMutex);
    expect_value(wrap_WaitForSingleObject, value, 1000000L);
    will_return(wrap_WaitForSingleObject, WAIT_OBJECT_0);

    expect_string(__wrap_send_msg, msg, "1:loc||msg|:test:message");
    will_return(__wrap_send_msg, 0);

    expect_any_always(wrap_ReleaseMutex, hMutex);
    will_return(wrap_ReleaseMutex, 0);
    expect_string(__wrap__merror, formatted_msg, "Error releasing mutex.");

    int ret = SendMSG(0, "message", "loc|msg:test", LOCALFILE_MQ);

    assert_int_equal(ret, 0);
}

static void test_SendMSGAction_multi_escape(void **state) {

    agt->buffer = 0;

    expect_any(wrap_WaitForSingleObject, hMutex);
    expect_value(wrap_WaitForSingleObject, value, 1000000L);
    will_return(wrap_WaitForSingleObject, WAIT_OBJECT_0);

    expect_string(__wrap_send_msg, msg, "1:a||||a|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:a||||a:message");
    will_return(__wrap_send_msg, 0);

    expect_any_always(wrap_ReleaseMutex, hMutex);
    will_return(wrap_ReleaseMutex, 1);

    int ret = SendMSG(0, "message", "a||a::::::::::::::::a||a", LOCALFILE_MQ);

    assert_int_equal(ret, 0);
}

static void test_SendBinaryMSGAction_mutex_abandoned(void **state) {
    (void) state;

    expect_any(wrap_WaitForSingleObject, hMutex);
    expect_value(wrap_WaitForSingleObject, value, 1000000L);
    will_return(wrap_WaitForSingleObject, WAIT_ABANDONED);

    expect_string(__wrap__merror, formatted_msg, "Error waiting mutex (abandoned).");

    int ret = SendBinaryMSG(0, "data", 4, "locmsg", 's');
    assert_int_equal(ret, -1);
}

static void test_SendBinaryMSGAction_message_too_large(void **state) {
    (void) state;

    size_t payload_len = OS_MAXSTR;
    char payload[payload_len];
    memset(payload, 'A', payload_len);

    expect_any(wrap_WaitForSingleObject, hMutex);
    expect_value(wrap_WaitForSingleObject, value, 1000000L);
    will_return(wrap_WaitForSingleObject, WAIT_OBJECT_0);

    expect_string(__wrap__mwarn, formatted_msg, "Binary message is too large to be sent (65542 bytes required, 65536 max). Payload of 65536 bytes for module 'FIM' was dropped.");

    expect_any(wrap_ReleaseMutex, hMutex);
    will_return(wrap_ReleaseMutex, 1);

    int ret = SendBinaryMSG(0, payload, payload_len, "FIM", 's');
    assert_int_equal(ret, -1);
}

static void test_SendBinaryMSGAction_direct_send_success(void **state) {
    (void) state;

    agt->buffer = 0;

    const char payload[] = {'d', 'a', 't', 'a', '\0', 'm', 'o', 'r', 'e'};
    size_t payload_len = sizeof(payload);
    const char *locmsg = "FIM";
    char loc = 's';

    char expected_msg[100];
    char *p = expected_msg;
    strcpy(p, "s:FIM:");
    p += strlen("s:FIM:");
    memcpy(p, payload, payload_len);
    size_t total_len = strlen("s:FIM:") + payload_len;

    expect_any(wrap_WaitForSingleObject, hMutex);
    expect_value(wrap_WaitForSingleObject, value, 1000000L);
    will_return(wrap_WaitForSingleObject, WAIT_OBJECT_0);

    expect_memory(__wrap_send_msg, msg, expected_msg, total_len);
    will_return(__wrap_send_msg, 0);

    expect_any(wrap_ReleaseMutex, hMutex);
    will_return(wrap_ReleaseMutex, 1);

    int ret = SendBinaryMSG(0, payload, payload_len, locmsg, loc);
    assert_int_equal(ret, 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_get_agent_ip_legacy_win32_update_ip_success), cmocka_unit_test(test_get_agent_ip_legacy_win32_sysinfo_error),
        cmocka_unit_test(test_get_agent_ip_legacy_win32_iface_bad_name),    cmocka_unit_test(test_get_agent_ip_legacy_win32_iface_no_elements),
        cmocka_unit_test(test_get_agent_ip_legacy_win32_gateway_unknown),   cmocka_unit_test(test_get_agent_ip_legacy_win32_no_update),
        cmocka_unit_test(test_get_agent_ip_legacy_win32_update_ipv6_gateway_ipv6_success),
        cmocka_unit_test(test_get_agent_ip_legacy_win32_update_ipv6_gateway_ipv4_success),
        cmocka_unit_test(test_get_agent_ip_legacy_win32_update_ipv4_gateway_ipv4_success),
        cmocka_unit_test(test_get_agent_ip_legacy_win32_update_ipv4_gateway_ipv6_success),
        cmocka_unit_test(test_SendMSGAction_mutex_abandoned), cmocka_unit_test(test_SendMSGAction_mutex_error),
        cmocka_unit_test(test_SendMSGAction_non_escape), cmocka_unit_test(test_SendMSGAction_escape),
        cmocka_unit_test(test_SendMSGAction_multi_escape),
        cmocka_unit_test(test_SendBinaryMSGAction_mutex_abandoned),
        cmocka_unit_test(test_SendBinaryMSGAction_message_too_large),
        cmocka_unit_test(test_SendBinaryMSGAction_direct_send_success),
    };

    return cmocka_run_group_tests(tests, setup_group, NULL);
}

#endif
