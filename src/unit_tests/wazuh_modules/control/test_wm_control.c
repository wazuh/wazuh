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
#include <stdio.h>
#include "../../wrappers/wazuh/data_provider/sysInfo_wrappers.h"
#include "../../../data_provider/include/sysInfo.h"
#include "../../../wazuh_modules/wm_control.h"

extern sysinfo_networks_func sysinfo_network_ptr;
extern sysinfo_free_result_func sysinfo_free_result_ptr;

static void test_wm_control_getPrimaryIP_no_sysinfo_network(void ** state) {
    sysinfo_network_ptr = NULL;

    char * ip = getPrimaryIP();

    assert_null(ip);
}

static void test_wm_control_getPrimaryIP_no_sysinfo_free(void ** state) {
    sysinfo_network_ptr = (int (*)(cJSON **)) 1;
    sysinfo_free_result_ptr = NULL;

    char * ip = getPrimaryIP();

    assert_null(ip);
}

static void test_wm_control_getPrimaryIP_sysinfo_network_return_error(void ** state) {
    sysinfo_network_ptr = __wrap_sysinfo_networks;
    sysinfo_free_result_ptr = __wrap_sysinfo_free_result;
    cJSON * networks = NULL;

    will_return(__wrap_sysinfo_networks, networks);
    will_return(__wrap_sysinfo_networks, 1234);
    expect_string(__wrap__mterror, tag, "wazuh-modulesd:control");
    expect_string(__wrap__mterror, formatted_msg, "Unable to get system network information. Error code: 1234.");

    char * ip = getPrimaryIP();

    assert_null(ip);
}
static void test_wm_control_getPrimaryIP_sysinfo_network_no_object(void ** state) {
    sysinfo_network_ptr = __wrap_sysinfo_networks;
    sysinfo_free_result_ptr = __wrap_sysinfo_free_result;
    cJSON * networks = NULL;

    will_return(__wrap_sysinfo_networks, networks);
    will_return(__wrap_sysinfo_networks, 0);

    char * ip = getPrimaryIP();

    assert_null(ip);
}

static void test_wm_control_getPrimaryIP_sysinfo_network_no_iface(void ** state) {
    sysinfo_network_ptr = __wrap_sysinfo_networks;
    sysinfo_free_result_ptr = __wrap_sysinfo_free_result;
    cJSON * networks = cJSON_Parse("{}");

    will_return(__wrap_sysinfo_networks, networks);
    will_return(__wrap_sysinfo_networks, 0);
    will_return(__wrap_sysinfo_free_result, networks);

    char * ip = getPrimaryIP();

    assert_null(ip);

    cJSON_Delete(networks);
}

static void test_wm_control_getPrimaryIP_sysinfo_network_no_iface_array(void ** state) {
    sysinfo_network_ptr = __wrap_sysinfo_networks;
    sysinfo_free_result_ptr = __wrap_sysinfo_free_result;
    cJSON * networks = cJSON_Parse("{\"iface\":{}}");

    will_return(__wrap_sysinfo_networks, networks);
    will_return(__wrap_sysinfo_networks, 0);
    will_return(__wrap_sysinfo_free_result, networks);

    char * ip = getPrimaryIP();

    assert_null(ip);

    cJSON_Delete(networks);
}
static void test_wm_control_getPrimaryIP_sysinfo_network_iface_empty_array(void ** state) {
    sysinfo_network_ptr = __wrap_sysinfo_networks;
    sysinfo_free_result_ptr = __wrap_sysinfo_free_result;
    cJSON * networks = cJSON_Parse("{\"iface\":[]}");

    will_return(__wrap_sysinfo_networks, networks);
    will_return(__wrap_sysinfo_networks, 0);
    will_return(__wrap_sysinfo_free_result, networks);

    char * ip = getPrimaryIP();

    assert_null(ip);

    cJSON_Delete(networks);
}

static void test_wm_control_getPrimaryIP_sysinfo_network_iface_no_gateway(void ** state) {
    sysinfo_network_ptr = __wrap_sysinfo_networks;
    sysinfo_free_result_ptr = __wrap_sysinfo_free_result;
    cJSON * networks = cJSON_Parse("{\"iface\":[{\"name\":\"eth0\"}]}");

    will_return(__wrap_sysinfo_networks, networks);
    will_return(__wrap_sysinfo_networks, 0);
    will_return(__wrap_sysinfo_free_result, networks);

    char * ip = getPrimaryIP();

    assert_null(ip);

    cJSON_Delete(networks);
}

static void test_wm_control_getPrimaryIP_sysinfo_network_iface_invalid_gateway_type(void ** state) {
    sysinfo_network_ptr = __wrap_sysinfo_networks;
    sysinfo_free_result_ptr = __wrap_sysinfo_free_result;
    cJSON * networks = cJSON_Parse("{\"iface\":[{\"name\":\"eth0\",\"gateway\":1234}]}");

    will_return(__wrap_sysinfo_networks, networks);
    will_return(__wrap_sysinfo_networks, 0);
    will_return(__wrap_sysinfo_free_result, networks);

    char * ip = getPrimaryIP();

    assert_null(ip);

    cJSON_Delete(networks);
}

static void test_wm_control_getPrimaryIP_sysinfo_network_iface_empty_gateway(void ** state) {
    sysinfo_network_ptr = __wrap_sysinfo_networks;
    sysinfo_free_result_ptr = __wrap_sysinfo_free_result;
    cJSON * networks = cJSON_Parse("{\"iface\":[{\"name\":\"eth0\",\"gateway\":\" \"}]}");

    will_return(__wrap_sysinfo_networks, networks);
    will_return(__wrap_sysinfo_networks, 0);
    will_return(__wrap_sysinfo_free_result, networks);

    char * ip = getPrimaryIP();

    assert_null(ip);

    cJSON_Delete(networks);
}

static void test_wm_control_getPrimaryIP_sysinfo_network_iface_ipv6_gateway_ipv6_address(void ** state) {
    sysinfo_network_ptr = __wrap_sysinfo_networks;
    sysinfo_free_result_ptr = __wrap_sysinfo_free_result;
    cJSON * networks = cJSON_Parse("{\"iface\":[{\"name\":\"eth0\",\"gateway\":\"fe80::\",\"IPv6\":[{\"address\":"
                                   "\"fe80::a00:27ff:fee0:d046\"}]}]}");

    will_return(__wrap_sysinfo_networks, networks);
    will_return(__wrap_sysinfo_networks, 0);
    will_return(__wrap_sysinfo_free_result, networks);

    char * ip = getPrimaryIP();

    assert_string_equal(ip, "FE80:0000:0000:0000:0A00:27FF:FEE0:D046");

    os_free(ip);
    cJSON_Delete(networks);
}

static void test_wm_control_getPrimaryIP_sysinfo_network_iface_ipv6_gateway_ipv4_address(void ** state) {
    sysinfo_network_ptr = __wrap_sysinfo_networks;
    sysinfo_free_result_ptr = __wrap_sysinfo_free_result;
    cJSON * networks = cJSON_Parse(
        "{\"iface\":[{\"name\":\"eth0\",\"gateway\":\"fe80::\",\"IPv4\":[{\"address\":\"192.168.1.10\"}]}]}");

    will_return(__wrap_sysinfo_networks, networks);
    will_return(__wrap_sysinfo_networks, 0);
    will_return(__wrap_sysinfo_free_result, networks);

    char * ip = getPrimaryIP();

    assert_string_equal(ip, "192.168.1.10");

    os_free(ip);
    cJSON_Delete(networks);
}

static void test_wm_control_getPrimaryIP_sysinfo_network_iface_ipv4_gateway_ipv6_address(void ** state) {
    sysinfo_network_ptr = __wrap_sysinfo_networks;
    sysinfo_free_result_ptr = __wrap_sysinfo_free_result;
    cJSON * networks = cJSON_Parse("{\"iface\":[{\"name\":\"eth0\",\"gateway\":\"192.168.1.1\",\"IPv6\":[{\"address\":"
                                   "\"fe80::a00:27ff:fee0:d046\"}]}]}");

    will_return(__wrap_sysinfo_networks, networks);
    will_return(__wrap_sysinfo_networks, 0);
    will_return(__wrap_sysinfo_free_result, networks);

    char * ip = getPrimaryIP();

    assert_string_equal(ip, "FE80:0000:0000:0000:0A00:27FF:FEE0:D046");

    os_free(ip);
    cJSON_Delete(networks);
}

static void test_wm_control_getPrimaryIP_sysinfo_network_iface_ipv4_gateway_ipv4_address(void ** state) {
    sysinfo_network_ptr = __wrap_sysinfo_networks;
    sysinfo_free_result_ptr = __wrap_sysinfo_free_result;
    cJSON * networks = cJSON_Parse(
        "{\"iface\":[{\"name\":\"eth0\",\"gateway\":\"192.168.1.1\",\"IPv4\":[{\"address\":\"192.168.1.10\"}]}]}");

    will_return(__wrap_sysinfo_networks, networks);
    will_return(__wrap_sysinfo_networks, 0);
    will_return(__wrap_sysinfo_free_result, networks);

    char * ip = getPrimaryIP();

    assert_string_equal(ip, "192.168.1.10");

    os_free(ip);
    cJSON_Delete(networks);
}

static void test_wm_control_getPrimaryIP_sysinfo_network_iface_valid_gateway_no_address_array(void ** state) {
    sysinfo_network_ptr = __wrap_sysinfo_networks;
    sysinfo_free_result_ptr = __wrap_sysinfo_free_result;
    cJSON * networks = cJSON_Parse("{\"iface\":[{\"name\":\"eth0\",\"gateway\":\"192.168.1.1\"}]}");

    will_return(__wrap_sysinfo_networks, networks);
    will_return(__wrap_sysinfo_networks, 0);
    will_return(__wrap_sysinfo_free_result, networks);

    char * ip = getPrimaryIP();

    assert_null(ip);

    cJSON_Delete(networks);
}

static void test_wm_control_getPrimaryIP_sysinfo_network_iface_valid_gateway_address_invalid_type(void ** state) {
    sysinfo_network_ptr = __wrap_sysinfo_networks;
    sysinfo_free_result_ptr = __wrap_sysinfo_free_result;
    cJSON * networks =
        cJSON_Parse("{\"iface\":[{\"name\":\"eth0\",\"gateway\":\"192.168.1.1\",\"IPv4\":[{\"address\":1234}]}]}");

    will_return(__wrap_sysinfo_networks, networks);
    will_return(__wrap_sysinfo_networks, 0);
    will_return(__wrap_sysinfo_free_result, networks);

    char * ip = getPrimaryIP();

    assert_null(ip);

    cJSON_Delete(networks);
}

static void test_wm_control_getPrimaryIP_sysinfo_network_iface_valid_gateway_multiple_address_array(void ** state) {
    sysinfo_network_ptr = __wrap_sysinfo_networks;
    sysinfo_free_result_ptr = __wrap_sysinfo_free_result;
    cJSON * networks = cJSON_Parse("{\"iface\":[{\"name\":\"eth0\",\"gateway\":\"192.168.1.1\",\"IPv4\":[{\"address\":"
                                   "\"192.168.1.10\"},{\"address\":\"192.168.1.11\"}]}]}");

    will_return(__wrap_sysinfo_networks, networks);
    will_return(__wrap_sysinfo_networks, 0);
    will_return(__wrap_sysinfo_free_result, networks);

    char * ip = getPrimaryIP();

    assert_string_equal(ip, "192.168.1.10");

    os_free(ip);
    cJSON_Delete(networks);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_wm_control_getPrimaryIP_no_sysinfo_network),
        cmocka_unit_test(test_wm_control_getPrimaryIP_no_sysinfo_free),
        cmocka_unit_test(test_wm_control_getPrimaryIP_sysinfo_network_return_error),
        cmocka_unit_test(test_wm_control_getPrimaryIP_sysinfo_network_no_object),
        cmocka_unit_test(test_wm_control_getPrimaryIP_sysinfo_network_no_iface),
        cmocka_unit_test(test_wm_control_getPrimaryIP_sysinfo_network_no_iface_array),
        cmocka_unit_test(test_wm_control_getPrimaryIP_sysinfo_network_iface_empty_array),
        cmocka_unit_test(test_wm_control_getPrimaryIP_sysinfo_network_iface_no_gateway),
        cmocka_unit_test(test_wm_control_getPrimaryIP_sysinfo_network_iface_invalid_gateway_type),
        cmocka_unit_test(test_wm_control_getPrimaryIP_sysinfo_network_iface_empty_gateway),
        cmocka_unit_test(test_wm_control_getPrimaryIP_sysinfo_network_iface_ipv6_gateway_ipv6_address),
        cmocka_unit_test(test_wm_control_getPrimaryIP_sysinfo_network_iface_ipv6_gateway_ipv4_address),
        cmocka_unit_test(test_wm_control_getPrimaryIP_sysinfo_network_iface_ipv4_gateway_ipv6_address),
        cmocka_unit_test(test_wm_control_getPrimaryIP_sysinfo_network_iface_ipv4_gateway_ipv4_address),
        cmocka_unit_test(test_wm_control_getPrimaryIP_sysinfo_network_iface_valid_gateway_no_address_array),
        cmocka_unit_test(test_wm_control_getPrimaryIP_sysinfo_network_iface_valid_gateway_address_invalid_type),
        cmocka_unit_test(test_wm_control_getPrimaryIP_sysinfo_network_iface_valid_gateway_multiple_address_array)};
    return cmocka_run_group_tests(tests, NULL, NULL);
}
