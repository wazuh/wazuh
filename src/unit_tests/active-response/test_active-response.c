/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <setjmp.h>
#include <stdio.h>
#include <cmocka.h>
#include <stdlib.h>
#include <string.h>

#include "shared.h"
#include "active_responses.h"

#include "../wrappers/common.h"

// Structs
typedef struct test_struct {
    struct addrinfo *addr;
} test_struct_t;

// Setup / Teardown

static int test_setup(void **state) {
    test_struct_t *init_data = NULL;

    os_calloc(1,sizeof(test_struct_t),init_data);
    os_calloc(1, sizeof(struct addrinfo), init_data->addr);
    os_calloc(1, sizeof(struct sockaddr), init_data->addr->ai_addr);

    *state = init_data;

    test_mode = 1;

    return OS_SUCCESS;
}

static int test_teardown(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    os_free(data->addr->ai_addr);
    os_free(data->addr);
    os_free(data);

    test_mode = 0;

    return OS_SUCCESS;
}

// Tests
void test_get_ip_version_success_ipv4(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    char *dummy_ipaddr = "";

    data->addr->ai_family = AF_INET;

    expect_string(__wrap_getaddrinfo, node, dummy_ipaddr);
    will_return(__wrap_getaddrinfo, data->addr);
    will_return(__wrap_getaddrinfo, 0);     //0 means success

    int ret = get_ip_version(dummy_ipaddr);

    assert_int_equal(ret, 4);
}

void test_get_ip_version_success_ipv6(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    char *dummy_ipaddr = "";

    data->addr->ai_family = AF_INET6;

    expect_string(__wrap_getaddrinfo, node, dummy_ipaddr);
    will_return(__wrap_getaddrinfo, data->addr);
    will_return(__wrap_getaddrinfo, 0);     //0 means success

    int ret = get_ip_version(dummy_ipaddr);

    assert_int_equal(ret, 6);
}

void test_get_ip_version_no_success(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    char *dummy_ipaddr = "";

    data->addr->ai_family = AF_INET6;

    expect_string(__wrap_getaddrinfo, node, dummy_ipaddr);
    will_return(__wrap_getaddrinfo, data->addr);
    will_return(__wrap_getaddrinfo, 1);

    int ret = get_ip_version(dummy_ipaddr);

    assert_int_equal(ret, -1);    //OS_INVALID
}

void test_get_ip_version_success_invalid_ip(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    char *dummy_ipaddr = "";

    data->addr->ai_family = -1;         //invalid family

    expect_string(__wrap_getaddrinfo, node, dummy_ipaddr);
    will_return(__wrap_getaddrinfo, data->addr);
    will_return(__wrap_getaddrinfo, 0);     //0 means success

    int ret = get_ip_version(dummy_ipaddr);

    assert_int_equal(ret, -1);    //OS_INVALID
}

// validate_srcip: strict numeric-IP whitelist

void test_validate_srcip_ipv4(void **state) {
    (void)state;
    assert_int_equal(validate_srcip("192.168.1.100"), 4);
    assert_int_equal(validate_srcip("10.0.0.1"), 4);
}

void test_validate_srcip_ipv6(void **state) {
    (void)state;
    assert_int_equal(validate_srcip("2001:db8::1"), 6);
    assert_int_equal(validate_srcip("::1"), 6);
    assert_int_equal(validate_srcip("fe80::a1b2:c3d4"), 6);
}

void test_validate_srcip_ipv4_mapped_ipv6(void **state) {
    (void)state;
    // IPv4-mapped IPv6 contains both ':' and '.', classified as IPv6
    assert_int_equal(validate_srcip("::ffff:1.2.3.4"), 6);
}

void test_validate_srcip_null_and_empty(void **state) {
    (void)state;
    assert_int_equal(validate_srcip(NULL), OS_INVALID);
    assert_int_equal(validate_srcip(""), OS_INVALID);
    assert_int_equal(validate_srcip("a"), OS_INVALID);    // shorter than minimum length
}

void test_validate_srcip_rejects_cidr(void **state) {
    (void)state;
    // A '/' would let a CIDR prefix (or extra path) reach the command line
    assert_int_equal(validate_srcip("192.168.1.100/32"), OS_INVALID);
    assert_int_equal(validate_srcip("2001:db8::1/128"), OS_INVALID);
}

void test_validate_srcip_rejects_argument_injection(void **state) {
    (void)state;
    // wpopenv does not quote arguments on Windows; whitespace/metacharacters must be rejected
    // so a crafted source.ip cannot inject extra tokens into the netsh/route command line.
    assert_int_equal(validate_srcip("1.2.3.4 action=allow"), OS_INVALID);
    assert_int_equal(validate_srcip("1.2.3.4 enable=no"), OS_INVALID);
    assert_int_equal(validate_srcip("::1 remoteip=any"), OS_INVALID);
    assert_int_equal(validate_srcip("1.2.3.4&calc"), OS_INVALID);
    assert_int_equal(validate_srcip("1.2.3.4;rm"), OS_INVALID);
    assert_int_equal(validate_srcip("1.2.3.4\""), OS_INVALID);
}

void test_validate_srcip_rejects_hostname(void **state) {
    (void)state;
    assert_int_equal(validate_srcip("google.com"), OS_INVALID);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_get_ip_version_success_ipv4, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_get_ip_version_success_ipv6, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_get_ip_version_no_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_get_ip_version_success_invalid_ip, test_setup, test_teardown),
        cmocka_unit_test(test_validate_srcip_ipv4),
        cmocka_unit_test(test_validate_srcip_ipv6),
        cmocka_unit_test(test_validate_srcip_ipv4_mapped_ipv6),
        cmocka_unit_test(test_validate_srcip_null_and_empty),
        cmocka_unit_test(test_validate_srcip_rejects_cidr),
        cmocka_unit_test(test_validate_srcip_rejects_argument_injection),
        cmocka_unit_test(test_validate_srcip_rejects_hostname),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
