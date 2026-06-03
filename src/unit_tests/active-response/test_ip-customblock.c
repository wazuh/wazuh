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

#include "../../headers/shared.h"
#include "../../active-response/active_responses.h"

#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/file_op_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

// Structs
typedef struct test_struct {
    struct addrinfo *addr;
} test_struct_t;

// Setup / Teardown

static int test_setup(void **state) {
    test_struct_t *init_data = NULL;

    os_calloc(1, sizeof(test_struct_t), init_data);
    os_calloc(1, sizeof(struct addrinfo), init_data->addr);
    os_calloc(1, sizeof(struct sockaddr), init_data->addr->ai_addr);

    *state = init_data;

    test_mode = 1;

    return OS_SUCCESS;
}

static int test_teardown(void **state) {
    test_struct_t *data = (test_struct_t *)*state;

    os_free(data->addr->ai_addr);
    os_free(data->addr);
    os_free(data);

    test_mode = 0;

    return OS_SUCCESS;
}

// Tests

void test_ip_customblock_valid_ipv4(void **state) {
    test_struct_t *data = (test_struct_t *)*state;
    char *valid_ipv4 = "192.168.1.100";

    data->addr->ai_family = AF_INET;

    expect_string(__wrap_getaddrinfo, node, valid_ipv4);
    will_return(__wrap_getaddrinfo, data->addr);
    will_return(__wrap_getaddrinfo, 0);

    int ret = get_ip_version(valid_ipv4);

    assert_int_equal(ret, 4);
}

void test_ip_customblock_valid_ipv6(void **state) {
    test_struct_t *data = (test_struct_t *)*state;
    char *valid_ipv6 = "2001:0db8::1";

    data->addr->ai_family = AF_INET6;

    expect_string(__wrap_getaddrinfo, node, valid_ipv6);
    will_return(__wrap_getaddrinfo, data->addr);
    will_return(__wrap_getaddrinfo, 0);

    int ret = get_ip_version(valid_ipv6);

    assert_int_equal(ret, 6);
}

void test_ip_customblock_invalid_ip_with_path_traversal(void **state) {
    test_struct_t *data = (test_struct_t *)*state;
    char *malicious_ip = "../../tmp/malicious";

    expect_string(__wrap_getaddrinfo, node, malicious_ip);
    will_return(__wrap_getaddrinfo, data->addr);
    will_return(__wrap_getaddrinfo, 1);

    int ret = get_ip_version(malicious_ip);

    assert_int_equal(ret, OS_INVALID);
}

void test_ip_customblock_invalid_ip_with_special_chars(void **state) {
    test_struct_t *data = (test_struct_t *)*state;
    char *malicious_ip = "192.168.1.1; rm -rf /";

    expect_string(__wrap_getaddrinfo, node, malicious_ip);
    will_return(__wrap_getaddrinfo, data->addr);
    will_return(__wrap_getaddrinfo, 1);

    int ret = get_ip_version(malicious_ip);

    assert_int_equal(ret, OS_INVALID);
}

void test_ip_customblock_invalid_ip_empty_string(void **state) {
    test_struct_t *data = (test_struct_t *)*state;
    char *empty_ip = "";

    expect_string(__wrap_getaddrinfo, node, empty_ip);
    will_return(__wrap_getaddrinfo, data->addr);
    will_return(__wrap_getaddrinfo, 1);

    int ret = get_ip_version(empty_ip);

    assert_int_equal(ret, OS_INVALID);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_ip_customblock_valid_ipv4, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_ip_customblock_valid_ipv6, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_ip_customblock_invalid_ip_with_path_traversal, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_ip_customblock_invalid_ip_with_special_chars, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_ip_customblock_invalid_ip_empty_string, test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
