/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../../headers/shared.h"
#include "../../headers/validate_op.h"
#include "../wrappers/wazuh/shared/expression_wrappers.h"
#include "../wrappers/wazuh/os_net/os_net_wrappers.h"
#include "../../shared/validate_op.c"

/* tests */

#define TEST_MOCKED

void w_validate_bytes_non_number (void **state)
{
    const char * value = "hello";
    long long expected_value = -1;

    long long ret = w_validate_bytes(value);
    assert_memory_equal(&ret, &expected_value, sizeof(long long));
}

void w_validate_bytes_bytes (void **state)
{
    const char * value = "1024B";
    long long expected_value = 1024;

    long long ret = w_validate_bytes(value);
    assert_memory_equal(&ret, &expected_value, sizeof(long long));
}

void w_validate_bytes_kilobytes (void **state)
{
    const char * value = "1024KB";
    long long expected_value = 1024*1024;

    long long ret = w_validate_bytes(value);
    assert_memory_equal(&ret, &expected_value, sizeof(long long));
}

void w_validate_bytes_megabytes (void **state)
{
    const char * value = "1024MB";
    long long expected_value = 1024*1024*1024;

    long long ret = w_validate_bytes(value);
    assert_memory_equal(&ret, &expected_value, sizeof(long long));
}

void w_validate_bytes_gigabytes (void **state)
{
    const char * value = "1024GB";
    long long expected_value = 1024 * ((long long) 1024*1024*1024);

    long long ret = w_validate_bytes(value);
    assert_memory_equal(&ret, &expected_value, sizeof(long long));
}

void OS_IsValidIP_null(void **state)
{
    int ret = OS_IsValidIP(NULL, NULL);
    assert_int_equal(ret, 0);
}

void OS_IsValidIP_any(void **state)
{
    int ret = OS_IsValidIP("any", NULL);
    assert_int_equal(ret, 2);
}

void OS_IsValidIP_any_struct(void **state)
{
    int ret = 0;
    os_ip *ret_ip;

    os_calloc(1, sizeof(os_ip), ret_ip);

    expect_value(__wrap_w_calloc_expression_t, type, EXP_TYPE_PCRE2);
    will_return(__wrap_w_expression_compile, true);
    will_return(__wrap_w_expression_match, true);

    ret = OS_IsValidIP("any", ret_ip);
    assert_int_equal(ret, 2);
    assert_int_equal(ret_ip->is_ipv6, FALSE);

    w_free_os_ip(ret_ip);
}

void OS_IsValidIP_not_valid_ip(void **state)
{
    unsigned int i = 0;
    while (ip_address_regex[i] != NULL) {
        expect_value(__wrap_w_calloc_expression_t, type, EXP_TYPE_PCRE2);
        will_return(__wrap_w_expression_compile, true);
        will_return(__wrap_w_expression_match, false);
        i++;
    }

    int ret = OS_IsValidIP("12.0", NULL);
    assert_int_equal(ret, 0);
}

void OS_IsValidIP_valid_multi_ipv4(void **state)
{
    const char * ip_to_test[] = {
        "1.1.1.1",
        "255.255.255.255",
        "100.100.100.100",
        "10.10.10.10",
        "111.111.111.111",
        "222.222.222.222",
        "127.0.0.1",
        NULL,
    };

    int ret = 0;
    os_ip *ret_ip;

    for (int i = 0; ip_to_test[i] != NULL; i++) {

        os_calloc(1, sizeof(os_ip), ret_ip);

        expect_value(__wrap_w_calloc_expression_t, type, EXP_TYPE_PCRE2);
        will_return(__wrap_w_expression_compile, true);
        will_return(__wrap_w_expression_match, true);

        expect_value(__wrap_w_calloc_expression_t, type, EXP_TYPE_PCRE2);
        will_return(__wrap_w_expression_compile, true);
        will_return(__wrap_w_expression_match, -1);
        will_return(__wrap_w_expression_match, ip_to_test);

        will_return(__wrap_get_ipv4_numeric, OS_SUCCESS);

        ret = OS_IsValidIP(ip_to_test[i], ret_ip);
        assert_string_equal(ip_to_test[i], ret_ip->ip);
        assert_int_equal(ret, 1);
        assert_int_equal(ret_ip->is_ipv6, FALSE);

        w_free_os_ip(ret_ip);
    }
}

void OS_IsValidIP_not_valid_multi_ipv4(void **state)
{
    const char * ip_to_test[] = {
        // more or less than 4 octets
        "111",
        "01.01",
        "01.01.01",
        "10.10.10.10.10",
        "222.222.222.222.222",
        // octet limit exceeded (more than 255)
        "333.333.334.334",
        "256.1.01.001",
        "1.1.1.256",
        "327.0.0.1",
        "4000.00.0.1",
        // ip with index limit exceeded (more than 32)
        "10.10.10.10/",
        "10.10.10.10/33",
        "10.10.10.10/99",
        "10.10.10.10/123",
        "10.10.10.10/12345",
        // ip with extra 0
        "01.01.01.01",
        "001.001.001.001",
        "000.00.0.1",
        // ip with invalid netmask
        "1.1.1.10/36.255.255",
        "1.1.1.1/36.1.1.256",
        "1.1.1.300/36.1.1.255",
        NULL,
    };

    int ret = 0;
    os_ip *ret_ip;

    for (int i = 0; ip_to_test[i] != NULL; i++) {

        os_calloc(1, sizeof(os_ip), ret_ip);

        expect_value(__wrap_w_calloc_expression_t, type, EXP_TYPE_PCRE2);
        will_return(__wrap_w_expression_compile, true);
        will_return(__wrap_w_expression_match, true);

        unsigned int a = 0;
        while (ip_address_regex[a] != NULL) {
            expect_value(__wrap_w_calloc_expression_t, type, EXP_TYPE_PCRE2);
            will_return(__wrap_w_expression_compile, true);
            will_return(__wrap_w_expression_match, false);
            a++;
        }

        ret = OS_IsValidIP(ip_to_test[i], ret_ip);
        assert_string_equal(ip_to_test[i], ret_ip->ip);
        assert_int_equal(ret, 0);

        w_free_os_ip(ret_ip);
    }
}

void OS_IsValidIP_valid_ipv4_CIDR(void **state)
{
    char ip_to_test[] = {"192.168.10.12/32"};

    os_ip *ret_ip;
    os_calloc(1, sizeof(os_ip), ret_ip);

    expect_value(__wrap_w_calloc_expression_t, type, EXP_TYPE_PCRE2);
    will_return(__wrap_w_expression_compile, true);
    will_return(__wrap_w_expression_match, true);

    expect_value(__wrap_w_calloc_expression_t, type, EXP_TYPE_PCRE2);
    will_return(__wrap_w_expression_compile, true);
    will_return(__wrap_w_expression_match, -2);
    will_return(__wrap_w_expression_match, "192.168.10.12");
    will_return(__wrap_w_expression_match, "32");

    will_return(__wrap_get_ipv4_numeric, OS_SUCCESS);

    int ret = OS_IsValidIP(ip_to_test, ret_ip);
    assert_string_equal(ip_to_test, ret_ip->ip);
    assert_int_equal(ret, 2);
    assert_int_equal(ret_ip->is_ipv6, FALSE);

    w_free_os_ip(ret_ip);
}

void OS_IsValidIP_valid_ipv4_fail(void **state)
{
    char ip_to_test[] = {"192.168.10.12/32"};

    os_ip *ret_ip;
    os_calloc(1, sizeof(os_ip), ret_ip);

    expect_value(__wrap_w_calloc_expression_t, type, EXP_TYPE_PCRE2);
    will_return(__wrap_w_expression_compile, true);
    will_return(__wrap_w_expression_match, true);

    expect_value(__wrap_w_calloc_expression_t, type, EXP_TYPE_PCRE2);
    will_return(__wrap_w_expression_compile, true);
    will_return(__wrap_w_expression_match, -2);
    will_return(__wrap_w_expression_match, "192.168.10.12");
    will_return(__wrap_w_expression_match, "32");

    will_return(__wrap_get_ipv4_numeric, OS_INVALID);

    int ret = OS_IsValidIP(ip_to_test, ret_ip);
    assert_int_equal(ret, 0);

    w_free_os_ip(ret_ip);
}

void OS_IsValidIP_valid_ipv4_zero_fail(void **state)
{
    char ip_to_test[] = {"0.0.0.0/32"};

    os_ip *ret_ip;
    os_calloc(1, sizeof(os_ip), ret_ip);

    expect_value(__wrap_w_calloc_expression_t, type, EXP_TYPE_PCRE2);
    will_return(__wrap_w_expression_compile, true);
    will_return(__wrap_w_expression_match, true);

    expect_value(__wrap_w_calloc_expression_t, type, EXP_TYPE_PCRE2);
    will_return(__wrap_w_expression_compile, true);
    will_return(__wrap_w_expression_match, -2);
    will_return(__wrap_w_expression_match, "0.0.0");
    will_return(__wrap_w_expression_match, "32");

    will_return(__wrap_get_ipv4_numeric, OS_INVALID);

    int ret = OS_IsValidIP(ip_to_test, ret_ip);
    assert_int_equal(ret, 0);

    w_free_os_ip(ret_ip);
}

void OS_IsValidIP_valid_ipv4_zero_pass(void **state)
{
    char ip_to_test[] = {"0.0.0.0/32"};

    os_ip *ret_ip;
    os_calloc(1, sizeof(os_ip), ret_ip);

    expect_value(__wrap_w_calloc_expression_t, type, EXP_TYPE_PCRE2);
    will_return(__wrap_w_expression_compile, true);
    will_return(__wrap_w_expression_match, true);

    expect_value(__wrap_w_calloc_expression_t, type, EXP_TYPE_PCRE2);
    will_return(__wrap_w_expression_compile, true);
    will_return(__wrap_w_expression_match, -2);
    will_return(__wrap_w_expression_match, "0.0.0.0");
    will_return(__wrap_w_expression_match, "32");

    will_return(__wrap_get_ipv4_numeric, OS_INVALID);

    int ret = OS_IsValidIP(ip_to_test, ret_ip);
    assert_int_equal(ret, 2);

    w_free_os_ip(ret_ip);
}

void OS_IsValidIP_valid_ipv4_netmask(void **state)
{
    char ip_to_test[] = {"32.32.32.32/255.255.255.255"};

    os_ip *ret_ip;
    os_calloc(1, sizeof(os_ip), ret_ip);

    expect_value(__wrap_w_calloc_expression_t, type, EXP_TYPE_PCRE2);
    will_return(__wrap_w_expression_compile, true);
    will_return(__wrap_w_expression_match, true);

    expect_value(__wrap_w_calloc_expression_t, type, EXP_TYPE_PCRE2);
    will_return(__wrap_w_expression_compile, true);
    will_return(__wrap_w_expression_match, -2);
    will_return(__wrap_w_expression_match, "32.32.32.32");
    will_return(__wrap_w_expression_match, "255.255.255.255");

    will_return(__wrap_get_ipv4_numeric, OS_SUCCESS);
    will_return(__wrap_get_ipv4_numeric, OS_SUCCESS);


    int ret = OS_IsValidIP(ip_to_test, ret_ip);
    assert_string_equal(ip_to_test, ret_ip->ip);
    assert_int_equal(ret, 2);
    assert_int_equal(ret_ip->is_ipv6, FALSE);

    w_free_os_ip(ret_ip);
}

void OS_IsValidIP_valid_ipv4_0_netmask(void **state)
{
    char ip_to_test[] = {"0.0.0.0/255.255.255.255"};

    os_ip *ret_ip;
    os_calloc(1, sizeof(os_ip), ret_ip);

    expect_value(__wrap_w_calloc_expression_t, type, EXP_TYPE_PCRE2);
    will_return(__wrap_w_expression_compile, true);
    will_return(__wrap_w_expression_match, true);

    expect_value(__wrap_w_calloc_expression_t, type, EXP_TYPE_PCRE2);
    will_return(__wrap_w_expression_compile, true);
    will_return(__wrap_w_expression_match, -2);
    will_return(__wrap_w_expression_match, "0.0.0.0");
    will_return(__wrap_w_expression_match, "255.255.255.255");

    will_return(__wrap_get_ipv4_numeric, OS_SUCCESS);
    will_return(__wrap_get_ipv4_numeric, OS_SUCCESS);

    int ret = OS_IsValidIP(ip_to_test, ret_ip);
    assert_string_equal(ip_to_test, ret_ip->ip);
    assert_int_equal(ret, 2);
    assert_int_equal(ret_ip->is_ipv6, FALSE);

    w_free_os_ip(ret_ip);
}

void OS_IsValidIP_valid_ipv4_netmask_0(void **state)
{
    char ip_to_test[] = {"16.16.16.16/255.255.255.0"};

    os_ip *ret_ip;
    os_calloc(1, sizeof(os_ip), ret_ip);

    expect_value(__wrap_w_calloc_expression_t, type, EXP_TYPE_PCRE2);
    will_return(__wrap_w_expression_compile, true);
    will_return(__wrap_w_expression_match, true);

    expect_value(__wrap_w_calloc_expression_t, type, EXP_TYPE_PCRE2);
    will_return(__wrap_w_expression_compile, true);
    will_return(__wrap_w_expression_match, -2);
    will_return(__wrap_w_expression_match, "16.16.16.16");
    will_return(__wrap_w_expression_match, "255.255.255.0");

    will_return(__wrap_get_ipv4_numeric, OS_SUCCESS);
    will_return(__wrap_get_ipv4_numeric, OS_SUCCESS);

    int ret = OS_IsValidIP(ip_to_test, ret_ip);
    assert_string_equal(ip_to_test, ret_ip->ip);
    assert_int_equal(ret, 2);
    assert_int_equal(ret_ip->is_ipv6, FALSE);

    w_free_os_ip(ret_ip);
}

void OS_IsValidIP_valid_ipv4_netmask_fail(void **state)
{
    char ip_to_test[] = {"32.32.32.32/255.255.255.255"};

    os_ip *ret_ip;
    os_calloc(1, sizeof(os_ip), ret_ip);

    expect_value(__wrap_w_calloc_expression_t, type, EXP_TYPE_PCRE2);
    will_return(__wrap_w_expression_compile, true);
    will_return(__wrap_w_expression_match, true);

    expect_value(__wrap_w_calloc_expression_t, type, EXP_TYPE_PCRE2);
    will_return(__wrap_w_expression_compile, true);
    will_return(__wrap_w_expression_match, -2);
    will_return(__wrap_w_expression_match, "32.32.32.32");
    will_return(__wrap_w_expression_match, "255.255.255.255");

    will_return(__wrap_get_ipv4_numeric, OS_SUCCESS);
    will_return(__wrap_get_ipv4_numeric, OS_INVALID);


    int ret = OS_IsValidIP(ip_to_test, ret_ip);
    assert_int_equal(ret, 0);

    w_free_os_ip(ret_ip);
}

void OS_IsValidIP_valid_ipv4_sub_string_0(void **state)
{
    char ip_to_test[] = {"32.32.32.32/255.255.255.255"};

    os_ip *ret_ip;
    os_calloc(1, sizeof(os_ip), ret_ip);

    expect_value(__wrap_w_calloc_expression_t, type, EXP_TYPE_PCRE2);
    will_return(__wrap_w_expression_compile, true);
    will_return(__wrap_w_expression_match, true);

    expect_value(__wrap_w_calloc_expression_t, type, EXP_TYPE_PCRE2);
    will_return(__wrap_w_expression_compile, true);
    will_return(__wrap_w_expression_match, -2);
    will_return(__wrap_w_expression_match, "32.32.32.32");
    will_return(__wrap_w_expression_match, "255.255.255.255");

    will_return(__wrap_get_ipv4_numeric, 1);
    will_return(__wrap_get_ipv4_numeric, 0xFFFFFFFF);

    will_return(__wrap_get_ipv4_numeric, 1);
    will_return(__wrap_get_ipv4_numeric, 0xFFFFFFFF);

    int ret = OS_IsValidIP(ip_to_test, ret_ip);
    assert_int_equal(ret, 2);

    w_free_os_ip(ret_ip);
}

void OS_IsValidIP_valid_ipv4_netmask_0_NULL_struct(void **state)
{
    char ip_to_test[] = {"16.16.16.16/255.255.255.0"};

    expect_value(__wrap_w_calloc_expression_t, type, EXP_TYPE_PCRE2);
    will_return(__wrap_w_expression_compile, true);
    will_return(__wrap_w_expression_match, -2);
    will_return(__wrap_w_expression_match, "16.16.16.16");
    will_return(__wrap_w_expression_match, "255.255.255.0");

    int ret = OS_IsValidIP(ip_to_test, NULL);
    assert_int_equal(ret, 2);
}

void OS_IsValidIP_valid_multi_ipv6(void **state)
{
    const char * ip_to_test[] = {
        "2001:db8:abcd:0012:0000:0000:0000:0000",
        "2001:db8:abcd:0012:ffff:ffff:ffff:ffff",
        "fe80::ceaf:9ff2:b33c:1ca7",
        "11AA:11AA:11AA:11AA:11AA:11AA:11AA:11AA",
        "11AA::11AA:11AA:11AA:11AA:11AA:11AA",
        "11AA::11AA:11AA:11AA:11AA:11AA",
        "11AA::11AA:11AA:11AA:11AA",
        "11AA::11AA:11AA:11AA",
        "11AA::11AA:11AA",
        "11AA::11AA",
        "11AA:11AA:11AA:11AA:11AA:11AA::11AA",
        "11AA:11AA:11AA:11AA:11AA::11AA",
        "11AA:11AA:11AA:11AA::11AA",
        "11AA:11AA:11AA::11AA",
        "11AA:11AA::11AA",
        "11AA::11AA",
        "11AA::11AA:11AA:11AA:11AA:11AA:11AA",
        "11AA:11AA::11AA:11AA:11AA:11AA:11AA",
        "11AA:11AA:11AA::11AA:11AA:11AA:11AA",
        "11AA:11AA:11AA:11AA::11AA:11AA:11AA",
        "11AA:11AA:11AA:11AA:11AA::11AA:11AA",
        "11AA:11AA:11AA:11AA:11AA:11AA::11AA",
        "11AA:11AA:11AA:11AA:11AA:11AA:11AA::",
        "11AA:11AA:11AA:11AA:11AA:11AA::",
        "11AA:11AA:11AA:11AA:11AA::",
        "11AA:11AA:11AA:11AA::",
        "11AA:11AA:11AA::",
        "11AA:11AA::",
        "11AA::",
        "::11AA:11AA:11AA:11AA:11AA:11AA:11AA",
        "::11AA:11AA:11AA:11AA:11AA:11AA",
        "::11AA:11AA:11AA:11AA:11AA",
        "::11AA:11AA:11AA:11AA",
        "::11AA:11AA:11AA",
        "::11AA:11AA",
        "::11AA",
        "::",
        "::ffff:10.2.3.1",
        NULL,
    };

    int ret = 0;
    os_ip *ret_ip;

    for (int i = 0; ip_to_test[i] != NULL; i++) {

        os_calloc(1, sizeof(os_ip), ret_ip);

        expect_value(__wrap_w_calloc_expression_t, type, EXP_TYPE_PCRE2);
        will_return(__wrap_w_expression_compile, true);
        will_return(__wrap_w_expression_match, true);

        /* First call to __wrap_w_expression_match fail */
        expect_value(__wrap_w_calloc_expression_t, type, EXP_TYPE_PCRE2);
        will_return(__wrap_w_expression_compile, true);
        will_return(__wrap_w_expression_match, false);

        /* Second call to __wrap_w_expression_match pass */
        expect_value(__wrap_w_calloc_expression_t, type, EXP_TYPE_PCRE2);
        will_return(__wrap_w_expression_compile, true);
        will_return(__wrap_w_expression_match, -1);
        will_return(__wrap_w_expression_match, ip_to_test);

        will_return(__wrap_get_ipv6_numeric, OS_SUCCESS);
        will_return(__wrap_get_ipv6_numeric, OS_SUCCESS);

        ret = OS_IsValidIP(ip_to_test[i], ret_ip);
        //assert_string_equal(ip_to_test[i], ret_ip->ip);
        assert_int_equal(ret, 1);
        assert_int_equal(ret_ip->is_ipv6, TRUE);
        assert_non_null(ret_ip->ipv6->ip_address);

        w_free_os_ip(ret_ip);
    }
}

void OS_IsValidIP_not_valid_multi_ipv6(void **state)
{

    const char * ip_to_test[] = {
        "::11AA:11AA:11AA:11AA:11AA::11AA",
        "::11AA:11AA:11AA:11AA:11AA:11AA:",
        "::11AA:11AA::11AA:11AA:11AA:",
        "::11AA:11AA:11AA:11AA:::",
        "::11AA::11AA:11AA::11AA:11AA:11AA::11AA",
        "11AA:11AA:11AA:11AA:11AA:11AA:11AA:11AA:11AA",
        "GGAA:11AA:11AA:11AA:11AA:11AA:11AA:11AA",
        NULL,
    };

    int ret = 0;
    os_ip *ret_ip;

    for (int i = 0; ip_to_test[i] != NULL; i++) {

        os_calloc(1, sizeof(os_ip), ret_ip);

        expect_value(__wrap_w_calloc_expression_t, type, EXP_TYPE_PCRE2);
        will_return(__wrap_w_expression_compile, true);
        will_return(__wrap_w_expression_match, true);

        int a = 0;
        while (ip_address_regex[a] != NULL) {
            expect_value(__wrap_w_calloc_expression_t, type, EXP_TYPE_PCRE2);
            will_return(__wrap_w_expression_compile, true);
            will_return(__wrap_w_expression_match, false);
            a++;
        }

        ret = OS_IsValidIP(ip_to_test[i], ret_ip);
        assert_string_equal(ip_to_test[i], ret_ip->ip);
        assert_int_equal(ret, 0);

        w_free_os_ip(ret_ip);
    }
}

void OS_IsValidIP_valid_ipv6_prefix(void **state)
{
    char ip_to_test[] = {"2001:db8:abcd:0012:0000:0000:0000:0000/60"};

    int ret = 0;
    os_ip *ret_ip;
    os_calloc(1, sizeof(os_ip), ret_ip);

    expect_value(__wrap_w_calloc_expression_t, type, EXP_TYPE_PCRE2);
    will_return(__wrap_w_expression_compile, true);
    will_return(__wrap_w_expression_match, true);

    /* First call to __wrap_w_expression_match fail */
    expect_value(__wrap_w_calloc_expression_t, type, EXP_TYPE_PCRE2);
    will_return(__wrap_w_expression_compile, true);
    will_return(__wrap_w_expression_match, false);

    /* Second call to __wrap_w_expression_match pass */
    expect_value(__wrap_w_calloc_expression_t, type, EXP_TYPE_PCRE2);
    will_return(__wrap_w_expression_compile, true);
    will_return(__wrap_w_expression_match, -2);
    will_return(__wrap_w_expression_match, "2001:db8:abcd:0012:0000:0000:0000:0000");
    will_return(__wrap_w_expression_match, "60");

    will_return(__wrap_get_ipv6_numeric, OS_SUCCESS);
    will_return(__wrap_get_ipv6_numeric, OS_SUCCESS);

    ret = OS_IsValidIP(ip_to_test, ret_ip);
    //assert_string_equal(ip_to_test, ret_ip->ip);
    assert_int_equal(ret, 2);
    assert_int_equal(ret_ip->is_ipv6, TRUE);

    w_free_os_ip(ret_ip);
}

void OS_IsValidIP_valid_ipv6_prefix_NULL_struct(void **state)
{
    char ip_to_test[] = {"2001:db8:abcd:0012:0000:0000:0000:0000/64"};

    /* First call to __wrap_w_expression_match fail */
    expect_value(__wrap_w_calloc_expression_t, type, EXP_TYPE_PCRE2);
    will_return(__wrap_w_expression_compile, true);
    will_return(__wrap_w_expression_match, false);

    /* Second call to __wrap_w_expression_match pass */
    expect_value(__wrap_w_calloc_expression_t, type, EXP_TYPE_PCRE2);
    will_return(__wrap_w_expression_compile, true);
    will_return(__wrap_w_expression_match, -2);
    will_return(__wrap_w_expression_match, "2001:db8:abcd:0012:0000:0000:0000:0000");
    will_return(__wrap_w_expression_match, "64");

    int ret = OS_IsValidIP(ip_to_test, NULL);
    assert_int_equal(ret, 2);
}

void OS_IsValidIP_valid_ipv6_numeric_fail(void **state)
{
    char ip_to_test[] = {"2001:db8:abcd:0012:0000:0000:0000:0000"};

    int ret = 0;
    os_ip *ret_ip;
    os_calloc(1, sizeof(os_ip), ret_ip);

    expect_value(__wrap_w_calloc_expression_t, type, EXP_TYPE_PCRE2);
    will_return(__wrap_w_expression_compile, true);
    will_return(__wrap_w_expression_match, true);

    /* First call to __wrap_w_expression_match fail */
    expect_value(__wrap_w_calloc_expression_t, type, EXP_TYPE_PCRE2);
    will_return(__wrap_w_expression_compile, true);
    will_return(__wrap_w_expression_match, false);

    /* Second call to __wrap_w_expression_match pass */
    expect_value(__wrap_w_calloc_expression_t, type, EXP_TYPE_PCRE2);
    will_return(__wrap_w_expression_compile, true);
    will_return(__wrap_w_expression_match, -1);
    will_return(__wrap_w_expression_match, "2001:db8:abcd:0012:0000:0000:0000:0000");

    will_return(__wrap_get_ipv6_numeric, OS_INVALID);

    ret = OS_IsValidIP(ip_to_test, ret_ip);
    assert_int_equal(ret, 0);

    w_free_os_ip(ret_ip);
}

void OS_IsValidIP_valid_ipv6_converNetmask_fail(void **state)
{
    char ip_to_test[] = {"2001:db8:abcd:0012:0000:0000:0000:0000/64"};

    int ret = 0;
    os_ip *ret_ip;
    os_calloc(1, sizeof(os_ip), ret_ip);

    expect_value(__wrap_w_calloc_expression_t, type, EXP_TYPE_PCRE2);
    will_return(__wrap_w_expression_compile, true);
    will_return(__wrap_w_expression_match, true);

    /* First call to __wrap_w_expression_match fail */
    expect_value(__wrap_w_calloc_expression_t, type, EXP_TYPE_PCRE2);
    will_return(__wrap_w_expression_compile, true);
    will_return(__wrap_w_expression_match, false);

    /* Second call to __wrap_w_expression_match pass */
    expect_value(__wrap_w_calloc_expression_t, type, EXP_TYPE_PCRE2);
    will_return(__wrap_w_expression_compile, true);
    will_return(__wrap_w_expression_match, -2);
    will_return(__wrap_w_expression_match, "2001:db8:abcd:0012:0000:0000:0000:0000");
    will_return(__wrap_w_expression_match, "644");

    will_return(__wrap_get_ipv6_numeric, OS_SUCCESS);

    ret = OS_IsValidIP(ip_to_test, ret_ip);
    assert_int_equal(ret, 0);

    w_free_os_ip(ret_ip);
}

void OS_IsValidIP_valid_ipv6_sub_string_0(void **state)
{
    char ip_to_test[] = {"2001:db8:abcd:0012:0000:0000:0000:0000/64"};

    int ret = 0;
    os_ip *ret_ip;
    os_calloc(1, sizeof(os_ip), ret_ip);

    expect_value(__wrap_w_calloc_expression_t, type, EXP_TYPE_PCRE2);
    will_return(__wrap_w_expression_compile, true);
    will_return(__wrap_w_expression_match, true);

    /* First call to __wrap_w_expression_match fail */
    expect_value(__wrap_w_calloc_expression_t, type, EXP_TYPE_PCRE2);
    will_return(__wrap_w_expression_compile, true);
    will_return(__wrap_w_expression_match, false);

    /* Second call to __wrap_w_expression_match pass */
    expect_value(__wrap_w_calloc_expression_t, type, EXP_TYPE_PCRE2);
    will_return(__wrap_w_expression_compile, true);
    will_return(__wrap_w_expression_match, -2);
    will_return(__wrap_w_expression_match, "2001:db8:abcd:0012:0000:0000:0000:0000");
    will_return(__wrap_w_expression_match, "64");

    will_return(__wrap_get_ipv6_numeric, 1);
    will_return(__wrap_get_ipv6_numeric, 0xFFFFFFFF);

    will_return(__wrap_get_ipv6_numeric, 1);
    will_return(__wrap_get_ipv6_numeric, 0xFFFFFFFF);

    ret = OS_IsValidIP(ip_to_test, ret_ip);
    assert_int_equal(ret, 2);

    w_free_os_ip(ret_ip);
}

void OS_IPFound_not_valid_ip(void **state)
{
    char ip_to_test[] = {"2001::db8:abcd::0012/64"};

    int ret = 0;
    os_ip *ret_ip;
    os_calloc(1, sizeof(os_ip), ret_ip);

    will_return(__wrap_get_ipv4_numeric, OS_INVALID);
    will_return(__wrap_get_ipv6_numeric, OS_INVALID);

    ret = OS_IPFound(ip_to_test, ret_ip);
    assert_int_equal(ret, 0);

    w_free_os_ip(ret_ip);
}

void OS_IPFound_valid_ipv4(void **state)
{
    char ip_to_test[] = {"255.255.255.255"};

    int ret = 0;
    os_ip *ret_ip;
    os_calloc(1, sizeof(os_ip), ret_ip);
    os_strdup("255.255.255.255", ret_ip->ip);
    os_calloc(1, sizeof(os_ipv4), ret_ip->ipv4);

    ret_ip->ipv4->ip_address = 0xFFFFFFFF;
    ret_ip->ipv4->netmask = 0xFFFFFFFF;

    will_return(__wrap_get_ipv4_numeric, 1);
    will_return(__wrap_get_ipv4_numeric, 0xFFFFFFFF);

    ret = OS_IPFound(ip_to_test, ret_ip);
    assert_int_equal(ret, 1);

    w_free_os_ip(ret_ip);
}

void OS_IPFound_valid_ipv4_negated(void **state)
{
    char ip_to_test[] = {"16.16.16.16"};

    int ret = 0;
    os_ip *ret_ip;
    os_calloc(1, sizeof(os_ip), ret_ip);
    os_strdup("!16.16.16.16", ret_ip->ip);
    os_calloc(1, sizeof(os_ipv4), ret_ip->ipv4);

    ret_ip->ipv4->ip_address = 0x10101010;
    ret_ip->ipv4->netmask = 0xFFFFFFFF;

    will_return(__wrap_get_ipv4_numeric, 1);
    will_return(__wrap_get_ipv4_numeric, 0x10101010);

    ret = OS_IPFound(ip_to_test, ret_ip);
    assert_int_equal(ret, 0);

    w_free_os_ip(ret_ip);
}

void OS_IPFound_valid_ipv6(void **state)
{
    char ip_to_test[] = {"1010:1010:1010:1010:1010:1010:1010:1010"};

    int ret = 0;
    os_ip *ret_ip;
    os_calloc(1, sizeof(os_ip), ret_ip);
    os_strdup("1010:1010:1010:1010:1010:1010:1010:1010", ret_ip->ip);
    os_calloc(1, sizeof(os_ipv6), ret_ip->ipv6);

    unsigned int a = 0;
    for(a = 0; a < 16; a++) {
        ret_ip->ipv6->ip_address[a] = 0x10;
    }
    for(a = 0; a < 16; a++) {
        ret_ip->ipv6->netmask[a] = 0xFF;
    }

    will_return(__wrap_get_ipv4_numeric, OS_INVALID);
    will_return(__wrap_get_ipv6_numeric, 1);
    will_return(__wrap_get_ipv6_numeric, 0x10);

    ret = OS_IPFound(ip_to_test, ret_ip);
    assert_int_equal(ret, 1);

    w_free_os_ip(ret_ip);
}

void OS_IPFound_valid_ipv6_fail(void **state)
{
    char ip_to_test[] = {"1010:1010:1010:1010:1010:1010:1010:1010"};

    int ret = 0;
    os_ip *ret_ip;
    os_calloc(1, sizeof(os_ip), ret_ip);
    os_strdup("1010:1010:1010:1010:1010:1010:1010:1010", ret_ip->ip);
    os_calloc(1, sizeof(os_ipv6), ret_ip->ipv6);

    unsigned int a = 0;
    for(a = 0; a < 16; a++) {
        ret_ip->ipv6->ip_address[a] = 0x10;
    }
    for(a = 0; a < 16; a++) {
        ret_ip->ipv6->netmask[a] = 0xFF;
    }

    will_return(__wrap_get_ipv4_numeric, OS_INVALID);
    will_return(__wrap_get_ipv6_numeric, 1);
    will_return(__wrap_get_ipv6_numeric, 0x00);

    ret = OS_IPFound(ip_to_test, ret_ip);
    assert_int_equal(ret, 0);

    w_free_os_ip(ret_ip);
}

void OS_IPFoundList_fail(void **state)
{
    char ip_to_test[] = {"1010:1010:1010:1010:1010:1010:1010:1010"};

    int ret = 0;
    os_ip *ret_ip;
    os_calloc(1, sizeof(os_ip), ret_ip);

    will_return(__wrap_get_ipv4_numeric, OS_INVALID);
    will_return(__wrap_get_ipv6_numeric, OS_INVALID);

    ret = OS_IPFoundList(ip_to_test, &ret_ip);
    assert_int_equal(ret, 0);

    w_free_os_ip(ret_ip);
}

void OS_IPFoundList_valid_ipv4(void **state)
{
    char ip_to_test[] = {"16.16.16.32"};

    int ret = 0;
    os_ip **ret_ip;
    os_calloc(3, sizeof(os_ip *), ret_ip);
    os_calloc(1, sizeof(os_ip), ret_ip[0]);
    os_calloc(1, sizeof(os_ip), ret_ip[1]);

    os_strdup("16.16.16.16", (*ret_ip[0]).ip);
    os_calloc(1, sizeof(os_ipv4), (*ret_ip[0]).ipv4);

    (*ret_ip[0]).ipv4->ip_address = 0x10101010;
    (*ret_ip[0]).ipv4->netmask = 0xFFFFFFFF;

    os_strdup("16.16.16.32", (*ret_ip[1]).ip);
    os_calloc(1, sizeof(os_ipv4), (*ret_ip[1]).ipv4);

    (*ret_ip[1]).ipv4->ip_address = 0x10101020;
    (*ret_ip[1]).ipv4->netmask = 0xFFFFFFFF;

    will_return(__wrap_get_ipv4_numeric, 1);
    will_return(__wrap_get_ipv4_numeric, 0x10101020);

    ret = OS_IPFoundList(ip_to_test, ret_ip);
    assert_int_equal(ret, 1);

    w_free_os_ip(ret_ip[0]);
    w_free_os_ip(ret_ip[1]);
    free(ret_ip);
}

void OS_IPFoundList_valid_ipv4_negated(void **state)
{
    char ip_to_test[] = {"!16.16.16.16"};

    int ret = 0;
    os_ip **ret_ip;
    os_calloc(2, sizeof(os_ip *), ret_ip);
    os_calloc(1, sizeof(os_ip), ret_ip[0]);

    os_strdup("!16.16.16.16", (*ret_ip[0]).ip);
    os_calloc(1, sizeof(os_ipv4), (*ret_ip[0]).ipv4);

    (*ret_ip[0]).ipv4->ip_address = 0x10101010;
    (*ret_ip[0]).ipv4->netmask = 0xFFFFFFFF;

    will_return(__wrap_get_ipv4_numeric, 1);
    will_return(__wrap_get_ipv4_numeric, 0x10101010);

    ret = OS_IPFoundList(ip_to_test, ret_ip);
    assert_int_equal(ret, 0);

    w_free_os_ip(ret_ip[0]);
    w_free_os_ip(ret_ip[1]);
    free(ret_ip);
}

void OS_IPFoundList_valid_ipv4_not_found(void **state)
{
    char ip_to_test[] = {"16.16.16.32"};

    int ret = 0;
    os_ip **ret_ip;
    os_calloc(4, sizeof(os_ip *), ret_ip);
    os_calloc(1, sizeof(os_ip), ret_ip[0]);
    os_calloc(1, sizeof(os_ip), ret_ip[1]);
    os_calloc(1, sizeof(os_ip), ret_ip[2]);

    os_strdup("16.16.16.16", (*ret_ip[0]).ip);
    os_calloc(1, sizeof(os_ipv4), (*ret_ip[0]).ipv4);

    (*ret_ip[0]).ipv4->ip_address = 0x10101010;
    (*ret_ip[0]).ipv4->netmask = 0xFFFFFFFF;

    os_strdup("16.16.16.32", (*ret_ip[1]).ip);
    os_calloc(1, sizeof(os_ipv4), (*ret_ip[1]).ipv4);

    (*ret_ip[1]).ipv4->ip_address = 0x10101020;
    (*ret_ip[1]).ipv4->netmask = 0xFFFFFFFF;

    os_strdup("16.16.32.32", (*ret_ip[2]).ip);
    os_calloc(1, sizeof(os_ipv4), (*ret_ip[2]).ipv4);

    (*ret_ip[2]).ipv4->ip_address = 0x10102020;
    (*ret_ip[2]).ipv4->netmask = 0xFFFFFFFF;

    will_return(__wrap_get_ipv4_numeric, 1);
    will_return(__wrap_get_ipv4_numeric, 0x10202020);

    ret = OS_IPFoundList(ip_to_test, ret_ip);
    assert_int_equal(ret, 0);

    w_free_os_ip(ret_ip[0]);
    w_free_os_ip(ret_ip[1]);
    w_free_os_ip(ret_ip[2]);
    free(ret_ip);
}

void OS_IPFoundList_valid_ipv6_fail(void **state)
{
    char ip_to_test[] = {"1010:1010:1010:1010:1010:1010:1010:1010"};

    int ret = 0;
    os_ip **ret_ip;
    os_calloc(3, sizeof(os_ip *), ret_ip);
    os_calloc(1, sizeof(os_ip), ret_ip[0]);
    os_calloc(1, sizeof(os_ip), ret_ip[1]);

    for(unsigned int i = 0; i < 2; i++) {
        os_strdup("0101:0101:0101:0101:0101:0101:0101:0101", (*ret_ip[i]).ip);
        os_calloc(1, sizeof(os_ipv6), (*ret_ip[i]).ipv6);

        unsigned int a = 0;
        for(a = 0; a < 16; a++) {
            (*ret_ip[i]).ipv6->ip_address[a] = 0x10;
        }
        for(a = 0; a < 16; a++) {
            (*ret_ip[i]).ipv6->netmask[a] = 0xFF;
        }
    }

    will_return(__wrap_get_ipv4_numeric, OS_INVALID);
    will_return(__wrap_get_ipv6_numeric, 1);
    will_return(__wrap_get_ipv6_numeric, 0x00);

    ret = OS_IPFoundList(ip_to_test, ret_ip);
    assert_int_equal(ret, 0);

    w_free_os_ip(ret_ip[0]);
    w_free_os_ip(ret_ip[1]);
    free(ret_ip);
}

void OS_IPFoundList_valid_ipv6(void **state)
{
    char ip_to_test[] = {"1010:1010:1010:1010:1010:1010:1010:1010"};

    int ret = 0;
    os_ip **ret_ip;
    os_calloc(3, sizeof(os_ip *), ret_ip);
    os_calloc(1, sizeof(os_ip), ret_ip[0]);
    os_calloc(1, sizeof(os_ip), ret_ip[1]);

    for(unsigned int i = 0; i < 2; i++) {
        os_strdup("0101:0101:0101:0101:0101:0101:0101:0101", (*ret_ip[i]).ip);
        os_calloc(1, sizeof(os_ipv6), (*ret_ip[i]).ipv6);

        unsigned int a = 0;
        for(a = 0; a < 16; a++) {
            (*ret_ip[i]).ipv6->ip_address[a] = 0x20;
        }
        for(a = 0; a < 16; a++) {
            (*ret_ip[i]).ipv6->netmask[a] = 0xFF;
        }
    }

    will_return(__wrap_get_ipv4_numeric, OS_INVALID);
    will_return(__wrap_get_ipv6_numeric, 1);
    will_return(__wrap_get_ipv6_numeric, 0x20);

    ret = OS_IPFoundList(ip_to_test, ret_ip);
    assert_int_equal(ret, 1);

    w_free_os_ip(ret_ip[0]);
    w_free_os_ip(ret_ip[1]);
    free(ret_ip);
}

void OS_CIDRtoStr_any(void **state)
{
    char ip_to_test[IPSIZE] = {0};

    int ret = 0;
    os_ip *ret_ip;
    os_calloc(1, sizeof(os_ip), ret_ip);

    os_strdup("any", ret_ip->ip);
    os_calloc(1, sizeof(os_ipv4), ret_ip->ipv4);

    ret_ip->is_ipv6 = false;
    ret_ip->ipv4->ip_address = 0x0;
    ret_ip->ipv4->netmask = 0x0;

    ret = OS_CIDRtoStr(ret_ip, ip_to_test, IPSIZE);
    assert_int_equal(ret, 0);
    assert_string_equal(ip_to_test, "any");

    w_free_os_ip(ret_ip);
}

void OS_CIDRtoStr_valid_ipv4(void **state)
{
    char ip_to_test[IPSIZE] = {0};

    int ret = 0;
    os_ip *ret_ip;
    os_calloc(1, sizeof(os_ip), ret_ip);

    os_strdup("16.16.16.16", ret_ip->ip);
    os_calloc(1, sizeof(os_ipv4), ret_ip->ipv4);

    ret_ip->is_ipv6 = false;
    ret_ip->ipv4->ip_address = 0x10101010;
    ret_ip->ipv4->netmask = 0xFFFFFFFF;

    ret = OS_CIDRtoStr(ret_ip, ip_to_test, IPSIZE);
    assert_int_equal(ret, 0);
    assert_string_equal(ip_to_test, "16.16.16.16");

    w_free_os_ip(ret_ip);
}

void OS_CIDRtoStr_valid_ipv6CIDR_64(void **state)
{
    char ip_to_test[IPSIZE] = {0};

    int ret = 0;
    os_ip *ret_ip;
    os_calloc(1, sizeof(os_ip), ret_ip);

    os_strdup("0101:0101:0101:0101:0101:0101:0101:0101", ret_ip->ip);
    os_calloc(1, sizeof(os_ipv6), ret_ip->ipv6);

    ret_ip->is_ipv6 = true;
    for (unsigned int a = 0; a < 8; a++) {
        ret_ip->ipv6->netmask[a] = 0xFF;
    }

    ret = OS_CIDRtoStr(ret_ip, ip_to_test, IPSIZE);
    assert_int_equal(ret, 0);
    assert_string_equal(ip_to_test, "0101:0101:0101:0101:0101:0101:0101:0101/64");

    w_free_os_ip(ret_ip);
}

void OS_CIDRtoStr_valid_ipv6CIDR_127(void **state)
{
    char ip_to_test[IPSIZE] = {0};

    int ret = 0;
    os_ip *ret_ip;
    os_calloc(1, sizeof(os_ip), ret_ip);

    os_strdup("0101:0101:0101:0101:0101:0101:0101:0101", ret_ip->ip);
    os_calloc(1, sizeof(os_ipv6), ret_ip->ipv6);

    ret_ip->is_ipv6 = true;
    for (unsigned int a = 0; a < 15; a++) {
        ret_ip->ipv6->netmask[a] = 0xFF;
    }
    ret_ip->ipv6->netmask[15] = 0xFE;

    ret = OS_CIDRtoStr(ret_ip, ip_to_test, IPSIZE);
    assert_int_equal(ret, 0);
    assert_string_equal(ip_to_test, "0101:0101:0101:0101:0101:0101:0101:0101/127");

    w_free_os_ip(ret_ip);
}

void OS_CIDRtoStr_valid_ipv6CIDR_128(void **state)
{
    char ip_to_test[IPSIZE] = {0};

    int ret = 0;
    os_ip *ret_ip;
    os_calloc(1, sizeof(os_ip), ret_ip);

    os_strdup("0101:0101:0101:0101:0101:0101:0101:0101", ret_ip->ip);
    os_calloc(1, sizeof(os_ipv6), ret_ip->ipv6);

    ret_ip->is_ipv6 = true;
    for (unsigned int a = 0; a < 16; a++) {
        ret_ip->ipv6->netmask[a] = 0xFF;
    }

    ret = OS_CIDRtoStr(ret_ip, ip_to_test, IPSIZE);
    assert_int_equal(ret, 0);
    assert_string_equal(ip_to_test, "0101:0101:0101:0101:0101:0101:0101:0101");

    w_free_os_ip(ret_ip);
}

void OS_CIDRtoStr_valid_ipv6(void **state)
{
    char ip_to_test[IPSIZE] = {0};

    int ret = 0;
    os_ip *ret_ip;
    os_calloc(1, sizeof(os_ip), ret_ip);

    os_strdup("0101:0101:0101:0101:0101:0101:0101:0101", ret_ip->ip);
    os_calloc(1, sizeof(os_ipv6), ret_ip->ipv6);

    ret_ip->is_ipv6 = true;

    ret = OS_CIDRtoStr(ret_ip, ip_to_test, IPSIZE);
    assert_int_equal(ret, 0);
    assert_string_equal(ip_to_test, "0101:0101:0101:0101:0101:0101:0101:0101/0");

    w_free_os_ip(ret_ip);
}

void OS_CIDRtoStr_valid_ipv4_CIDR_24(void **state)
{
    char ip_to_test[IPSIZE] = {0};

    int ret = 0;
    os_ip *ret_ip;
    os_calloc(1, sizeof(os_ip), ret_ip);

    os_strdup("16.16.16.16", ret_ip->ip);
    os_calloc(1, sizeof(os_ipv4), ret_ip->ipv4);

    ret_ip->is_ipv6 = false;
    ret_ip->ipv4->ip_address = 0x10101010;
    /* FFFFFF = 24 bits */
    ret_ip->ipv4->netmask = 0xFFFFFF;

    ret = OS_CIDRtoStr(ret_ip, ip_to_test, IPSIZE);
    assert_int_equal(ret, 0);
    assert_string_equal(ip_to_test, "16.16.16.16/24");

    w_free_os_ip(ret_ip);
}

void OS_CIDRtoStr_valid_ipv4_CIDR_0(void **state)
{
    char ip_to_test[IPSIZE] = {0};

    int ret = 0;
    os_ip *ret_ip;
    os_calloc(1, sizeof(os_ip), ret_ip);

    os_strdup("32.32.32.32", ret_ip->ip);
    os_calloc(1, sizeof(os_ipv4), ret_ip->ipv4);

    ret_ip->is_ipv6 = false;
    ret_ip->ipv4->ip_address = 0x20202020;
    /* Zero bits */
    ret_ip->ipv4->netmask = 0x0;

    ret = OS_CIDRtoStr(ret_ip, ip_to_test, IPSIZE);
    assert_int_equal(ret, 0);
    assert_string_equal(ip_to_test, "32.32.32.32/0");

    w_free_os_ip(ret_ip);
}

void OS_GetIPv4FromIPv6_success(void **state) {

    char address[IPSIZE + 1] = {0};
    strncpy(address, "::ffff:10.2.2.3", IPSIZE);

    expect_value(__wrap_w_calloc_expression_t, type, EXP_TYPE_PCRE2);
    will_return(__wrap_w_expression_compile, true);
    will_return(__wrap_w_expression_match, -1);
    will_return(__wrap_w_expression_match, "10.2.2.3");

    int ret = OS_GetIPv4FromIPv6(address, IPSIZE);

    assert_string_equal("10.2.2.3", address);
    assert_int_equal(ret, 1);
}

void OS_GetIPv4FromIPv6_netmask_success(void **state) {

    char address[IPSIZE + 1] = {0};
    strncpy(address, "::ffff:10.2.2.3/255.255.255.255", IPSIZE);

    expect_value(__wrap_w_calloc_expression_t, type, EXP_TYPE_PCRE2);
    will_return(__wrap_w_expression_compile, true);
    will_return(__wrap_w_expression_match, -1);
    will_return(__wrap_w_expression_match, "10.2.2.3/255.255.255.255");

    int ret = OS_GetIPv4FromIPv6(address, IPSIZE);

    assert_string_equal("10.2.2.3/255.255.255.255", address);
    assert_int_equal(ret, 1);
}

void OS_GetIPv4FromIPv6_compile_fail(void **state) {

    char address[IPSIZE + 1] = {0};
    strncpy(address, "10.2.2.4", IPSIZE);

    expect_value(__wrap_w_calloc_expression_t, type, EXP_TYPE_PCRE2);
    will_return(__wrap_w_expression_compile, false);

    int ret = OS_GetIPv4FromIPv6(address, IPSIZE);

    assert_string_equal("10.2.2.4", address);
    assert_int_equal(ret, 0);
}

void OS_GetIPv4FromIPv6_match_fail(void **state) {

    char address[IPSIZE + 1] = {0};
    strncpy(address, "10.2.2.5/64", IPSIZE);

    expect_value(__wrap_w_calloc_expression_t, type, EXP_TYPE_PCRE2);
    will_return(__wrap_w_expression_compile, true);
    will_return(__wrap_w_expression_match, false);

    int ret = OS_GetIPv4FromIPv6(address, IPSIZE);

    assert_string_equal("10.2.2.5/64", address);
    assert_int_equal(ret, 0);
}

void OS_GetIPv4FromIPv6_empty_group(void **state) {

    char address[IPSIZE + 1] = {0};
    strncpy(address, "::ffff:10.2.2.3/255.255.255.255", IPSIZE);

    expect_value(__wrap_w_calloc_expression_t, type, EXP_TYPE_PCRE2);
    will_return(__wrap_w_expression_compile, true);
    will_return(__wrap_w_expression_match, -1);
    will_return(__wrap_w_expression_match, NULL);

    int ret = OS_GetIPv4FromIPv6(address, IPSIZE);

    assert_string_equal("::ffff:10.2.2.3/255.255.255.255", address);
    assert_int_equal(ret, 0);
}

int main(void) {

    const struct CMUnitTest tests[] = {
        // Tests w_validate_bytes
        cmocka_unit_test(w_validate_bytes_non_number),
        cmocka_unit_test(w_validate_bytes_bytes),
        cmocka_unit_test(w_validate_bytes_kilobytes),
        cmocka_unit_test(w_validate_bytes_megabytes),
        cmocka_unit_test(w_validate_bytes_gigabytes),
        // Test OS_IsValidIP
        cmocka_unit_test(OS_IsValidIP_null),
        cmocka_unit_test(OS_IsValidIP_any),
        cmocka_unit_test(OS_IsValidIP_any_struct),
        cmocka_unit_test(OS_IsValidIP_not_valid_ip),
        cmocka_unit_test(OS_IsValidIP_valid_multi_ipv4),
        cmocka_unit_test(OS_IsValidIP_not_valid_multi_ipv4),
        cmocka_unit_test(OS_IsValidIP_valid_ipv4_CIDR),
        cmocka_unit_test(OS_IsValidIP_valid_ipv4_fail),
        cmocka_unit_test(OS_IsValidIP_valid_ipv4_zero_fail),
        cmocka_unit_test(OS_IsValidIP_valid_ipv4_zero_pass),
        cmocka_unit_test(OS_IsValidIP_valid_ipv4_netmask),
        cmocka_unit_test(OS_IsValidIP_valid_ipv4_0_netmask),
        cmocka_unit_test(OS_IsValidIP_valid_ipv4_netmask_0),
        cmocka_unit_test(OS_IsValidIP_valid_ipv4_netmask_fail),
        cmocka_unit_test(OS_IsValidIP_valid_ipv4_sub_string_0),
        cmocka_unit_test(OS_IsValidIP_valid_ipv4_netmask_0_NULL_struct),
        cmocka_unit_test(OS_IsValidIP_valid_multi_ipv6),
        cmocka_unit_test(OS_IsValidIP_not_valid_multi_ipv6),
        cmocka_unit_test(OS_IsValidIP_valid_ipv6_prefix),
        cmocka_unit_test(OS_IsValidIP_valid_ipv6_prefix_NULL_struct),
        cmocka_unit_test(OS_IsValidIP_valid_ipv6_numeric_fail),
        cmocka_unit_test(OS_IsValidIP_valid_ipv6_converNetmask_fail),
        cmocka_unit_test(OS_IsValidIP_valid_ipv6_sub_string_0),
        // Test OS_IPFound
        cmocka_unit_test(OS_IPFound_not_valid_ip),
        cmocka_unit_test(OS_IPFound_valid_ipv4),
        cmocka_unit_test(OS_IPFound_valid_ipv4_negated),
        cmocka_unit_test(OS_IPFound_valid_ipv6),
        cmocka_unit_test(OS_IPFound_valid_ipv6_fail),
        // Test OS_IPFoundList
        cmocka_unit_test(OS_IPFoundList_fail),
        cmocka_unit_test(OS_IPFoundList_valid_ipv4),
        cmocka_unit_test(OS_IPFoundList_valid_ipv4_negated),
        cmocka_unit_test(OS_IPFoundList_valid_ipv4_not_found),
        cmocka_unit_test(OS_IPFoundList_valid_ipv6_fail),
        cmocka_unit_test(OS_IPFoundList_valid_ipv6),
        // Test OS_CIDRtoStr
        cmocka_unit_test(OS_CIDRtoStr_any),
        cmocka_unit_test(OS_CIDRtoStr_valid_ipv4),
        cmocka_unit_test(OS_CIDRtoStr_valid_ipv6),
        cmocka_unit_test(OS_CIDRtoStr_valid_ipv6CIDR_64),
        cmocka_unit_test(OS_CIDRtoStr_valid_ipv6CIDR_127),
        cmocka_unit_test(OS_CIDRtoStr_valid_ipv6CIDR_128),
        cmocka_unit_test(OS_CIDRtoStr_valid_ipv4_CIDR_24),
        cmocka_unit_test(OS_CIDRtoStr_valid_ipv4_CIDR_0),
        // Test OS_GetIPv4FromIPv6
        cmocka_unit_test(OS_GetIPv4FromIPv6_success),
        cmocka_unit_test(OS_GetIPv4FromIPv6_netmask_success),
        cmocka_unit_test(OS_GetIPv4FromIPv6_compile_fail),
        cmocka_unit_test(OS_GetIPv4FromIPv6_match_fail),
        cmocka_unit_test(OS_GetIPv4FromIPv6_empty_group),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
