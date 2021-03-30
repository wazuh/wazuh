/*
 * Copyright (C) 2015-2021, Wazuh Inc.
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
#include <string.h>

#include "headers/shared.h"
#include "../wrappers/common.h"

void resolve_hostname(char **hostname, int attempts);

// setup / teardown

static int setup_hostname(void **state) {
    char *hostname;
    os_strdup("localhost", hostname);
    *state = hostname;

    return 0;
}

static int teardown_hostname(void **state) {
    char *hostname = *state;
    os_free(hostname);

    return 0;
}

/* Tests */

void test_resolve_hostname_success(void ** state){
    char *hostname = *state;
    char *ip_str = "127.0.0.1";

    expect_string(__wrap_OS_IsValidIP, ip_address, hostname);
    expect_value(__wrap_OS_IsValidIP, final_ip, NULL);
    will_return(__wrap_OS_IsValidIP, 0);

    expect_string(__wrap_OS_GetHost, host, hostname);
    will_return(__wrap_OS_GetHost, strdup(ip_str));

    resolve_hostname(&hostname, 5);

    assert_string_equal(hostname, "localhost/127.0.0.1");
}

void test_resolve_hostname_valid_ip(void ** state){
    char *hostname = "127.0.0.1";

    expect_string(__wrap_OS_IsValidIP, ip_address, hostname);
    expect_value(__wrap_OS_IsValidIP, final_ip, NULL);
    will_return(__wrap_OS_IsValidIP, 1);

    resolve_hostname(&hostname, 5);
}

void test_resolve_hostname_not_resolved(void ** state){
    char *hostname = *state;

    expect_string(__wrap_OS_IsValidIP, ip_address, hostname);
    expect_value(__wrap_OS_IsValidIP, final_ip, NULL);
    will_return(__wrap_OS_IsValidIP, 0);

    expect_string(__wrap_OS_GetHost, host, hostname);
    will_return(__wrap_OS_GetHost, NULL);

    resolve_hostname(&hostname, 5);

    assert_string_equal(hostname, "localhost/");
}

void test_get_ip_from_resolved_hostname_ip(void ** state){
    const char *resolved_hostname = "localhost/127.0.0.1";

    char *ret = get_ip_from_resolved_hostname(resolved_hostname);

    assert_string_equal(ret, "127.0.0.1");
}

void test_get_ip_from_resolved_hostname_no_ip(void ** state){
    const char *resolved_hostname = "localhost/";

    char *ret = get_ip_from_resolved_hostname(resolved_hostname);

    assert_string_equal(ret, "");
}

// Main test function

int main(void){
    const struct CMUnitTest tests[] = {
       cmocka_unit_test_setup_teardown(test_resolve_hostname_success, setup_hostname, teardown_hostname),
       cmocka_unit_test(test_resolve_hostname_valid_ip),
       cmocka_unit_test_setup_teardown(test_resolve_hostname_not_resolved, setup_hostname, teardown_hostname),
       cmocka_unit_test(test_get_ip_from_resolved_hostname_ip),
       cmocka_unit_test(test_get_ip_from_resolved_hostname_no_ip),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
