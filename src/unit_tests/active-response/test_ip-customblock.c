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

// Tests

void test_ip_customblock_valid_ipv4(void **state) {
    (void) state;
    assert_int_equal(get_ip_version("192.168.1.100"), 4);
}

void test_ip_customblock_valid_ipv6(void **state) {
    (void) state;
    assert_int_equal(get_ip_version("2001:db8::1"), 6);
}

void test_ip_customblock_invalid_ip_with_dots_and_slashes(void **state) {
    (void) state;
    assert_int_equal(get_ip_version("../../tmp/other"), OS_INVALID);
}

void test_ip_customblock_invalid_ip_with_special_chars(void **state) {
    (void) state;
    assert_int_equal(get_ip_version("192.168.1.1;x"), OS_INVALID);
}

void test_ip_customblock_invalid_ip_empty_string(void **state) {
    (void) state;
    assert_int_equal(get_ip_version(""), OS_INVALID);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ip_customblock_valid_ipv4),
        cmocka_unit_test(test_ip_customblock_valid_ipv6),
        cmocka_unit_test(test_ip_customblock_invalid_ip_with_dots_and_slashes),
        cmocka_unit_test(test_ip_customblock_invalid_ip_with_special_chars),
        cmocka_unit_test(test_ip_customblock_invalid_ip_empty_string),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
