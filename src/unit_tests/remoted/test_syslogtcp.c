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
#include <stdlib.h>

#include "../../remoted/remoted.h"
#include "../../headers/shared.h"
#include "../../os_net/os_net.h"


/* Forward declarations */
size_t w_get_pri_header_len(const char * syslog_msg);

/* setup/teardown */

static int group_setup(void ** state) {
    test_mode = 1;
    return 0;
}

static int group_teardown(void ** state) {
    test_mode = 0;
    return 0;
}

/* Wrappers */

/* Tests */

// w_get_pri_header_len

void test_w_get_pri_header_len_null(void ** state) {

    const ssize_t expected_retval = 0;
    ssize_t retval = w_get_pri_header_len(NULL);

    assert_int_equal(retval, expected_retval);
}

void test_w_get_pri_header_len_no_pri(void ** state) {

    const ssize_t expected_retval = 0;
    ssize_t retval = w_get_pri_header_len("test log");

    assert_int_equal(retval, expected_retval);
}

void test_w_get_pri_header_len_w_pri(void ** state) {

    const ssize_t expected_retval = 4;
    ssize_t retval = w_get_pri_header_len("<18>test log");

    assert_int_equal(retval, expected_retval);
}

void test_w_get_pri_header_len_not_end(void ** state) {

    const ssize_t expected_retval = 0;
    ssize_t retval = w_get_pri_header_len("<18 test log");

    assert_int_equal(retval, expected_retval);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // Test w_get_pri_header_len
        cmocka_unit_test(test_w_get_pri_header_len_null),
        cmocka_unit_test(test_w_get_pri_header_len_no_pri),
        cmocka_unit_test(test_w_get_pri_header_len_w_pri),
        cmocka_unit_test(test_w_get_pri_header_len_not_end),

    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
