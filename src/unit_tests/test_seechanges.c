/*
 * Copyright (C) 2015-2019, Wazuh Inc.
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
#include <string.h>

#include "../syscheckd/syscheck.h"
#include "../config/syscheck-config.h"

/* redefinitons/wrapping */


/* tests */

void test_is_nodiff_true(void **state)
{
    (void) state;
    int ret;

    Read_Syscheck_Config("test_syscheck.conf");

    const char * file_name = "/etc/ssl/private.key";

    ret = is_nodiff(file_name);

    assert_int_equal(ret, 1);
}


void test_is_nodiff_false(void **state)
{
    (void) state;
    int ret;

    Read_Syscheck_Config("test_syscheck.conf");

    const char * file_name = "/dummy_file.key";

    ret = is_nodiff(file_name);

    assert_int_equal(ret, 0);
}


void test_is_nodiff_regex_true(void **state)
{
    (void) state;
    int ret;

    Read_Syscheck_Config("test_syscheck.conf");

    const char * file_name = "file.test";

    ret = is_nodiff(file_name);

    assert_int_equal(ret, 1);
}


void test_is_nodiff_regex_false(void **state)
{
    (void) state;
    int ret;

    Read_Syscheck_Config("test_syscheck.conf");

    const char * file_name = "test.file";

    ret = is_nodiff(file_name);

    assert_int_equal(ret, 0);
}


int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_is_nodiff_true),
        cmocka_unit_test(test_is_nodiff_false),
        cmocka_unit_test(test_is_nodiff_regex_true),
        cmocka_unit_test(test_is_nodiff_regex_false),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
