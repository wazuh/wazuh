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
#include <string.h>
#include <stdbool.h>

#include "../headers/shared.h"


/* tests */

void test_is_leap_year_two(void **state)
{
    (void) state;
    bool ret;
    int year = 2;
    ret = is_leap_year(year);

    assert_false(ret);
}

void test_is_leap_year_four(void **state)
{
    (void) state;
    bool ret;
    int year = 4;
    ret = is_leap_year(year);

    assert_true(ret);
}

void test_is_leap_year_one_hundred(void **state)
{
    (void) state;
    bool ret;
    int year = 100;
    ret = is_leap_year(year);

    assert_false(ret);
}

void test_is_leap_year_two_hundred(void **state)
{
    (void) state;
    bool ret;
    int year = 200;
    ret = is_leap_year(year);

    assert_false(ret);
}

void test_is_leap_year_three_hundred(void **state)
{
    (void) state;
    bool ret;
    int year = 300;
    ret = is_leap_year(year);

    assert_false(ret);
}

void test_is_leap_year_four_hundred(void **state)
{
    (void) state;
    bool ret;
    int year = 400;
    ret = is_leap_year(year);

    assert_true(ret);
}


int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_is_leap_year_two),
        cmocka_unit_test(test_is_leap_year_four),
        cmocka_unit_test(test_is_leap_year_one_hundred),
        cmocka_unit_test(test_is_leap_year_two_hundred),
        cmocka_unit_test(test_is_leap_year_three_hundred),
        cmocka_unit_test(test_is_leap_year_four_hundred)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
