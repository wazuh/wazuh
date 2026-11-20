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

#ifdef TEST_WINAGENT
ULONGLONG w_extend_tick_count(DWORD * last, ULONGLONG * high, DWORD tick);
#endif


/* tests */

#ifdef TEST_WINAGENT
void test_w_extend_tick_count_no_wrap(void **state)
{
    (void) state;
    DWORD last = 0;
    ULONGLONG high = 0;

    assert_int_equal(w_extend_tick_count(&last, &high, 1000), 1000);
    assert_int_equal(w_extend_tick_count(&last, &high, 2000), 2000);
    assert_int_equal(high, 0);
}

void test_w_extend_tick_count_same_tick(void **state)
{
    (void) state;
    DWORD last = 0;
    ULONGLONG high = 0;

    assert_int_equal(w_extend_tick_count(&last, &high, 5000), 5000);
    assert_int_equal(w_extend_tick_count(&last, &high, 5000), 5000);
    assert_int_equal(high, 0);
}

void test_w_extend_tick_count_wrap(void **state)
{
    (void) state;
    DWORD last = 0;
    ULONGLONG high = 0;
    ULONGLONG before = w_extend_tick_count(&last, &high, 0xFFFFFC18);
    ULONGLONG after = w_extend_tick_count(&last, &high, 0x3E8);

    assert_int_equal(after, 0x1000003E8ULL);
    assert_int_equal(after - before, 2000);
    assert_int_equal(after / 1000 - before / 1000, 2);
}

void test_w_extend_tick_count_two_wraps(void **state)
{
    (void) state;
    DWORD last = 0;
    ULONGLONG high = 0;

    w_extend_tick_count(&last, &high, 0xFFFFFF00);
    w_extend_tick_count(&last, &high, 0x10);
    w_extend_tick_count(&last, &high, 0xFFFFFF00);

    assert_int_equal(w_extend_tick_count(&last, &high, 0x20), (2ULL << 32) | 0x20);
    assert_int_equal(high, 2ULL << 32);
}
#endif

void test_w_get_monotonic_time_is_positive(void **state)
{
    (void) state;
    time_t t = w_get_monotonic_time();
    assert_true(t > 0);
}

void test_w_get_monotonic_time_is_nondecreasing(void **state)
{
    (void) state;
    time_t t1 = w_get_monotonic_time();
    time_t t2 = w_get_monotonic_time();
    assert_true(t2 >= t1);
}

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
        cmocka_unit_test(test_w_get_monotonic_time_is_positive),
        cmocka_unit_test(test_w_get_monotonic_time_is_nondecreasing),
#ifdef TEST_WINAGENT
        cmocka_unit_test(test_w_extend_tick_count_no_wrap),
        cmocka_unit_test(test_w_extend_tick_count_same_tick),
        cmocka_unit_test(test_w_extend_tick_count_wrap),
        cmocka_unit_test(test_w_extend_tick_count_two_wraps),
#endif
        cmocka_unit_test(test_is_leap_year_two),
        cmocka_unit_test(test_is_leap_year_four),
        cmocka_unit_test(test_is_leap_year_one_hundred),
        cmocka_unit_test(test_is_leap_year_two_hundred),
        cmocka_unit_test(test_is_leap_year_three_hundred),
        cmocka_unit_test(test_is_leap_year_four_hundred)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
