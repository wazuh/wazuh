/*
 * Copyright (C) Wazuh Inc.
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

#include "shared.h"

/* On Windows the unit-test wrappers (wrappers/common.h, pulled in by shared.h) redefine time() as a
 * macro that returns time_mock_value. The wall-clock check below needs the real clock. */
#ifdef WIN32
#undef time
#endif


/* tests */

void test_w_get_monotonic_time_is_positive(void **state)
{
    (void) state;
    time_t t = w_get_monotonic_time();
    assert_true(t > 0);
}

/* Shares an epoch with other processes and cluster nodes, which is the whole reason it exists
 * alongside the monotonic clock: a deadline one party stamps is compared by another. */
void test_w_get_epoch_ms_matches_wall_clock(void **state)
{
    (void) state;
    const time_t before = time(NULL);
    const int64_t ms = w_get_epoch_ms();
    const time_t after = time(NULL);

    assert_true(ms > 0);
    /* Same epoch as time(), in milliseconds. One second of slack on each side: time() and
     * gettimeofday() may read the clock through different sources (a coarse clock on Linux, the
     * CRT on Windows) that do not tick over to the next second at the same instant. A wrong epoch
     * would be off by far more than a second. */
    assert_true(ms / 1000 >= (int64_t)before - 1);
    assert_true(ms / 1000 <= (int64_t)after + 1);
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
        cmocka_unit_test(test_w_get_epoch_ms_matches_wall_clock),
        cmocka_unit_test(test_is_leap_year_two),
        cmocka_unit_test(test_is_leap_year_four),
        cmocka_unit_test(test_is_leap_year_one_hundred),
        cmocka_unit_test(test_is_leap_year_two_hundred),
        cmocka_unit_test(test_is_leap_year_three_hundred),
        cmocka_unit_test(test_is_leap_year_four_hundred)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
