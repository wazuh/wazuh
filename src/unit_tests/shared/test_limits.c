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

#include "shared.h"
#include "limits_op.h"

limits_t *test_limits;

void generate_eps_credits(limits_t *limits);
void increase_event_counter(limits_t *limits);

/* Tests */

// init_limits
void test_init_limits_disabled(void ** state) {
    expect_string(__wrap__minfo, formatted_msg, "EPS limit disabled");

    test_limits = init_limits(0, 5);

    assert_false(test_limits->enabled);

    free_limits(&test_limits);
}


void test_init_limits_enabled(void ** state) {
    int current_credits;

    expect_string(__wrap__minfo, formatted_msg, "EPS limit enabled, EPS: '100', timeframe: '5'");

    test_limits = init_limits(100, 5);

    assert_int_equal(test_limits->eps, 100);
    assert_int_equal(test_limits->timeframe, 5);
    assert_true(test_limits->enabled);
    sem_getvalue(&test_limits->credits_eps_semaphore, &current_credits);
    assert_int_equal(500, current_credits);
}

// update_limits
void test_update_limits(void ** state) {
    int current_credits;

    for (int i = 0; i < 5; i++) {
        for (int j = 0; j < 100; j++) {
            get_eps_credit(test_limits);
        }
        update_limits(test_limits);
    }


    assert_int_equal(test_limits->eps, 100);
    assert_int_equal(test_limits->timeframe, 5);
    assert_int_equal(test_limits->current_cell, 4);
    assert_int_equal(test_limits->circ_buf[0], 100);
    assert_int_equal(test_limits->circ_buf[1], 100);
    assert_int_equal(test_limits->circ_buf[2], 100);
    assert_int_equal(test_limits->circ_buf[3], 100);
    assert_int_equal(test_limits->circ_buf[4], 0);
    sem_getvalue(&test_limits->credits_eps_semaphore, &current_credits);
    assert_int_equal(100, current_credits);
}

// limit_reached
void test_limit_reached(void ** state) {
    bool result;
    int current_credits;

    result = limit_reached(test_limits, &current_credits);
    assert_false(result);
    assert_int_equal(100, current_credits);

    for (int j = 0; j < 100; j++) {
        get_eps_credit(test_limits);
    }

    result = limit_reached(test_limits, &current_credits);
    assert_true(result);
    assert_int_equal(0, current_credits);
}

// generate_eps_credits
void test_generate_eps_credits(void ** state) {
    int current_credits;

    generate_eps_credits(test_limits);

    sem_getvalue(&test_limits->credits_eps_semaphore, &current_credits);
    assert_int_equal(100, current_credits);
}

// get_eps_credit
void test_get_eps_credit(void ** state) {
    int current_credits;

    get_eps_credit(test_limits);

    sem_getvalue(&test_limits->credits_eps_semaphore, &current_credits);
    assert_int_equal(99, current_credits);
}

// free_limits
void test_free_limits(void ** state) {
    free_limits(&test_limits);
    assert_null(test_limits);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        // Tests init_limits
        cmocka_unit_test(test_init_limits_disabled),
        cmocka_unit_test(test_init_limits_enabled),
        // Test update_limits
        cmocka_unit_test(test_update_limits),
        // Test limit_reached
        cmocka_unit_test(test_limit_reached),
        // Test generate_eps_credits
        cmocka_unit_test(test_generate_eps_credits),
        // Test get_eps_credit
        cmocka_unit_test(test_get_eps_credit),
        // Test free_limits
        cmocka_unit_test(test_free_limits),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
