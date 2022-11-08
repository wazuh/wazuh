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
#include "../../analysisd/limits.h"

extern sem_t credits_eps_semaphore;
extern limits_t limits;

void generate_eps_credits(unsigned int credits);
void increase_event_counter(void);

// Setup / Teardown

static int test_setup(void **state) {
    memset(&limits, 0, sizeof(limits));
    limits.enabled = true;
    limits.timeframe = 10;
    limits.eps = 10;
    os_calloc(limits.timeframe, sizeof(unsigned int), limits.circ_buf);

    return OS_SUCCESS;
}

static int test_teardown(void **state) {
    if (limits.circ_buf) {
        os_free(limits.circ_buf);
    }
    memset(&limits, 0, sizeof(limits));
    return OS_SUCCESS;
}

/* Tests */

// generate_eps_credits
void test_generate_eps_credits_ok(void ** state)
{
    int current_credits;
    sem_init(&credits_eps_semaphore, 0, 0);

    generate_eps_credits(5);

    sem_getvalue(&credits_eps_semaphore, &current_credits);
    assert_int_equal(5, current_credits);
    sem_destroy(&credits_eps_semaphore);
}

void test_generate_eps_credits_ok_zero(void ** state)
{
    int current_credits;
    sem_init(&credits_eps_semaphore, 0, 0);

    generate_eps_credits(0);

    sem_getvalue(&credits_eps_semaphore, &current_credits);
    assert_int_equal(0, current_credits);
    sem_destroy(&credits_eps_semaphore);
}

// increase_event_counter
void test_increase_event_counter_ok(void ** state)
{
    limits.current_cell = 0;
    assert_int_equal(0, limits.circ_buf[limits.current_cell]);
    increase_event_counter();
    assert_int_equal(1, limits.circ_buf[limits.current_cell]);
}

// limit_reached
void test_limit_reached_disabled(void ** state)
{
    limits.enabled = false;

    bool result = limit_reached(NULL);

    assert_false(result);
}

void test_limit_reached_enabled_non_zero(void ** state)
{
    limits.enabled = true;
    sem_init(&credits_eps_semaphore, 0, 5);

    bool result = limit_reached(NULL);

    assert_false(result);
    sem_destroy(&credits_eps_semaphore);
}

void test_limit_reached_enabled_non_zero_value(void ** state)
{
    int credits = 0;
    limits.enabled = true;
    sem_init(&credits_eps_semaphore, 0, 5);

    bool result = limit_reached(&credits);

    assert_false(result);
    assert_int_equal(credits, 5);
    sem_destroy(&credits_eps_semaphore);
}

void test_limit_reached_enabled_zero(void ** state)
{
    limits.enabled = true;
    sem_init(&credits_eps_semaphore, 0, 0);

    bool result = limit_reached(NULL);

    assert_true(result);
    sem_destroy(&credits_eps_semaphore);
}

void test_limit_reached_enabled_zero_value(void ** state)
{
    int credits = 0;
    limits.enabled = true;
    sem_init(&credits_eps_semaphore, 0, 0);

    bool result = limit_reached(&credits);

    assert_true(result);
    assert_int_equal(credits, 0);
    sem_destroy(&credits_eps_semaphore);
}

// get_eps_credit
void test_get_eps_credit_ok(void ** state)
{
    int current_credits;
    sem_init(&credits_eps_semaphore, 0, 5);

    get_eps_credit();

    sem_getvalue(&credits_eps_semaphore, &current_credits);
    assert_int_equal(4, current_credits);
    assert_int_equal(1, limits.circ_buf[limits.current_cell]);
    sem_destroy(&credits_eps_semaphore);
}

// load_limits
void test_load_limits_disabled(void ** state)
{
    int current_credits;
    limits.enabled = false;

    expect_string(__wrap__minfo, formatted_msg, "EPS limit disabled");

    load_limits(0, 5, true);

    assert_false(limits.enabled);
}

// load_limits
void test_load_limits_maximun_block_not_found(void ** state)
{
    int current_credits;
    limits.enabled = false;

    expect_string(__wrap__mwarn, formatted_msg, "EPS limit disabled. The maximum value is missing in the configuration block.");

    load_limits(0, 5, false);

    assert_false(limits.enabled);
}

void test_load_limits_timeframe_zero(void ** state)
{
    int current_credits;
    limits.enabled = false;

    expect_string(__wrap__minfo, formatted_msg, "EPS limit disabled");

    load_limits(100, 0, true);

    assert_false(limits.enabled);
}

void test_load_limits_ok(void ** state)
{
    int current_credits;
    limits.enabled = false;

    expect_string(__wrap__minfo, formatted_msg, "EPS limit enabled, EPS: '100', timeframe: '5'");

    load_limits(100, 5, true);

    assert_int_equal(limits.eps, 100);
    assert_int_equal(limits.timeframe, 5);
    assert_true(limits.enabled);
    sem_getvalue(&credits_eps_semaphore, &current_credits);
    assert_int_equal(500, current_credits);
    sem_destroy(&credits_eps_semaphore);
}

// update_limits
void test_update_limits_current_cell_less_than_timeframe(void ** state)
{
    limits.current_cell = 5;
    limits.circ_buf[0] = 5;
    limits.circ_buf[1] = 10;
    limits.circ_buf[limits.current_cell] = 25;

    update_limits();

    assert_int_equal(limits.eps, 10);
    assert_int_equal(limits.timeframe, 10);
    assert_int_equal(limits.current_cell, 6);
    assert_int_equal(limits.circ_buf[0], 5);
    assert_int_equal(limits.circ_buf[1], 10);
    assert_int_equal(limits.circ_buf[limits.current_cell - 1], 25);
    assert_int_equal(limits.circ_buf[limits.current_cell], 0);
}

void test_update_limits_current_cell_timeframe_limit(void ** state)
{
    limits.current_cell = limits.timeframe - 1;
    limits.circ_buf[0] = 5;
    limits.circ_buf[1] = 10;
    limits.circ_buf[limits.current_cell] = 25;

    update_limits();

    assert_int_equal(limits.eps, 10);
    assert_int_equal(limits.timeframe, 10);
    assert_int_equal(limits.current_cell, limits.timeframe - 1);
    assert_int_equal(limits.circ_buf[0], 10);
    assert_int_equal(limits.circ_buf[1], 0);
    assert_int_equal(limits.circ_buf[limits.current_cell - 1], 25);
    assert_int_equal(limits.circ_buf[limits.current_cell], 0);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        // Tests generate_eps_credits
        cmocka_unit_test(test_generate_eps_credits_ok),
        cmocka_unit_test(test_generate_eps_credits_ok_zero),
        // Test increase_event_counter
        cmocka_unit_test_setup_teardown(test_increase_event_counter_ok, test_setup, test_teardown),
        // Test limit_reached
        cmocka_unit_test(test_limit_reached_disabled),
        cmocka_unit_test(test_limit_reached_enabled_non_zero),
        cmocka_unit_test(test_limit_reached_enabled_non_zero_value),
        cmocka_unit_test(test_limit_reached_enabled_zero),
        cmocka_unit_test(test_limit_reached_enabled_zero_value),
        // Test get_eps_credit
        cmocka_unit_test_setup_teardown(test_get_eps_credit_ok, test_setup, test_teardown),
        // Test load_limits
        cmocka_unit_test_teardown(test_load_limits_disabled, test_teardown),
        cmocka_unit_test_teardown(test_load_limits_maximun_block_not_found, test_teardown),
        cmocka_unit_test_teardown(test_load_limits_timeframe_zero, test_teardown),
        cmocka_unit_test_teardown(test_load_limits_ok, test_teardown),
        // // Test update_limits
        cmocka_unit_test_setup_teardown(test_update_limits_current_cell_less_than_timeframe, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_update_limits_current_cell_timeframe_limit, test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
