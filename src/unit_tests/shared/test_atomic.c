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
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "../../headers/atomic.h"
#include "../wrappers/posix/pthread_wrappers.h"

atomic_int_t test_variable = ATOMIC_INT_INITIALIZER(0);


static int setup_variable(void **state) {
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    atomic_int_set(&test_variable, 1231);
    return 0;
}

static int teardown_variable(void **state) {
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    atomic_int_set(&test_variable, 0);
    return 0;
}


static void test_atomic_int_get(void **state) {
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    int ret = atomic_int_get(&test_variable);

    assert_int_equal(ret, 1231);
    assert_int_equal(test_variable.data, 1231);

}

static void test_atomic_int_set(void **state) {
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    atomic_int_set(&test_variable, 2718);

    assert_int_equal(test_variable.data, 2718);
}

static void test_atomic_int_inc(void **state) {
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    int ret = atomic_int_inc(&test_variable);

    assert_int_equal(test_variable.data, 1232);
    assert_int_equal(ret, 1232);
}


static void test_atomic_int_dec(void **state) {
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    int ret = atomic_int_dec(&test_variable);

    assert_int_equal(test_variable.data, 1230);
    assert_int_equal(ret, 1230);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_atomic_int_get, setup_variable, teardown_variable),
        cmocka_unit_test_setup_teardown(test_atomic_int_set, setup_variable, teardown_variable),
        cmocka_unit_test_setup_teardown(test_atomic_int_inc, setup_variable, teardown_variable),
        cmocka_unit_test_setup_teardown(test_atomic_int_dec, setup_variable, teardown_variable),
        };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
