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
#include <errno.h>
#include <string.h>

#include "../../headers/atomic.h"
#include "../wrappers/posix/pthread_wrappers.h"

static void test_atomic_int_get(void **state) {
    atomic_int_t test_variable = ATOMIC_INT_INITIALIZER(1231);

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    int ret = atomic_int_get(&test_variable);

    assert_int_equal(ret, 1231);
}

static void test_atomic_int_set(void **state) {
    atomic_int_t test_variable = ATOMIC_INT_INITIALIZER(1231);

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    atomic_int_set(&test_variable, 2718);

    assert_int_equal(test_variable.data, 2718);
}

static void test_atomic_int_inc(void **state) {
    atomic_int_t test_variable = ATOMIC_INT_INITIALIZER(1231);

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    int ret = atomic_int_inc(&test_variable);

    assert_int_equal(ret, 1232);
}

static void test_atomic_int_dec(void **state) {
    atomic_int_t test_variable = ATOMIC_INT_INITIALIZER(1231);

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    int ret = atomic_int_dec(&test_variable);

    assert_int_equal(ret, 1230);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_atomic_int_get),
        cmocka_unit_test(test_atomic_int_set),
        cmocka_unit_test(test_atomic_int_inc),
        cmocka_unit_test(test_atomic_int_dec),
        };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
