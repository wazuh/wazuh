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
#include <string.h>

#include "../headers/defs.h"
#include "../headers/buffer_op.h"

/* setup / teardown */
int test_setup_ok(void **state)
{
    buffer_t *buff = buffer_initialize(OS_SIZE_32);
    *state = buff;
    return 0;
}

int test_teardown_ok(void **state)
{
    buffer_t *buff = *state;
    buffer_free(buff);
    return 0;
}

void test_buffer_null(void **state)
{
    buffer_push(NULL, NULL, 0);
}

void test_buffer_src_null(void **state)
{
    buffer_t *buff = *state;
    buffer_push(buff, NULL, 0);
    assert_int_equal(buff->used, 0);
    assert_int_equal(buff->size, 32);
}

void test_buffer_src_null_with_size(void **state)
{
    buffer_t *buff = *state;
    buffer_push(buff, NULL, 11000);
    assert_int_equal(buff->used, 0);
    assert_int_equal(buff->size, 32);
}

void test_buffer_overrun(void **state)
{
    buffer_t *buff = *state;
    buffer_push(buff, "hello_world hello_world hello_world hello_world hello_world", strlen("hello_world hello_world hello_world hello_world hello_world"));
    assert_int_equal(buff->used, 0);
    assert_int_equal(buff->size, 32);
}

void test_buffer_overrun_bad_size(void **state)
{
    buffer_t *buff = *state;
    buffer_push(buff, "hello_world hello_world hello_world hello_world hello_world", 5);
    assert_int_not_equal(buff->used, 0);
    assert_string_equal(buff->data, "hello");
    assert_int_equal(buff->size, 32);
}

void test_buffer_ok(void **state)
{
    buffer_t *buff = *state;
    buffer_push(buff, "hello_world", strlen("hello_world"));
    assert_int_equal(buff->used, strlen("hello_world"));
    assert_string_equal(buff->data, "hello_world");
    assert_int_equal(buff->size, 32);
}

void test_buffer_multiple_push_ok(void **state)
{
    buffer_t *buff = *state;
    buffer_push(buff, "hello", strlen("hello"));
    buffer_push(buff, "_", strlen("_"));
    buffer_push(buff, "world", strlen("world"));
    assert_int_equal(buff->used, strlen("hello_world"));
    assert_string_equal(buff->data, "hello_world");
    assert_int_equal(buff->size, 32);
}

void test_buffer_multiple_push_bad_size(void **state)
{
    buffer_t *buff = *state;
    buffer_push(buff, "hello", strlen("hello"));
    buffer_push(buff, "____________________________________________________________________", strlen("____________________________________________________________________"));
    assert_int_equal(buff->used, strlen("hello"));
    assert_string_equal(buff->data, "hello");
    assert_int_equal(buff->size, 32);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_buffer_null, test_setup_ok, test_teardown_ok),
        cmocka_unit_test_setup_teardown(test_buffer_src_null, test_setup_ok, test_teardown_ok),
        cmocka_unit_test_setup_teardown(test_buffer_src_null_with_size, test_setup_ok, test_teardown_ok),
        cmocka_unit_test_setup_teardown(test_buffer_overrun, test_setup_ok, test_teardown_ok),
        cmocka_unit_test_setup_teardown(test_buffer_overrun_bad_size, test_setup_ok, test_teardown_ok),
        cmocka_unit_test_setup_teardown(test_buffer_ok, test_setup_ok, test_teardown_ok),
        cmocka_unit_test_setup_teardown(test_buffer_multiple_push_ok, test_setup_ok, test_teardown_ok),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
