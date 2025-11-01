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

void test_buffer_push_normal_case(void **state) {
    buffer_t *buffer = *state;
    const char test_data[] = "test";
    const size_t test_size = sizeof(test_data);

    buffer_push(buffer, test_data, test_size);
    assert_int_equal(buffer->used, test_size);
    assert_string_equal(buffer->data, test_data);
    assert_int_equal(buffer->size, OS_SIZE_32);
    assert_int_equal(buffer->status, TRUE);
}

void test_buffer_push_NULL_buffer(void **state) {
    const char test_data[] = "test";
    const size_t test_size = sizeof(test_data);

    buffer_push(NULL, test_data, test_size);
    // Nothing should happen
}

void test_buffer_push_NULL_data(void **state) {
    buffer_t *buffer = *state;
    const size_t test_size = 5;
    
    buffer_push(buffer, NULL, test_size);
    assert_int_equal(buffer->used, 0);
    assert_int_equal(buffer->size, OS_SIZE_32);
    assert_int_equal(buffer->status, FALSE);
}

void test_buffer_push_insufficient_space(void **state) {
    buffer_t *buffer = *state;
    const char large_data[] = "this is a very long string that won't fit";
    const size_t large_data_size = sizeof(large_data);

    buffer_push(buffer, large_data, large_data_size);
    assert_int_equal(buffer->used, 0);
    assert_int_equal(buffer->size, OS_SIZE_32);
    assert_int_equal(buffer->status, FALSE);
}

void test_buffer_push_higher_size_than_actual(void **state) {
    buffer_t *buffer = *state;
    const char test_data[] = "test";  // size = 5
    const size_t wrong_size = sizeof(test_data) * 2;
    
    // This operation is unsafe and could cause issues
    buffer_push(buffer, test_data, wrong_size);
    assert_int_equal(buffer->used, 0);
    assert_int_equal(buffer->size, OS_SIZE_32);
    assert_int_equal(buffer->status, FALSE);
}

void test_buffer_push_lower_size_than_actual(void **state) {
    buffer_t *buffer = *state;
    const char test_data[] = "test";  // size = 5
    const size_t wrong_size = sizeof(test_data) / 2;

    // This operation is safe but will only copy part of the data
    buffer_push(buffer, test_data, wrong_size);
    assert_int_equal(buffer->used, wrong_size);
    assert_int_equal(buffer->size, OS_SIZE_32);
    assert_int_equal(buffer->status, TRUE);
}

void test_buffer_push_multiple_calls(void **state) {
    buffer_t *buffer = *state;
    const char test_data1[] = "hello";
    const char test_data2[] = "world";
    const size_t size1 = sizeof(test_data1) - 1; // To avoid copying the null terminator
    const size_t size2 = sizeof(test_data2);

    buffer_push(buffer, test_data1, size1);
    assert_int_equal(buffer->used, size1);
    assert_string_equal(buffer->data, "hello");
    assert_int_equal(buffer->size, OS_SIZE_32);
    assert_int_equal(buffer->status, TRUE);
    buffer_push(buffer, test_data2, size2);
    assert_int_equal(buffer->used, size1 + size2);
    assert_string_equal(buffer->data, "helloworld");
    assert_int_equal(buffer->size, OS_SIZE_32);
    assert_int_equal(buffer->status, TRUE);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_buffer_push_normal_case, test_setup_ok, test_teardown_ok),
        cmocka_unit_test_setup_teardown(test_buffer_push_NULL_buffer, test_setup_ok, test_teardown_ok),
        cmocka_unit_test_setup_teardown(test_buffer_push_NULL_data, test_setup_ok, test_teardown_ok),
        cmocka_unit_test_setup_teardown(test_buffer_push_insufficient_space, test_setup_ok, test_teardown_ok),
//        cmocka_unit_test_setup_teardown(test_buffer_push_higher_size_than_actual, test_setup_ok, test_teardown_ok),
        cmocka_unit_test_setup_teardown(test_buffer_push_lower_size_than_actual, test_setup_ok, test_teardown_ok),
        cmocka_unit_test_setup_teardown(test_buffer_push_multiple_calls, test_setup_ok, test_teardown_ok),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
