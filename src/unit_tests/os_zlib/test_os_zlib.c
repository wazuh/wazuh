/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>
#include "shared.h"

#include "../os_zlib/os_zlib.h"

#define TEST_STRING_1 "Hello World!"
#define TEST_STRING_2 "Test hello \n test \t test \r World\n"
#define BUFFER_LENGTH 200

typedef struct test_struct {
    unsigned long int i1;
    char *buffer;
} test_struct_t;

/* setup/teardown */
int setup_uncompress_string1(void **state) {
    test_struct_t *init_data = calloc(1, sizeof(test_struct_t));
    init_data->buffer = malloc(BUFFER_LENGTH*sizeof(char));
    init_data->i1 = os_zlib_compress(TEST_STRING_1, init_data->buffer, strlen(TEST_STRING_1), BUFFER_LENGTH);
    assert_int_not_equal(init_data->i1, 0);

    *state = init_data;
    return 0;
}

int setup_uncompress_string2(void **state) {
    test_struct_t *init_data = calloc(1, sizeof(test_struct_t));
    init_data->buffer = malloc(BUFFER_LENGTH*sizeof(char));
    init_data->i1 = os_zlib_compress(TEST_STRING_2, init_data->buffer, strlen(TEST_STRING_2), BUFFER_LENGTH);
    assert_int_not_equal(init_data->i1, 0);

    *state = init_data;
    return 0;
}

int teardown_uncompress(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    os_free(data->buffer);
    os_free(data);
    return 0;
}

/* Test */

void test_success_compress_string(void **state) {
    char buffer[BUFFER_LENGTH];
    unsigned long int i1 = os_zlib_compress(TEST_STRING_1, buffer, strlen(TEST_STRING_1), BUFFER_LENGTH);
    assert_int_not_equal(i1, 0);
}

void test_success_compress_special_string(void **state) {
    char buffer[BUFFER_LENGTH];
    unsigned long int i1 = os_zlib_compress(TEST_STRING_2, buffer, strlen(TEST_STRING_2), BUFFER_LENGTH);
    assert_int_not_equal(i1, 0);
}

void test_fail_compress_null_src(void **state) {
    char buffer[BUFFER_LENGTH];
    unsigned long int i1 = os_zlib_compress(NULL, buffer, strlen(TEST_STRING_1), BUFFER_LENGTH);
    assert_int_equal(i1, 0);
}

void test_fail_compress_no_dest(void **state) {
    unsigned long int i1 = os_zlib_compress(TEST_STRING_1, NULL, strlen(TEST_STRING_1), BUFFER_LENGTH);
    assert_int_equal(i1, 0);
}

void test_fail_compress_no_dest_size(void **state) {
    char buffer[BUFFER_LENGTH];
    unsigned long int i1 = os_zlib_compress(TEST_STRING_1, buffer, strlen(TEST_STRING_1), 0);
    assert_int_equal(i1, 0);
}

void test_success_uncompress(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    char buffer2[BUFFER_LENGTH];
    unsigned long int i2 = os_zlib_uncompress(data->buffer, buffer2, data->i1, BUFFER_LENGTH);

    assert_int_not_equal(i2, 0);
    assert_string_equal(buffer2, TEST_STRING_1);
}

void test_success_uncompress_special_string(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    char buffer2[BUFFER_LENGTH];
    unsigned long int i2 = os_zlib_uncompress(data->buffer, buffer2, data->i1, BUFFER_LENGTH);

    assert_int_not_equal(i2, 0);
    assert_string_equal(buffer2, TEST_STRING_2);
}

void test_fail_uncompress_null_src(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    char buffer2[BUFFER_LENGTH];
    unsigned long int i2 = os_zlib_uncompress(NULL, buffer2, data->i1, BUFFER_LENGTH);
    assert_int_equal(i2, 0);
}

void test_fail_uncompress_null_dst(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    unsigned long int i2 = os_zlib_uncompress(data->buffer, NULL, data->i1, BUFFER_LENGTH);
    assert_int_equal(i2, 0);
}

void test_fail_uncompress_no_src_size(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    char buffer2[BUFFER_LENGTH];
    unsigned long int i2 = os_zlib_uncompress(data->buffer, buffer2, 0, BUFFER_LENGTH);
    assert_int_equal(i2, 0);
}

void test_fail_uncompress_no_dest_size(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    char buffer2[BUFFER_LENGTH];
    unsigned long int i2 = os_zlib_uncompress(data->buffer, buffer2, data->i1, 0);
    assert_int_equal(i2, 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_success_compress_string),
        cmocka_unit_test(test_success_compress_special_string),
        cmocka_unit_test(test_fail_compress_null_src),
        cmocka_unit_test(test_fail_compress_no_dest),
        cmocka_unit_test(test_fail_compress_no_dest_size),
        cmocka_unit_test_setup_teardown(test_success_uncompress, setup_uncompress_string1, teardown_uncompress),
        cmocka_unit_test_setup_teardown(test_success_uncompress_special_string, setup_uncompress_string2, teardown_uncompress),
        cmocka_unit_test_setup_teardown(test_fail_uncompress_null_src, setup_uncompress_string1, teardown_uncompress),
        cmocka_unit_test_setup_teardown(test_fail_uncompress_null_dst, setup_uncompress_string1, teardown_uncompress),
        cmocka_unit_test_setup_teardown(test_fail_uncompress_no_src_size, setup_uncompress_string1, teardown_uncompress),
        cmocka_unit_test_setup_teardown(test_fail_uncompress_no_dest_size, setup_uncompress_string1, teardown_uncompress),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
