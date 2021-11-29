/*
 * Copyright (C) 2015-2021, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

#include "../../headers/validate_op.h"

/* tests */

void w_validate_bytes_non_number (void **state)
{
    const char * value = "hello";
    long long expected_value = -1;

    long long ret = w_validate_bytes(value);
    assert_memory_equal(&ret, &expected_value, sizeof(long long));
}

void w_validate_bytes_bytes (void **state)
{
    const char * value = "1024B";
    long long expected_value = 1024;

    long long ret = w_validate_bytes(value);
    assert_memory_equal(&ret, &expected_value, sizeof(long long));
}

void w_validate_bytes_kilobytes (void **state)
{
    const char * value = "1024KB";
    long long expected_value = 1024*1024;

    long long ret = w_validate_bytes(value);
    assert_memory_equal(&ret, &expected_value, sizeof(long long));
}

void w_validate_bytes_megabytes (void **state)
{
    const char * value = "1024MB";
    long long expected_value = 1024*1024*1024;

    long long ret = w_validate_bytes(value);
    assert_memory_equal(&ret, &expected_value, sizeof(long long));
}

void w_validate_bytes_gigabytes (void **state)
{
    const char * value = "1024GB";
    long long expected_value = 1024 * ((long long) 1024*1024*1024);

    long long ret = w_validate_bytes(value);
    assert_memory_equal(&ret, &expected_value, sizeof(long long));
}

int main(void) {

    const struct CMUnitTest tests[] = {
        // Tests w_validate_bytes
        cmocka_unit_test(w_validate_bytes_non_number),
        cmocka_unit_test(w_validate_bytes_bytes),
        cmocka_unit_test(w_validate_bytes_kilobytes),
        cmocka_unit_test(w_validate_bytes_megabytes),
        cmocka_unit_test(w_validate_bytes_gigabytes),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
