/*
 * Copyright (C) 2015-2020, Wazuh Inc.
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

#include "../headers/shared.h"

#define STR_LEN              20
#define SUCCESS               0
#define INVALID_STR_POSITION -1
#define INVALID_STR          -2
#define UNSUPPORTED_LEN_STR  -3

char * w_tolower_str(const char *string);
int os_substr(char *dest, const char *src, size_t position, ssize_t length);

/* tests */

/* w_tolower_str */
void test_w_tolower_str_NULL(void **state)
{
    char * string = NULL;

    char* ret = w_tolower_str(string);
    assert_null(ret);

}

void test_w_tolower_str_empty(void **state)
{
    char * string = "";

    char* ret = w_tolower_str(string);
    assert_string_equal(ret, "");

    os_free(ret);

}

void test_w_tolower_str_caps(void **state)
{
    char * string = "TEST";

    char* ret = w_tolower_str(string);
    assert_string_equal(ret, "test");

    os_free(ret);

}

void test_os_substr_src_NULL(void **state)
{
    const char * string = NULL;
    char dest[STR_LEN];
    const int position = 5;
    const int length = STR_LEN;

    // If the src to make the substr is NULL the method should return
    // -2 (INVALID_STRING).
    const int res = os_substr(dest, string, position, length);

    assert_int_equal(res, INVALID_STR);
}

void test_os_substr_length_negative(void **state)
{
    const char * string = "Source string";
    char dest[STR_LEN];
    const int position = 5;
    const int length = -1;

    // If the length to make the substr is negative the method should return
    // -3 (UNSUPPORTED_LEN_STRING).
    const int res = os_substr(dest, string, position, length);

    assert_string_equal(dest, "");
    assert_int_equal(res, UNSUPPORTED_LEN_STR);
}

void test_os_substr_length_greater_than_src(void **state)
{
    const char * string = "Source string";
    char dest[STR_LEN];
    const int position = 5000;
    const int length = STR_LEN;

    // If the position to make the substr is greater than lenght the method should return
    // -1 (INVALID_STR_POSITION).
    const int res = os_substr(dest, string, position, length);

    assert_string_equal(dest, "");
    assert_int_equal(res, INVALID_STR_POSITION);
}

void test_os_substr_OK(void **state)
{
    const char * string = "Source string";
    char dest[STR_LEN];
    const int position = 7;
    const int length = STR_LEN;

    // From "Source String" taking the position 7, dest should hold "string"
    // word if everything is ok
    const int res = os_substr(dest, string, position, length);

    // os_substr should return only "string" (without "Source")
    assert_string_equal(dest, "string");
    assert_int_equal(res, SUCCESS);
}

/* Tests */

int main(void) {
    const struct CMUnitTest tests[] = {
        //Tests w_tolower_str
        cmocka_unit_test(test_w_tolower_str_NULL),
        cmocka_unit_test(test_w_tolower_str_empty),
        cmocka_unit_test(test_w_tolower_str_caps),
        cmocka_unit_test(test_os_substr_src_NULL),
        cmocka_unit_test(test_os_substr_length_negative),
        cmocka_unit_test(test_os_substr_length_greater_than_src),
        cmocka_unit_test(test_os_substr_OK)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
