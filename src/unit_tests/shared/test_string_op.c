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

char * w_tolower_str(const char *string);

/* redefinitons/wrapping */

void __wrap__mwarn(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

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

void test_os_snprintf_short(void **state)
{
    int ret;
    size_t size = 10;
    char str[size + 1];

    ret = os_snprintf(str, size, "%s%3d", "agent", 1);
    assert_int_equal(ret, 8);
}

void test_os_snprintf_long(void **state)
{
    int ret;
    size_t size = 5;
    char str[size + 1];

    expect_string(__wrap__mwarn, formatted_msg,"String may be truncated because it is too long.");
    ret = os_snprintf(str, size, "%s%3d", "agent", 1);
    assert_int_equal(ret, 8);
}

void test_os_snprintf_more_parameters(void **state)
{
    int ret;
    size_t size = 100;
    char str[size + 1];

    ret = os_snprintf(str, size, "%s%3d:%s%s", "agent", 1, "sent ", "message");
    assert_int_equal(ret, 21);
}


/* Tests */

int main(void) {
    const struct CMUnitTest tests[] = {
        //Tests w_tolower_str
        cmocka_unit_test(test_w_tolower_str_NULL),
        cmocka_unit_test(test_w_tolower_str_empty),
        cmocka_unit_test(test_w_tolower_str_caps),
        cmocka_unit_test(test_os_snprintf_short),
        cmocka_unit_test(test_os_snprintf_long),
        cmocka_unit_test(test_os_snprintf_more_parameters)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
