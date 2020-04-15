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
#include <string.h>
#include <stdlib.h>

#include "../headers/string_op.h"

static int unit_testing;
const void * CALL_REAL_FUNCTION = (void *)0xffffffff;

// mock
void *__real_calloc(size_t num, size_t size);
void *__wrap_calloc(size_t num, size_t size) {
    void * ret_val = mock_ptr_type(void *);

    if (CALL_REAL_FUNCTION == ret_val) {
       ret_val = __real_calloc(num, size);
    } 

    return ret_val;
}
/* setup/teardowns */
static int setup_group(void **state) {
    unit_testing = 1;
    return 0;
}

static int teardown_group(void **state) {
    unit_testing = 0;
    return 0;
}

/* tests */
void test_substr_src_nullptr(void **state)
{
    char dst[] = {""};
    const char * src = NULL;
    int ret_val = os_substr(dst,src, 0, 1);

    assert_int_equal(ret_val, -2);
    assert_string_equal(dst, "");
}

void test_substr_lenght_zero(void **state)
{
    char dst[] = {""};
    int ret_val = os_substr(dst, 0, 0, 0);

    assert_int_equal(ret_val, -3);
    assert_string_equal(dst, "");
}

void test_substr_position_overrun(void **state)
{
    char dst[] = {""};
    const char src[] = {"helloworld\0"};
    int ret_val = os_substr(dst,src, 999, 1);

    assert_int_equal(ret_val, -1);
    assert_string_equal(dst, "");
}
void test_substr_success_case(void **state)
{
    char dst[] = {""};
    const char src[] = {"helloworld"};
    int ret_val = os_substr(dst,src, 5, 5);

    assert_int_equal(ret_val, 0);
    assert_string_equal(dst, "world");
}

void test_trimcrlf_nullptr()
{
    char * str = NULL;
    os_trimcrlf(str);
    assert_null(str);
}
void test_trimcrlf_nosize()
{
    char str[] = {};
    os_trimcrlf(str);
    assert_string_equal(str,"");
}
void test_trimcrlf_cr()
{
    char str[] = { "helloworld\n\n" };
    os_trimcrlf(str);
    assert_string_equal(str, "helloworld");
}
void test_trimcrlf_lf()
{
    char str[] = { "helloworld\r\r" };
    os_trimcrlf(str);
    assert_string_equal(str, "helloworld");
}
void test_trimcrlf_nocr_nolf()
{
    char str[] = { "helloworld" };
    os_trimcrlf(str);
    assert_string_equal(str, "helloworld");
}

void test_trimcrlf_only_crlf()
{
    char str[] = { "\n\r" };
    os_trimcrlf(str);
    assert_string_equal(str, "");
}

void test_shell_escape_nullptr()
{
    const char* str = NULL;
    const char* const escaped_str = os_shell_escape(str);
    assert_null(escaped_str);
}

void test_shell_escape_success_case()
{
    const char str[] = { "hello**world" };
    will_return(__wrap_calloc, CALL_REAL_FUNCTION);
    char* const escaped_str = os_shell_escape(str);
    assert_non_null(escaped_str);
    assert_string_equal(escaped_str, "hello\\*\\*world");
    free(escaped_str);
}

void test_shell_calloc_fail()
{
    const char str[] = { "hello**world" };
    will_return(__wrap_calloc, NULL);
    const char* const escaped_str = os_shell_escape(str);
    assert_null(escaped_str);
}


int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_substr_src_nullptr),
        cmocka_unit_test(test_substr_lenght_zero),
        cmocka_unit_test(test_substr_position_overrun),
        cmocka_unit_test(test_substr_success_case), 
        cmocka_unit_test(test_trimcrlf_nullptr),
        cmocka_unit_test(test_trimcrlf_nosize),
        cmocka_unit_test(test_trimcrlf_cr),
        cmocka_unit_test(test_trimcrlf_lf),
        cmocka_unit_test(test_trimcrlf_nocr_nolf),
        cmocka_unit_test(test_trimcrlf_only_crlf),
        cmocka_unit_test(test_shell_escape_nullptr),
        cmocka_unit_test(test_shell_escape_success_case),
        cmocka_unit_test(test_shell_calloc_fail)
    };
    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
