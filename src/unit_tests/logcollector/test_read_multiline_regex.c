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

#include "../../logcollector/logcollector.h"
#include "../../headers/shared.h"

void multiline_replace(char * buffer, w_multiline_replace_type_t type);

/* setup/teardown */

/* wraps */

/* tests */

/* read_multiline_regex */
void test_read_multiline_regex(void ** state) { assert_null(read_multiline_regex(NULL, NULL, 0)); }

/* multiline_replace linux */
void test_multiline_replace_ws_not_found(void ** state) {

    char str[] = "test replace white space";
    w_multiline_replace_type_t type = ML_REPLACE_WSPACE;
    const char str_expected[] = "test replace white space";

    multiline_replace(str, type);
    assert_string_equal(str, str_expected);
}

void test_multiline_replace_ws_char_null_str(void ** state) {

    w_multiline_replace_type_t type = ML_REPLACE_WSPACE;
    multiline_replace(NULL, type);
}

void test_multiline_replace_ws_char_empty_str(void ** state) {

    w_multiline_replace_type_t type = ML_REPLACE_WSPACE;
    char str[] = "";
    multiline_replace(str, type);
}

void test_multiline_replace_ws_char_noreplace(void ** state) {

    char str[] = "test replace\nwhite space";
    w_multiline_replace_type_t type = ML_REPLACE_WSPACE;
    const char str_expected[] = "test replace\nwhite space";

    multiline_replace(str, type);
    assert_string_equal(str, str_expected);
}

void test_multiline_replace_ws_char_replace_last(void ** state) {

    char str[] = "test replace\ntab\n";
    w_multiline_replace_type_t type = ML_REPLACE_WSPACE;
    const char str_expected[] = "test replace\ntab ";

    multiline_replace(str, type);
    assert_string_equal(str, str_expected);
}

void test_multiline_replace_tab_not_found(void ** state) {

    char str[] = "test replace tab";
    w_multiline_replace_type_t type = ML_REPLACE_TAB;
    const char str_expected[] = "test replace tab";

    multiline_replace(str, type);
    assert_string_equal(str, str_expected);
}

void test_multiline_replace_tab_char_null_str(void ** state) {

    w_multiline_replace_type_t type = ML_REPLACE_TAB;
    multiline_replace(NULL, type);
}

void test_multiline_replace_tab_char_empty_str(void ** state) {

    w_multiline_replace_type_t type = ML_REPLACE_TAB;
    char str[] = "";
    multiline_replace(str, type);
}

void test_multiline_replace_tab_char_noreplace(void ** state) {

    char str[] = "test replace\ntab";
    w_multiline_replace_type_t type = ML_REPLACE_TAB;
    const char str_expected[] = "test replace\ntab";

    multiline_replace(str, type);
    assert_string_equal(str, str_expected);
}

void test_multiline_replace_tab_char_replace_last(void ** state) {

    char str[] = "test replace\ntab\n";
    w_multiline_replace_type_t type = ML_REPLACE_TAB;
    const char str_expected[] = "test replace\ntab\t";

    multiline_replace(str, type);
    assert_string_equal(str, str_expected);
}

void test_multiline_replace_none_not_found(void ** state) {

    char str[] = "test replace none";
    w_multiline_replace_type_t type = ML_REPLACE_NONE;
    const char str_expected[] = "test replace none";

    multiline_replace(str, type);
    assert_string_equal(str, str_expected);
}

void test_multiline_replace_none_char_null_str(void ** state) {

    w_multiline_replace_type_t type = ML_REPLACE_NONE;
    multiline_replace(NULL, type);
}

void test_multiline_replace_none_char_empty_str(void ** state) {

    w_multiline_replace_type_t type = ML_REPLACE_NONE;
    char str[] = "";
    multiline_replace(str, type);
}

void test_multiline_replace_none_char_noreplace(void ** state) {

    char str[] = "test replace\nnone";
    w_multiline_replace_type_t type = ML_REPLACE_NONE;
    const char str_expected[] = "test replace\nnone";

    multiline_replace(str, type);
    assert_string_equal(str, str_expected);
}

void test_multiline_replace_none_char_replace_last(void ** state) {

    char str[] = "test replace\nnone\n";
    w_multiline_replace_type_t type = ML_REPLACE_NONE;
    const char str_expected[] = "test replace\nnone";

    multiline_replace(str, type);
    assert_string_equal(str, str_expected);
}

void test_multiline_replace_noreplace_not_found(void ** state) {

    char str[] = "test replace no replace";
    w_multiline_replace_type_t type = ML_REPLACE_NO_REPLACE;
    const char str_expected[] = "test replace no replace";

    multiline_replace(str, type);
    assert_string_equal(str, str_expected);
}

void test_multiline_replace_noreplace_char_null_str(void ** state) {

    w_multiline_replace_type_t type = ML_REPLACE_NO_REPLACE;
    multiline_replace(NULL, type);
}

void test_multiline_replace_noreplace_char_replace(void ** state) {

    char str[] = "test replace\nno replace";
    w_multiline_replace_type_t type = ML_REPLACE_NO_REPLACE;
    const char str_expected[] = "test replace\nno replace";

    multiline_replace(str, type);
    assert_string_equal(str, str_expected);
}

void test_multiline_replace_noreplace_char_replace_last(void ** state) {

    char str[] = "test replace\nno replace\n";
    w_multiline_replace_type_t type = ML_REPLACE_NO_REPLACE;
    const char str_expected[] = "test replace\nno replace\n";

    multiline_replace(str, type);
    assert_string_equal(str, str_expected);
}

/* multiline_replace windows */
void test_multiline_replace_w_ws_not_found(void ** state) {

    char str[] = "test replace white space";
    w_multiline_replace_type_t type = ML_REPLACE_WSPACE;
    const char str_expected[] = "test replace white space";

    multiline_replace(str, type);
    assert_string_equal(str, str_expected);
}

void test_multiline_replace_w_ws_char_null_str(void ** state) {

    w_multiline_replace_type_t type = ML_REPLACE_WSPACE;
    multiline_replace(NULL, type);
}

void test_multiline_replace_w_ws_char_noreplace(void ** state) {

    char str[] = "test replace\r\nwhite space";
    w_multiline_replace_type_t type = ML_REPLACE_WSPACE;
    const char str_expected[] = "test replace\r\nwhite space";

    multiline_replace(str, type);
    assert_string_equal(str, str_expected);
}

void test_multiline_replace_w_ws_char_replace_last(void ** state) {

    char str[] = "test replace\r\ntab\r\n";
    w_multiline_replace_type_t type = ML_REPLACE_WSPACE;
    const char str_expected[] = "test replace\r\ntab ";

    multiline_replace(str, type);
    assert_string_equal(str, str_expected);
}

void test_multiline_replace_w_tab_not_found(void ** state) {

    char str[] = "test replace tab";
    w_multiline_replace_type_t type = ML_REPLACE_TAB;
    const char str_expected[] = "test replace tab";

    multiline_replace(str, type);
    assert_string_equal(str, str_expected);
}

void test_multiline_replace_w_tab_char_null_str(void ** state) {

    w_multiline_replace_type_t type = ML_REPLACE_TAB;
    multiline_replace(NULL, type);
}

void test_multiline_replace_w_tab_char_noreplace(void ** state) {

    char str[] = "test replace\r\ntab";
    w_multiline_replace_type_t type = ML_REPLACE_TAB;
    const char str_expected[] = "test replace\r\ntab";

    multiline_replace(str, type);
    assert_string_equal(str, str_expected);
}

void test_multiline_replace_w_tab_char_replace_last(void ** state) {

    char str[] = "test replace\r\ntab\r\n";
    w_multiline_replace_type_t type = ML_REPLACE_TAB;
    const char str_expected[] = "test replace\r\ntab\t";

    multiline_replace(str, type);
    assert_string_equal(str, str_expected);
}

void test_multiline_replace_w_none_not_found(void ** state) {

    char str[] = "test replace none";
    w_multiline_replace_type_t type = ML_REPLACE_NONE;
    const char str_expected[] = "test replace none";

    multiline_replace(str, type);
    assert_string_equal(str, str_expected);
}

void test_multiline_replace_w_none_char_null_str(void ** state) {

    w_multiline_replace_type_t type = ML_REPLACE_NONE;
    multiline_replace(NULL, type);
}

void test_multiline_replace_w_none_char_noreplace(void ** state) {

    char str[] = "test replace\r\nnone";
    w_multiline_replace_type_t type = ML_REPLACE_NONE;
    const char str_expected[] = "test replace\r\nnone";

    multiline_replace(str, type);
    assert_string_equal(str, str_expected);
}

void test_multiline_replace_w_none_char_replace_last(void ** state) {

    char str[] = "test replace\r\nnone\r\n";
    w_multiline_replace_type_t type = ML_REPLACE_NONE;
    const char str_expected[] = "test replace\r\nnone";

    multiline_replace(str, type);
    assert_string_equal(str, str_expected);
}

void test_multiline_replace_w_noreplace_not_found(void ** state) {

    char str[] = "test replace no replace";
    w_multiline_replace_type_t type = ML_REPLACE_NO_REPLACE;
    const char str_expected[] = "test replace no replace";

    multiline_replace(str, type);
    assert_string_equal(str, str_expected);
}

void test_multiline_replace_w_noreplace_char_null_str(void ** state) {

    w_multiline_replace_type_t type = ML_REPLACE_NO_REPLACE;
    multiline_replace(NULL, type);
}

void test_multiline_replace_w_noreplace_char_noreplace(void ** state) {

    char str[] = "test replace\r\nno replace";
    w_multiline_replace_type_t type = ML_REPLACE_NO_REPLACE;
    const char str_expected[] = "test replace\r\nno replace";

    multiline_replace(str, type);
    assert_string_equal(str, str_expected);
}

void test_multiline_replace_w_noreplace_char_replace_last(void ** state) {

    char str[] = "test replace\r\nno replace\r\n";
    w_multiline_replace_type_t type = ML_REPLACE_NO_REPLACE;
    const char str_expected[] = "test replace\r\nno replace\r\n";

    multiline_replace(str, type);
    assert_string_equal(str, str_expected);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // Test read_multiline_regex
        // Test replace_char
        cmocka_unit_test(test_multiline_replace_ws_not_found),
        cmocka_unit_test(test_multiline_replace_ws_char_null_str),
        cmocka_unit_test(test_multiline_replace_ws_char_empty_str),
        cmocka_unit_test(test_multiline_replace_ws_char_noreplace),
        cmocka_unit_test(test_multiline_replace_ws_char_replace_last),
        cmocka_unit_test(test_multiline_replace_tab_not_found),
        cmocka_unit_test(test_multiline_replace_tab_char_null_str),
        cmocka_unit_test(test_multiline_replace_tab_char_empty_str),
        cmocka_unit_test(test_multiline_replace_tab_char_noreplace),
        cmocka_unit_test(test_multiline_replace_tab_char_replace_last),
        cmocka_unit_test(test_multiline_replace_none_not_found),
        cmocka_unit_test(test_multiline_replace_none_char_null_str),
        cmocka_unit_test(test_multiline_replace_none_char_empty_str),
        cmocka_unit_test(test_multiline_replace_none_char_noreplace),
        cmocka_unit_test(test_multiline_replace_none_char_replace_last),
        cmocka_unit_test(test_multiline_replace_noreplace_not_found),
        cmocka_unit_test(test_multiline_replace_noreplace_char_null_str),
        cmocka_unit_test(test_multiline_replace_noreplace_char_replace),
        cmocka_unit_test(test_multiline_replace_noreplace_char_replace_last),
        cmocka_unit_test(test_multiline_replace_w_ws_not_found),
        cmocka_unit_test(test_multiline_replace_w_ws_char_null_str),
        cmocka_unit_test(test_multiline_replace_w_ws_char_noreplace),
        cmocka_unit_test(test_multiline_replace_w_ws_char_replace_last),
        cmocka_unit_test(test_multiline_replace_w_tab_not_found),
        cmocka_unit_test(test_multiline_replace_w_tab_char_null_str),
        cmocka_unit_test(test_multiline_replace_w_tab_char_noreplace),
        cmocka_unit_test(test_multiline_replace_w_tab_char_replace_last),
        cmocka_unit_test(test_multiline_replace_w_none_not_found),
        cmocka_unit_test(test_multiline_replace_w_none_char_null_str),
        cmocka_unit_test(test_multiline_replace_w_none_char_noreplace),
        cmocka_unit_test(test_multiline_replace_w_none_char_replace_last),
        cmocka_unit_test(test_multiline_replace_w_noreplace_not_found),
        cmocka_unit_test(test_multiline_replace_w_noreplace_char_null_str),
        cmocka_unit_test(test_multiline_replace_w_noreplace_char_noreplace),
        cmocka_unit_test(test_multiline_replace_w_noreplace_char_replace_last),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
