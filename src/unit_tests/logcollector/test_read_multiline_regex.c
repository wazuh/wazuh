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
#include <time.h>

#include "../../logcollector/logcollector.h"
#include "../../headers/shared.h"

void multiline_replace(char * buffer, w_multiline_replace_type_t type);
bool multiline_ctxt_is_expired(unsigned int timeout, w_multiline_ctxt_t * ctxt);
bool multiline_ctxt_restore(char * buffer, int * readed_lines, w_multiline_ctxt_t * ctxt);
void multiline_ctxt_free(w_multiline_ctxt_t ** ctxt);
void multiline_ctxt_backup(char * buffer, int readed_lines, w_multiline_ctxt_t ** ctxt);

/* setup/teardown */

/* wraps */
time_t __wrap_time(time_t * t) {
    return mock_type(time_t);
}

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
// Test multiline_ctxt_is_expired
void test_multiline_ctxt_is_expired_not_found(void ** state) {
    assert_true(multiline_ctxt_is_expired(1, NULL));
}

void test_multiline_ctxt_is_expired_not_expired(void ** state) {

    w_multiline_ctxt_t ctxt = {.timestamp = 50};
    unsigned int timeout = 75;

    will_return(__wrap_time, (unsigned int) 100);

    assert_false(multiline_ctxt_is_expired(timeout, &ctxt));
}

void test_multiline_ctxt_is_expired_expired(void ** state) {
    w_multiline_ctxt_t ctxt = {.timestamp = 50};
    unsigned int timeout = 10;

    will_return(__wrap_time, (unsigned int) 100);

    assert_true(multiline_ctxt_is_expired(timeout, &ctxt));
}

/* multiline_ctxt_restore */
void test_multiline_ctxt_restore_restore(void ** state) {

    // orginal content
    w_multiline_ctxt_t ctxt = {
        .buffer = "Test buffer",
        .lines_count = 100,
        .timestamp = 0,
    };
    // restore
    int readed_lines = -1;
    char * buffer;
    os_calloc(strlen(ctxt.buffer) + 1, sizeof(char), buffer);

    assert_true(multiline_ctxt_restore(buffer, &readed_lines, &ctxt));
    assert_int_equal(readed_lines, ctxt.lines_count);
    assert_string_equal(buffer, ctxt.buffer);

    os_free(buffer);

}

void test_multiline_ctxt_restore_null(void ** state) {

    // restore
    int readed_lines = -1;
    char * buffer = NULL;

    assert_false(multiline_ctxt_restore(buffer, &readed_lines, NULL));
    assert_int_equal(readed_lines, -1);
    assert_null(buffer);

}

/* multiline_ctxt_free */
void test_multiline_ctxt_free_null(void ** state) {

    w_multiline_ctxt_t * ctxt = NULL;
    multiline_ctxt_free(&ctxt);

}

void test_multiline_ctxt_free_free(void ** state) {

    w_multiline_ctxt_t * ctxt;
    os_calloc(1, sizeof(w_multiline_ctxt_t), ctxt);
    os_calloc(1, sizeof(char), ctxt->buffer);
    multiline_ctxt_free(&ctxt);
    assert_null(ctxt);

}

/* multiline_ctxt_backup */
void test_multiline_ctxt_backup_no_restore(void ** state) {

    char buffer[] = "hi!, no new content";
    int readed_lines = 6;
    w_multiline_ctxt_t * ctxt;
    os_calloc(1, sizeof(w_multiline_ctxt_t), ctxt);
    w_strdup(buffer, ctxt->buffer);
    ctxt->lines_count = readed_lines;
    ctxt->timestamp = (time_t) 5;

    multiline_ctxt_backup(buffer, readed_lines, &ctxt);
    
    assert_int_equal(ctxt->timestamp, 5);
    assert_int_equal(readed_lines, 6);
    assert_string_equal(buffer, ctxt->buffer);

    multiline_ctxt_free(&ctxt);
}

void test_multiline_ctxt_backup_new_ctxt(void ** state) {

    char buffer[] = "hi!, new content";
    int readed_lines = 6;
    w_multiline_ctxt_t * ctxt = NULL;

    will_return(__wrap_time, 10);
    multiline_ctxt_backup(buffer, readed_lines, &ctxt);
    
    assert_int_equal(ctxt->timestamp, 10);
    assert_int_equal(readed_lines, 6);
    assert_string_equal(buffer, ctxt->buffer);

    multiline_ctxt_free(&ctxt);
}

void test_multiline_ctxt_backup_increment(void ** state) {

    char buffer[] = "old content + New content";
    int readed_lines = 6;
    w_multiline_ctxt_t * ctxt;
    os_calloc(1, sizeof(w_multiline_ctxt_t), ctxt);
    w_strdup("old content + ", ctxt->buffer);
    ctxt->lines_count = 5;
    ctxt->timestamp = (time_t) 5;

    will_return(__wrap_time, 10);
    multiline_ctxt_backup(buffer, readed_lines, &ctxt);

    assert_int_equal(ctxt->timestamp, 10);
    assert_int_equal(readed_lines, 6);
    assert_string_equal(buffer, ctxt->buffer);

    multiline_ctxt_free(&ctxt);

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
        // Test multiline_ctxt_is_expired
        cmocka_unit_test(test_multiline_ctxt_is_expired_not_found),
        cmocka_unit_test(test_multiline_ctxt_is_expired_not_expired),
        cmocka_unit_test(test_multiline_ctxt_is_expired_expired),
        // Test multiline_ctxt_restore
        cmocka_unit_test(test_multiline_ctxt_restore_null),
        cmocka_unit_test(test_multiline_ctxt_restore_restore),
        // Test multiline_ctxt_free
        cmocka_unit_test(test_multiline_ctxt_free_null),
        cmocka_unit_test(test_multiline_ctxt_free_free),
        // Test multiline_ctxt_backup
        cmocka_unit_test(test_multiline_ctxt_backup_no_restore),
        cmocka_unit_test(test_multiline_ctxt_backup_new_ctxt),
        cmocka_unit_test(test_multiline_ctxt_backup_increment),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
