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
#include <time.h>

#include "../../logcollector/logcollector.h"
#include "../../headers/shared.h"
#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/file_op_wrappers.h"
#include "../wrappers/libc/stdio_wrappers.h"

void multiline_replace(char * buffer, w_multiline_replace_type_t type);
bool multiline_ctxt_is_expired(time_t timeout, w_multiline_ctxt_t * ctxt);
bool multiline_ctxt_restore(char * buffer, int * readed_lines, w_multiline_ctxt_t * ctxt);
void multiline_ctxt_free(w_multiline_ctxt_t ** ctxt);
void multiline_ctxt_backup(char * buffer, int readed_lines, w_multiline_ctxt_t ** ctxt);

int multiline_getlog_start(char * buffer, int length, FILE * stream, w_multiline_config_t * ml_cfg);
int multiline_getlog_end(char * buffer, int length, FILE * stream, w_multiline_config_t * ml_cfg);
int multiline_getlog_all(char * buffer, int length, FILE * stream, w_multiline_config_t * ml_cfg);
int multiline_getlog(char * buffer, int length, FILE * stream, w_multiline_config_t * ml_cfg);
void * read_multiline_regex(logreader * lf, int * rc, int drop_it);
char * get_file_chunk(FILE * stream, int64_t initial_pos, int64_t final_pos);

/* setup/teardown */

static int group_setup(void ** state) {
    test_mode = 1;
    return 0;
}

static int group_teardown(void ** state) {
    test_mode = 0;
    return 0;
}

/* wraps */
int __wrap_can_read() {
    return mock_type(int);
}

bool __wrap_w_expression_match(w_expression_t * expression, const char * str_test, const char ** end_match,
                               regex_matching * regex_match) {
    return mock_type(bool);
}

int __wrap_w_msg_hash_queues_push(const char * str, char * file, unsigned long size, logtarget * targets,
                                  char queue_mq) {
    return mock_type(int);
}

bool __wrap_w_get_hash_context(const char * path, EVP_MD_CTX * context, int64_t position) {
    return mock_type(bool);
}

int __wrap_w_update_file_status(const char * path, int64_t pos, EVP_MD_CTX * context) {
    bool free_context = mock_type(bool);
    if (free_context) {
        EVP_MD_CTX_free(context);
    }
    return mock_type(int);
}

void __wrap_OS_SHA1_Stream(EVP_MD_CTX *c, os_sha1 output, char * buf) {
    function_called();
    return;
}

/* tests */

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
void test_multiline_ctxt_is_expired_not_found(void ** state) { assert_true(multiline_ctxt_is_expired(1, NULL)); }

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

/* multiline_getlog_start */
void test_multiline_getlog_start_single_no_context(void ** state) {

    int retval;
    const size_t buffer_size = 500;
    const time_t timeout = (time_t) 100;
    char buffer[500 + 1];
    w_multiline_config_t ml_confg = {0};

    ml_confg.timeout = timeout;
    ml_confg.replace_type = ML_REPLACE_NO_REPLACE;
    ml_confg.match_type = ML_MATCH_START;

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);
    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "no match\n");

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);
    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, NULL);

    will_return(__wrap_time, 1);

    retval = multiline_getlog_start(buffer, buffer_size, 0, &ml_confg);

    assert_int_equal(retval, 0);
    assert_string_equal(ml_confg.ctxt->buffer, "no match\n");
    assert_int_equal(ml_confg.ctxt->lines_count, 1);
    assert_int_equal(ml_confg.ctxt->timestamp, 1);
    multiline_ctxt_free(&ml_confg.ctxt);
}

void test_multiline_getlog_start_ctxt_timeout(void ** state) {
    int retval;
    const size_t buffer_size = 500;
    const time_t timeout = (time_t) 100;
    char buffer[500 + 1] = {0};

    w_multiline_config_t ml_confg = {0};
    os_calloc(1, sizeof(w_multiline_config_t), ml_confg.ctxt);
    ml_confg.timeout = timeout;
    ml_confg.replace_type = ML_REPLACE_NO_REPLACE;
    ml_confg.match_type = ML_MATCH_START;
    os_strdup("no match\n", ml_confg.ctxt->buffer);
    ml_confg.ctxt->lines_count = 1;
    ml_confg.ctxt->timestamp = 0;

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);
    will_return(__wrap_time, timeout + 1);

    retval = multiline_getlog_start(buffer, buffer_size, 0, &ml_confg);

    assert_int_equal(retval, 1);
    assert_null(ml_confg.ctxt);
    assert_string_equal(buffer, "no match");
}

void test_multiline_getlog_start_ctxt_append_ctxt(void ** state) {

    int retval;
    const size_t buffer_size = 500;
    const time_t timeout = (time_t) 100;
    char buffer[500 + 1] = {0};
    const char * msg = "no match\nno match2\n";
    w_multiline_config_t ml_confg = {0};
    os_calloc(1, sizeof(w_multiline_config_t), ml_confg.ctxt);
    os_strdup(msg, ml_confg.ctxt->buffer);
    ml_confg.ctxt->lines_count = 2;
    ml_confg.ctxt->timestamp = 0;
    ml_confg.timeout = timeout;

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, 0);
    will_return(__wrap_time, timeout - 1);

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "no match3\n");
    will_return(__wrap_w_expression_match, false);
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, 0);

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, NULL);
    will_return(__wrap_time, timeout);

    retval = multiline_getlog_start(buffer, buffer_size, 0, &ml_confg);

    assert_int_equal(retval, 0);
    assert_non_null(ml_confg.ctxt);
    assert_string_equal(ml_confg.ctxt->buffer, "no match\nno match2\nno match3\n");
    assert_int_equal(ml_confg.ctxt->lines_count, 3);
    assert_int_equal(ml_confg.ctxt->timestamp, timeout);
    multiline_ctxt_free(&ml_confg.ctxt);
}

void test_multiline_getlog_start_ctxt_match(void ** state) {

    int retval;
    const size_t buffer_size = 500;
    const time_t timeout = (time_t) 100;
    char buffer[500 + 1] = {0};
    const char * msg = "no match\nno match2\n";
    w_multiline_config_t ml_confg = {0};
    os_calloc(1, sizeof(w_multiline_config_t), ml_confg.ctxt);
    os_strdup(msg, ml_confg.ctxt->buffer);
    ml_confg.ctxt->lines_count = 2;
    ml_confg.ctxt->timestamp = 0;
    ml_confg.timeout = timeout;

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, 0);
    will_return(__wrap_time, timeout - 1);

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "match");
    will_return(__wrap_w_expression_match, true);

    expect_any(__wrap_w_fseek, x);
    expect_value(__wrap_w_fseek, pos, 0);
    will_return(__wrap_w_fseek, 0);

    retval = multiline_getlog_start(buffer, buffer_size, 0, &ml_confg);

    assert_int_equal(retval, 2);
    assert_null(ml_confg.ctxt);
    assert_string_equal(buffer, "no match\nno match2");
}

void test_multiline_getlog_start_no_ctxt_match(void ** state) {

    int retval;
    const size_t buffer_size = 500;
    const time_t timeout = (time_t) 100;
    char buffer[500 + 1];
    w_multiline_config_t ml_confg = {0};

    ml_confg.timeout = timeout;
    ml_confg.replace_type = ML_REPLACE_NO_REPLACE;
    ml_confg.match_type = ML_MATCH_START;

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "no match\n");
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "no match2\n");
    will_return(__wrap_w_expression_match, false);
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "match");
    will_return(__wrap_w_expression_match, true);

    expect_any(__wrap_w_fseek, x);
    expect_value(__wrap_w_fseek, pos, 0);
    will_return(__wrap_w_fseek, 0);

    retval = multiline_getlog_start(buffer, buffer_size, 0, &ml_confg);

    assert_int_equal(retval, 2);
    assert_string_equal(buffer, "no match\nno match2");
    assert_null(ml_confg.ctxt);
}

void test_multiline_getlog_start_no_ctxt_overflow(void ** state) {

    int retval;
    const size_t buffer_size = 20;
    const time_t timeout = (time_t) 100;
    char buffer[20];
    w_multiline_config_t ml_confg = {0};

    ml_confg.timeout = timeout;
    ml_confg.replace_type = ML_REPLACE_NO_REPLACE;
    ml_confg.match_type = ML_MATCH_START;

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, 0);
    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "01234567890123456789------");

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, 0);
    will_return(__wrap_fgetc, '-');
    will_return(__wrap_fgetc, '-');
    will_return(__wrap_fgetc, '-');
    will_return(__wrap_fgetc, '-');
    will_return(__wrap_fgetc, '-');
    will_return(__wrap_fgetc, '-');
    will_return(__wrap_fgetc, '\0');

    retval = multiline_getlog_start(buffer, buffer_size, 0, &ml_confg);
    assert_int_equal(retval, 1);
    assert_null(ml_confg.ctxt);
    assert_string_equal(buffer, "0123456789012345678");
}

void test_multiline_getlog_start_ctxt_overflow(void ** state) {

    int retval;
    const size_t buffer_size = 20;
    const time_t timeout = (time_t) 100;
    char buffer[20];
    w_multiline_config_t ml_confg = {0};

    const char * msg = "123456789\n";
    os_calloc(1, sizeof(w_multiline_config_t), ml_confg.ctxt);
    os_strdup(msg, ml_confg.ctxt->buffer);
    ml_confg.timeout = timeout;
    ml_confg.replace_type = ML_REPLACE_NO_REPLACE;
    ml_confg.match_type = ML_MATCH_START;

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, 0);
    will_return(__wrap_time, 0);

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "0123456789------");

    will_return(__wrap_w_expression_match, false);
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, 0);
    will_return(__wrap_fgetc, '-');
    will_return(__wrap_fgetc, '-');
    will_return(__wrap_fgetc, '-');
    will_return(__wrap_fgetc, '-');
    will_return(__wrap_fgetc, '-');
    will_return(__wrap_fgetc, '-');
    will_return(__wrap_fgetc, '\0');

    retval = multiline_getlog_start(buffer, buffer_size, 0, &ml_confg);
    assert_int_equal(retval, 1);
    assert_null(ml_confg.ctxt);
    assert_string_equal(buffer, "123456789\n012345678");
}

void test_multiline_getlog_start_no_ctxt_cant_read(void ** state) {

    int retval;
    const size_t buffer_size = 20;
    const time_t timeout = (time_t) 100;
    char buffer[20];
    w_multiline_config_t ml_confg = {0};

    ml_confg.timeout = timeout;
    ml_confg.replace_type = ML_REPLACE_NO_REPLACE;
    ml_confg.match_type = ML_MATCH_START;

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, 0);
    will_return(__wrap_can_read, 0);
    retval = multiline_getlog_start(buffer, buffer_size, 0, &ml_confg);
    assert_int_equal(retval, 0);
    assert_null(ml_confg.ctxt);
}

void test_multiline_getlog_start_ctxt_cant_read(void ** state) {

    int retval;
    const size_t buffer_size = 20;
    const time_t timeout = (time_t) 100;
    char buffer[20];
    w_multiline_config_t ml_confg = {0};

    const char * msg = "123456789\n";
    os_calloc(1, sizeof(w_multiline_config_t), ml_confg.ctxt);
    os_strdup(msg, ml_confg.ctxt->buffer);
    ml_confg.timeout = timeout;
    ml_confg.replace_type = ML_REPLACE_NO_REPLACE;
    ml_confg.match_type = ML_MATCH_START;
    ml_confg.ctxt->lines_count = 1;

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, 0);
    will_return(__wrap_time, 0);

    will_return(__wrap_can_read, 0);
    retval = multiline_getlog_start(buffer, buffer_size, 0, &ml_confg);
    assert_int_equal(retval, 0);
    assert_non_null(ml_confg.ctxt);
    assert_string_equal(ml_confg.ctxt->buffer, "123456789\n");
    assert_int_equal(ml_confg.ctxt->lines_count, 1);
    multiline_ctxt_free(&ml_confg.ctxt);
}

void test_multiline_getlog_start_match_multi_replace(void ** state) {
    int retval;
    const size_t buffer_size = 500;
    const time_t timeout = (time_t) 100;
    char buffer[500 + 1];
    w_multiline_config_t ml_confg = {0};

    ml_confg.timeout = timeout;
    ml_confg.replace_type = ML_REPLACE_NONE;
    ml_confg.match_type = ML_MATCH_START;

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, 0);
    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "no match-\n");

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, 0);
    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, ">no match2\n");

    will_return(__wrap_w_expression_match, false);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, 0);
    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "next header");
    will_return(__wrap_w_expression_match, true);
    expect_any(__wrap_w_fseek, x);
    expect_value(__wrap_w_fseek, pos, 0);
    will_return(__wrap_w_fseek, 0);

    retval = multiline_getlog_start(buffer, buffer_size, 0, &ml_confg);

    assert_int_equal(retval, 2);
    assert_null(ml_confg.ctxt);
    assert_string_equal(buffer, "no match->no match2");
}

/* multiline_getlog_end_single */
void test_multiline_getlog_end_single_match_no_context(void ** state) {

    int retval;
    const size_t buffer_size = 500;
    const time_t timeout = (time_t) 100;
    char buffer[500];
    w_multiline_config_t ml_confg = {0};

    ml_confg.timeout = timeout;
    ml_confg.replace_type = ML_REPLACE_NO_REPLACE;
    ml_confg.match_type = ML_MATCH_END;

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "end match\n");
    will_return(__wrap_w_expression_match, true);

    retval = multiline_getlog_end(buffer, buffer_size, 0, &ml_confg);

    assert_int_equal(retval, 1);
    assert_null(ml_confg.ctxt);
    assert_string_equal(buffer, "end match");
}

void test_multiline_getlog_end_ctxt_timeout(void ** state) {

    int retval;
    const size_t buffer_size = 500;
    const time_t timeout = (time_t) 100;
    char buffer[500 + 1] = {0};

    w_multiline_config_t ml_confg = {0};
    os_calloc(1, sizeof(w_multiline_config_t), ml_confg.ctxt);
    ml_confg.timeout = timeout;
    ml_confg.replace_type = ML_REPLACE_NO_REPLACE;
    ml_confg.match_type = ML_MATCH_END;
    os_strdup("no match\n", ml_confg.ctxt->buffer);
    ml_confg.ctxt->lines_count = 1;
    ml_confg.ctxt->timestamp = 0;

    will_return(__wrap_time, timeout + 1);

    retval = multiline_getlog_end(buffer, buffer_size, 0, &ml_confg);

    assert_int_equal(retval, 1);
    assert_null(ml_confg.ctxt);
    assert_string_equal(buffer, "no match");
}

void test_multiline_getlog_end_ctxt_append_ctxt(void ** state) {

    int retval;
    const size_t buffer_size = 500;
    const time_t timeout = (time_t) 100;
    char buffer[500 + 1] = {0};
    const char * msg = "no match\nno match2\n";
    w_multiline_config_t ml_confg = {0};
    os_calloc(1, sizeof(w_multiline_config_t), ml_confg.ctxt);
    os_strdup(msg, ml_confg.ctxt->buffer);
    ml_confg.ctxt->lines_count = 2;
    ml_confg.ctxt->timestamp = 0;
    ml_confg.timeout = timeout;

    will_return(__wrap_time, timeout - 1);

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "no match3\n");
    will_return(__wrap_w_expression_match, false);

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, NULL);
    will_return(__wrap_time, timeout);

    retval = multiline_getlog_end(buffer, buffer_size, 0, &ml_confg);

    assert_int_equal(retval, 0);
    assert_non_null(ml_confg.ctxt);
    assert_string_equal(ml_confg.ctxt->buffer, "no match\nno match2\nno match3\n");
    assert_int_equal(ml_confg.ctxt->lines_count, 3);
    assert_int_equal(ml_confg.ctxt->timestamp, timeout);
    multiline_ctxt_free(&ml_confg.ctxt);
}

void test_multiline_getlog_end_multi_match_no_context(void ** state) {
    int retval;
    const size_t buffer_size = 500;
    const time_t timeout = (time_t) 100;
    char buffer[500];
    w_multiline_config_t ml_confg = {0};

    os_calloc(1, sizeof(w_multiline_config_t), ml_confg.ctxt);
    os_strdup("initial\n ctx\n", ml_confg.ctxt->buffer);
    ml_confg.ctxt->lines_count = 2;
    ml_confg.ctxt->timestamp = 0;
    ml_confg.timeout = timeout;
    ml_confg.replace_type = ML_REPLACE_NO_REPLACE;
    ml_confg.match_type = ML_MATCH_END;

    will_return(__wrap_time, timeout - 1);
    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "no match\n");
    will_return(__wrap_w_expression_match, false);

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "end match\n");
    will_return(__wrap_w_expression_match, true);

    retval = multiline_getlog_end(buffer, buffer_size, 0, &ml_confg);

    assert_int_equal(retval, 4);
    assert_null(ml_confg.ctxt);
    assert_string_equal(buffer, "initial\n ctx\nno match\nend match");
}

void test_multiline_getlog_end_multi_match_context(void ** state) {

    int retval;
    const size_t buffer_size = 500;
    const time_t timeout = (time_t) 100;
    char buffer[500];
    w_multiline_config_t ml_confg = {0};

    ml_confg.timeout = timeout;
    ml_confg.replace_type = ML_REPLACE_NO_REPLACE;
    ml_confg.match_type = ML_MATCH_END;

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "no match\n");
    will_return(__wrap_w_expression_match, false);

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "end match\n");
    will_return(__wrap_w_expression_match, true);

    retval = multiline_getlog_end(buffer, buffer_size, 0, &ml_confg);

    assert_int_equal(retval, 2);
    assert_null(ml_confg.ctxt);
    assert_string_equal(buffer, "no match\nend match");
}

void test_multiline_getlog_end_no_ctxt_overflow(void ** state) {

    int retval;
    const size_t buffer_size = 20;
    const time_t timeout = (time_t) 100;
    char buffer[20];
    w_multiline_config_t ml_confg = {0};

    ml_confg.timeout = timeout;
    ml_confg.replace_type = ML_REPLACE_NO_REPLACE;
    ml_confg.match_type = ML_MATCH_END;

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "01234567890123456789------");
    will_return(__wrap_w_expression_match, false);

    will_return(__wrap_fgetc, '-');
    will_return(__wrap_fgetc, '-');
    will_return(__wrap_fgetc, '-');
    will_return(__wrap_fgetc, '-');
    will_return(__wrap_fgetc, '-');
    will_return(__wrap_fgetc, '-');
    will_return(__wrap_fgetc, '\0');

    retval = multiline_getlog_end(buffer, buffer_size, 0, &ml_confg);
    assert_int_equal(retval, 1);
    assert_null(ml_confg.ctxt);
    assert_string_equal(buffer, "0123456789012345678");
}

void test_multiline_getlog_end_ctxt_overflow(void ** state) {
    int retval;
    const size_t buffer_size = 20;
    const time_t timeout = (time_t) 100;
    char buffer[20];
    w_multiline_config_t ml_confg = {0};

    const char * msg = "123456789\n";
    os_calloc(1, sizeof(w_multiline_config_t), ml_confg.ctxt);
    os_strdup(msg, ml_confg.ctxt->buffer);
    ml_confg.timeout = timeout;
    ml_confg.replace_type = ML_REPLACE_NO_REPLACE;
    ml_confg.match_type = ML_MATCH_END;

    will_return(__wrap_time, 0);

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "0123456789------");

    will_return(__wrap_w_expression_match, false);
    will_return(__wrap_fgetc, '-');
    will_return(__wrap_fgetc, '-');
    will_return(__wrap_fgetc, '-');
    will_return(__wrap_fgetc, '-');
    will_return(__wrap_fgetc, '-');
    will_return(__wrap_fgetc, '-');
    will_return(__wrap_fgetc, '\0');

    retval = multiline_getlog_end(buffer, buffer_size, 0, &ml_confg);
    assert_int_equal(retval, 1);
    assert_null(ml_confg.ctxt);
    assert_string_equal(buffer, "123456789\n012345678");
}

void test_multiline_getlog_end_no_ctxt_cant_read(void ** state) {

    int retval;
    const size_t buffer_size = 20;
    const time_t timeout = (time_t) 100;
    char buffer[20];
    w_multiline_config_t ml_confg = {0};

    ml_confg.timeout = timeout;
    ml_confg.replace_type = ML_REPLACE_NO_REPLACE;
    ml_confg.match_type = ML_MATCH_END;

    will_return(__wrap_can_read, 0);
    retval = multiline_getlog_end(buffer, buffer_size, 0, &ml_confg);
    assert_int_equal(retval, 0);
    assert_null(ml_confg.ctxt);
}

void test_multiline_getlog_end_ctxt_cant_read(void ** state) {

    int retval;
    const size_t buffer_size = 20;
    const time_t timeout = (time_t) 100;
    char buffer[20];
    w_multiline_config_t ml_confg = {0};

    const char * msg = "123456789\n";
    os_calloc(1, sizeof(w_multiline_config_t), ml_confg.ctxt);
    os_strdup(msg, ml_confg.ctxt->buffer);
    ml_confg.timeout = timeout;
    ml_confg.replace_type = ML_REPLACE_NO_REPLACE;
    ml_confg.match_type = ML_MATCH_END;
    ml_confg.ctxt->lines_count = 1;

    will_return(__wrap_time, 0);

    will_return(__wrap_can_read, 0);
    retval = multiline_getlog_end(buffer, buffer_size, 0, &ml_confg);
    assert_int_equal(retval, 0);
    assert_non_null(ml_confg.ctxt);
    assert_string_equal(ml_confg.ctxt->buffer, "123456789\n");
    assert_int_equal(ml_confg.ctxt->lines_count, 1);
    multiline_ctxt_free(&ml_confg.ctxt);
}

void test_multiline_getlog_end_match_multi_replace(void ** state) {
    int retval;
    const size_t buffer_size = 500;
    const time_t timeout = (time_t) 100;
    char buffer[500];
    w_multiline_config_t ml_confg = {0};

    os_calloc(1, sizeof(w_multiline_config_t), ml_confg.ctxt);
    os_strdup("initial ctx", ml_confg.ctxt->buffer);
    ml_confg.ctxt->lines_count = 2;
    ml_confg.ctxt->timestamp = 0;
    ml_confg.timeout = timeout;
    ml_confg.replace_type = ML_REPLACE_NONE;
    ml_confg.match_type = ML_MATCH_END;

    will_return(__wrap_time, timeout - 1);
    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "no match\n");
    will_return(__wrap_w_expression_match, false);

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "end match\n");
    will_return(__wrap_w_expression_match, true);

    retval = multiline_getlog_end(buffer, buffer_size, 0, &ml_confg);

    assert_int_equal(retval, 4);
    assert_null(ml_confg.ctxt);
    assert_string_equal(buffer, "initial ctxno matchend match");
}

// Test multiline_getlog_all
void test_multiline_getlog_all_single_match_no_context(void ** state) {

    int retval;
    const size_t buffer_size = 500;
    const time_t timeout = (time_t) 100;
    char buffer[500];
    w_multiline_config_t ml_confg = {0};

    ml_confg.timeout = timeout;
    ml_confg.replace_type = ML_REPLACE_NO_REPLACE;
    ml_confg.match_type = ML_MATCH_ALL;

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "all match\n");
    will_return(__wrap_w_expression_match, true);

    retval = multiline_getlog_all(buffer, buffer_size, 0, &ml_confg);

    assert_int_equal(retval, 1);
    assert_null(ml_confg.ctxt);
    assert_string_equal(buffer, "all match");
}

void test_multiline_getlog_all_ctxt_timeout(void ** state) {

    int retval;
    const size_t buffer_size = 500;
    const time_t timeout = (time_t) 100;
    char buffer[500 + 1] = {0};

    w_multiline_config_t ml_confg = {0};
    os_calloc(1, sizeof(w_multiline_config_t), ml_confg.ctxt);
    ml_confg.timeout = timeout;
    ml_confg.replace_type = ML_REPLACE_NO_REPLACE;
    ml_confg.match_type = ML_MATCH_ALL;
    os_strdup("no match\n", ml_confg.ctxt->buffer);
    ml_confg.ctxt->lines_count = 1;
    ml_confg.ctxt->timestamp = 0;

    will_return(__wrap_time, timeout + 1);

    retval = multiline_getlog_all(buffer, buffer_size, 0, &ml_confg);

    assert_int_equal(retval, 1);
    assert_null(ml_confg.ctxt);
    assert_string_equal(buffer, "no match");
}

void test_multiline_getlog_all_ctxt_append_ctxt(void ** state) {

    int retval;
    const size_t buffer_size = 500;
    const time_t timeout = (time_t) 100;
    char buffer[500 + 1] = {0};
    const char * msg = "no match\nno match2\n";
    w_multiline_config_t ml_confg = {0};
    os_calloc(1, sizeof(w_multiline_config_t), ml_confg.ctxt);
    os_strdup(msg, ml_confg.ctxt->buffer);
    ml_confg.ctxt->lines_count = 2;
    ml_confg.ctxt->timestamp = 0;
    ml_confg.timeout = timeout;

    will_return(__wrap_time, timeout - 1);

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "no match3\n");
    will_return(__wrap_w_expression_match, false);

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, NULL);
    will_return(__wrap_time, timeout);

    retval = multiline_getlog_all(buffer, buffer_size, 0, &ml_confg);

    assert_int_equal(retval, 0);
    assert_non_null(ml_confg.ctxt);
    assert_string_equal(ml_confg.ctxt->buffer, "no match\nno match2\nno match3\n");
    assert_int_equal(ml_confg.ctxt->lines_count, 3);
    assert_int_equal(ml_confg.ctxt->timestamp, timeout);
    multiline_ctxt_free(&ml_confg.ctxt);
}

void test_multiline_getlog_all_multi_match_no_context(void ** state) {
    int retval;
    const size_t buffer_size = 500;
    const time_t timeout = (time_t) 100;
    char buffer[500];
    w_multiline_config_t ml_confg = {0};

    os_calloc(1, sizeof(w_multiline_config_t), ml_confg.ctxt);
    os_strdup("initial\n ctx\n", ml_confg.ctxt->buffer);
    ml_confg.ctxt->lines_count = 2;
    ml_confg.ctxt->timestamp = 0;
    ml_confg.timeout = timeout;
    ml_confg.replace_type = ML_REPLACE_NO_REPLACE;
    ml_confg.match_type = ML_MATCH_ALL;

    will_return(__wrap_time, timeout - 1);
    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "no match\n");
    will_return(__wrap_w_expression_match, false);

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "end match\n");
    will_return(__wrap_w_expression_match, true);

    retval = multiline_getlog_all(buffer, buffer_size, 0, &ml_confg);

    assert_int_equal(retval, 4);
    assert_null(ml_confg.ctxt);
    assert_string_equal(buffer, "initial\n ctx\nno match\nend match");
}

void test_multiline_getlog_all_multi_match_context(void ** state) {

    int retval;
    const size_t buffer_size = 500;
    const time_t timeout = (time_t) 100;
    char buffer[500];
    w_multiline_config_t ml_confg = {0};

    ml_confg.timeout = timeout;
    ml_confg.replace_type = ML_REPLACE_NO_REPLACE;
    ml_confg.match_type = ML_MATCH_ALL;

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "no match\n");
    will_return(__wrap_w_expression_match, false);

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "end match\n");
    will_return(__wrap_w_expression_match, true);

    retval = multiline_getlog_all(buffer, buffer_size, 0, &ml_confg);

    assert_int_equal(retval, 2);
    assert_null(ml_confg.ctxt);
    assert_string_equal(buffer, "no match\nend match");
}

void test_multiline_getlog_all_no_ctxt_overflow(void ** state) {

    int retval;
    const size_t buffer_size = 20;
    const time_t timeout = (time_t) 100;
    char buffer[20];
    w_multiline_config_t ml_confg = {0};

    ml_confg.timeout = timeout;
    ml_confg.replace_type = ML_REPLACE_NO_REPLACE;
    ml_confg.match_type = ML_MATCH_ALL;

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "01234567890123456789------");
    will_return(__wrap_w_expression_match, false);

    will_return(__wrap_fgetc, '-');
    will_return(__wrap_fgetc, '-');
    will_return(__wrap_fgetc, '-');
    will_return(__wrap_fgetc, '-');
    will_return(__wrap_fgetc, '-');
    will_return(__wrap_fgetc, '-');
    will_return(__wrap_fgetc, '\0');

    retval = multiline_getlog_all(buffer, buffer_size, 0, &ml_confg);
    assert_int_equal(retval, 1);
    assert_null(ml_confg.ctxt);
    assert_string_equal(buffer, "0123456789012345678");
}

void test_multiline_getlog_all_ctxt_overflow(void ** state) {
    int retval;
    const size_t buffer_size = 20;
    const time_t timeout = (time_t) 100;
    char buffer[20];
    w_multiline_config_t ml_confg = {0};

    const char * msg = "123456789\n";
    os_calloc(1, sizeof(w_multiline_config_t), ml_confg.ctxt);
    os_strdup(msg, ml_confg.ctxt->buffer);
    ml_confg.timeout = timeout;
    ml_confg.replace_type = ML_REPLACE_NO_REPLACE;
    ml_confg.match_type = ML_MATCH_ALL;

    will_return(__wrap_time, 0);

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "0123456789------");

    will_return(__wrap_w_expression_match, false);
    will_return(__wrap_fgetc, '-');
    will_return(__wrap_fgetc, '-');
    will_return(__wrap_fgetc, '-');
    will_return(__wrap_fgetc, '-');
    will_return(__wrap_fgetc, '-');
    will_return(__wrap_fgetc, '-');
    will_return(__wrap_fgetc, '\0');

    retval = multiline_getlog_all(buffer, buffer_size, 0, &ml_confg);
    assert_int_equal(retval, 1);
    assert_null(ml_confg.ctxt);
    assert_string_equal(buffer, "123456789\n012345678");
}

void test_multiline_getlog_all_no_ctxt_cant_read(void ** state) {

    int retval;
    const size_t buffer_size = 20;
    const time_t timeout = (time_t) 100;
    char buffer[20];
    w_multiline_config_t ml_confg = {0};

    ml_confg.timeout = timeout;
    ml_confg.replace_type = ML_REPLACE_NO_REPLACE;
    ml_confg.match_type = ML_MATCH_ALL;

    will_return(__wrap_can_read, 0);
    retval = multiline_getlog_all(buffer, buffer_size, 0, &ml_confg);
    assert_int_equal(retval, 0);
    assert_null(ml_confg.ctxt);
}

void test_multiline_getlog_all_ctxt_cant_read(void ** state) {

    int retval;
    const size_t buffer_size = 20;
    const time_t timeout = (time_t) 100;
    char buffer[20];
    w_multiline_config_t ml_confg = {0};

    const char * msg = "123456789\n";
    os_calloc(1, sizeof(w_multiline_config_t), ml_confg.ctxt);
    os_strdup(msg, ml_confg.ctxt->buffer);
    ml_confg.timeout = timeout;
    ml_confg.replace_type = ML_REPLACE_NO_REPLACE;
    ml_confg.match_type = ML_MATCH_ALL;
    ml_confg.ctxt->lines_count = 1;

    will_return(__wrap_time, 0);

    will_return(__wrap_can_read, 0);
    retval = multiline_getlog_all(buffer, buffer_size, 0, &ml_confg);
    assert_int_equal(retval, 0);
    assert_non_null(ml_confg.ctxt);
    assert_string_equal(ml_confg.ctxt->buffer, "123456789\n");
    assert_int_equal(ml_confg.ctxt->lines_count, 1);
    multiline_ctxt_free(&ml_confg.ctxt);
}

void test_multiline_getlog_all_match_multi_replace(void ** state) {
    int retval;
    const size_t buffer_size = 500;
    const time_t timeout = (time_t) 100;
    char buffer[500];
    w_multiline_config_t ml_confg = {0};

    os_calloc(1, sizeof(w_multiline_config_t), ml_confg.ctxt);
    os_strdup("initial ctx", ml_confg.ctxt->buffer);
    ml_confg.ctxt->lines_count = 2;
    ml_confg.ctxt->timestamp = 0;
    ml_confg.timeout = timeout;
    ml_confg.replace_type = ML_REPLACE_NONE;
    ml_confg.match_type = ML_MATCH_ALL;

    will_return(__wrap_time, timeout - 1);
    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "no match\n");
    will_return(__wrap_w_expression_match, false);

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "end match\n");
    will_return(__wrap_w_expression_match, true);

    retval = multiline_getlog_all(buffer, buffer_size, 0, &ml_confg);

    assert_int_equal(retval, 4);
    assert_null(ml_confg.ctxt);
    assert_string_equal(buffer, "initial ctxno matchend match");
}

/* multiline_getlog */
void test_multiline_getlog_unknown(void ** state) {

    char buffer[] = "1234567890";
    int length = 100;
    int retval;
    w_multiline_config_t ml_cfg = {0};
    ml_cfg.match_type = ML_MATCH_MAX;

    retval = multiline_getlog(buffer, length, 0, &ml_cfg);

    assert_int_equal(retval, 0);
    assert_int_equal(strlen(buffer), 0);
}

void test_multiline_getlog_start(void ** state) {

    int retval;
    const size_t buffer_size = 500;
    const time_t timeout = (time_t) 100;
    char buffer[500] = {0};
    const char * msg = "no match\nno match2\n";
    w_multiline_config_t ml_confg = {0};

    os_calloc(1, sizeof(w_multiline_config_t), ml_confg.ctxt);
    os_strdup(msg, ml_confg.ctxt->buffer);
    ml_confg.ctxt->lines_count = 2;
    ml_confg.ctxt->timestamp = 0;
    ml_confg.timeout = timeout;
    ml_confg.match_type = ML_MATCH_START;

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, 0);
    will_return(__wrap_time, timeout - 1);

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "match");
    will_return(__wrap_w_expression_match, true);
    expect_any(__wrap_w_fseek, x);
    expect_value(__wrap_w_fseek, pos, 0);
    will_return(__wrap_w_fseek, 0);

    retval = multiline_getlog(buffer, buffer_size, 0, &ml_confg);

    assert_int_equal(retval, 2);
    assert_null(ml_confg.ctxt);
    assert_string_equal(buffer, "no match\nno match2");
}

void test_multiline_getlog_end(void ** state) {

    int retval;
    const size_t buffer_size = 500;
    const time_t timeout = (time_t) 100;
    char buffer[500];
    w_multiline_config_t ml_confg = {0};

    ml_confg.timeout = timeout;
    ml_confg.replace_type = ML_REPLACE_NO_REPLACE;
    ml_confg.match_type = ML_MATCH_END;

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "end match\n");
    will_return(__wrap_w_expression_match, true);

    retval = multiline_getlog(buffer, buffer_size, 0, &ml_confg);

    assert_int_equal(retval, 1);
    assert_null(ml_confg.ctxt);
    assert_string_equal(buffer, "end match");
}

void test_multiline_getlog_all(void ** state) {

    int retval;
    const size_t buffer_size = 500;
    const time_t timeout = (time_t) 100;
    char buffer[500];
    w_multiline_config_t ml_confg = {0};

    ml_confg.timeout = timeout;
    ml_confg.replace_type = ML_REPLACE_NO_REPLACE;
    ml_confg.match_type = ML_MATCH_ALL;

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "end match\n");
    will_return(__wrap_w_expression_match, true);

    retval = multiline_getlog(buffer, buffer_size, 0, &ml_confg);

    assert_int_equal(retval, 1);
    assert_null(ml_confg.ctxt);
    assert_string_equal(buffer, "end match");
}

/* read_multiline_regex */
void test_read_multiline_regex_log_process(void ** state) {

    logreader lf = {0};
    int rc = 0;
    int drop_it = 0;

    w_multiline_config_t ml_confg = {0};

    ml_confg.timeout = 500;
    ml_confg.replace_type = ML_REPLACE_NO_REPLACE;
    ml_confg.match_type = ML_MATCH_END;

    lf.multiline = &ml_confg;

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 5);
    will_return(__wrap_w_get_hash_context, true);

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "end match\n");
    will_return(__wrap_w_expression_match, true);
    will_return(__wrap_w_msg_hash_queues_push, 0);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 10);

    expect_any(__wrap_w_fseek, x);
    expect_value(__wrap_w_fseek, pos, 5);
    will_return(__wrap_w_fseek, 0);

    will_return(__wrap_fread, "test0");
    will_return(__wrap_fread, 5);

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, NULL);

    expect_function_call(__wrap_OS_SHA1_Stream);
    will_return(__wrap_w_update_file_status, true);
    will_return(__wrap_w_update_file_status, 0);

    void * retval = read_multiline_regex(&lf, &rc, drop_it);
    assert_ptr_equal(retval, NULL);
    assert_null(ml_confg.ctxt);
}

void test_read_multiline_regex_no_aviable_log(void ** state) {
    logreader lf = {0};
    int rc = 0;
    int drop_it = 0;

    w_multiline_config_t ml_confg = {0};

    ml_confg.timeout = 500;
    ml_confg.replace_type = ML_REPLACE_NO_REPLACE;
    ml_confg.match_type = ML_MATCH_END;

    lf.multiline = &ml_confg;

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 5);
    will_return(__wrap_w_get_hash_context, true);

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, NULL);

    will_return(__wrap_w_update_file_status, true);
    will_return(__wrap_w_update_file_status, 0);

    void * retval = read_multiline_regex(&lf, &rc, drop_it);
    assert_ptr_equal(retval, NULL);
    assert_null(ml_confg.ctxt);
}

void test_read_multiline_regex_cant_read(void ** state) {
    logreader lf = {0};
    int rc = 0;
    int drop_it = 0;

    w_multiline_config_t ml_confg = {0};

    ml_confg.timeout = 500;
    ml_confg.replace_type = ML_REPLACE_NO_REPLACE;
    ml_confg.match_type = ML_MATCH_END;

    lf.multiline = &ml_confg;

    will_return(__wrap_can_read, 0);
    void * retval = read_multiline_regex(&lf, &rc, drop_it);
    assert_ptr_equal(retval, NULL);
    assert_null(ml_confg.ctxt);
}

void test_read_multiline_regex_invalid_context(void ** state) {

    logreader lf = {0};
    int rc = 0;
    int drop_it = 0;

    w_multiline_config_t ml_confg = {0};

    ml_confg.timeout = 500;
    ml_confg.replace_type = ML_REPLACE_NO_REPLACE;
    ml_confg.match_type = ML_MATCH_END;

    lf.multiline = &ml_confg;

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 5);
    will_return(__wrap_w_get_hash_context, false);

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "end match\n");
    will_return(__wrap_w_expression_match, true);
    will_return(__wrap_w_msg_hash_queues_push, 0);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 10);

    expect_any(__wrap_w_fseek, x);
    expect_value(__wrap_w_fseek, pos, 5);
    will_return(__wrap_w_fseek, 0);

    will_return(__wrap_fread, "test0");
    will_return(__wrap_fread, 5);

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, NULL);

    void * retval = read_multiline_regex(&lf, &rc, drop_it);
    assert_ptr_equal(retval, NULL);
    assert_null(ml_confg.ctxt);
}

void test_read_multiline_regex_log_ignored(void ** state) {

    logreader lf = {0};
    int rc = 0;
    int drop_it = 0;
    char log_str[PATH_MAX + 1] = {0};
    w_expression_t * expression_ignore;

    lf.regex_ignore = OSList_Create();
    OSList_SetFreeDataPointer(lf.regex_ignore, (void (*)(void *))w_free_expression);

    w_calloc_expression_t(&expression_ignore, EXP_TYPE_PCRE2);
    w_expression_compile(expression_ignore, "ignore.*", 0);
    OSList_InsertData(lf.regex_ignore, NULL, expression_ignore);

    w_multiline_config_t ml_confg = {0};

    ml_confg.timeout = 500;
    ml_confg.replace_type = ML_REPLACE_NO_REPLACE;
    ml_confg.match_type = ML_MATCH_END;

    lf.multiline = &ml_confg;

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 5);
    will_return(__wrap_w_get_hash_context, true);

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "ignore this log\n");
    will_return(__wrap_w_expression_match, true);

    will_return(__wrap_w_expression_match, true);

    snprintf(log_str, PATH_MAX, LF_MATCH_REGEX, "ignore this log", "ignore", "ignore.*");
    expect_string(__wrap__mdebug2, formatted_msg, log_str);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 10);

    expect_any(__wrap_w_fseek, x);
    expect_value(__wrap_w_fseek, pos, 5);
    will_return(__wrap_w_fseek, 0);

    will_return(__wrap_fread, "test0");
    will_return(__wrap_fread, 5);

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, NULL);

    expect_function_call(__wrap_OS_SHA1_Stream);
    will_return(__wrap_w_update_file_status, true);
    will_return(__wrap_w_update_file_status, 0);

    void * retval = read_multiline_regex(&lf, &rc, drop_it);

    assert_ptr_equal(retval, NULL);
    assert_null(ml_confg.ctxt);

    if (lf.regex_ignore) {
        OSList_Destroy(lf.regex_ignore);
        lf.regex_ignore = NULL;
    }
}

// Test get_file_chunk
void test_get_file_chunk_fseek_fail(void ** state) {

    char * retval;
    int64_t initial_pos = 10;
    int64_t final_pos = 5;

    retval = get_file_chunk(NULL, initial_pos, final_pos);
    assert_null(retval);
}

void test_get_file_chunk_size_reduce(void ** state) {

    char * retval;
    int64_t initial_pos = 5;
    int64_t final_pos = 10;

    will_return(__wrap_fread, "test");
    will_return(__wrap_fread, 4);

    expect_any(__wrap_w_fseek, x);
    expect_value(__wrap_w_fseek, pos, 5);
    will_return(__wrap_w_fseek, 0);

    retval = get_file_chunk(NULL, initial_pos, final_pos);
    assert_null(retval);
}

void test_get_file_chunk_ok(void ** state) {

    char * retval;
    int64_t initial_pos = 5;
    int64_t final_pos = 10;

    expect_any(__wrap_w_fseek, x);
    expect_value(__wrap_w_fseek, pos, 5);
    will_return(__wrap_w_fseek, 0);
    will_return(__wrap_fread, "test");
    will_return(__wrap_fread, 5);

    retval = get_file_chunk(NULL, initial_pos, final_pos);
    assert_string_equal("test", retval);
    os_free(retval);
}

int main(void) {
    const struct CMUnitTest tests[] = {
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
        // Test multiline_getlog_start
        cmocka_unit_test(test_multiline_getlog_start_single_no_context),
        cmocka_unit_test(test_multiline_getlog_start_ctxt_timeout),
        cmocka_unit_test(test_multiline_getlog_start_ctxt_append_ctxt),
        cmocka_unit_test(test_multiline_getlog_start_ctxt_match),
        cmocka_unit_test(test_multiline_getlog_start_no_ctxt_match),
        cmocka_unit_test(test_multiline_getlog_start_no_ctxt_overflow),
        cmocka_unit_test(test_multiline_getlog_start_ctxt_overflow),
        cmocka_unit_test(test_multiline_getlog_start_no_ctxt_cant_read),
        cmocka_unit_test(test_multiline_getlog_start_ctxt_cant_read),
        cmocka_unit_test(test_multiline_getlog_start_match_multi_replace),
        // Test multiline_getlog_end
        cmocka_unit_test(test_multiline_getlog_end_single_match_no_context),
        cmocka_unit_test(test_multiline_getlog_end_ctxt_timeout),
        cmocka_unit_test(test_multiline_getlog_end_ctxt_append_ctxt),
        cmocka_unit_test(test_multiline_getlog_end_multi_match_no_context),
        cmocka_unit_test(test_multiline_getlog_end_multi_match_context),
        cmocka_unit_test(test_multiline_getlog_end_no_ctxt_overflow),
        cmocka_unit_test(test_multiline_getlog_end_ctxt_overflow),
        cmocka_unit_test(test_multiline_getlog_end_no_ctxt_cant_read),
        cmocka_unit_test(test_multiline_getlog_end_ctxt_cant_read),
        cmocka_unit_test(test_multiline_getlog_end_match_multi_replace),
        // Test multiline_getlog_all
        cmocka_unit_test(test_multiline_getlog_all_single_match_no_context),
        cmocka_unit_test(test_multiline_getlog_all_ctxt_timeout),
        cmocka_unit_test(test_multiline_getlog_all_ctxt_append_ctxt),
        cmocka_unit_test(test_multiline_getlog_all_multi_match_no_context),
        cmocka_unit_test(test_multiline_getlog_all_multi_match_context),
        cmocka_unit_test(test_multiline_getlog_all_no_ctxt_overflow),
        cmocka_unit_test(test_multiline_getlog_all_ctxt_overflow),
        cmocka_unit_test(test_multiline_getlog_all_no_ctxt_cant_read),
        cmocka_unit_test(test_multiline_getlog_all_ctxt_cant_read),
        cmocka_unit_test(test_multiline_getlog_all_match_multi_replace),
        // Tests multiline_getlog
        cmocka_unit_test(test_multiline_getlog_unknown),
        cmocka_unit_test(test_multiline_getlog_start),
        cmocka_unit_test(test_multiline_getlog_end),
        cmocka_unit_test(test_multiline_getlog_all),
        // Tests read_multiline_regex
        cmocka_unit_test(test_read_multiline_regex_no_aviable_log),
        cmocka_unit_test(test_read_multiline_regex_log_process),
        cmocka_unit_test(test_read_multiline_regex_cant_read),
        cmocka_unit_test(test_read_multiline_regex_invalid_context),
        cmocka_unit_test(test_read_multiline_regex_log_ignored),
        // Test get_file_chunk
        cmocka_unit_test(test_get_file_chunk_fseek_fail),
        cmocka_unit_test(test_get_file_chunk_size_reduce),
        cmocka_unit_test(test_get_file_chunk_ok),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
