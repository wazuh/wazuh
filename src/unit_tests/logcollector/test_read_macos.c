/*
 * Copyright (C) 2015-2021, Wazuh Inc.
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
#include "../wrappers/linux/socket_wrappers.h"
#include "../wrappers/wazuh/shared/expression_wrappers.h"
#include "../wrappers/wazuh/logcollector/logcollector_wrappers.h"

bool w_macos_log_ctxt_restore(char * buffer, w_macos_log_ctxt_t * ctxt);
void w_macos_log_ctxt_backup(char * buffer, w_macos_log_ctxt_t * ctxt);
void w_macos_log_ctxt_clean(w_macos_log_ctxt_t * ctxt);
bool w_macos_is_log_ctxt_expired(time_t timeout, w_macos_log_ctxt_t * ctxt);
char * w_macos_log_get_last_valid_line(char * str);
bool w_macos_is_log_header(w_macos_log_config_t * macos_log_cfg, char * buffer);
bool w_macos_is_log_header(w_macos_log_config_t * macos_log_cfg, char * buffer);
bool w_macos_log_getlog(char * buffer, int length, FILE * stream, w_macos_log_config_t * macos_log_cfg);

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

/* tests */

/* w_macos_log_ctxt_restore */

void test_w_macos_log_ctxt_restore_false(void ** state) {

    w_macos_log_ctxt_t ctxt;
    ctxt.buffer[0] = '\0';

    char * buffer = NULL;

    bool ret = w_macos_log_ctxt_restore(buffer, &ctxt);
    assert_false(ret);

}

void test_w_macos_log_ctxt_restore_true(void ** state) {

    w_macos_log_ctxt_t ctxt;
    strncpy(ctxt.buffer,"test",OS_MAXSTR);

    char buffer[OS_MAXSTR + 1];
    buffer[OS_MAXSTR] = '\0';

    bool ret = w_macos_log_ctxt_restore(buffer, &ctxt);
    assert_true(ret);

}

/* w_macos_log_ctxt_backup */

void test_w_macos_log_ctxt_backup_success(void ** state) {

    w_macos_log_ctxt_t ctxt;
    char buffer[OS_MAXSTR + 1];

    buffer[OS_MAXSTR] = '\0';

    strncpy(buffer,"test",OS_MAXSTR);

    w_macos_log_ctxt_backup(buffer, &ctxt);

    assert_non_null(ctxt.buffer);
    assert_non_null(ctxt.timestamp);

}

/* w_macos_log_ctxt_clean */

void test_w_macos_log_ctxt_clean_success(void ** state) {

    w_macos_log_ctxt_t ctxt;

    strncpy(ctxt.buffer,"test",OS_MAXSTR);
    ctxt.timestamp = time(NULL);


    w_macos_log_ctxt_clean(&ctxt);

    assert_int_equal(ctxt.timestamp, 0);
    assert_string_equal(ctxt.buffer, "\0");

}

/* w_macos_is_log_ctxt_expired */

void test_w_macos_is_log_ctxt_expired_true(void ** state) {

    w_macos_log_ctxt_t ctxt;
    time_t timeout = (time_t) MACOS_LOG_TIMEOUT;

    ctxt.timestamp = (time_t) 1;

    bool ret = w_macos_is_log_ctxt_expired(timeout, &ctxt);

    assert_true(ret);

}

void test_w_macos_is_log_ctxt_expired_false(void ** state) {

    w_macos_log_ctxt_t ctxt;
    time_t timeout = (time_t) MACOS_LOG_TIMEOUT;

    ctxt.timestamp = time(NULL);

    bool ret = w_macos_is_log_ctxt_expired(timeout, &ctxt);

    assert_false(ret);

}

/* w_macos_log_get_last_valid_line */

void test_w_macos_log_get_last_valid_line_str_null(void ** state) {

    char * str = NULL;

    char * ret = w_macos_log_get_last_valid_line(str);

    assert_null(ret);

}

void test_w_macos_log_get_last_valid_line_str_empty(void ** state) {

    char * str = '\0';

    char * ret = w_macos_log_get_last_valid_line(str);

    assert_null(ret);

}

void test_w_macos_log_get_last_valid_line_str_without_new_line(void ** state) {

    char * str = NULL;

    os_strdup("2021-04-22 12:00:00.230270-0700 test", str);

    char * ret = w_macos_log_get_last_valid_line(str);

    assert_null(ret);
    os_free(str);

}

void test_w_macos_log_get_last_valid_line_str_with_new_line_end(void ** state) {

    char * str = NULL;

    os_strdup("2021-04-22 12:00:00.230270-0700 test\n", str);

    char * ret = w_macos_log_get_last_valid_line(str);

    assert_null(ret);
    os_free(str);

}

void test_w_macos_log_get_last_valid_line_str_with_new_line_not_end(void ** state) {

    char * str = NULL;

    os_strdup("2021-04-22 12:00:00.230270-0700 test\n2021-04-22 12:00:00.230270-0700 test2", str);

    char * ret = w_macos_log_get_last_valid_line(str);

    assert_string_equal(ret, "\n2021-04-22 12:00:00.230270-0700 test2");
    os_free(str);

}

void test_w_macos_log_get_last_valid_line_str_with_two_new_lines_end(void ** state) {

    char * str = NULL;

    os_strdup("2021-04-22 12:00:00.230270-0700 test\n2021-04-22 12:00:00.230270-0700 test2\n", str);

    char * ret = w_macos_log_get_last_valid_line(str);

    assert_string_equal(ret, "\n2021-04-22 12:00:00.230270-0700 test2\n");
    os_free(str);

}

void test_w_macos_log_get_last_valid_line_str_with_two_new_lines_not_end(void ** state) {

    char * str = NULL;

    os_strdup("2021-04-22 12:00:00.230270-0700 test\n2021-04-22 12:00:00.230270-0700 test2\n2021-04-22 12:00:00.230270-0700 test3", str);

    char * ret = w_macos_log_get_last_valid_line(str);

    assert_string_equal(ret, "\n2021-04-22 12:00:00.230270-0700 test3");
    os_free(str);

}

void test_w_macos_log_get_last_valid_line_str_with_three_new_lines_end(void ** state) {

    char * str = NULL;

    os_strdup("2021-04-22 12:00:00.230270-0700 test\n2021-04-22 12:00:00.230270-0700 test2\n2021-04-22 12:00:00.230270-0700 test3\n", str);

    char * ret = w_macos_log_get_last_valid_line(str);

    assert_string_equal(ret, "\n2021-04-22 12:00:00.230270-0700 test3\n");
    os_free(str);

}

void test_w_macos_log_get_last_valid_line_str_with_three_new_lines_not_end(void ** state) {

    char * str = NULL;

    os_strdup("2021-04-22 12:00:00.230270-0700 test\n2021-04-22 12:00:00.230270-0700 test2\n2021-04-22 12:00:00.230270-0700 test3\n2021-04-22 12:00:00.230270-0700 test4", str);

    char * ret = w_macos_log_get_last_valid_line(str);

    assert_string_equal(ret, "\n2021-04-22 12:00:00.230270-0700 test4");
    os_free(str);

}

/* w_macos_is_log_header */

void test_w_macos_is_log_header_false(void ** state) {

    w_macos_log_ctxt_t ctxt;
    strncpy(ctxt.buffer,"test\n",OS_MAXSTR);

    char * buffer = NULL;
    os_strdup("test", buffer);

    w_macos_log_config_t macos_log_cfg;
    macos_log_cfg.ctxt = ctxt;
    macos_log_cfg.log_start_regex = NULL;
    macos_log_cfg.is_header_processed = false;

    will_return(__wrap_w_expression_match, true);

    bool ret = w_macos_is_log_header(& macos_log_cfg, buffer);

    assert_false(ret);

    os_free(buffer);

}

void test_w_macos_is_log_header_log_stream_execution_error_after_exec(void ** state) {

    w_macos_log_ctxt_t ctxt;
    strncpy(ctxt.buffer,"test\n",OS_MAXSTR);

    char * buffer = NULL;
    os_strdup("log: test", buffer);

    w_macos_log_config_t macos_log_cfg;
    macos_log_cfg.ctxt = ctxt;
    macos_log_cfg.log_start_regex = NULL;
    macos_log_cfg.is_header_processed = true;

    will_return(__wrap_w_expression_match, false);

    expect_string(__wrap__merror, formatted_msg, "(1602): Execution error 'log: test'");

    bool ret = w_macos_is_log_header(& macos_log_cfg, buffer);

    assert_true(ret);

    os_free(buffer);

}

void test_w_macos_is_log_header_log_stream_execution_error_colon(void ** state) {

    w_macos_log_ctxt_t ctxt;
    strncpy(ctxt.buffer,"test\n",OS_MAXSTR);

    char * buffer = NULL;
    os_strdup("log: ", buffer);

    w_macos_log_config_t macos_log_cfg;
    macos_log_cfg.ctxt = ctxt;
    macos_log_cfg.log_start_regex = NULL;
    macos_log_cfg.is_header_processed = true;

    will_return(__wrap_w_expression_match, false);

    expect_string(__wrap__merror, formatted_msg, "(1602): Execution error 'log'");

    bool ret = w_macos_is_log_header(& macos_log_cfg, buffer);

    assert_true(ret);

    os_free(buffer);

}

void test_w_macos_is_log_header_log_stream_execution_error_line_break(void ** state) {

    w_macos_log_ctxt_t ctxt;
    strncpy(ctxt.buffer,"test\n",OS_MAXSTR);

    char * buffer = NULL;
    os_strdup("log: test\n", buffer);

    w_macos_log_config_t macos_log_cfg;
    macos_log_cfg.ctxt = ctxt;
    macos_log_cfg.log_start_regex = NULL;
    macos_log_cfg.is_header_processed = true;

    will_return(__wrap_w_expression_match, false);

    expect_string(__wrap__merror, formatted_msg, "(1602): Execution error 'log: test'");

    bool ret = w_macos_is_log_header(& macos_log_cfg, buffer);

    assert_true(ret);

    os_free(buffer);

}

void test_w_macos_is_log_header_reading_other_log(void ** state) {

    w_macos_log_ctxt_t ctxt;
    strncpy(ctxt.buffer,"test\n",OS_MAXSTR);

    char * buffer = NULL;
    os_strdup("test", buffer);

    w_macos_log_config_t macos_log_cfg;
    macos_log_cfg.ctxt = ctxt;
    macos_log_cfg.log_start_regex = NULL;
    macos_log_cfg.is_header_processed = false;

    will_return(__wrap_w_expression_match, false);

    expect_string(__wrap__mdebug2, formatted_msg, "macOS ULS: Reading other log headers or errors: 'test'");

    bool ret = w_macos_is_log_header(& macos_log_cfg, buffer);

    assert_true(ret);

    os_free(buffer);

}

void test_w_macos_is_log_header_reading_other_log_line_break(void ** state) {

    w_macos_log_ctxt_t ctxt;
    strncpy(ctxt.buffer,"test\n",OS_MAXSTR);

    char * buffer = NULL;
    os_strdup("test\n", buffer);

    w_macos_log_config_t macos_log_cfg;
    macos_log_cfg.ctxt = ctxt;
    macos_log_cfg.log_start_regex = NULL;
    macos_log_cfg.is_header_processed = false;

    will_return(__wrap_w_expression_match, false);

    expect_string(__wrap__mdebug2, formatted_msg, "macOS ULS: Reading other log headers or errors: 'test'");

    bool ret = w_macos_is_log_header(& macos_log_cfg, buffer);

    assert_true(ret);

    os_free(buffer);

}

/* w_macos_log_getlog */
void test_w_macos_log_getlog_context_expired(void ** state) {

    //test_oslog_ctxt_restore_true
    w_macos_log_ctxt_t ctxt;
    strncpy(ctxt.buffer,"test",OS_MAXSTR);

    char buffer[OS_MAXSTR + 1];
    buffer[OS_MAXSTR] = '\0';

    //test_oslog_ctxt_is_expired_true
    ctxt.timestamp = (time_t) 1;

    w_macos_log_config_t macos_log_cfg;
    macos_log_cfg.ctxt = ctxt;
    macos_log_cfg.is_header_processed = true;

    int length =  OS_MAXSTR - OS_LOG_HEADER;

    FILE * stream = NULL;

    bool ret = w_macos_log_getlog(buffer, length, stream, &macos_log_cfg);

    assert_true(ret);

}

void test_w_macos_log_getlog_context_expired_new_line(void ** state) {

    //test_oslog_ctxt_restore_true
    w_macos_log_ctxt_t ctxt;
    strncpy(ctxt.buffer,"test\n",OS_MAXSTR);

    char buffer[OS_MAXSTR + 1];
    buffer[OS_MAXSTR] = '\0';

    //test_oslog_ctxt_is_expired_true
    ctxt.timestamp = (time_t) 1;

    w_macos_log_config_t macos_log_cfg;
    macos_log_cfg.ctxt = ctxt;
    macos_log_cfg.is_header_processed = true;

    int length =  OS_MAXSTR - OS_LOG_HEADER;

    FILE * stream = NULL;

    bool ret = w_macos_log_getlog(buffer, length, stream, &macos_log_cfg);

    assert_true(ret);

}

void test_w_macos_log_getlog_context_not_expired(void ** state) {

    //test_oslog_ctxt_restore_true
    w_macos_log_ctxt_t ctxt;
    strncpy(ctxt.buffer,"test\n",OS_MAXSTR);

    char buffer[OS_MAXSTR + 1];
    buffer[OS_MAXSTR] = '\0';

    //test_oslog_ctxt_is_expired_false
    ctxt.timestamp = time(NULL);

    w_macos_log_config_t macos_log_cfg;
    macos_log_cfg.ctxt = ctxt;
    macos_log_cfg.is_header_processed = true;

    int length =  OS_MAXSTR - OS_LOG_HEADER;

    FILE * stream = (FILE*)1;

    will_return(__wrap_can_read, 1);

    expect_value(__wrap_fgets, __stream, (FILE*)1);
    will_return(__wrap_fgets, NULL);

    bool ret = w_macos_log_getlog(buffer, length, stream, &macos_log_cfg);

    assert_false(ret);

}

void test_w_macos_log_getlog_context_buffer_full(void ** state) {

    //test_oslog_ctxt_restore_true
    w_macos_log_ctxt_t ctxt;
    strncpy(ctxt.buffer,"test\n",OS_MAXSTR);

    char buffer[OS_MAXSTR + 1];
    buffer[OS_MAXSTR] = '\0';

    //test_oslog_ctxt_is_expired_false
    ctxt.timestamp = time(NULL);

    w_macos_log_config_t macos_log_cfg;
    macos_log_cfg.ctxt = ctxt;
    macos_log_cfg.is_header_processed = true;

    int length =  strlen(ctxt.buffer)+1;

    FILE * stream;
    os_calloc(1, sizeof(FILE *), stream);

    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "test");

    //test_oslog_ctxt_clean_success

    //test_oslog_get_valid_lastline

    bool ret = w_macos_log_getlog(buffer, length, stream, &macos_log_cfg);

    assert_string_equal(buffer,"test");
    assert_true(ret);

    os_free(stream);

}

void test_w_macos_log_getlog_context_not_endline(void ** state) {

    //test_oslog_ctxt_restore_true
    w_macos_log_ctxt_t ctxt;
    strncpy(ctxt.buffer,"test\0",OS_MAXSTR);

    char buffer[OS_MAXSTR + 1];
    buffer[OS_MAXSTR] = '\0';

    //test_oslog_ctxt_is_expired_false
    ctxt.timestamp = time(NULL);

    w_macos_log_config_t macos_log_cfg;
    macos_log_cfg.ctxt = ctxt;
    macos_log_cfg.is_header_processed = true;

    int length =  strlen(ctxt.buffer)+10;

    FILE * stream;
    os_calloc(1, sizeof(FILE *), stream);

    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "test");

    expect_string(__wrap__mdebug2, formatted_msg, "macOS ULS: Incomplete message...");

    //test_oslog_ctxt_backup_success

    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, NULL);

    bool ret = w_macos_log_getlog(buffer, length, stream, &macos_log_cfg);

    //assert_string_equal(buffer,"test");
    assert_false(ret);

    os_free(stream);

}

void test_w_macos_log_getlog_context_not_header_processed(void ** state) {

    //test_oslog_ctxt_restore_true
    w_macos_log_ctxt_t ctxt;
    strncpy(ctxt.buffer,"test\0",OS_MAXSTR);

    char buffer[OS_MAXSTR + 1];
    buffer[OS_MAXSTR] = '\0';

    //test_oslog_ctxt_is_expired_false
    ctxt.timestamp = time(NULL);

    w_macos_log_config_t macos_log_cfg;
    macos_log_cfg.ctxt = ctxt;
    macos_log_cfg.is_header_processed = false;

    int length =  strlen(ctxt.buffer)+1;

    FILE * stream;
    os_calloc(1, sizeof(FILE *), stream);

    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "test");

    //test_oslog_ctxt_backup_success

    //test_w_macos_is_log_header_false
    will_return(__wrap_w_expression_match, true);

    will_return(__wrap_fgetc,'\n');

    expect_string(__wrap__mdebug2, formatted_msg, "macOS ULS: Maximum message length reached. The remainder was discarded");

    bool ret = w_macos_log_getlog(buffer, length, stream, &macos_log_cfg);

    //assert_string_equal(buffer,"test");
    assert_true(ret);

    os_free(stream);

}

void test_w_macos_log_getlog_context_header_processed(void ** state) {

    //test_oslog_ctxt_restore_true
    w_macos_log_ctxt_t ctxt;
    strncpy(ctxt.buffer,"test\0",OS_MAXSTR);

    char buffer[OS_MAXSTR + 1];
    buffer[OS_MAXSTR] = '\0';

    //test_oslog_ctxt_is_expired_false
    ctxt.timestamp = time(NULL);

    w_macos_log_config_t macos_log_cfg;
    macos_log_cfg.ctxt = ctxt;
    macos_log_cfg.is_header_processed = false;

    int length =  strlen(ctxt.buffer)+1;

    FILE * stream;
    os_calloc(1, sizeof(FILE *), stream);

    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "test");

    //test_oslog_ctxt_backup_success

    //test_w_macos_is_log_header_reading_other_log
    will_return(__wrap_w_expression_match, false);

    expect_string(__wrap__mdebug2, formatted_msg, "macOS ULS: Reading other log headers or errors: 'test'");

    bool ret = w_macos_log_getlog(buffer, length, stream, &macos_log_cfg);

    //assert_string_equal(buffer,"test");
    assert_true(ret);

    os_free(stream);

}

void test_w_macos_log_getlog_split_two_logs(void ** state) {

    //test_oslog_ctxt_restore_true
    w_macos_log_ctxt_t ctxt;
    strncpy(ctxt.buffer,"test\ntest\n",OS_MAXSTR);

    char buffer[OS_MAXSTR + 1];
    buffer[OS_MAXSTR] = '\0';

    //test_oslog_ctxt_is_expired_false
    ctxt.timestamp = time(NULL);

    w_macos_log_config_t macos_log_cfg;
    macos_log_cfg.ctxt = ctxt;
    macos_log_cfg.is_header_processed = false;

    int length =  strlen(ctxt.buffer)+1;

    FILE * stream;
    os_calloc(1, sizeof(FILE *), stream);

    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "test");

    //test_oslog_ctxt_backup_success

    //test_w_macos_is_log_header_false
    will_return(__wrap_w_expression_match, true);

    //will_return(__wrap_fgetc, "\n");

    //test_oslog_get_valid_lastline
    will_return(__wrap_w_expression_match, true);

    bool ret = w_macos_log_getlog(buffer, length, stream, &macos_log_cfg);

    //assert_string_equal(buffer,"test");
    assert_true(ret);

    os_free(stream);

}

int main(void) {
    const struct CMUnitTest tests[] = {
        // Test w_macos_log_ctxt_restore
        cmocka_unit_test(test_w_macos_log_ctxt_restore_false),
        cmocka_unit_test(test_w_macos_log_ctxt_restore_true),
        // Test w_macos_log_ctxt_backup
        cmocka_unit_test(test_w_macos_log_ctxt_backup_success),
        // Test w_macos_log_ctxt_clean
        cmocka_unit_test(test_w_macos_log_ctxt_clean_success),
        // Test w_macos_is_log_ctxt_expired
        cmocka_unit_test(test_w_macos_is_log_ctxt_expired_true),
        cmocka_unit_test(test_w_macos_is_log_ctxt_expired_false),
        // Test w_macos_log_get_last_valid_line
        cmocka_unit_test(test_w_macos_log_get_last_valid_line_str_null),
        cmocka_unit_test(test_w_macos_log_get_last_valid_line_str_empty),
        cmocka_unit_test(test_w_macos_log_get_last_valid_line_str_without_new_line),
        cmocka_unit_test(test_w_macos_log_get_last_valid_line_str_with_new_line_end),
        cmocka_unit_test(test_w_macos_log_get_last_valid_line_str_with_new_line_not_end),
        cmocka_unit_test(test_w_macos_log_get_last_valid_line_str_with_two_new_lines_end),
        cmocka_unit_test(test_w_macos_log_get_last_valid_line_str_with_two_new_lines_not_end),
        cmocka_unit_test(test_w_macos_log_get_last_valid_line_str_with_three_new_lines_not_end),
        // Test w_macos_is_log_header
        cmocka_unit_test(test_w_macos_is_log_header_false),
        cmocka_unit_test(test_w_macos_is_log_header_log_stream_execution_error_after_exec),
        cmocka_unit_test(test_w_macos_is_log_header_log_stream_execution_error_colon),
        cmocka_unit_test(test_w_macos_is_log_header_log_stream_execution_error_line_break),
        cmocka_unit_test(test_w_macos_is_log_header_reading_other_log),
        cmocka_unit_test(test_w_macos_is_log_header_reading_other_log_line_break),
        // Test w_macos_log_getlog
        cmocka_unit_test(test_w_macos_log_getlog_context_expired),
        cmocka_unit_test(test_w_macos_log_getlog_context_expired_new_line),
        cmocka_unit_test(test_w_macos_log_getlog_context_not_expired),
        cmocka_unit_test(test_w_macos_log_getlog_context_buffer_full),
        cmocka_unit_test(test_w_macos_log_getlog_context_not_endline),
        cmocka_unit_test(test_w_macos_log_getlog_context_not_header_processed),
        cmocka_unit_test(test_w_macos_log_getlog_context_header_processed),
        cmocka_unit_test(test_w_macos_log_getlog_split_two_logs),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
