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

bool oslog_ctxt_restore(char * buffer, w_oslog_ctxt_t * ctxt);
void oslog_ctxt_backup(char * buffer, w_oslog_ctxt_t * ctxt);
void oslog_ctxt_clean(w_oslog_ctxt_t * ctxt);
bool oslog_ctxt_is_expired(time_t timeout, w_oslog_ctxt_t * ctxt);
char * oslog_get_valid_lastline(char * str);
bool oslog_getlog(char * buffer, int length, FILE * stream, w_oslog_config_t * oslog_cfg);
bool oslog_is_header(w_oslog_config_t * oslog_cfg, char * buffer);

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

/* oslog_ctxt_restore */

void test_oslog_ctxt_restore_false(void ** state) {

    w_oslog_ctxt_t ctxt;
    ctxt.buffer[0] = '\0';

    char * buffer = NULL;

    bool ret = oslog_ctxt_restore(buffer, &ctxt);
    assert_false(ret);

}

void test_oslog_ctxt_restore_true(void ** state) {

    w_oslog_ctxt_t ctxt;
    strncpy(ctxt.buffer,"test",OS_MAXSTR);

    char buffer[OS_MAXSTR + 1];
    buffer[OS_MAXSTR] = '\0';

    bool ret = oslog_ctxt_restore(buffer, &ctxt);
    assert_true(ret);

}

/* oslog_ctxt_backup */

void test_oslog_ctxt_backup_success(void ** state) {

    w_oslog_ctxt_t ctxt;
    char buffer[OS_MAXSTR + 1];

    buffer[OS_MAXSTR] = '\0';

    strncpy(buffer,"test",OS_MAXSTR);

    oslog_ctxt_backup(buffer, &ctxt);

    assert_non_null(ctxt.buffer);
    assert_non_null(ctxt.timestamp);

}

/* oslog_ctxt_clean */

void test_oslog_ctxt_clean_success(void ** state) {

    w_oslog_ctxt_t ctxt;

    strncpy(ctxt.buffer,"test",OS_MAXSTR);
    ctxt.timestamp = time(NULL);


    oslog_ctxt_clean(&ctxt);

    assert_int_equal(ctxt.timestamp, 0);
    assert_string_equal(ctxt.buffer,"\0");

}

/* oslog_ctxt_is_expired */

void test_oslog_ctxt_is_expired_true(void ** state) {

    w_oslog_ctxt_t ctxt;
    time_t timeout = (time_t) OSLOG_TIMEOUT;

    ctxt.timestamp = (time_t) 1;

    bool ret = oslog_ctxt_is_expired(timeout, &ctxt);

    assert_true(ret);

}

void test_oslog_ctxt_is_expired_false(void ** state) {

    w_oslog_ctxt_t ctxt;
    time_t timeout = (time_t) OSLOG_TIMEOUT;

    ctxt.timestamp = time(NULL);

    bool ret = oslog_ctxt_is_expired(timeout, &ctxt);

    assert_false(ret);

}

/* oslog_get_valid_lastline */

void test_oslog_get_valid_lastline_str_null(void ** state) {

    char * str = NULL;

    char * ret =oslog_get_valid_lastline(str);

    assert_null(ret);

}

void test_oslog_get_valid_lastline_str_empty(void ** state) {

    char * str = '\0';

    char * ret =oslog_get_valid_lastline(str);

    assert_null(ret);

}

void test_oslog_get_valid_lastline_str_without_new_line(void ** state) {

    char * str = NULL;

    os_strdup("2021-04-22 12:00:00.230270-0700 test", str);

    char * ret =oslog_get_valid_lastline(str);

    assert_null(ret);
    os_free(str);

}

void test_oslog_get_valid_lastline_str_with_new_line_end(void ** state) {

    char * str = NULL;

    os_strdup("2021-04-22 12:00:00.230270-0700 test\n", str);

    char * ret =oslog_get_valid_lastline(str);

    assert_null(ret);
    os_free(str);

}

void test_oslog_get_valid_lastline_str_with_new_line_not_end(void ** state) {

    char * str = NULL;

    os_strdup("2021-04-22 12:00:00.230270-0700 test\n2021-04-22 12:00:00.230270-0700 test2", str);

    char * ret =oslog_get_valid_lastline(str);

    assert_string_equal(ret, "\n2021-04-22 12:00:00.230270-0700 test2");
    os_free(str);

}

void test_oslog_get_valid_lastline_str_with_two_new_lines_end(void ** state) {

    char * str = NULL;

    os_strdup("2021-04-22 12:00:00.230270-0700 test\n2021-04-22 12:00:00.230270-0700 test2\n", str);

    char * ret =oslog_get_valid_lastline(str);

    assert_string_equal(ret, "\n2021-04-22 12:00:00.230270-0700 test2\n");
    os_free(str);

}

void test_oslog_get_valid_lastline_str_with_two_new_lines_not_end(void ** state) {

    char * str = NULL;

    os_strdup("2021-04-22 12:00:00.230270-0700 test\n2021-04-22 12:00:00.230270-0700 test2\n2021-04-22 12:00:00.230270-0700 test3", str);

    char * ret =oslog_get_valid_lastline(str);

    assert_string_equal(ret, "\n2021-04-22 12:00:00.230270-0700 test3");
    os_free(str);

}

void test_oslog_get_valid_lastline_str_with_three_new_lines_end(void ** state) {

    char * str = NULL;

    os_strdup("2021-04-22 12:00:00.230270-0700 test\n2021-04-22 12:00:00.230270-0700 test2\n2021-04-22 12:00:00.230270-0700 test3\n", str);

    char * ret =oslog_get_valid_lastline(str);

    assert_string_equal(ret, "\n2021-04-22 12:00:00.230270-0700 test3\n");
    os_free(str);

}

void test_oslog_get_valid_lastline_str_with_three_new_lines_not_end(void ** state) {

    char * str = NULL;

    os_strdup("2021-04-22 12:00:00.230270-0700 test\n2021-04-22 12:00:00.230270-0700 test2\n2021-04-22 12:00:00.230270-0700 test3\n2021-04-22 12:00:00.230270-0700 test4", str);

    char * ret =oslog_get_valid_lastline(str);

    assert_string_equal(ret, "\n2021-04-22 12:00:00.230270-0700 test4");
    os_free(str);

}

/* oslog_is_header */

void test_oslog_is_header_success(void ** state) {

    w_oslog_ctxt_t ctxt;
    strncpy(ctxt.buffer,"test\n",OS_MAXSTR);

    char * buffer = NULL;
    os_strdup("test", buffer);

    w_oslog_config_t oslog_cfg;
    oslog_cfg.ctxt = ctxt;
    oslog_cfg.start_log_regex = NULL;
    oslog_cfg.is_header_processed = false;

    will_return(__wrap_w_expression_match, true);

    bool ret = oslog_is_header(& oslog_cfg, buffer);

    assert_false(ret);

    os_free(buffer);

}

void test_oslog_is_header_log_stream_execution_error_after_exec(void ** state) {

    w_oslog_ctxt_t ctxt;
    strncpy(ctxt.buffer,"test\n",OS_MAXSTR);

    char * buffer = NULL;
    os_strdup("log: test", buffer);

    w_oslog_config_t oslog_cfg;
    oslog_cfg.ctxt = ctxt;
    oslog_cfg.start_log_regex = NULL;
    oslog_cfg.is_header_processed = true;

    will_return(__wrap_w_expression_match, false);

    expect_string(__wrap__merror, formatted_msg, "(1602): Execution error 'log: test'");

    bool ret = oslog_is_header(& oslog_cfg, buffer);

    assert_true(ret);

    os_free(buffer);

}

void test_oslog_is_header_log_stream_execution_error_colon(void ** state) {

    w_oslog_ctxt_t ctxt;
    strncpy(ctxt.buffer,"test\n",OS_MAXSTR);

    char * buffer = NULL;
    os_strdup("log: ", buffer);

    w_oslog_config_t oslog_cfg;
    oslog_cfg.ctxt = ctxt;
    oslog_cfg.start_log_regex = NULL;
    oslog_cfg.is_header_processed = true;

    will_return(__wrap_w_expression_match, false);

    expect_string(__wrap__merror, formatted_msg, "(1602): Execution error 'log'");

    bool ret = oslog_is_header(& oslog_cfg, buffer);

    assert_true(ret);

    os_free(buffer);

}

void test_oslog_is_header_log_stream_execution_error_line_break(void ** state) {

    w_oslog_ctxt_t ctxt;
    strncpy(ctxt.buffer,"test\n",OS_MAXSTR);

    char * buffer = NULL;
    os_strdup("log: test\n", buffer);

    w_oslog_config_t oslog_cfg;
    oslog_cfg.ctxt = ctxt;
    oslog_cfg.start_log_regex = NULL;
    oslog_cfg.is_header_processed = true;

    will_return(__wrap_w_expression_match, false);

    expect_string(__wrap__merror, formatted_msg, "(1602): Execution error 'log: test'");

    bool ret = oslog_is_header(& oslog_cfg, buffer);

    assert_true(ret);

    os_free(buffer);

}

void test_oslog_is_header_reading_other_log(void ** state) {

    w_oslog_ctxt_t ctxt;
    strncpy(ctxt.buffer,"test\n",OS_MAXSTR);

    char * buffer = NULL;
    os_strdup("test", buffer);

    w_oslog_config_t oslog_cfg;
    oslog_cfg.ctxt = ctxt;
    oslog_cfg.start_log_regex = NULL;
    oslog_cfg.is_header_processed = false;

    will_return(__wrap_w_expression_match, false);

    expect_string(__wrap__mdebug2, formatted_msg, "Reading other log headers or errors: 'test'");

    bool ret = oslog_is_header(& oslog_cfg, buffer);

    assert_true(ret);

    os_free(buffer);

}

void test_oslog_is_header_reading_other_log_line_break(void ** state) {

    w_oslog_ctxt_t ctxt;
    strncpy(ctxt.buffer,"test\n",OS_MAXSTR);

    char * buffer = NULL;
    os_strdup("test\n", buffer);

    w_oslog_config_t oslog_cfg;
    oslog_cfg.ctxt = ctxt;
    oslog_cfg.start_log_regex = NULL;
    oslog_cfg.is_header_processed = false;

    will_return(__wrap_w_expression_match, false);

    expect_string(__wrap__mdebug2, formatted_msg, "Reading other log headers or errors: 'test'");

    bool ret = oslog_is_header(& oslog_cfg, buffer);

    assert_true(ret);

    os_free(buffer);

}

int main(void) {
    const struct CMUnitTest tests[] = {
        // Test oslog_ctxt_restore
        cmocka_unit_test(test_oslog_ctxt_restore_false),
        cmocka_unit_test(test_oslog_ctxt_restore_true),
        // Test oslog_ctxt_backup
        cmocka_unit_test(test_oslog_ctxt_backup_success),
        // Test oslog_ctxt_clean
        cmocka_unit_test(test_oslog_ctxt_clean_success),
        // Test oslog_ctxt_is_expired
        cmocka_unit_test(test_oslog_ctxt_is_expired_true),
        cmocka_unit_test(test_oslog_ctxt_is_expired_false),
        // Test oslog_get_valid_lastline
        cmocka_unit_test(test_oslog_get_valid_lastline_str_null),
        cmocka_unit_test(test_oslog_get_valid_lastline_str_empty),
        cmocka_unit_test(test_oslog_get_valid_lastline_str_without_new_line),
        cmocka_unit_test(test_oslog_get_valid_lastline_str_with_new_line_end),
        cmocka_unit_test(test_oslog_get_valid_lastline_str_with_new_line_not_end),
        cmocka_unit_test(test_oslog_get_valid_lastline_str_with_two_new_lines_end),
        cmocka_unit_test(test_oslog_get_valid_lastline_str_with_two_new_lines_not_end),
        cmocka_unit_test(test_oslog_get_valid_lastline_str_with_three_new_lines_not_end),
        // Test oslog_is_header
        cmocka_unit_test(test_oslog_is_header_success),
        cmocka_unit_test(test_oslog_is_header_log_stream_execution_error_after_exec),
        cmocka_unit_test(test_oslog_is_header_log_stream_execution_error_colon),
        cmocka_unit_test(test_oslog_is_header_log_stream_execution_error_line_break),
        cmocka_unit_test(test_oslog_is_header_reading_other_log),
        cmocka_unit_test(test_oslog_is_header_reading_other_log_line_break),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
