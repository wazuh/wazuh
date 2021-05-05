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

bool macos_log_ctxt_restore(char * buffer, w_macos_log_ctxt_t * ctxt);
void macos_log_ctxt_backup(char * buffer, w_macos_log_ctxt_t * ctxt);
void macos_log_ctxt_clean(w_macos_log_ctxt_t * ctxt);
bool macos_is_log_ctxt_expired(time_t timeout, w_macos_log_ctxt_t * ctxt);
char * macos_log_get_last_valid_line(char * str);
bool MACOS_LOG_Header_check(w_macos_log_config_t * macos_log_cfg, char * buffer);

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


/* tests */

/* macos_log_ctxt_restore */

void test_macos_log_ctxt_restore_false(void ** state) {

    w_macos_log_ctxt_t ctxt;
    ctxt.buffer[0] = '\0';

    char * buffer = NULL;

    bool ret = macos_log_ctxt_restore(buffer, &ctxt);
    assert_false(ret);

}

void test_macos_log_ctxt_restore_true(void ** state) {

    w_macos_log_ctxt_t ctxt;
    strncpy(ctxt.buffer,"test",OS_MAXSTR);

    char buffer[OS_MAXSTR + 1];
    buffer[OS_MAXSTR] = '\0';

    bool ret = macos_log_ctxt_restore(buffer, &ctxt);
    assert_true(ret);

}

/* macos_log_ctxt_backup */

void test_macos_log_ctxt_backup_success(void ** state) {

    w_macos_log_ctxt_t ctxt;
    char buffer[OS_MAXSTR + 1];

    buffer[OS_MAXSTR] = '\0';

    strncpy(buffer,"test",OS_MAXSTR);

    macos_log_ctxt_backup(buffer, &ctxt);

    assert_non_null(ctxt.buffer);
    assert_non_null(ctxt.timestamp);

}

/* macos_log_ctxt_clean */

void test_macos_log_ctxt_clean_success(void ** state) {

    w_macos_log_ctxt_t ctxt;

    strncpy(ctxt.buffer,"test",OS_MAXSTR);
    ctxt.timestamp = time(NULL);


    macos_log_ctxt_clean(&ctxt);

    assert_int_equal(ctxt.timestamp, 0);
    assert_string_equal(ctxt.buffer,"\0");

}

/* macos_is_log_ctxt_expired */

void test_macos_is_log_ctxt_expired_true(void ** state) {

    w_macos_log_ctxt_t ctxt;
    time_t timeout = (time_t) MACOS_LOG_TIMEOUT;

    ctxt.timestamp = (time_t) 1;

    bool ret = macos_is_log_ctxt_expired(timeout, &ctxt);

    assert_true(ret);

}

void test_macos_is_log_ctxt_expired_false(void ** state) {

    w_macos_log_ctxt_t ctxt;
    time_t timeout = (time_t) MACOS_LOG_TIMEOUT;

    ctxt.timestamp = time(NULL);

    bool ret = macos_is_log_ctxt_expired(timeout, &ctxt);

    assert_false(ret);

}

/* macos_log_get_last_valid_line */

void test_macos_log_get_last_valid_line_str_null(void ** state) {

    char * str = NULL;

    char * ret =macos_log_get_last_valid_line(str);

    assert_null(ret);

}

void test_macos_log_get_last_valid_line_str_empty(void ** state) {

    char * str = '\0';

    char * ret =macos_log_get_last_valid_line(str);

    assert_null(ret);

}

void test_macos_log_get_last_valid_line_str_without_new_line(void ** state) {

    char * str = NULL;

    os_strdup("2021-04-22 12:00:00.230270-0700 test", str);

    char * ret =macos_log_get_last_valid_line(str);

    assert_null(ret);
    os_free(str);

}

void test_macos_log_get_last_valid_line_str_with_new_line_end(void ** state) {

    char * str = NULL;

    os_strdup("2021-04-22 12:00:00.230270-0700 test\n", str);

    char * ret =macos_log_get_last_valid_line(str);

    assert_null(ret);
    os_free(str);

}

void test_macos_log_get_last_valid_line_str_with_new_line_not_end(void ** state) {

    char * str = NULL;

    os_strdup("2021-04-22 12:00:00.230270-0700 test\n2021-04-22 12:00:00.230270-0700 test2", str);

    char * ret =macos_log_get_last_valid_line(str);

    assert_string_equal(ret, "\n2021-04-22 12:00:00.230270-0700 test2");
    os_free(str);

}

void test_macos_log_get_last_valid_line_str_with_two_new_lines_end(void ** state) {

    char * str = NULL;

    os_strdup("2021-04-22 12:00:00.230270-0700 test\n2021-04-22 12:00:00.230270-0700 test2\n", str);

    char * ret =macos_log_get_last_valid_line(str);

    assert_string_equal(ret, "\n2021-04-22 12:00:00.230270-0700 test2\n");
    os_free(str);

}

void test_macos_log_get_last_valid_line_str_with_two_new_lines_not_end(void ** state) {

    char * str = NULL;

    os_strdup("2021-04-22 12:00:00.230270-0700 test\n2021-04-22 12:00:00.230270-0700 test2\n2021-04-22 12:00:00.230270-0700 test3", str);

    char * ret =macos_log_get_last_valid_line(str);

    assert_string_equal(ret, "\n2021-04-22 12:00:00.230270-0700 test3");
    os_free(str);

}

void test_macos_log_get_last_valid_line_str_with_three_new_lines_end(void ** state) {

    char * str = NULL;

    os_strdup("2021-04-22 12:00:00.230270-0700 test\n2021-04-22 12:00:00.230270-0700 test2\n2021-04-22 12:00:00.230270-0700 test3\n", str);

    char * ret =macos_log_get_last_valid_line(str);

    assert_string_equal(ret, "\n2021-04-22 12:00:00.230270-0700 test3\n");
    os_free(str);

}

void test_macos_log_get_last_valid_line_str_with_three_new_lines_not_end(void ** state) {

    char * str = NULL;

    os_strdup("2021-04-22 12:00:00.230270-0700 test\n2021-04-22 12:00:00.230270-0700 test2\n2021-04-22 12:00:00.230270-0700 test3\n2021-04-22 12:00:00.230270-0700 test4", str);

    char * ret =macos_log_get_last_valid_line(str);

    assert_string_equal(ret, "\n2021-04-22 12:00:00.230270-0700 test4");
    os_free(str);

}

int main(void) {
    const struct CMUnitTest tests[] = {
        // Test macos_log_ctxt_restore
        cmocka_unit_test(test_macos_log_ctxt_restore_false),
        cmocka_unit_test(test_macos_log_ctxt_restore_true),
        // Test macos_log_ctxt_backup
        cmocka_unit_test(test_macos_log_ctxt_backup_success),
        // Test macos_log_ctxt_clean
        cmocka_unit_test(test_macos_log_ctxt_clean_success),
        // Test macos_is_log_ctxt_expired
        cmocka_unit_test(test_macos_is_log_ctxt_expired_true),
        cmocka_unit_test(test_macos_is_log_ctxt_expired_false),
        // Test macos_log_get_last_valid_line
        cmocka_unit_test(test_macos_log_get_last_valid_line_str_null),
        cmocka_unit_test(test_macos_log_get_last_valid_line_str_empty),
        cmocka_unit_test(test_macos_log_get_last_valid_line_str_without_new_line),
        cmocka_unit_test(test_macos_log_get_last_valid_line_str_with_new_line_end),
        cmocka_unit_test(test_macos_log_get_last_valid_line_str_with_new_line_not_end),
        cmocka_unit_test(test_macos_log_get_last_valid_line_str_with_two_new_lines_end),
        cmocka_unit_test(test_macos_log_get_last_valid_line_str_with_two_new_lines_not_end),
        cmocka_unit_test(test_macos_log_get_last_valid_line_str_with_three_new_lines_not_end),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
