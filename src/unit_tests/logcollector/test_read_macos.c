/*
 * Copyright (C) 2015-2021, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Includes */

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
#include "../wrappers/posix/signal_wrappers.h"
#include "../wrappers/linux/wait_wrappers.h"
#include "../wrappers/posix/time_wrappers.h"

/* Defines */

#define TESTING_MAXIMUM_LINES   1000

/* Prototypes */

bool w_macos_log_ctxt_restore(char * buffer, w_macos_log_ctxt_t * ctxt);
void w_macos_log_ctxt_backup(char * buffer, w_macos_log_ctxt_t * ctxt);
void w_macos_log_ctxt_clean(w_macos_log_ctxt_t * ctxt);
bool w_macos_is_log_ctxt_expired(time_t timeout, w_macos_log_ctxt_t * ctxt);
char * w_macos_log_get_last_valid_line(char * str);
bool w_macos_is_log_header(w_macos_log_config_t * macos_log_cfg, char * buffer);
bool w_macos_is_log_header(w_macos_log_config_t * macos_log_cfg, char * buffer);
bool w_macos_log_getlog(char * buffer, int length, FILE * stream, w_macos_log_config_t * macos_log_cfg);
char * w_macos_trim_full_timestamp(char *);
char * w_macos_get_last_log_timestamp(void);

/* Data Types */

typedef struct{
    wfd_t * show;
    wfd_t * stream;
} w_macos_log_wfd_t;

/* Globals */

extern w_macos_log_vault_t macos_log_vault;
extern w_macos_log_wfd_t macos_log_wfd;

extern int maximum_lines;
extern int errno;

/* Tests */

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

// todo: this function is repeated in other file
int __wrap_w_msg_hash_queues_push(void) {

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

    strncpy(buffer,"test\n",OS_MAXSTR);
    will_return(__wrap_time, 123456);

    w_macos_log_ctxt_backup(buffer, &ctxt);

    assert_string_equal(ctxt.buffer, "test\n");
    assert_int_equal(ctxt.timestamp, 123456);
}

/* w_macos_log_ctxt_clean */

void test_w_macos_log_ctxt_clean_success(void ** state) {

    w_macos_log_ctxt_t ctxt;

    strncpy(ctxt.buffer,"test\n",OS_MAXSTR);
    ctxt.timestamp = 123456;


    w_macos_log_ctxt_clean(&ctxt);

    assert_int_equal(ctxt.timestamp, 0);
    assert_string_equal(ctxt.buffer, "\0");
}

/* w_macos_is_log_ctxt_expired */

void test_w_macos_is_log_ctxt_expired_true(void ** state) {

    w_macos_log_ctxt_t ctxt;
    time_t timeout = (time_t) MACOS_LOG_TIMEOUT;

    ctxt.timestamp = (time_t) 1000;

    will_return(__wrap_time, 1000 + MACOS_LOG_TIMEOUT + 1);
    bool ret = w_macos_is_log_ctxt_expired(timeout, &ctxt);

    assert_true(ret);
}

void test_w_macos_is_log_ctxt_expired_false(void ** state) {

    w_macos_log_ctxt_t ctxt;
    time_t timeout = (time_t) MACOS_LOG_TIMEOUT;

    ctxt.timestamp = 1000;

    // threshold timeout
    will_return(__wrap_time, 1000 + MACOS_LOG_TIMEOUT);

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

    expect_string(__wrap__mdebug2, formatted_msg, "macOS ULS: Reading other log headers or errors: 'test'.");

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

    expect_string(__wrap__mdebug2, formatted_msg, "macOS ULS: Reading other log headers or errors: 'test'.");

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
    ctxt.timestamp = (time_t) 1000;
    will_return(__wrap_time, 1000 + MACOS_LOG_TIMEOUT + 1);

    w_macos_log_config_t macos_log_cfg;
    macos_log_cfg.ctxt = ctxt;
    macos_log_cfg.is_header_processed = true;

    int length =  OS_MAXSTR - OS_LOG_HEADER;

    FILE * stream = NULL;

    bool ret = w_macos_log_getlog(buffer, length, stream, &macos_log_cfg);

    assert_true(ret);
    assert_string_equal(buffer, "test");
}

void test_w_macos_log_getlog_context_expired_new_line(void ** state) {

    //test_oslog_ctxt_restore_true
    w_macos_log_ctxt_t ctxt;
    strncpy(ctxt.buffer,"test\n",OS_MAXSTR);

    char buffer[OS_MAXSTR + 1];
    buffer[OS_MAXSTR] = '\0';

    //test_oslog_ctxt_is_expired_true
    ctxt.timestamp = (time_t) 1000;
    will_return(__wrap_time, 1000 + MACOS_LOG_TIMEOUT + 1);

    w_macos_log_config_t macos_log_cfg;
    macos_log_cfg.ctxt = ctxt;
    macos_log_cfg.is_header_processed = true;

    int length =  OS_MAXSTR - OS_LOG_HEADER;

    FILE * stream = NULL;

    bool ret = w_macos_log_getlog(buffer, length, stream, &macos_log_cfg);

    assert_true(ret);
    assert_string_equal(buffer, "test");
}

void test_w_macos_log_getlog_context_not_expired(void ** state) {

    //test_oslog_ctxt_restore_true
    w_macos_log_ctxt_t ctxt;
    strncpy(ctxt.buffer,"test\n",OS_MAXSTR);

    char buffer[OS_MAXSTR + 1];
    buffer[OS_MAXSTR] = '\0';

    //test_oslog_ctxt_is_expired_false
    ctxt.timestamp = 1000;
    will_return(__wrap_time, 1000 + MACOS_LOG_TIMEOUT);

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
    assert_string_equal("test\n", macos_log_cfg.ctxt.buffer);
    assert_int_equal(ctxt.timestamp, 1000);
}

void test_w_macos_log_getlog_context_buffer_full(void ** state) {

    //test_oslog_ctxt_restore_true
    w_macos_log_ctxt_t ctxt;
    strncpy(ctxt.buffer,"test\n",OS_MAXSTR);

    char buffer[OS_MAXSTR + 1];
    buffer[OS_MAXSTR] = '\0';

    //test_oslog_ctxt_is_expired_false
    ctxt.timestamp = 1000;
    will_return(__wrap_time, 999 + MACOS_LOG_TIMEOUT);

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

void test_w_macos_log_getlog_context_buffer_full_no_endl_force_split(void ** state) {

    /* It must split the log, because the last line received (incomplete) can be part of a second log  */
    w_macos_log_ctxt_t ctxt;
    ctxt.buffer[0] = '\0';
    ctxt.timestamp = 1000;

    const char *test_str = "test large\nlog";
    char buffer[OS_MAXSTR + 1];

    w_macos_log_config_t macos_log_cfg;
    macos_log_cfg.ctxt = ctxt;
    macos_log_cfg.is_header_processed = true;

    int length = strlen(test_str) + 1;

    FILE * stream;
    os_calloc(1, sizeof(FILE *), stream);

    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, test_str);

    expect_string(__wrap__mdebug2, formatted_msg, "macOS ULS: Maximum message length reached. The remainder will be send separately.");
    will_return(__wrap_time, 1000);

    bool ret = w_macos_log_getlog(buffer, length, stream, &macos_log_cfg);

    assert_string_equal(buffer, "test large");
    assert_string_equal(macos_log_cfg.ctxt.buffer, "log");
    assert_int_equal(macos_log_cfg.ctxt.timestamp, 1000);
    assert_true(ret);

    os_free(stream);
}

void test_w_macos_log_getlog_context_not_endline(void ** state) {

    //test_oslog_ctxt_restore_true
    w_macos_log_ctxt_t ctxt;
    strncpy(ctxt.buffer,"test-\0",OS_MAXSTR);

    char buffer[OS_MAXSTR + 1];
    buffer[OS_MAXSTR] = '\0';

    //test_oslog_ctxt_is_expired_false
    ctxt.timestamp = 1000;
    will_return(__wrap_time, 999 + MACOS_LOG_TIMEOUT);

    w_macos_log_config_t macos_log_cfg;
    macos_log_cfg.ctxt = ctxt;
    macos_log_cfg.is_header_processed = true;

    int length =  strlen(ctxt.buffer)+10;

    FILE * stream;
    os_calloc(1, sizeof(FILE *), stream);

    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "test");

    expect_string(__wrap__mdebug2, formatted_msg, "macOS ULS: Incomplete message.");
    will_return(__wrap_time, ctxt.timestamp + 1);

    //test_oslog_ctxt_backup_success

    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, NULL);

    bool ret = w_macos_log_getlog(buffer, length, stream, &macos_log_cfg);

    assert_string_equal(macos_log_cfg.ctxt.buffer, "test-test");
    assert_int_equal(macos_log_cfg.ctxt.timestamp, 1000 + 1);
    assert_false(ret);

    os_free(stream);
}

void test_w_macos_log_getlog_context_full_buffer(void ** state) {

    //test_oslog_ctxt_restore_true
    w_macos_log_ctxt_t ctxt;
    strncpy(ctxt.buffer,"test--max...\0",OS_MAXSTR);

    char buffer[OS_MAXSTR + 1];
    buffer[OS_MAXSTR] = '\0';

    //test_oslog_ctxt_is_expired_false
    ctxt.timestamp = 1000;
    will_return(__wrap_time, 999 + MACOS_LOG_TIMEOUT);

    w_macos_log_config_t macos_log_cfg;
    macos_log_cfg.ctxt = ctxt;
    macos_log_cfg.is_header_processed = false;

    FILE * stream;
    os_calloc(1, sizeof(FILE *), stream);

    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "more content................");
    int length =  strlen(ctxt.buffer) + strlen("more content...") + 1;

    //test_w_macos_is_log_header_false
    will_return(__wrap_w_expression_match, true);

    will_return(__wrap_fgetc,'\n');

    expect_string(__wrap__mdebug2, formatted_msg, "macOS ULS: Maximum message length reached. The remainder was discarded.");

    bool ret = w_macos_log_getlog(buffer, length, stream, &macos_log_cfg);

    assert_string_equal(buffer,"test--max...more content...");
    assert_string_equal("", macos_log_cfg.ctxt.buffer);
    assert_int_equal(0, macos_log_cfg.ctxt.timestamp);
    assert_true(ret);

    os_free(stream);
}

void test_w_macos_log_getlog_discards_irrelevant_headers(void ** state) {

    //test_oslog_ctxt_restore_true
    w_macos_log_ctxt_t ctxt;
    strncpy(ctxt.buffer,"Other headers, line1\n\0",OS_MAXSTR);

    char buffer[OS_MAXSTR + 1];
    buffer[OS_MAXSTR] = '\0';

    //test_oslog_ctxt_is_expired_false
    ctxt.timestamp = 1000;
    will_return(__wrap_time, 999 + MACOS_LOG_TIMEOUT);

    w_macos_log_config_t macos_log_cfg;
    macos_log_cfg.ctxt = ctxt;
    macos_log_cfg.is_header_processed = false;

    int length =  strlen(ctxt.buffer) + 100;

    FILE * stream;
    os_calloc(1, sizeof(FILE *), stream);

    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "Other headers, line2\n");

    //test_oslog_ctxt_backup_success

    //test_w_macos_is_log_header_reading_other_log
    will_return(__wrap_w_expression_match, false);

    expect_string(__wrap__mdebug2, formatted_msg, "macOS ULS: Reading other log headers or errors:"
                                                  " 'Other headers, line1\nOther headers, line2'.");

    bool ret = w_macos_log_getlog(buffer, length, stream, &macos_log_cfg);

    assert_string_equal(buffer,"");
    assert_true(ret);

    os_free(stream);
}

void test_w_macos_log_getlog_split_two_logs(void ** state) {

    //test_oslog_ctxt_restore_true
    w_macos_log_ctxt_t ctxt;
    strncpy(ctxt.buffer, "log 1 first line\nlog 1 second line\n", OS_MAXSTR);

    char buffer[OS_MAXSTR + 1];
    buffer[OS_MAXSTR] = '\0';

    //test_oslog_ctxt_is_expired_false
    ctxt.timestamp = 1000;
    will_return(__wrap_time, 999 + MACOS_LOG_TIMEOUT);

    w_macos_log_config_t macos_log_cfg;
    macos_log_cfg.ctxt = ctxt;
    macos_log_cfg.is_header_processed = false;

    int length =  strlen(ctxt.buffer) + 100;

    FILE * stream;
    os_calloc(1, sizeof(FILE *), stream);

    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "log 2 first line\n");

    //test_oslog_ctxt_backup_success

    //test_w_macos_is_log_header_false
    will_return(__wrap_w_expression_match, true);

    //test_oslog_get_valid_lastline
    will_return(__wrap_w_expression_match, true);
    will_return(__wrap_time, 1001);

    bool ret = w_macos_log_getlog(buffer, length, stream, &macos_log_cfg);

    assert_string_equal(buffer, "log 1 first line\nlog 1 second line");
    assert_string_equal(macos_log_cfg.ctxt.buffer, "log 2 first line\n");
    assert_int_equal(macos_log_cfg.ctxt.timestamp, 1001);
    assert_true(ret);

    os_free(stream);
}

void test_w_macos_log_getlog_backup_context(void ** state) {

    w_macos_log_ctxt_t ctxt;
    ctxt.buffer[0] = '\0';
    ctxt.timestamp = 0;

    char buffer[OS_MAXSTR + 1];
    buffer[OS_MAXSTR] = '\0';

    w_macos_log_config_t macos_log_cfg;
    macos_log_cfg.ctxt = ctxt;
    macos_log_cfg.is_header_processed = true;

    int length =  OS_MAXSTR;

    FILE * stream;
    os_calloc(1, sizeof(FILE *), stream);

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "test\n");
    will_return(__wrap_time, 1000);
    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, NULL);

    bool ret = w_macos_log_getlog(buffer, length, stream, &macos_log_cfg);

    assert_false(ret);
    assert_string_equal(macos_log_cfg.ctxt.buffer, "test\n");
    assert_int_equal(macos_log_cfg.ctxt.timestamp, 1000);

    os_free(stream);
}

void test_w_macos_log_getlog_cannot_read(void ** state) {

    w_macos_log_ctxt_t ctxt;
    strncpy(ctxt.buffer,"test",OS_MAXSTR);
    time_t now = 1000;
    ctxt.timestamp = now;
    will_return(__wrap_time, 1000 + 1);

    char buffer[OS_MAXSTR + 1];
    buffer[OS_MAXSTR] = '\0';

    w_macos_log_config_t macos_log_cfg;
    macos_log_cfg.ctxt = ctxt;
    macos_log_cfg.is_header_processed = true;

    int length =  OS_MAXSTR;

    FILE * stream;
    os_calloc(1, sizeof(FILE *), stream);

    will_return(__wrap_can_read, 0);

    bool ret = w_macos_log_getlog(buffer, length, stream, &macos_log_cfg);

    assert_false(ret);
    assert_string_equal(macos_log_cfg.ctxt.buffer, "test");
    assert(macos_log_cfg.ctxt.timestamp == now);
    os_free(stream);

}

void test_w_macos_log_getlog_discard_until_null(void ** state) {

    //test_oslog_ctxt_restore_true
    w_macos_log_ctxt_t ctxt;
    strncpy(ctxt.buffer,"test\0",OS_MAXSTR);

    char buffer[OS_MAXSTR + 1];
    buffer[OS_MAXSTR] = '\0';

    //test_oslog_ctxt_is_expired_false
    ctxt.timestamp = 1000;
    will_return(__wrap_time, 999 + MACOS_LOG_TIMEOUT);

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

    will_return(__wrap_fgetc,'X');
    will_return(__wrap_fgetc,'X');
    will_return(__wrap_fgetc,NULL);

    expect_string(__wrap__mdebug2, formatted_msg, "macOS ULS: Maximum message length reached. The remainder was discarded.");

    bool ret = w_macos_log_getlog(buffer, length, stream, &macos_log_cfg);

    //assert_string_equal(buffer,"test");
    assert_true(ret);

    os_free(stream);

}

void test_w_macos_log_getlog_discard_until_eof(void ** state) {

    //test_oslog_ctxt_restore_true
    w_macos_log_ctxt_t ctxt;
    strncpy(ctxt.buffer,"test\0",OS_MAXSTR);

    char buffer[OS_MAXSTR + 1];
    buffer[OS_MAXSTR] = '\0';

    //test_oslog_ctxt_is_expired_false
    ctxt.timestamp = 1000;
    will_return(__wrap_time, 999 + MACOS_LOG_TIMEOUT);

    w_macos_log_config_t macos_log_cfg;
    macos_log_cfg.ctxt = ctxt;
    macos_log_cfg.is_header_processed = false;

    int length =  strlen(ctxt.buffer)+1;

    FILE * stream;
    os_calloc(1, sizeof(FILE *), stream);

    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "test");

    //test_w_macos_is_log_header_false
    will_return(__wrap_w_expression_match, true);

    will_return(__wrap_fgetc,'X');
    will_return(__wrap_fgetc,'X');
    will_return(__wrap_fgetc,EOF);

    expect_string(__wrap__mdebug2, formatted_msg, "macOS ULS: Maximum message length reached. The remainder was discarded.");

    bool ret = w_macos_log_getlog(buffer, length, stream, &macos_log_cfg);

    //assert_string_equal(buffer,"test");
    assert_true(ret);

    os_free(stream);

}

void test_w_macos_trim_full_timestamp_null_pointer(void ** state) {

    assert_null(w_macos_trim_full_timestamp(NULL));
}

void test_w_macos_trim_full_timestamp_empty_string(void ** state) {

    assert_null(w_macos_trim_full_timestamp(""));
}

void test_w_macos_trim_full_timestamp_incomplete_timestamp(void ** state) {

    char * INCOMPLETE_TIMESTAMP = "2019-12-14 05:43:58.9";

    assert_null(w_macos_trim_full_timestamp(INCOMPLETE_TIMESTAMP));
}

void test_w_macos_trim_full_timestamp_full_timestamp(void ** state) {

    char * FULL_TIMESTAMP = "2019-12-14 05:43:58.972536-0800";
    char * EXPECTED_TRIMMED_TIMESTAMP = "2019-12-14 05:43:58-0800";
    char * retstr;

    retstr = w_macos_trim_full_timestamp(FULL_TIMESTAMP);

    assert_non_null(retstr);
    assert_string_equal(retstr, EXPECTED_TRIMMED_TIMESTAMP);

    os_free(retstr);
}

void test_read_macos_can_read_false(void ** state) {

    logreader dummy_lf;
    int dummy_rc;

    os_calloc(1, sizeof(w_macos_log_config_t), dummy_lf.macos_log);
    dummy_lf.macos_log->state = LOG_RUNNING_STREAM;

    will_return(__wrap_can_read, 0);

    assert_null(read_macos(&dummy_lf, &dummy_rc, 0));

    os_free(dummy_lf.macos_log);
}

void test_read_macos_getlog_false(void ** state) {

    logreader lf;
    int dummy_rc;

    os_calloc(1, sizeof(w_macos_log_config_t), lf.macos_log);
    os_calloc(1, sizeof(wfd_t), lf.macos_log->stream_wfd);
    lf.macos_log->state = LOG_RUNNING_STREAM;
    lf.macos_log->stream_wfd->pid = getpid();

    will_return(__wrap_can_read, 1);
    will_return(__wrap_can_read, 0); // forces w_macos_log_getlog to return NULL

    expect_any(__wrap_waitpid, __pid);
    expect_any(__wrap_waitpid, __options);
    will_return(__wrap_waitpid, 0);
    will_return(__wrap_waitpid, 0);

    assert_null(read_macos(&lf, &dummy_rc, 0));

    os_free(lf.macos_log->stream_wfd);
    os_free(lf.macos_log);
}

void test_read_macos_empty_log(void ** state) {

    logreader lf;
    int dummy_rc;

    os_calloc(1, sizeof(w_macos_log_config_t), lf.macos_log);
    os_calloc(1, sizeof(wfd_t), lf.macos_log->stream_wfd);
    lf.macos_log->state = LOG_RUNNING_STREAM;
    lf.macos_log->stream_wfd->pid = getpid();

    will_return(__wrap_can_read, 1);

    // This block forces w_macos_log_getlog to return "true" and an empty buffer
    lf.macos_log->ctxt.buffer[0] = '\n';
    lf.macos_log->ctxt.buffer[1] = '\0';
    lf.macos_log->ctxt.timestamp = 1000;
    will_return(__wrap_time, 1000 + MACOS_LOG_TIMEOUT + 1);

    expect_string(__wrap__mdebug2, formatted_msg, "macOS ULS: Discarding empty message.");
    will_return(__wrap_can_read, 0); // second loop

    expect_any(__wrap_waitpid, __pid);
    expect_any(__wrap_waitpid, __options);
    will_return(__wrap_waitpid, 0);
    will_return(__wrap_waitpid, 0);

    assert_null(read_macos(&lf, &dummy_rc, 0));

    os_free(lf.macos_log->stream_wfd);
    os_free(lf.macos_log);
}

void test_read_macos_incomplete_short_log(void ** state) {

    logreader lf;
    int dummy_rc;

    os_calloc(1, sizeof(w_macos_log_config_t), lf.macos_log);
    os_calloc(1, sizeof(wfd_t), lf.macos_log->stream_wfd);
    lf.macos_log->state = LOG_RUNNING_STREAM;
    lf.macos_log->stream_wfd->pid = getpid();
    lf.macos_log->ctxt.buffer[0] = '\0';

    will_return(__wrap_can_read, 1);

    will_return(__wrap_can_read, 1);
    lf.macos_log->ctxt.timestamp = 1000;
    will_return(__wrap_time, 999 + MACOS_LOG_TIMEOUT);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "test");

    expect_string(__wrap__mdebug2, formatted_msg, "macOS ULS: Incomplete message.");
    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, NULL);

    expect_any(__wrap_waitpid, __pid);
    expect_any(__wrap_waitpid, __options);
    will_return(__wrap_waitpid, 0);
    will_return(__wrap_waitpid, 0);

    assert_null(read_macos(&lf, &dummy_rc, 0));

    os_free(lf.macos_log->stream_wfd);
    os_free(lf.macos_log);
}

void test_read_macos_single_full_log(void ** state) {

    logreader lf;
    int dummy_rc;

    os_calloc(1, sizeof(w_macos_log_config_t), lf.macos_log);
    os_calloc(1, sizeof(wfd_t), lf.macos_log->stream_wfd);
    lf.macos_log->state = LOG_RUNNING_STREAM;
    lf.macos_log->stream_wfd->pid = getpid();
    lf.macos_log->is_header_processed = true;
    lf.macos_log->ctxt.timestamp = 1000;
    strcpy(lf.macos_log->ctxt.buffer, "2021-05-17 15:31:53.586313-0700  localhost sshd[880]: (libsystem_info.dylib) Created Activity ID: 0x2040, Description: Retrieve User by Name\n");

    will_return(__wrap_can_read, 1);
    will_return(__wrap_time, 1000 + MACOS_LOG_TIMEOUT + 1);
    will_return(__wrap_w_msg_hash_queues_push, 0);
    will_return(__wrap_can_read, 0);

    expect_any(__wrap_waitpid, __pid);
    expect_any(__wrap_waitpid, __options);
    will_return(__wrap_waitpid, 0);
    will_return(__wrap_waitpid, 0);
    assert_null(read_macos(&lf, &dummy_rc, 0));
    char * last_timestamp = w_macos_get_last_log_timestamp();
    assert_string_equal(last_timestamp, "2021-05-17 15:31:53-0700");

    os_free(lf.macos_log->stream_wfd);
    os_free(lf.macos_log);
    os_free(last_timestamp);
}

void test_read_macos_more_logs_than_maximum(void ** state) {

    logreader lf;
    int dummy_rc;
    int TIMESTAMP_TIME = 10;

    os_calloc(1, sizeof(w_macos_log_config_t), lf.macos_log);
    os_calloc(1, sizeof(wfd_t), lf.macos_log->stream_wfd);
    lf.macos_log->state = LOG_RUNNING_STREAM;
    lf.macos_log->stream_wfd->pid = getpid();
    lf.macos_log->is_header_processed = true;
    lf.macos_log->ctxt.timestamp = TIMESTAMP_TIME;
    maximum_lines = 3;

    will_return(__wrap_can_read, 1);

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "2021-05-17 15:31:53.586313-0700  localhost sshd[880]: (libsystem_info.dylib) Created Activity ID: 0x2040, Description: Retrieve User by Name\n");
    will_return(__wrap_time, TIMESTAMP_TIME);

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "2021-05-17 15:31:54.586313-0700  localhost sshd[880]: (libsystem_info.dylib) Created Activity ID: 0x2040, Description: Retrieve User by Name\n");
    will_return(__wrap_w_expression_match, true);
    will_return(__wrap_time, TIMESTAMP_TIME);
    will_return(__wrap_w_msg_hash_queues_push, 0);
    will_return(__wrap_time, TIMESTAMP_TIME);

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "2021-05-17 15:31:55.586313-0700  localhost sshd[880]: (libsystem_info.dylib) Created Activity ID: 0x2040, Description: Retrieve User by Name\n");
    will_return(__wrap_w_expression_match, true);
    will_return(__wrap_time, TIMESTAMP_TIME);
    will_return(__wrap_w_msg_hash_queues_push, 0);
    will_return(__wrap_time, TIMESTAMP_TIME);

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "2021-05-17 15:31:56.586313-0700  localhost sshd[880]: (libsystem_info.dylib) Created Activity ID: 0x2040, Description: Retrieve User by Name\n");
    will_return(__wrap_w_expression_match, true);
    will_return(__wrap_time, TIMESTAMP_TIME);
    will_return(__wrap_w_msg_hash_queues_push, 0);

    assert_null(read_macos(&lf, &dummy_rc, 0));
    char * last_timestamp = w_macos_get_last_log_timestamp();
    assert_string_equal(last_timestamp, "2021-05-17 15:31:55-0700");    // Last message (15:31:56) is not yet stored

    maximum_lines = TESTING_MAXIMUM_LINES;
    os_free(lf.macos_log->stream_wfd);
    os_free(lf.macos_log);
    os_free(last_timestamp);
}

void test_read_macos_disable_maximum_lines(void ** state) {

    logreader lf;
    int dummy_rc;
    int TIMESTAMP_TIME = 10;

    os_calloc(1, sizeof(w_macos_log_config_t), lf.macos_log);
    os_calloc(1, sizeof(wfd_t), lf.macos_log->stream_wfd);
    lf.macos_log->state = LOG_RUNNING_STREAM;
    lf.macos_log->stream_wfd->pid = getpid();
    lf.macos_log->is_header_processed = true;
    lf.macos_log->ctxt.timestamp = TIMESTAMP_TIME;
    maximum_lines = 0;

    will_return(__wrap_can_read, 1);

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "2021-05-17 15:31:53.586313-0700  localhost sshd[880]: (libsystem_info.dylib) Created Activity ID: 0x2040, Description: Retrieve User by Name\n");
    will_return(__wrap_time, TIMESTAMP_TIME);

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "2021-05-17 15:31:54.586313-0700  localhost sshd[880]: (libsystem_info.dylib) Created Activity ID: 0x2040, Description: Retrieve User by Name\n");
    will_return(__wrap_w_expression_match, true);
    will_return(__wrap_time, TIMESTAMP_TIME);
    will_return(__wrap_w_msg_hash_queues_push, 0);
    will_return(__wrap_time, TIMESTAMP_TIME);

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "2021-05-17 15:31:55.586313-0700  localhost sshd[880]: (libsystem_info.dylib) Created Activity ID: 0x2040, Description: Retrieve User by Name\n");
    will_return(__wrap_w_expression_match, true);
    will_return(__wrap_time, TIMESTAMP_TIME);
    will_return(__wrap_w_msg_hash_queues_push, 0);
    will_return(__wrap_time, TIMESTAMP_TIME);

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "2021-05-17 15:31:56.586313-0700  localhost sshd[880]: (libsystem_info.dylib) Created Activity ID: 0x2040, Description: Retrieve User by Name\n");
    will_return(__wrap_w_expression_match, true);
    will_return(__wrap_time, TIMESTAMP_TIME);
    will_return(__wrap_w_msg_hash_queues_push, 0);
    will_return(__wrap_time, TIMESTAMP_TIME+100);
    will_return(__wrap_w_msg_hash_queues_push, 0);

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, NULL);

    assert_null(read_macos(&lf, &dummy_rc, 0));
    char * last_timestamp = w_macos_get_last_log_timestamp();
    assert_string_equal(last_timestamp, "2021-05-17 15:31:56-0700");

    maximum_lines = TESTING_MAXIMUM_LINES;
    os_free(lf.macos_log->stream_wfd);
    os_free(lf.macos_log);
    os_free(last_timestamp);
}

void test_read_macos_toggle_correctly_ended_show_to_stream(void ** state) {

    logreader lf;
    int dummy_rc;

    os_calloc(1, sizeof(w_macos_log_config_t), lf.macos_log);
    os_calloc(1, sizeof(wfd_t), lf.macos_log->show_wfd);
    os_calloc(1, sizeof(wfd_t), lf.macos_log->stream_wfd);

    lf.macos_log->state = LOG_RUNNING_SHOW;
    lf.macos_log->show_wfd->pid = 10;
    lf.macos_log->stream_wfd->pid = 11;
    macos_log_wfd.show = lf.macos_log->show_wfd;
    macos_log_wfd.stream = lf.macos_log->stream_wfd;

    // Save an expired context to send it immediately 
    strcpy(lf.macos_log->ctxt.buffer, "2021-05-17 15:31:53.586313-0700  localhost sshd[880]: (libsystem_info.dylib)\n");
    lf.macos_log->ctxt.timestamp = 1000;
    will_return(__wrap_time, 1000 + MACOS_LOG_TIMEOUT + 1);

    will_return(__wrap_can_read, 1);
    will_return(__wrap_w_msg_hash_queues_push, 0);
    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, NULL);

    expect_any(__wrap_waitpid, __pid);
    expect_any(__wrap_waitpid, __options);
    will_return(__wrap_waitpid, 0);
    will_return(__wrap_waitpid, 10);

    expect_string(__wrap__minfo, formatted_msg, "(1607): macOS 'log show' process exited, pid: 10, exit value: 0.");
    expect_string(__wrap__mdebug1, formatted_msg, "macOS ULS: Releasing macOS `log show` resources.");

    expect_value(__wrap_kill, sig, SIGTERM);
    expect_value(__wrap_kill, pid, 10);
    will_return(__wrap_kill, 0);
    will_return(__wrap_wpclose, NULL);

    assert_null(read_macos(&lf, &dummy_rc, 0));
    assert_string_equal(lf.macos_log->ctxt.buffer, "");
    assert_true(lf.macos_log->store_current_settings);
    assert_string_equal(macos_log_vault.timestamp, "2021-05-17 15:31:53-0700");
    assert_int_equal(lf.macos_log->state, LOG_RUNNING_STREAM);
    assert_non_null(lf.macos_log->stream_wfd);
    assert_false(lf.macos_log->is_header_processed);

    os_free(lf.macos_log->show_wfd);
    os_free(lf.macos_log->stream_wfd);
    os_free(lf.macos_log);
}

void test_read_macos_toggle_faulty_ended_show_to_stream(void ** state) {

    logreader lf;
    int dummy_rc;

    os_calloc(1, sizeof(w_macos_log_config_t), lf.macos_log);
    os_calloc(1, sizeof(wfd_t), lf.macos_log->show_wfd);
    os_calloc(1, sizeof(wfd_t), lf.macos_log->stream_wfd);

    lf.macos_log->state = LOG_RUNNING_SHOW;
    lf.macos_log->show_wfd->pid = 10;
    lf.macos_log->stream_wfd->pid = 11;
    macos_log_wfd.show = lf.macos_log->show_wfd;
    macos_log_wfd.stream = lf.macos_log->stream_wfd;

    // Save an expired context to send it immediately 
    strcpy(lf.macos_log->ctxt.buffer, "2021-05-17 15:31:53.586313-0700  localhost sshd[880]: (libsystem_info.dylib)\n");
    lf.macos_log->ctxt.timestamp = 1000;
    will_return(__wrap_time, 1000 + MACOS_LOG_TIMEOUT + 1);

    will_return(__wrap_can_read, 1);
    will_return(__wrap_w_msg_hash_queues_push, 0);
    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, NULL);

    expect_any(__wrap_waitpid, __pid);
    expect_any(__wrap_waitpid, __options);
    will_return(__wrap_waitpid, 1);
    will_return(__wrap_waitpid, 10);

    expect_string(__wrap__merror, formatted_msg, "(1607): macOS 'log show' process exited, pid: 10, exit value: 1.");
    expect_string(__wrap__mdebug1, formatted_msg, "macOS ULS: Releasing macOS `log show` resources.");

    expect_value(__wrap_kill, sig, SIGTERM);
    expect_value(__wrap_kill, pid, 10);
    will_return(__wrap_kill, 0);
    will_return(__wrap_wpclose, NULL);

    assert_null(read_macos(&lf, &dummy_rc, 0));
    assert_string_equal(lf.macos_log->ctxt.buffer, "");
    assert_true(lf.macos_log->store_current_settings);
    assert_string_equal(macos_log_vault.timestamp, "2021-05-17 15:31:53-0700");
    assert_int_equal(lf.macos_log->state, LOG_RUNNING_STREAM);
    assert_non_null(lf.macos_log->stream_wfd);
    assert_false(lf.macos_log->is_header_processed);

    os_free(lf.macos_log->show_wfd);
    os_free(lf.macos_log->stream_wfd);
    os_free(lf.macos_log);
}

void test_read_macos_toggle_correctly_ended_show_to_faulty_stream(void ** state) {

    logreader lf;
    int dummy_rc;

    os_calloc(1, sizeof(w_macos_log_config_t), lf.macos_log);
    os_calloc(1, sizeof(wfd_t), lf.macos_log->show_wfd);

    lf.macos_log->state = LOG_RUNNING_SHOW;
    lf.macos_log->show_wfd->pid = 10;
    lf.macos_log->stream_wfd = NULL;
    macos_log_wfd.show = lf.macos_log->show_wfd;
    macos_log_wfd.stream = lf.macos_log->stream_wfd;

    // Save an expired context to send it immediately 
    strcpy(lf.macos_log->ctxt.buffer, "2021-05-17 15:31:53.586313-0700  localhost sshd[880]: (libsystem_info.dylib)\n");
    lf.macos_log->ctxt.timestamp = 1000;
    will_return(__wrap_time, 1000 + MACOS_LOG_TIMEOUT + 1);

    will_return(__wrap_can_read, 1);
    will_return(__wrap_w_msg_hash_queues_push, 0);
    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, NULL);

    expect_any(__wrap_waitpid, __pid);
    expect_any(__wrap_waitpid, __options);
    will_return(__wrap_waitpid, 0);
    will_return(__wrap_waitpid, 10);

    expect_string(__wrap__minfo, formatted_msg, "(1607): macOS 'log show' process exited, pid: 10, exit value: 0.");
    expect_string(__wrap__mdebug1, formatted_msg, "macOS ULS: Releasing macOS `log show` resources.");

    expect_value(__wrap_kill, sig, SIGTERM);
    expect_value(__wrap_kill, pid, 10);
    will_return(__wrap_kill, 0);
    will_return(__wrap_wpclose, NULL);

    assert_null(read_macos(&lf, &dummy_rc, 0));
    assert_string_equal(lf.macos_log->ctxt.buffer, "");
    assert_true(lf.macos_log->store_current_settings);
    assert_string_equal(macos_log_vault.timestamp, "2021-05-17 15:31:53-0700");
    assert_int_equal(lf.macos_log->state, LOG_NOT_RUNNING);
    assert_null(macos_log_wfd.show);

    os_free(lf.macos_log->show_wfd);
    os_free(lf.macos_log);
}

void test_read_macos_faulty_ended_stream(void ** state) {

    logreader lf;
    int dummy_rc;

    os_calloc(1, sizeof(w_macos_log_config_t), lf.macos_log);
    os_calloc(1, sizeof(wfd_t), lf.macos_log->stream_wfd);

    lf.macos_log->state = LOG_RUNNING_STREAM;
    lf.macos_log->stream_wfd->pid = 10;
    macos_log_wfd.stream = lf.macos_log->stream_wfd;

    // Save an expired context to send it immediately 
    strcpy(lf.macos_log->ctxt.buffer, "2021-05-17 15:31:53.586313-0700  localhost sshd[880]: (libsystem_info.dylib)\n");
    lf.macos_log->ctxt.timestamp = 1000;

    will_return(__wrap_can_read, 1);

    will_return(__wrap_time, 1000 + MACOS_LOG_TIMEOUT + 1);

    will_return(__wrap_w_msg_hash_queues_push, 0);
    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, NULL);

    expect_any(__wrap_waitpid, __pid);
    expect_any(__wrap_waitpid, __options);
    will_return(__wrap_waitpid, 1);
    will_return(__wrap_waitpid, 10);

    expect_string(__wrap__merror, formatted_msg, "(1607): macOS 'log stream' process exited, pid: 10, exit value: 1.");
    expect_string(__wrap__mdebug1, formatted_msg, "macOS ULS: Releasing macOS `log stream` resources.");

    expect_value(__wrap_kill, sig, SIGTERM);
    expect_value(__wrap_kill, pid, 10);
    will_return(__wrap_kill, 0);
    will_return(__wrap_wpclose, NULL);

    assert_null(read_macos(&lf, &dummy_rc, 0));
    assert_string_equal(lf.macos_log->ctxt.buffer, "");
    assert_true(lf.macos_log->store_current_settings);
    assert_string_equal(macos_log_vault.timestamp, "2021-05-17 15:31:53-0700");
    assert_int_equal(lf.macos_log->state, LOG_NOT_RUNNING);
    assert_null(macos_log_wfd.show);


    os_free(lf.macos_log->stream_wfd);
    os_free(lf.macos_log);
}

void test_read_macos_faulty_waitpid(void ** state) {

    logreader lf;
    int dummy_rc;
    errno = 123;

    os_calloc(1, sizeof(w_macos_log_config_t), lf.macos_log);
    os_calloc(1, sizeof(wfd_t), lf.macos_log->stream_wfd);

    lf.macos_log->state = LOG_RUNNING_STREAM;
    lf.macos_log->stream_wfd->pid = 10;
    macos_log_wfd.stream = lf.macos_log->stream_wfd;

    // Save an expired context to send it immediately 
    strcpy(lf.macos_log->ctxt.buffer, "2021-05-17 15:31:53.586313-0700  localhost sshd[880]: (libsystem_info.dylib)\n");
    lf.macos_log->ctxt.timestamp = 1000;

    will_return(__wrap_time, 1000 + MACOS_LOG_TIMEOUT + 1);

    will_return(__wrap_can_read, 1);
    will_return(__wrap_w_msg_hash_queues_push, 0);
    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, NULL);

    expect_any(__wrap_waitpid, __pid);
    expect_any(__wrap_waitpid, __options);
    will_return(__wrap_waitpid, 1);
    will_return(__wrap_waitpid, 2);
    will_return(__wrap_strerror, "error test");

    expect_string(__wrap__merror, formatted_msg, "(1111): Error during waitpid()-call due to [(123)-(error test)].");

    assert_null(read_macos(&lf, &dummy_rc, 0));
    assert_string_equal(lf.macos_log->ctxt.buffer, "");
    assert_true(lf.macos_log->store_current_settings);
    assert_string_equal(macos_log_vault.timestamp, "2021-05-17 15:31:53-0700");
    assert_null(macos_log_wfd.show);


    os_free(lf.macos_log->stream_wfd);
    os_free(lf.macos_log);
}

int main(void) {

    maximum_lines = TESTING_MAXIMUM_LINES;
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
        cmocka_unit_test(test_w_macos_log_getlog_context_buffer_full_no_endl_force_split),
        cmocka_unit_test(test_w_macos_log_getlog_context_not_endline),
        cmocka_unit_test(test_w_macos_log_getlog_context_full_buffer),
        cmocka_unit_test(test_w_macos_log_getlog_discards_irrelevant_headers),
        cmocka_unit_test(test_w_macos_log_getlog_split_two_logs),
        cmocka_unit_test(test_w_macos_log_getlog_backup_context),
        cmocka_unit_test(test_w_macos_log_getlog_cannot_read),
        cmocka_unit_test(test_w_macos_log_getlog_discard_until_eof),
        cmocka_unit_test(test_w_macos_log_getlog_discard_until_null),
        // Test w_macos_trim_full_timestamp
        cmocka_unit_test(test_w_macos_trim_full_timestamp_null_pointer),
        cmocka_unit_test(test_w_macos_trim_full_timestamp_empty_string),
        cmocka_unit_test(test_w_macos_trim_full_timestamp_incomplete_timestamp),
        cmocka_unit_test(test_w_macos_trim_full_timestamp_full_timestamp),
        // Test w_read_macos
        cmocka_unit_test(test_read_macos_can_read_false),
        cmocka_unit_test(test_read_macos_getlog_false),
        cmocka_unit_test(test_read_macos_empty_log),
        cmocka_unit_test(test_read_macos_incomplete_short_log),
        cmocka_unit_test(test_read_macos_single_full_log),
        cmocka_unit_test(test_read_macos_more_logs_than_maximum),
        cmocka_unit_test(test_read_macos_disable_maximum_lines),
        cmocka_unit_test(test_read_macos_toggle_correctly_ended_show_to_stream),
        cmocka_unit_test(test_read_macos_toggle_faulty_ended_show_to_stream),
        cmocka_unit_test(test_read_macos_toggle_correctly_ended_show_to_faulty_stream),
        cmocka_unit_test(test_read_macos_faulty_ended_stream),
        cmocka_unit_test(test_read_macos_faulty_waitpid),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
