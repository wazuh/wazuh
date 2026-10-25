/* Copyright (C) 2026, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include "../../logcollector/logcollector.h"
#include "../../headers/shared.h"
#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/file_op_wrappers.h"
#include "../wrappers/libc/stdio_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

#define MSSQL_HEADER "2009-03-25 04:47:30.01 Server test"
#define PGSQL_HEADER "[2007-08-31 19:17:32.186 ADT] 192.168.2.99:db_name"

/* Setup & Teardown */

static int group_setup(void **state) {
    test_mode = 1;
    return 0;
}

static int group_teardown(void **state) {
    test_mode = 0;
    return 0;
}

/* Wraps */

int __wrap_can_read() {
    return mock_type(int);
}

bool __wrap_w_get_hash_context(logreader *lf, EVP_MD_CTX **context, int64_t position) {
    return mock_type(bool);
}

int __wrap_w_update_file_status(const char *path, int64_t pos, EVP_MD_CTX *context) {
    EVP_MD_CTX_free(context);
    return mock_type(int);
}

void __wrap_OS_SHA1_Stream_Bytes(EVP_MD_CTX *c, const char * buf, size_t len) {
    function_called();
    check_expected(len);
}

int __wrap_w_msg_hash_queues_push(const char *str, char *file, unsigned long size, logtarget *log_target, char queue_mq) {
    check_expected(size);
    return mock_type(int);
}

bool __wrap_check_ignore_and_restrict(const char *ignore_regex, const char *restrict_regex, const char *str) {
    return mock_type(bool);
}

/* Helpers */

/* Tab-indented continuation line of len bytes, plus '\n' unless it is the unterminated last line of the file. */
static char * build_cont_line(size_t len, bool newline) {
    char *line = calloc(len + 2, sizeof(char));
    assert_non_null(line);
    memset(line, 'A', len);
    line[0] = '\t';
    if (newline) {
        line[len] = '\n';
    }
    return line;
}

/* File position reported by w_ftell after each line read */
static int64_t mock_position = 0;

/* Expect a line of line_len bytes, which may contain NUL bytes, to be read and hashed */
static void expect_line_bytes(char *line, size_t line_len) {
    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, line);
    mock_position += (int64_t) line_len;
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, mock_position);
    expect_function_call(__wrap_OS_SHA1_Stream_Bytes);
    expect_value(__wrap_OS_SHA1_Stream_Bytes, len, line_len);
}

static void expect_line(char *line) {
    expect_line_bytes(line, strlen(line));
}

/* Reads "<header>\n<continuation>" and expects a single message of expected_len bytes.
 * With hidden_len > 0 the continuation is followed by a NUL, hidden_len more bytes and '\n': the reader only
 * sees the bytes before the NUL, but every byte of the line must be hashed. */
static void run_reader_hidden(void *(*reader)(logreader *, int *, int), const char *header, size_t cont_len, bool newline,
                              size_t hidden_len, size_t expected_len) {
    logreader lf = {0};
    lf.file = "test.log";
    lf.fp = (FILE *) 1;
    int rc;

    char line1[OS_SIZE_256];
    snprintf(line1, sizeof(line1), "%s\n", header);
    char *line2 = NULL;
    size_t line2_len = 0;

    if (hidden_len > 0) {
        line2 = calloc(cont_len + hidden_len + 3, sizeof(char));
        assert_non_null(line2);
        memset(line2, 'A', cont_len);
        line2[0] = '\t';
        memset(line2 + cont_len + 1, 'B', hidden_len);
        line2[cont_len + 1 + hidden_len] = '\n';
        line2_len = cont_len + hidden_len + 2;
    } else {
        line2 = build_cont_line(cont_len, newline);
        line2_len = strlen(line2);
    }

    mock_position = 0;
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);
    will_return(__wrap_w_get_hash_context, true);

    expect_line(line1);
    expect_line_bytes(line2, line2_len);

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, NULL);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);
    will_return(__wrap_w_update_file_status, 0);

    will_return(__wrap_check_ignore_and_restrict, false);
    expect_value(__wrap_w_msg_hash_queues_push, size, expected_len + 1);
    will_return(__wrap_w_msg_hash_queues_push, 0);

    expect_any_count(__wrap__mdebug2, formatted_msg, 2);

    reader(&lf, &rc, 0);

    assert_int_equal(rc, 0);
    free(line2);
}

static void run_reader(void *(*reader)(logreader *, int *, int), const char *header, size_t cont_len, bool newline, size_t expected_len) {
    run_reader_hidden(reader, header, cont_len, newline, 0, expected_len);
}

/* Tests */

void test_read_mssql_log_last_line_fills_buffer(void **state) {
    size_t cont_len = OS_MAX_LOG_SIZE - strlen(MSSQL_HEADER) - 1;

    // No room left for the terminator: the continuation is dropped
    run_reader(read_mssql_log, MSSQL_HEADER, cont_len, false, strlen(MSSQL_HEADER));
}

void test_read_mssql_log_last_line_fits(void **state) {
    size_t cont_len = OS_MAX_LOG_SIZE - strlen(MSSQL_HEADER) - 2;

    run_reader(read_mssql_log, MSSQL_HEADER, cont_len, false, strlen(MSSQL_HEADER) + 1 + cont_len);
}

void test_read_mssql_log_newline_line_fits(void **state) {
    size_t cont_len = OS_MAX_LOG_SIZE - strlen(MSSQL_HEADER) - 2;

    // The '\n' is stripped before appending, so it must not count against the free space
    run_reader(read_mssql_log, MSSQL_HEADER, cont_len, true, strlen(MSSQL_HEADER) + 1 + cont_len);
}

void test_read_postgresql_log_last_line_fills_buffer(void **state) {
    size_t cont_len = OS_MAX_LOG_SIZE - strlen(PGSQL_HEADER) - 1;

    run_reader(read_postgresql_log, PGSQL_HEADER, cont_len, false, strlen(PGSQL_HEADER));
}

void test_read_postgresql_log_last_line_fits(void **state) {
    size_t cont_len = OS_MAX_LOG_SIZE - strlen(PGSQL_HEADER) - 2;

    run_reader(read_postgresql_log, PGSQL_HEADER, cont_len, false, strlen(PGSQL_HEADER) + 1 + cont_len);
}

void test_read_postgresql_log_newline_line_fits(void **state) {
    size_t cont_len = OS_MAX_LOG_SIZE - strlen(PGSQL_HEADER) - 2;

    run_reader(read_postgresql_log, PGSQL_HEADER, cont_len, true, strlen(PGSQL_HEADER) + 1 + cont_len);
}

void test_read_mssql_log_hashes_bytes_after_nul(void **state) {
    // Only "\tAAAA" reaches the message, but the 12 bytes of the line are hashed
    run_reader_hidden(read_mssql_log, MSSQL_HEADER, 5, false, 5, strlen(MSSQL_HEADER) + 1 + 5);
}

void test_read_postgresql_log_hashes_bytes_after_nul(void **state) {
    run_reader_hidden(read_postgresql_log, PGSQL_HEADER, 5, false, 5, strlen(PGSQL_HEADER) + 1 + 5);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_read_mssql_log_last_line_fills_buffer),
        cmocka_unit_test(test_read_mssql_log_last_line_fits),
        cmocka_unit_test(test_read_mssql_log_newline_line_fits),
        cmocka_unit_test(test_read_postgresql_log_last_line_fills_buffer),
        cmocka_unit_test(test_read_postgresql_log_last_line_fits),
        cmocka_unit_test(test_read_postgresql_log_newline_line_fits),
        cmocka_unit_test(test_read_mssql_log_hashes_bytes_after_nul),
        cmocka_unit_test(test_read_postgresql_log_hashes_bytes_after_nul),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
