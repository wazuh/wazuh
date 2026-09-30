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

void __wrap_OS_SHA1_Stream(EVP_MD_CTX *c, os_sha1 output, char *buf) {
    function_called();
}

int __wrap_w_msg_hash_queues_push(const char *str, char *file, unsigned long size, logtarget *log_target, char queue_mq) {
    check_expected(size);
    return mock_type(int);
}

bool __wrap_check_ignore_and_restrict(const char *ignore_regex, const char *restrict_regex, const char *str) {
    return mock_type(bool);
}

/* Helpers */

/* Tab-indented continuation line of len bytes, not terminated by '\n' (last line of the file). */
static char * build_last_line(size_t len) {
    char *line = calloc(len + 1, sizeof(char));
    assert_non_null(line);
    memset(line, 'A', len);
    line[0] = '\t';
    return line;
}

static void expect_line(char *line) {
    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, line);
    expect_function_call(__wrap_OS_SHA1_Stream);
}

/* Reads "<header>\n<continuation>" and expects a single message of expected_len bytes. */
static void run_reader(void *(*reader)(logreader *, int *, int), const char *header, size_t cont_len, size_t expected_len) {
    logreader lf = {0};
    lf.file = "test.log";
    lf.fp = (FILE *) 1;
    int rc;

    char line1[OS_SIZE_256];
    snprintf(line1, sizeof(line1), "%s\n", header);
    char *line2 = build_last_line(cont_len);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);
    will_return(__wrap_w_get_hash_context, true);

    expect_line(line1);
    expect_line(line2);

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

/* Tests */

void test_read_mssql_log_last_line_fills_buffer(void **state) {
    size_t cont_len = OS_MAX_LOG_SIZE - strlen(MSSQL_HEADER) - 1;

    // No room left for the terminator: the continuation is dropped
    run_reader(read_mssql_log, MSSQL_HEADER, cont_len, strlen(MSSQL_HEADER));
}

void test_read_mssql_log_last_line_fits(void **state) {
    size_t cont_len = OS_MAX_LOG_SIZE - strlen(MSSQL_HEADER) - 2;

    run_reader(read_mssql_log, MSSQL_HEADER, cont_len, strlen(MSSQL_HEADER) + 1 + cont_len);
}

void test_read_postgresql_log_last_line_fills_buffer(void **state) {
    size_t cont_len = OS_MAX_LOG_SIZE - strlen(PGSQL_HEADER) - 1;

    run_reader(read_postgresql_log, PGSQL_HEADER, cont_len, strlen(PGSQL_HEADER));
}

void test_read_postgresql_log_last_line_fits(void **state) {
    size_t cont_len = OS_MAX_LOG_SIZE - strlen(PGSQL_HEADER) - 2;

    run_reader(read_postgresql_log, PGSQL_HEADER, cont_len, strlen(PGSQL_HEADER) + 1 + cont_len);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_read_mssql_log_last_line_fills_buffer),
        cmocka_unit_test(test_read_mssql_log_last_line_fits),
        cmocka_unit_test(test_read_postgresql_log_last_line_fills_buffer),
        cmocka_unit_test(test_read_postgresql_log_last_line_fits),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
