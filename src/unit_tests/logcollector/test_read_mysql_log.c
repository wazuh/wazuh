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
}

int __wrap_w_msg_hash_queues_push(const char *str, char *file, unsigned long size, logtarget *log_target, char queue_mq) {
    check_expected(str);
    check_expected(size);
    return mock_type(int);
}

bool __wrap_check_ignore_and_restrict(const char *ignore_regex, const char *restrict_regex, const char *str) {
    return mock_type(bool);
}

/* Helpers */

typedef struct {
    const char *line;       // Line as written by the server
    const char *expected;   // Message sent to the manager, or NULL if the line is discarded
} mysql_line_t;

/* Reads the lines and expects each one to be sent with its message or discarded with a debug message */
static void run_reader(const mysql_line_t *lines, size_t count) {
    logreader lf = {0};
    lf.file = "test.log";
    lf.fp = (FILE *) 1;
    int rc;
    char (*debug_msgs)[OS_SIZE_2048] = calloc(count + 1, sizeof(*debug_msgs));
    assert_non_null(debug_msgs);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);
    will_return(__wrap_w_get_hash_context, false);

    for (size_t i = 0; i < count; i++) {
        will_return(__wrap_can_read, 1);
        expect_any(__wrap_fgets, __stream);
        will_return(__wrap_fgets, lines[i].line);

        if (lines[i].expected != NULL) {
            snprintf(debug_msgs[i], OS_SIZE_2048, "Reading mysql messages: '%s'", lines[i].expected);
            expect_string(__wrap__mdebug2, formatted_msg, debug_msgs[i]);
            will_return(__wrap_check_ignore_and_restrict, false);
            expect_string(__wrap_w_msg_hash_queues_push, str, lines[i].expected);
            expect_value(__wrap_w_msg_hash_queues_push, size, strlen(lines[i].expected) + 1);
            will_return(__wrap_w_msg_hash_queues_push, 0);
        } else {
            snprintf(debug_msgs[i], OS_SIZE_2048,
                     "Discarding line from 'test.log', it does not match any MySQL log format: '%.*s'",
                     (int) strcspn(lines[i].line, "\n"), lines[i].line);
            expect_string(__wrap__mdebug2, formatted_msg, debug_msgs[i]);
        }
    }

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, NULL);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);

    snprintf(debug_msgs[count], OS_SIZE_2048, "Read %zu lines from test.log", count);
    expect_string(__wrap__mdebug2, formatted_msg, debug_msgs[count]);

    read_mysql_log(&lf, &rc, 0);

    assert_int_equal(rc, 0);
    free(debug_msgs);
}

/* Tests */

void test_read_mysql_log_mysql8_general_log(void **state) {
    // MySQL 5.7 and later write a tab after the timestamp of the general log
    mysql_line_t lines[] = {
        {"2026-11-10T11:02:02.088283Z\t    9 Query\tselect @@version_comment limit 1\n",
         "MySQL log: 2026-11-10T11:02:02.088283Z 9 Query\tselect @@version_comment limit 1"},
        {"2026-11-10T11:02:02.088408Z\t    9 Query\tSELECT 'rv3-my8-q1'\n",
         "MySQL log: 2026-11-10T11:02:02.088408Z 9 Query\tSELECT 'rv3-my8-q1'"},
        {"2026-11-10T11:02:02.088545Z\t    9 Quit\t\n",
         "MySQL log: 2026-11-10T11:02:02.088545Z 9 Quit\t"},
    };

    run_reader(lines, sizeof(lines) / sizeof(lines[0]));
}

void test_read_mysql_log_mysql8_general_log_offset(void **state) {
    mysql_line_t lines[] = {
        {"2026-11-10T08:02:02.088408-03:00\t    9 Query\tSELECT 'rv3-my8-q1'\n",
         "MySQL log: 2026-11-10T08:02:02.088408-03:00 9 Query\tSELECT 'rv3-my8-q1'"},
    };

    run_reader(lines, sizeof(lines) / sizeof(lines[0]));
}

void test_read_mysql_log_mysql8_error_log(void **state) {
    mysql_line_t lines[] = {
        {"2026-11-10T11:15:00.000001Z 0 [System] [MY-000000] [Server] rv8-control\n",
         "MySQL log: 2026-11-10T11:15:00.000001Z 0 [System] [MY-000000] [Server] rv8-control"},
        {"2026-11-10T08:15:00.000001-03:00 0 [Warning] [MY-010068] [Server] rv8-offset\n",
         "MySQL log: 2026-11-10T08:15:00.000001-03:00 0 [Warning] [MY-010068] [Server] rv8-offset"},
    };

    run_reader(lines, sizeof(lines) / sizeof(lines[0]));
}

void test_read_mysql_log_general_log_early_hour(void **state) {
    // The hour is padded with a space before 10:00
    mysql_line_t lines[] = {
        {"261110  3:00:13\t     5 Connect\troot@localhost on  using SSL/TLS\n",
         "MySQL log: 261110  3:00:13 5 Connect\troot@localhost on  using SSL/TLS"},
        {"\t\t     5 Query\tSELECT 'rv2-la-q1'\n", "MySQL log: 261110  3:00:13 5 Query\tSELECT 'rv2-la-q1'"},
        {"\t\t     5 Query\tSELECT 'rv2-la-q2'\n", "MySQL log: 261110  3:00:13 5 Query\tSELECT 'rv2-la-q2'"},
        {"\t\t     5 Quit\t\n", "MySQL log: 261110  3:00:13 5 Quit\t"},
    };

    run_reader(lines, sizeof(lines) / sizeof(lines[0]));
}

void test_read_mysql_log_general_log_same_second(void **state) {
    // Each server right-aligns the thread id to its own width, with no padding when the id fills it
    mysql_line_t lines[] = {
        {"261110 12:00:13\t     4 Connect\troot@localhost on  using SSL/TLS\n",
         "MySQL log: 261110 12:00:13 4 Connect\troot@localhost on  using SSL/TLS"},
        {"\t\t     4 Query\tSELECT 'mariadb'\n", "MySQL log: 261110 12:00:13 4 Query\tSELECT 'mariadb'"},
        {"\t\t    3 Query\tSELECT 'mysql-5.5'\n", "MySQL log: 261110 12:00:13 3 Query\tSELECT 'mysql-5.5'"},
        {"\t\t      3 Query\tSELECT 'mysql-5.0'\n", "MySQL log: 261110 12:00:13 3 Query\tSELECT 'mysql-5.0'"},
        {"\t\t     12 Query\tSELECT 'mysql-5.0-id-12'\n", "MySQL log: 261110 12:00:13 12 Query\tSELECT 'mysql-5.0-id-12'"},
        {"\t\t1234567 Query\tSELECT 'mariadb-wide-id'\n", "MySQL log: 261110 12:00:13 1234567 Query\tSELECT 'mariadb-wide-id'"},
        {"\t\t     4 Init DB\tmysql\n", "MySQL log: 261110 12:00:13 4 Init DB\tmysql"},
    };

    run_reader(lines, sizeof(lines) / sizeof(lines[0]));
}

void test_read_mysql_log_mysql55_error_log(void **state) {
    mysql_line_t lines[] = {
        {"130925  9:15:44 [Note] Plugin 'FEDERATED' is disabled.\n",
         "MySQL log: 130925  9:15:44 [Note] Plugin 'FEDERATED' is disabled."},
    };

    run_reader(lines, sizeof(lines) / sizeof(lines[0]));
}

void test_read_mysql_log_mariadb_error_log(void **state) {
    mysql_line_t lines[] = {
        {"2026-11-10 11:13:00 0 [Note] rv-maria-err1\n", "MySQL log: 2026-11-10 11:13:00 0 [Note] rv-maria-err1"},
        {"2026-11-10  9:13:00 0 [Warning] rv-maria-err2\n", "MySQL log: 2026-11-10  9:13:00 0 [Warning] rv-maria-err2"},
    };

    run_reader(lines, sizeof(lines) / sizeof(lines[0]));
}

void test_read_mysql_log_discards_unknown_lines(void **state) {
    // Header lines and the lines of a multi-line query match no format
    mysql_line_t lines[] = {
        {"/usr/sbin/mysqld, Version: 8.0.46 (MySQL Community Server - GPL). started with:\n", NULL},
        {"Time                 Id Command    Argument\n", NULL},
        {"261110 12:00:13\t     4 Query\tSELECT 1,\n", "MySQL log: 261110 12:00:13 4 Query\tSELECT 1,"},
        {"\t\t2 AS y;\n", NULL},
    };

    run_reader(lines, sizeof(lines) / sizeof(lines[0]));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_read_mysql_log_mysql8_general_log),
        cmocka_unit_test(test_read_mysql_log_mysql8_general_log_offset),
        cmocka_unit_test(test_read_mysql_log_mysql8_error_log),
        cmocka_unit_test(test_read_mysql_log_general_log_early_hour),
        cmocka_unit_test(test_read_mysql_log_general_log_same_second),
        cmocka_unit_test(test_read_mysql_log_mysql55_error_log),
        cmocka_unit_test(test_read_mysql_log_mariadb_error_log),
        cmocka_unit_test(test_read_mysql_log_discards_unknown_lines),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
