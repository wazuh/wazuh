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
#include "../wrappers/libc/string_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

/* Globals */
extern int maximum_lines;

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
    bool free_context = mock_type(bool);
    if (free_context) {
        EVP_MD_CTX_free(context);
    }
    return mock_type(int);
}

void __wrap_OS_SHA1_Stream(EVP_MD_CTX *c, os_sha1 output, char *buf) {
    function_called();
    return;
}

int __wrap_w_msg_hash_queues_push(const char *str, char *file, unsigned long size, logtarget *log_target, char queue_mq) {
    check_expected(str);
    check_expected(size);
    return mock_type(int);
}

int __wrap_check_ignore_and_restrict(const char *ignore_regex, const char *restrict_regex, const char *str) {
    check_expected(str);
    return mock_type(int);
}

/* Helpers */

/* Builds "<prefix><filler repeated>\n" of total length len plus the newline. */
static char * build_line(const char *prefix, char filler, size_t len) {
    size_t prefix_len = strlen(prefix);
    char *line;

    assert_true(len >= prefix_len);

    line = calloc(len + 2, sizeof(char));
    assert_non_null(line);

    memcpy(line, prefix, prefix_len);
    memset(line + prefix_len, filler, len - prefix_len);
    line[len] = '\n';

    return line;
}

/* Builds a date line whose first space sits at index space_idx. */
static char * build_date_line(size_t space_idx, const char *tail) {
    size_t tail_len = strlen(tail);
    char *line;

    assert_true(space_idx >= 6);

    line = calloc(space_idx + tail_len + 3, sizeof(char));
    assert_non_null(line);

    memcpy(line, "01/13-", 6);
    memset(line + 6, 'Z', space_idx - 6);
    line[space_idx] = ' ';
    memcpy(line + space_idx + 1, tail, tail_len);
    line[space_idx + 1 + tail_len] = '\n';

    return line;
}

static void expect_line(char *line) {
    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, line);
    expect_function_call(__wrap_OS_SHA1_Stream);
}

/* A NULL msg skips the content check, for records too large to spell out. */
static void expect_queued(const char *msg, size_t size) {
    if (msg) {
        expect_string(__wrap_check_ignore_and_restrict, str, msg);
    } else {
        expect_any(__wrap_check_ignore_and_restrict, str);
    }
    will_return(__wrap_check_ignore_and_restrict, false);

    if (msg) {
        expect_string(__wrap_w_msg_hash_queues_push, str, msg);
    } else {
        expect_any(__wrap_w_msg_hash_queues_push, str);
    }
    expect_value(__wrap_w_msg_hash_queues_push, size, size);
    will_return(__wrap_w_msg_hash_queues_push, 0);
}

static void expect_prologue(void) {
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);
    will_return(__wrap_w_get_hash_context, true);
}

static void expect_epilogue(void) {
    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, NULL);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);

    will_return(__wrap_w_update_file_status, true);
    will_return(__wrap_w_update_file_status, 0);

    expect_any(__wrap__mdebug2, formatted_msg);
}

/* Tests */

/**
 * Test: well-formed three-line record.
 * The whole record is queued as one message, its parts separated by a space.
 */
void test_read_snortfull_complete_record(void **state) {
    logreader lf = {0};
    lf.file = "test.log";
    lf.fp = (FILE *) 1;
    int rc;

    char line1[] = "[**] [1:1000001:0] Test alert [**]\n";
    char line2[] = "[Classification: Attempted Information Leak] [Priority: 2]\n";
    char line3[] = "01/13-15:30:00.000000 10.0.0.1:1234 -> 10.0.0.2:80\n";

    expect_prologue();

    expect_line(line1);
    expect_line(line2);
    expect_line(line3);

    const char *msg = "[**] [1:1000001:0] Test alert [**] [Classification: Attempted Information Leak] [Priority: 2] "
                      "10.0.0.1:1234 -> 10.0.0.2:80";
    expect_queued(msg, strlen(msg) + 1);

    expect_epilogue();

    read_snortfull(&lf, &rc, 0);

    assert_int_equal(rc, 0);
}

/**
 * Test: preprocessor record whose first line already fills f_msg.
 * The free space left after the first line is smaller than the preprocessor
 * label, so both appends must be bounded to what is left.
 */
void test_read_snortfull_preprocessor_full_buffer(void **state) {
    logreader lf = {0};
    lf.file = "test.log";
    lf.fp = (FILE *) 1;
    int rc;

    char *line1 = build_line("[**] [", 'A', OS_MAX_LOG_SIZE - 10);
    char *line2 = build_line("01/13-15:30:00.000000 ", 'C', 2022);

    expect_prologue();

    expect_line(line1);
    expect_line(line2);

    expect_queued(NULL, OS_MAX_LOG_SIZE);

    expect_epilogue();

    read_snortfull(&lf, &rc, 0);

    assert_int_equal(rc, 0);

    free(line1);
    free(line2);
}

/**
 * Test: three-line record whose first two lines fill f_msg.
 * The third append must be bounded to zero bytes.
 */
void test_read_snortfull_third_line_full_buffer(void **state) {
    logreader lf = {0};
    lf.file = "test.log";
    lf.fp = (FILE *) 1;
    int rc;

    char *line1 = build_line("[**] [", 'A', 60024);
    char *line2 = build_line("[Classification: ", 'B', 40017);
    char *line3 = build_line("01/13-15:30:00.000000 ", 'C', 2022);

    expect_prologue();

    expect_line(line1);
    expect_line(line2);
    expect_line(line3);

    expect_queued(NULL, OS_MAX_LOG_SIZE);

    expect_epilogue();

    read_snortfull(&lf, &rc, 0);

    assert_int_equal(rc, 0);

    free(line1);
    free(line2);
    free(line3);
}

/**
 * Test: preprocessor record shorter than its own date line.
 * The queued message is the composed record, sized with its terminator.
 */
void test_read_snortfull_preprocessor_message_length(void **state) {
    logreader lf = {0};
    lf.file = "test.log";
    lf.fp = (FILE *) 1;
    int rc;

    char line1[] = "[**] [\n";
    char *line2 = build_date_line(50, "abcde");

    expect_prologue();

    expect_line(line1);
    expect_line(line2);

    const char *msg = "[**] [ [Classification: Preprocessor] [Priority: 3] abcde";
    expect_queued(msg, strlen(msg) + 1);

    expect_epilogue();

    read_snortfull(&lf, &rc, 0);

    assert_int_equal(rc, 0);

    free(line2);
}

/**
 * Test: record as written by Snort, with a trailing space after the priority.
 * No extra separator is added, so the address follows a single space.
 */
void test_read_snortfull_snort_trailing_space(void **state) {
    logreader lf = {0};
    lf.file = "test.log";
    lf.fp = (FILE *) 1;
    int rc;

    char line1[] = "[**] [1:1054:7] WEB-MISC weblogic/tomcat .jsp view source attempt [**]\n";
    char line2[] = "[Classification: Web Application Attack] [Priority: 1] \n";
    char line3[] = "10/06-08:25:55.575491 10.4.12.26:43832 -> 10.4.10.231:8080\n";
    char line4[] = "TCP TTL:64 TOS:0x0 ID:2148 IpLen:20 DgmLen:139 DF\n";
    char line5[] = "\n";

    expect_prologue();

    expect_line(line1);
    expect_line(line2);
    expect_line(line3);

    const char *msg = "[**] [1:1054:7] WEB-MISC weblogic/tomcat .jsp view source attempt [**] "
                      "[Classification: Web Application Attack] [Priority: 1] 10.4.12.26:43832 -> 10.4.10.231:8080";
    expect_queued(msg, strlen(msg) + 1);

    expect_line(line4);
    expect_line(line5);

    expect_epilogue();

    read_snortfull(&lf, &rc, 0);

    assert_int_equal(rc, 0);
}

/**
 * Test: record without classification.
 * The real priority line is kept.
 */
void test_read_snortfull_priority_only(void **state) {
    logreader lf = {0};
    lf.file = "test.log";
    lf.fp = (FILE *) 1;
    int rc;

    char line1[] = "[**] [1:1000003:1] no classtype test [**]\n";
    char line2[] = "[Priority: 0] \n";
    char line3[] = "10/06-08:25:55.601399 10.4.12.26:43844 -> 10.4.10.231:8080\n";

    expect_prologue();

    expect_line(line1);
    expect_line(line2);
    expect_line(line3);

    const char *msg = "[**] [1:1000003:1] no classtype test [**] [Priority: 0] 10.4.12.26:43844 -> 10.4.10.231:8080";
    expect_queued(msg, strlen(msg) + 1);

    expect_epilogue();

    read_snortfull(&lf, &rc, 0);

    assert_int_equal(rc, 0);
}

/**
 * Test: date line with the year (Snort show_year).
 */
void test_read_snortfull_date_with_year(void **state) {
    logreader lf = {0};
    lf.file = "test.log";
    lf.fp = (FILE *) 1;
    int rc;

    char line1[] = "[**] [1:1054:7] WEB-MISC test [**]\n";
    char line2[] = "[Classification: Web Application Attack] [Priority: 1] \n";
    char line3[] = "10/06/26-08:25:55.575491 10.4.12.26:43832 -> 10.4.10.231:8080\n";

    expect_prologue();

    expect_line(line1);
    expect_line(line2);
    expect_line(line3);

    const char *msg = "[**] [1:1054:7] WEB-MISC test [**] [Classification: Web Application Attack] [Priority: 1] "
                      "10.4.12.26:43832 -> 10.4.10.231:8080";
    expect_queued(msg, strlen(msg) + 1);

    expect_epilogue();

    read_snortfull(&lf, &rc, 0);

    assert_int_equal(rc, 0);
}

/**
 * Test: record with CRLF line endings.
 * The carriage returns are not queued.
 */
void test_read_snortfull_crlf(void **state) {
    logreader lf = {0};
    lf.file = "test.log";
    lf.fp = (FILE *) 1;
    int rc;

    char line1[] = "[**] [1:1054:7] WEB-MISC test [**]\r\n";
    char line2[] = "[Classification: Web Application Attack] [Priority: 1] \r\n";
    char line3[] = "10/06-08:25:55.575491 10.4.12.26:43832 -> 10.4.10.231:8080\r\n";

    expect_prologue();

    expect_line(line1);
    expect_line(line2);
    expect_line(line3);

    const char *msg = "[**] [1:1054:7] WEB-MISC test [**] [Classification: Web Application Attack] [Priority: 1] "
                      "10.4.12.26:43832 -> 10.4.10.231:8080";
    expect_queued(msg, strlen(msg) + 1);

    expect_epilogue();

    read_snortfull(&lf, &rc, 0);

    assert_int_equal(rc, 0);
}

/**
 * Test: record matched by <ignore>.
 * The filter is checked against the whole record and nothing is queued.
 */
void test_read_snortfull_ignored_record(void **state) {
    logreader lf = {0};
    lf.file = "test.log";
    lf.fp = (FILE *) 1;
    int rc;

    char line1[] = "[**] [1:1000001:1] ICMP PING test [**]\n";
    char line2[] = "[Classification: Misc activity] [Priority: 3] \n";
    char line3[] = "10/06-08:25:55.608163 10.4.12.26 -> 10.4.10.231\n";

    expect_prologue();

    expect_line(line1);
    expect_line(line2);
    expect_line(line3);

    expect_string(__wrap_check_ignore_and_restrict, str,
                  "[**] [1:1000001:1] ICMP PING test [**] [Classification: Misc activity] [Priority: 3] "
                  "10.4.12.26 -> 10.4.10.231");
    will_return(__wrap_check_ignore_and_restrict, true);

    expect_epilogue();

    read_snortfull(&lf, &rc, 0);

    assert_int_equal(rc, 0);
}

/**
 * Test: several oversized records in a row.
 * Verifies the buffer state is reset between records and every append stays
 * within bounds when the sequence is repeated.
 */
void test_read_snortfull_consecutive_full_records(void **state) {
    logreader lf = {0};
    lf.file = "test.log";
    lf.fp = (FILE *) 1;
    int rc;
    int i;

    char *line1 = build_line("[**] [", 'A', 60024);
    char *line2 = build_line("[Classification: ", 'B', 40017);
    char *line3 = build_line("01/13-15:30:00.000000 ", 'C', 2022);

    expect_prologue();

    for (i = 0; i < 3; i++) {
        expect_line(line1);
        expect_line(line2);
        expect_line(line3);

        expect_queued(NULL, OS_MAX_LOG_SIZE);
    }

    expect_epilogue();

    read_snortfull(&lf, &rc, 0);

    assert_int_equal(rc, 0);

    free(line1);
    free(line2);
    free(line3);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_read_snortfull_complete_record),
        cmocka_unit_test(test_read_snortfull_preprocessor_full_buffer),
        cmocka_unit_test(test_read_snortfull_third_line_full_buffer),
        cmocka_unit_test(test_read_snortfull_preprocessor_message_length),
        cmocka_unit_test(test_read_snortfull_consecutive_full_records),
        cmocka_unit_test(test_read_snortfull_snort_trailing_space),
        cmocka_unit_test(test_read_snortfull_priority_only),
        cmocka_unit_test(test_read_snortfull_ignored_record),
        cmocka_unit_test(test_read_snortfull_date_with_year),
        cmocka_unit_test(test_read_snortfull_crlf),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
