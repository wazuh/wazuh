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

#include "logcollector.h"
#include "shared.h"
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
    check_expected(size);
    return mock_type(int);
}

bool __wrap_check_ignore_and_restrict(const char *ignore_regex, const char *restrict_regex, const char *str) {
    return mock_type(bool);
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
 * Verifies the normal path is unaffected: the record is composed and pushed.
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

    will_return(__wrap_check_ignore_and_restrict, false);
    expect_value(__wrap_w_msg_hash_queues_push, size, strlen(line3));
    will_return(__wrap_w_msg_hash_queues_push, 0);

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

    will_return(__wrap_check_ignore_and_restrict, false);
    expect_value(__wrap_w_msg_hash_queues_push, size, strlen(line2));
    will_return(__wrap_w_msg_hash_queues_push, 0);

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

    will_return(__wrap_check_ignore_and_restrict, false);
    expect_value(__wrap_w_msg_hash_queues_push, size, strlen(line3));
    will_return(__wrap_w_msg_hash_queues_push, 0);

    expect_epilogue();

    read_snortfull(&lf, &rc, 0);

    assert_int_equal(rc, 0);

    free(line1);
    free(line2);
    free(line3);
}

/**
 * Test: preprocessor record shorter than its own date line.
 * The queued message must be sized from the line that is actually queued, so
 * that the copy carries its terminator regardless of how long the composed
 * record is.
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

    will_return(__wrap_check_ignore_and_restrict, false);
    expect_value(__wrap_w_msg_hash_queues_push, size, strlen(line2));
    will_return(__wrap_w_msg_hash_queues_push, 0);

    expect_epilogue();

    read_snortfull(&lf, &rc, 0);

    assert_int_equal(rc, 0);

    free(line2);
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

        will_return(__wrap_check_ignore_and_restrict, false);
        expect_value(__wrap_w_msg_hash_queues_push, size, strlen(line3));
        will_return(__wrap_w_msg_hash_queues_push, 0);
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
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
