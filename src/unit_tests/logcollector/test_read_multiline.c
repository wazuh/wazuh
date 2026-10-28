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

/* Globals */

extern int maximum_lines;

/* Setup & Teardown */

static int group_setup(void ** state) {
    test_mode = 1;
    return 0;
}

static int group_teardown(void ** state) {
    test_mode = 0;
    return 0;
}

/* Wraps */
int __wrap_can_read() {
    return mock_type(int);
}

extern int __real_feof(FILE * stream);
int __wrap_feof(FILE * stream) {
    if (test_mode) {
        return mock_type(int);
    }
    return __real_feof(stream);
}

bool __wrap_w_get_hash_context(const char * path, EVP_MD_CTX * context, int64_t position) {
    return mock_type(bool);
}

int __wrap_w_update_file_status(const char * path, int64_t pos, EVP_MD_CTX * context) {
    check_expected(pos);
    bool free_context = mock_type(bool);
    if (free_context) {
        EVP_MD_CTX_free(context);
    }
    return mock_type(int);
}

void __wrap_OS_SHA1_Stream_Bytes(EVP_MD_CTX *c, const char * buf, size_t len) {
    function_called();
    check_expected(len);
    return;
}

int __wrap_w_msg_hash_queues_push(const char *str, char *file, unsigned long size, logtarget *log_target, char queue_mq) {
    check_expected(str);
    return 0;
}

/* Tests */

void test_buffer_space(void ** state) {
    logreader lf = { .file = "test", .linecount = 2 };
    int rc;
    char * input_str = malloc(OS_MAX_LOG_SIZE);
    memset(input_str, '.', OS_MAX_LOG_SIZE - 1);
    input_str[OS_MAX_LOG_SIZE - 1] = '\0';

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);

    will_return(__wrap_w_get_hash_context, true);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);

    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, input_str);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) OS_MAX_LOG_SIZE - 1);

    expect_function_call(__wrap_OS_SHA1_Stream_Bytes);
    expect_any(__wrap_OS_SHA1_Stream_Bytes, len);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "\n");

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) OS_MAX_LOG_SIZE);

    expect_function_call(__wrap_OS_SHA1_Stream_Bytes);
    expect_any(__wrap_OS_SHA1_Stream_Bytes, len);

    will_return(__wrap_feof, 0);

    expect_any(__wrap__merror, formatted_msg);

    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, input_str);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) (OS_MAX_LOG_SIZE) * 2 - 1);

    expect_function_call(__wrap_OS_SHA1_Stream_Bytes);
    expect_any(__wrap_OS_SHA1_Stream_Bytes, len);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "\n");

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) (OS_MAX_LOG_SIZE) * 2);

    expect_function_call(__wrap_OS_SHA1_Stream_Bytes);
    expect_any(__wrap_OS_SHA1_Stream_Bytes, len);

    will_return(__wrap_feof, 0);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) (OS_MAX_LOG_SIZE) * 2);

    will_return(__wrap_can_read, 0);

    expect_value(__wrap_w_update_file_status, pos, (int64_t) (OS_MAX_LOG_SIZE) * 2);
    will_return(__wrap_w_update_file_status, true);
    will_return(__wrap_w_update_file_status, 0);

    read_multiline(&lf, &rc, 1);

    free(input_str);
}

void test_buffer_space_invalid_context(void ** state) {
    logreader lf = { .file = "test", .linecount = 2 };
    int rc;
    char * input_str = malloc(OS_MAX_LOG_SIZE);
    memset(input_str, '.', OS_MAX_LOG_SIZE - 1);
    input_str[OS_MAX_LOG_SIZE - 1] = '\0';

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);

    will_return(__wrap_w_get_hash_context, false);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);

    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, input_str);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) OS_MAX_LOG_SIZE - 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "\n");

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) OS_MAX_LOG_SIZE);

    will_return(__wrap_feof, 0);

    expect_any(__wrap__merror, formatted_msg);

    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, input_str);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) (OS_MAX_LOG_SIZE) * 2 - 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "\n");

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) (OS_MAX_LOG_SIZE) * 2);

    will_return(__wrap_feof, 0);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) (OS_MAX_LOG_SIZE) * 2);

    will_return(__wrap_can_read, 0);

    read_multiline(&lf, &rc, 1);

    free(input_str);
}

void test_maximum_lines(void ** state) {
    logreader lf = { .file = "test", .linecount = 3 };
    int rc;
    char line1[] = "Line 1\n";
    char line2[] = "Line 2\n";
    char line3[] = "Line 3\n";
    maximum_lines = 2;

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);

    will_return(__wrap_w_get_hash_context, true);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);

    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, line1);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) strlen(line1));

    expect_function_call(__wrap_OS_SHA1_Stream_Bytes);
    expect_any(__wrap_OS_SHA1_Stream_Bytes, len);

    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, line2);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) strlen(line1) + strlen(line2));

    expect_function_call(__wrap_OS_SHA1_Stream_Bytes);
    expect_any(__wrap_OS_SHA1_Stream_Bytes, len);

    will_return(__wrap_can_read, 1);

    // Stopped by the line limit inside a group: the stored offset covers the lines read
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) strlen(line1) + strlen(line2));

    expect_value(__wrap_w_update_file_status, pos, (int64_t) (strlen(line1) + strlen(line2)));
    will_return(__wrap_w_update_file_status, true);
    will_return(__wrap_w_update_file_status, 0);

    read_multiline(&lf, &rc, 1);
}

void test_maximum_lines_disabled(void ** state) {
    logreader lf = { .file = "test", .linecount = 3 };
    int rc;
    char line1[] = "Line 1\n";
    char line2[] = "Line 2\n";
    char line3[] = "Line 3\n";
    maximum_lines = 0;

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);

    will_return(__wrap_w_get_hash_context, true);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);

    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, line1);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) strlen(line1));

    expect_function_call(__wrap_OS_SHA1_Stream_Bytes);
    expect_any(__wrap_OS_SHA1_Stream_Bytes, len);

    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, line2);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) strlen(line1) + strlen(line2));

    expect_function_call(__wrap_OS_SHA1_Stream_Bytes);
    expect_any(__wrap_OS_SHA1_Stream_Bytes, len);

    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, line3);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) strlen(line1) + strlen(line2) + strlen(line3));

    expect_function_call(__wrap_OS_SHA1_Stream_Bytes);
    expect_any(__wrap_OS_SHA1_Stream_Bytes, len);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) strlen(line1) + strlen(line2) + strlen(line3));

    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, NULL);

    expect_value(__wrap_w_update_file_status, pos, (int64_t) (strlen(line1) + strlen(line2) + strlen(line3)));
    will_return(__wrap_w_update_file_status, true);
    will_return(__wrap_w_update_file_status, 0);

    read_multiline(&lf, &rc, 1);
}

/* A group still open at the end of the file is rolled back: the file is rewound to its first line */
void test_partial_group_at_eof(void ** state) {
    logreader lf = { .file = "test", .linecount = 3 };
    int rc;
    char line1[] = "Line 1\n";
    char line2[] = "Line 2\n";
    maximum_lines = 0;

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);

    will_return(__wrap_w_get_hash_context, true);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);

    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, line1);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) strlen(line1));

    expect_function_call(__wrap_OS_SHA1_Stream_Bytes);
    expect_value(__wrap_OS_SHA1_Stream_Bytes, len, strlen(line1));

    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, line2);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) strlen(line1) + strlen(line2));

    expect_function_call(__wrap_OS_SHA1_Stream_Bytes);
    expect_value(__wrap_OS_SHA1_Stream_Bytes, len, strlen(line2));

    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, NULL);

    // The group is not complete: back to its first line, which is also the stored offset
    expect_any(__wrap_w_fseek, x);
    expect_value(__wrap_w_fseek, pos, 0);
    will_return(__wrap_w_fseek, 0);

    expect_value(__wrap_w_update_file_status, pos, 0);
    will_return(__wrap_w_update_file_status, true);
    will_return(__wrap_w_update_file_status, 0);

    read_multiline(&lf, &rc, 1);
}

/* The line limit is reached on a line that is not complete yet: the open group is rolled back, not stored */
void test_partial_group_at_eof_maximum_lines(void ** state) {
    logreader lf = { .file = "test", .linecount = 3, .fp = (FILE *) 1 };
    int rc;
    char line1[] = "Line 1\n";
    char line2[] = "Line 2";
    maximum_lines = 2;

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);

    will_return(__wrap_w_get_hash_context, true);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);

    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, line1);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) strlen(line1));

    expect_function_call(__wrap_OS_SHA1_Stream_Bytes);
    expect_value(__wrap_OS_SHA1_Stream_Bytes, len, strlen(line1));

    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, line2);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) strlen(line1) + strlen(line2));

    will_return(__wrap_feof, 1);

    // The group is not complete: back to its first line, which is also the stored offset
    expect_any(__wrap_w_fseek, x);
    expect_value(__wrap_w_fseek, pos, 0);
    will_return(__wrap_w_fseek, 0);

    expect_value(__wrap_w_update_file_status, pos, 0);
    will_return(__wrap_w_update_file_status, true);
    will_return(__wrap_w_update_file_status, 0);

    read_multiline(&lf, &rc, 1);
}

void test_long_line_rest_discarded(void ** state) {
    logreader lf = { .file = "test", .linecount = 2 };
    int rc;
    char * input_str = malloc(OS_MAX_LOG_SIZE);
    memset(input_str, '.', OS_MAX_LOG_SIZE - 1);
    input_str[OS_MAX_LOG_SIZE - 1] = '\0';
    char expected_msg[OS_SIZE_256];
    maximum_lines = 0;
    sample_log_length = 4;

    snprintf(expected_msg, sizeof(expected_msg), "Large message size from file 'test' (length = %d): '....'...", OS_MAX_LOG_SIZE + 11);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);

    will_return(__wrap_w_get_hash_context, false);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);

    // Line 1: truncated, its rest is read right away and not counted as a line
    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, input_str);
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) OS_MAX_LOG_SIZE - 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "rest\n");
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) OS_MAX_LOG_SIZE + 4);

    will_return(__wrap_feof, 0);

    // Line 2 closes the group, which is reported with its whole length
    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "second\n");
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) OS_MAX_LOG_SIZE + 11);

    expect_any(__wrap_w_msg_hash_queues_push, str);
    expect_string(__wrap__merror, formatted_msg, expected_msg);
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) OS_MAX_LOG_SIZE + 11);

    // Next group
    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "third\n");
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) OS_MAX_LOG_SIZE + 17);

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "fourth\n");
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) OS_MAX_LOG_SIZE + 24);

    expect_string(__wrap_w_msg_hash_queues_push, str, "third fourth");
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) OS_MAX_LOG_SIZE + 24);

    will_return(__wrap_can_read, 0);

    read_multiline(&lf, &rc, 0);

    free(input_str);
}

void test_long_line_incomplete_rewinds_group(void ** state) {
    logreader lf = { .file = "test", .linecount = 2 };
    int rc;
    char * input_str = malloc(OS_MAX_LOG_SIZE);
    memset(input_str, '.', OS_MAX_LOG_SIZE - 1);
    input_str[OS_MAX_LOG_SIZE - 1] = '\0';
    maximum_lines = 0;

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);

    will_return(__wrap_w_get_hash_context, false);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "first\n");
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 6);

    // Truncated line whose rest has no newline yet
    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, input_str);
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) OS_MAX_LOG_SIZE + 5);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "partial");
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) OS_MAX_LOG_SIZE + 12);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, NULL);

    will_return(__wrap_feof, 1);

    // Back to the first line of the group, nothing sent or reported
    expect_any(__wrap_w_fseek, x);
    expect_value(__wrap_w_fseek, pos, 0);
    will_return(__wrap_w_fseek, 0);

    read_multiline(&lf, &rc, 0);

    free(input_str);
}

void test_long_line_group_incomplete_not_reported(void ** state) {
    logreader lf = { .file = "test", .linecount = 2 };
    int rc;
    char * input_str = malloc(OS_MAX_LOG_SIZE);
    memset(input_str, '.', OS_MAX_LOG_SIZE - 1);
    input_str[OS_MAX_LOG_SIZE - 1] = '\0';
    maximum_lines = 0;

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);

    will_return(__wrap_w_get_hash_context, false);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);

    // Complete long line, but the second line of the group is not written yet
    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, input_str);
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) OS_MAX_LOG_SIZE - 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "rest\n");
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) OS_MAX_LOG_SIZE + 4);

    will_return(__wrap_feof, 0);

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, NULL);

    // Back to the first line of the group, nothing sent or reported
    expect_any(__wrap_w_fseek, x);
    expect_value(__wrap_w_fseek, pos, 0);
    will_return(__wrap_w_fseek, 0);

    read_multiline(&lf, &rc, 0);

    free(input_str);
}

void test_group_overflow_keeps_next_group(void ** state) {
    logreader lf = { .file = "test", .linecount = 2 };
    int rc;
    char line_a[40002];
    char line_b[40002];
    char expected_msg[OS_SIZE_256];
    maximum_lines = 0;
    sample_log_length = 4;

    memset(line_a, 'a', 40000);
    strcpy(line_a + 40000, "\n");
    memset(line_b, 'b', 40000);
    strcpy(line_b + 40000, "\n");
    snprintf(expected_msg, sizeof(expected_msg), "Large message size from file 'test' (length = 80002): 'aaaa'...");

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);

    will_return(__wrap_w_get_hash_context, false);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 0);

    // First group: both lines are read whole, but they do not fit together
    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, line_a);
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 40001);

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, line_b);
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 80002);

    expect_string(__wrap__merror, formatted_msg, expected_msg);

    expect_any(__wrap_w_msg_hash_queues_push, str);
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 80002);

    // Second group is read whole
    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "third\n");
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 80008);

    will_return(__wrap_can_read, 1);
    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "fourth\n");
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 80015);

    expect_string(__wrap_w_msg_hash_queues_push, str, "third fourth");
    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) 80015);

    will_return(__wrap_can_read, 0);

    read_multiline(&lf, &rc, 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_buffer_space),
        cmocka_unit_test(test_buffer_space_invalid_context),
        cmocka_unit_test(test_maximum_lines),
        cmocka_unit_test(test_maximum_lines_disabled),
        cmocka_unit_test(test_partial_group_at_eof),
        cmocka_unit_test(test_partial_group_at_eof_maximum_lines),
        cmocka_unit_test(test_long_line_rest_discarded),
        cmocka_unit_test(test_long_line_incomplete_rewinds_group),
        cmocka_unit_test(test_long_line_group_incomplete_not_reported),
        cmocka_unit_test(test_group_overflow_keeps_next_group)
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
