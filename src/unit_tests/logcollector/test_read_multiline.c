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

/* Tests */

void test_buffer_space(void ** state) {
    logreader lf = { .file = "test", .linecount = 3 };
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

    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "\n");

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) OS_MAX_LOG_SIZE);

    expect_function_call(__wrap_OS_SHA1_Stream_Bytes);
    expect_any(__wrap_OS_SHA1_Stream_Bytes, len);

    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, input_str);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) (OS_MAX_LOG_SIZE) * 2 - 1);

    expect_function_call(__wrap_OS_SHA1_Stream_Bytes);
    expect_any(__wrap_OS_SHA1_Stream_Bytes, len);

    expect_any(__wrap__merror, formatted_msg);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, NULL);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) (OS_MAX_LOG_SIZE) * 2 - 1);

    will_return(__wrap_can_read, 0);

    expect_value(__wrap_w_update_file_status, pos, (int64_t) (OS_MAX_LOG_SIZE) * 2 - 1);
    will_return(__wrap_w_update_file_status, true);
    will_return(__wrap_w_update_file_status, 0);

    read_multiline(&lf, &rc, 1);

    free(input_str);
}

void test_buffer_space_invalid_context(void ** state) {
    logreader lf = { .file = "test", .linecount = 3 };
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

    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "\n");

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) OS_MAX_LOG_SIZE);

    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, input_str);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) (OS_MAX_LOG_SIZE) * 2 - 1);

    expect_any(__wrap__merror, formatted_msg);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, NULL);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) (OS_MAX_LOG_SIZE) * 2 - 1);

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

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_buffer_space),
        cmocka_unit_test(test_buffer_space_invalid_context),
        cmocka_unit_test(test_maximum_lines),
        cmocka_unit_test(test_maximum_lines_disabled),
        cmocka_unit_test(test_partial_group_at_eof),
        cmocka_unit_test(test_partial_group_at_eof_maximum_lines)
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
