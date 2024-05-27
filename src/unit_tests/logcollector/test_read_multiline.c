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

bool __wrap_w_get_hash_context(const char * path, EVP_MD_CTX * context, int64_t position) {
    return mock_type(bool);
}

int __wrap_w_update_file_status(const char * path, int64_t pos, EVP_MD_CTX * context) {
    bool free_context = mock_type(bool);
    if (free_context) {
        EVP_MD_CTX_free(context);
    }
    return mock_type(int);
}

void __wrap_OS_SHA1_Stream(EVP_MD_CTX *c, os_sha1 output, char * buf) {
    function_called();
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

    expect_function_call(__wrap_OS_SHA1_Stream);

    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, "\n");

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) OS_MAX_LOG_SIZE);

    expect_function_call(__wrap_OS_SHA1_Stream);

    will_return(__wrap_can_read, 1);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, input_str);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) (OS_MAX_LOG_SIZE) * 2 - 1);

    expect_function_call(__wrap_OS_SHA1_Stream);

    expect_any(__wrap__merror, formatted_msg);

    expect_any(__wrap_fgets, __stream);
    will_return(__wrap_fgets, NULL);

    expect_any(__wrap_w_ftell, x);
    will_return(__wrap_w_ftell, (int64_t) (OS_MAX_LOG_SIZE) * 2 - 1);

    will_return(__wrap_can_read, 0);

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

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_buffer_space),
        cmocka_unit_test(test_buffer_space_invalid_context),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
