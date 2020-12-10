/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

#include "../headers/shared.h"
#include "../../os_crypto/sha1/sha1_op.h"
#include "../../wrappers/libc/stdio_wrappers.h"
#include "../../wrappers/common.h"

/* setups/teardowns */
static int setup_group(void **state) {
    test_mode = 1;
    return 0;
}

static int teardown_group(void **state) {
    test_mode = 0;
    return 0;
}

/* test */

/* OS_SHA1_File_Nbytes */

void OS_SHA1_File_Nbytes_unable_open_file (void **state)
{
    const char *path = "/home/test_file";
    SHA_CTX context;
    os_sha1 output;
    ssize_t nbytes = 4096;

    expect_value(__wrap_fopen, path, path);
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    int ret = OS_SHA1_File_Nbytes(path, &context, output, nbytes);
    assert_int_equal(ret, -1);
}

void OS_SHA1_File_Nbytes_ok (void **state)
{
    const char *path = "/home/test_file";
    SHA_CTX context;
    os_sha1 output;
    ssize_t nbytes = 4000;

    expect_value(__wrap_fopen, path, path);
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "hello");

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, NULL);

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

    int ret = OS_SHA1_File_Nbytes(path, &context, output, nbytes);
    assert_int_equal(ret, 0);
}

void OS_SHA1_File_Nbytes_num_bytes_exceded (void **state)
{
    const char *path = "/home/test_file";
    SHA_CTX context;
    os_sha1 output;
    ssize_t nbytes = 6;

    expect_value(__wrap_fopen, path, path);
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "hello");

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "hello");

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "hello");

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

    int ret = OS_SHA1_File_Nbytes(path, &context, output, nbytes);
    assert_int_equal(ret, 0);
}

/* OS_SHA1_Stream */
//void OS_SHA1_Stream(SHA_CTX *c, os_sha1 output, char * buf)

void OS_SHA1_Stream_ok (void **state)
{
    char *buf = "hello";
    os_sha1 output;
    SHA_CTX context;

    SHA1_Init(&context);

    OS_SHA1_Stream(&context, output, buf);
}

void OS_SHA1_Stream_buf_null (void **state)
{
    char *buf = NULL;
    os_sha1 output;
    SHA_CTX context;

    SHA1_Init(&context);

    OS_SHA1_Stream(&context, output, buf);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // Tests OS_SHA1_File_Nbytes
        cmocka_unit_test(OS_SHA1_File_Nbytes_unable_open_file),
        cmocka_unit_test(OS_SHA1_File_Nbytes_ok),
        cmocka_unit_test(OS_SHA1_File_Nbytes_num_bytes_exceded),
        // Tests OS_SHA1_Stream
        cmocka_unit_test(OS_SHA1_Stream_ok),
        cmocka_unit_test(OS_SHA1_Stream_buf_null),
    };
    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
