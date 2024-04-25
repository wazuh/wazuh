/*
 * Copyright (C) 2015, Wazuh Inc.
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

int OS_SHA1_File_Nbytes(const char *fname, EVP_MD_CTX **c, os_sha1 output, int mode, int64_t nbytes);

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

void OS_SHA1_File_Nbytes_context_null (void **state)
{
    const char *path = "/home/test_file";
    EVP_MD_CTX *context = NULL;
    os_sha1 output;
    ssize_t nbytes = 4096;

    int mode = OS_BINARY;

    assert_int_equal(OS_SHA1_File_Nbytes(path, &context, output, mode, nbytes), -3);
}

void OS_SHA1_File_Nbytes_unable_open_file (void **state)
{
    const char *path = "/home/test_file";
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    os_sha1 output;
    ssize_t nbytes = 4096;

    int mode = OS_BINARY;

    expect_value(__wrap_wfopen, path, path);
    expect_string(__wrap_wfopen, mode, "rb");
    will_return(__wrap_wfopen, NULL);

    assert_int_equal(OS_SHA1_File_Nbytes(path, &context, output, mode, nbytes), -1);

    EVP_MD_CTX_free(context);
}

void OS_SHA1_File_Nbytes_ok (void **state)
{
    const char *path = "/home/test_file";
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    os_sha1 output;
    ssize_t nbytes = 4000;

    int mode = OS_BINARY;

    expect_value(__wrap_wfopen, path, path);
    expect_string(__wrap_wfopen, mode, "rb");
    will_return(__wrap_wfopen, 1);

    will_return(__wrap_fread, "test");
    will_return(__wrap_fread, 0);

    will_return(__wrap_fread, "test");
    will_return(__wrap_fread, 0);

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

    assert_int_equal(OS_SHA1_File_Nbytes(path, &context, output, mode, nbytes), 0);

    EVP_MD_CTX_free(context);
}

void OS_SHA1_File_Nbytes_num_bytes_exceded (void **state)
{
    const char *path = "/home/test_file";
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    os_sha1 output;
    ssize_t nbytes = 6;

    int mode = OS_BINARY;

    expect_value(__wrap_wfopen, path, path);
    expect_string(__wrap_wfopen, mode, "rb");
    will_return(__wrap_wfopen, 1);

    will_return(__wrap_fread, "test");
    will_return(__wrap_fread, 0);

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

    assert_int_equal(OS_SHA1_File_Nbytes(path, &context, output, mode, nbytes), 0);

    EVP_MD_CTX_free(context);
}

/* OS_SHA1_Stream */

void OS_SHA1_Stream_ok (void **state)
{
    char *buf = "hello";
    os_sha1 output;
    EVP_MD_CTX *context = EVP_MD_CTX_new();

    EVP_DigestInit(context, EVP_sha1());

    OS_SHA1_Stream(context, output, buf);

    EVP_MD_CTX_free(context);
}

void OS_SHA1_Stream_buf_null (void **state)
{
    char *buf = NULL;
    os_sha1 output;
    EVP_MD_CTX *context = EVP_MD_CTX_new();

    EVP_DigestInit(context, EVP_sha1());

    OS_SHA1_Stream(context, output, buf);
    EVP_MD_CTX_free(context);
}

void test_sha1_string(void **state)
{
    const char *string = "teststring";
    const char *string_sha1 = "b8473b86d4c2072ca9b08bd28e373e8253e865c4";
    os_sha1 buffer;

    assert_int_equal(OS_SHA1_Str(string, strlen(string), buffer), 0);

    assert_string_equal(buffer, string_sha1);
}

void test_sha1_string2(void **state)
{
    const char *string = "teststring";
    const char *string_sha1 = "b8473b86d4c2072ca9b08bd28e373e8253e865c4";
    os_sha1 buffer;

    assert_int_equal(OS_SHA1_Str2(string, strlen(string), buffer), 0);

    assert_string_equal(buffer, string_sha1);
}

void test_sha1_file(void **state)
{
    const char *string = "teststring";
    const char *string_sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
    os_sha1 buffer;

    char file_name[256];
    strncpy(file_name, "/tmp/tmp_file-XXXXXX", 256);

    expect_string(__wrap_wfopen, path, file_name);
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 1);

    will_return(__wrap_fread, string);
    will_return(__wrap_fread, 0);

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

    assert_int_equal(OS_SHA1_File(file_name, buffer, OS_TEXT), 0);

    assert_string_equal(buffer, string_sha1);
}

void test_sha1_file_fail(void **state)
{
    os_sha1 buffer;

    char file_name[256];
    strncpy(file_name, "not_existing_file", 256);

    expect_string(__wrap_wfopen, path, file_name);
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    assert_int_equal(OS_SHA1_File(file_name, buffer, OS_TEXT), -1);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // Tests OS_SHA1_File_Nbytes
        cmocka_unit_test(OS_SHA1_File_Nbytes_context_null),
        cmocka_unit_test(OS_SHA1_File_Nbytes_unable_open_file),
        cmocka_unit_test(OS_SHA1_File_Nbytes_ok),
        cmocka_unit_test(OS_SHA1_File_Nbytes_num_bytes_exceded),
        // Tests OS_SHA1_Stream
        cmocka_unit_test(OS_SHA1_Stream_ok),
        cmocka_unit_test(OS_SHA1_Stream_buf_null),
        // Tests OS_SHA1_File
        cmocka_unit_test(test_sha1_string),
        cmocka_unit_test(test_sha1_string2),
        cmocka_unit_test(test_sha1_file),
        cmocka_unit_test(test_sha1_file_fail),
    };
    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
