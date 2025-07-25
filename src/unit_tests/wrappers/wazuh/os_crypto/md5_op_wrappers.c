/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "md5_op_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>

int __wrap_OS_MD5_File(const char *fname, os_md5 output, int mode) {
    check_expected(fname);
    check_expected(mode);

    char *md5 = mock_type(char *);
    strncpy(output, md5, sizeof(os_md5));

    return mock();
}

int __wrap_OS_MD5_Str(const char *str, ssize_t length, os_md5 output) {
    check_expected(str);
    check_expected(length);

    char *md5 = mock_type(char *);
    strncpy(output, md5, sizeof(os_md5));

    return mock();
}

void expect_OS_MD5_File_call(const char *fname, os_md5 output, int mode, int ret) {
    expect_string(__wrap_OS_MD5_File, fname, fname);
    expect_value(__wrap_OS_MD5_File, mode, mode);
    will_return(__wrap_OS_MD5_File, output);
    will_return(__wrap_OS_MD5_File, ret);
}

int __wrap_OS_MD5_SHA1_SHA256_File(const char *fname, const char **prefilter_cmd, os_md5 md5output, os_sha1 sha1output,
                                   os_sha256 sha256output, int mode, size_t max_size) {
    check_expected(fname);
    check_expected_ptr(prefilter_cmd);
    check_expected(md5output);
    check_expected(sha1output);
    check_expected(sha256output);
    check_expected(mode);
    check_expected(max_size);

    return mock();
}

void expect_OS_MD5_SHA1_SHA256_File_call(char *file,
                                         char **prefilter_cmd,
                                         char *md5,
                                         char *sha1,
                                         char *sha256,
                                         int mode,
                                         int max_size,
                                         int ret) {

    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, fname, file);
    expect_value(__wrap_OS_MD5_SHA1_SHA256_File, prefilter_cmd, prefilter_cmd);
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, md5output, md5);
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, sha1output, sha1);
    expect_string(__wrap_OS_MD5_SHA1_SHA256_File, sha256output, sha256);
    expect_value(__wrap_OS_MD5_SHA1_SHA256_File, mode, mode);
    expect_value(__wrap_OS_MD5_SHA1_SHA256_File, max_size, max_size);
    will_return(__wrap_OS_MD5_SHA1_SHA256_File, ret);
}
