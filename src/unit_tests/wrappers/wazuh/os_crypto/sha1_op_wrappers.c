/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "sha1_op_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

int __wrap_OS_SHA1_File(const char *fname, os_sha1 output, int mode) {
    check_expected(fname);
    check_expected(mode);

    snprintf(output, 41, "%s", mock_type(char *));

    return mock();
}

int __wrap_OS_SHA1_File_Nbytes(const char *fname, __attribute__((unused))EVP_MD_CTX **c, os_sha1 output, int mode, ssize_t nbytes) {
    check_expected(fname);
    check_expected(mode);
    check_expected(nbytes);

    snprintf(output, 41, "%s", mock_type(char *));

    return mock();
}

void __wrap_OS_SHA1_Stream(__attribute__((unused))EVP_MD_CTX *c, os_sha1 output, char * buf) {
    check_expected(buf);

    snprintf(output, 41, "%s", mock_type(char *));

}

#ifndef WIN32
int __wrap_OS_SHA1_File_Nbytes_with_fp_check(const char * fname, __attribute__((unused))EVP_MD_CTX ** c, os_sha1 output,
                                      int mode, int64_t nbytes, ino_t fd_check) {
    check_expected(fname);
    check_expected(mode);
    check_expected(nbytes);
    check_expected(fd_check);

    snprintf(output, 41, "%s", mock_type(char *));

    return mock();
}
#else
int __wrap_OS_SHA1_File_Nbytes_with_fp_check(const char * fname, __attribute__((unused))EVP_MD_CTX ** c, os_sha1 output,
                                      int mode, int64_t nbytes, DWORD fd_check) {
    check_expected(fname);
    check_expected(mode);
    check_expected(nbytes);
    check_expected(fd_check);

    snprintf(output, 41, "%s", mock_type(char *));

    return mock();
}
#endif

int __wrap_OS_SHA1_Str(const char *str, ssize_t length, os_sha1 output) {
    check_expected(str);
    check_expected(length);

    snprintf(output, 41, "%s", mock_type(char *));

    return 0;
}
