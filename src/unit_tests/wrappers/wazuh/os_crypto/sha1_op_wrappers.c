/* Copyright (C) 2015-2021, Wazuh Inc.
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

int __wrap_OS_SHA1_File_Nbytes(const char *fname, __attribute__((unused))SHA_CTX *c, os_sha1 output, int mode, ssize_t nbytes) {
    check_expected(fname);
    check_expected(mode);
    check_expected(nbytes);

    snprintf(output, 41, "%s", mock_type(char *));

    return mock();
}

void __wrap_OS_SHA1_Stream(__attribute__((unused))SHA_CTX *c, os_sha1 output, char * buf) {
    check_expected(buf);

    snprintf(output, 41, "%s", mock_type(char *));

}
