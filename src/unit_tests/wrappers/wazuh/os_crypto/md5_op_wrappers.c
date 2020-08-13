/* Copyright (C) 2015-2020, Wazuh Inc.
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
#include <cmocka.h>

int __wrap_OS_MD5_File(const char *fname, os_md5 output, int mode) {
    check_expected(fname);
    check_expected(mode);

    char *md5 = mock_type(char *);
    strncpy(output, md5, sizeof(os_md5));

    return mock();
}

int __wrap_OS_MD5_SHA1_SHA256_File(const char *fname, const char *prefilter_cmd, os_md5 md5output, os_sha1 sha1output,
                                   os_sha256 sha256output, int mode, size_t max_size) {
    check_expected(fname);
    check_expected(prefilter_cmd);
    check_expected(md5output);
    check_expected(sha1output);
    check_expected(sha256output);
    check_expected(mode);
    check_expected(max_size);

    return mock();
}
