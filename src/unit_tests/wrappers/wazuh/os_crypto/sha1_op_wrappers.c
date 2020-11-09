/* Copyright (C) 2015-2020, Wazuh Inc.
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
