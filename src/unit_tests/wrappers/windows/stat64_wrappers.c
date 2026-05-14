/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "stat64_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>

int wrap__stat64(const char * __file, struct _stat64 * __buf) {
    struct _stat64 * mock_buf;

    check_expected(__file);
    mock_buf = mock_type(struct _stat64 *);
    if (mock_buf != NULL) {
        memcpy(__buf, mock_buf, sizeof(struct _stat64));
    }
    return mock_type(int);
}
