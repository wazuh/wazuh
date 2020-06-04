/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "fileapi_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

HANDLE wrap_CreateFile (LPCSTR lpFileName,
                                    __UNUSED_PARAM(DWORD dwDesiredAccess),
                                    __UNUSED_PARAM(DWORD dwShareMode),
                                    __UNUSED_PARAM(LPSECURITY_ATTRIBUTES lpSecurityAttributes),
                                    __UNUSED_PARAM(DWORD dwCreationDisposition),
                                    __UNUSED_PARAM(DWORD dwFlagsAndAttributes),
                                    __UNUSED_PARAM(HANDLE hTemplateFile)) {
    check_expected(lpFileName);

    return mock_type(HANDLE);
}

DWORD wrap_GetFileAttributesA (LPCSTR lpFileName) {
    check_expected(lpFileName);

    return mock();
}
