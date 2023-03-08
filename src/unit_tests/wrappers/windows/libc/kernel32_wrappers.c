/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <string.h>
#include "kernel32_wrappers.h"

DWORD wrap_WaitForSingleObject(HANDLE hMutex, long value) {
    check_expected(hMutex);
    check_expected(value);
    return mock();
}

bool wrap_ReleaseMutex(HANDLE hMutex) {
    check_expected(hMutex);
    return mock();
}
