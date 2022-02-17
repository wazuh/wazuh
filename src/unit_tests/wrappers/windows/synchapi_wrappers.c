/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "synchapi_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

VOID wrap_Sleep(DWORD dwMilliseconds) {
    check_expected(dwMilliseconds);
}

HANDLE wrap_CreateEvent(LPSECURITY_ATTRIBUTES lpEventAttributes,
                        WINBOOL bManualReset,
                        WINBOOL bInitialState,
                        LPCSTR lpName) {
    check_expected(lpEventAttributes);
    check_expected(bManualReset);
    check_expected(bInitialState);
    check_expected(lpName);
    return mock_type(HANDLE);
}

DWORD wrap_WaitForSingleObjectEx(HANDLE hHandle, DWORD dwMilliseconds, BOOL bAlertable) {
    check_expected(hHandle);
    check_expected(dwMilliseconds);
    check_expected(bAlertable);
    return mock_type(DWORD);
}
