/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "processthreadsapi_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

WINBOOL wrap_SetThreadPriority(HANDLE hThread, int nPriority) {
    check_expected(hThread);
    check_expected(nPriority);
    return mock();
}

HANDLE wrap_GetCurrentThread(VOID) {
    return mock_type(HANDLE);
}

HANDLE wrap_GetCurrentProcess(VOID) {
    return mock_type(HANDLE);
}

HANDLE wrap_CreateThread(__UNUSED_PARAM(LPSECURITY_ATTRIBUTES lpThreadAttributes),
                         __UNUSED_PARAM(SIZE_T dwStackSize),
                         __UNUSED_PARAM(LPTHREAD_START_ROUTINE lpStartAddress),
                         __UNUSED_PARAM(PVOID lpParameter),
                         __UNUSED_PARAM(DWORD dwCreationFlags),
                         __UNUSED_PARAM(LPDWORD lpThreadId)) {
    return mock_type(HANDLE);
}

BOOL wrap_OpenProcessToken(__UNUSED_PARAM (HANDLE  ProcessHandle),
                           DWORD DesiredAccess,
                           PHANDLE TokenHandle) {
    check_expected(DesiredAccess);
    *TokenHandle = mock_type(HANDLE);
    return mock();
}
