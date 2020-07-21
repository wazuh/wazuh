/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "run_check.h"
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

struct state_t state;

WINBOOL wrap_SetThreadPriority (HANDLE hThread, int nPriority) {
    check_expected(hThread);
    check_expected(nPriority);
    return mock();
}

HANDLE wrap_GetCurrentThread (VOID) {
    return mock_type(HANDLE);
}

DWORD wrap_GetLastError (VOID) {
    return mock();
}

VOID wrap_Sleep (DWORD dwMilliseconds) {
    state.sleep_seconds += dwMilliseconds;
}

HANDLE wrap_run_check_CreateThread(
    __UNUSED_PARAM(LPSECURITY_ATTRIBUTES   lpThreadAttributes),
    __UNUSED_PARAM(SIZE_T                  dwStackSize),
    __UNUSED_PARAM(LPTHREAD_START_ROUTINE  lpStartAddress),
    __UNUSED_PARAM(PVOID                   lpParameter),
    __UNUSED_PARAM(DWORD                   dwCreationFlags),
    __UNUSED_PARAM(LPDWORD                 lpThreadId)
) {
    return mock_type(HANDLE);
}
