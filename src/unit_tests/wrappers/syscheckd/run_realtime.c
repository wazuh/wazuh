/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "run_realtime.h"
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

HANDLE wrap_run_realtime_CreateEvent (LPSECURITY_ATTRIBUTES lpEventAttributes, WINBOOL bManualReset, WINBOOL bInitialState, LPCSTR lpName) {
    check_expected(lpEventAttributes);
    check_expected(bManualReset);
    check_expected(bInitialState);
    check_expected(lpName);

    return mock_type(HANDLE);
}

VOID wrap_run_realtime_Sleep (DWORD dwMilliseconds) {
    check_expected(dwMilliseconds);
}

WINBOOL wrap_run_realtime_ReadDirectoryChangesW (__UNUSED_PARAM(HANDLE hDirectory),
                                                 __UNUSED_PARAM(LPVOID lpBuffer),
                                                 __UNUSED_PARAM(DWORD nBufferLength),
                                                 __UNUSED_PARAM(WINBOOL bWatchSubtree),
                                                 __UNUSED_PARAM(DWORD dwNotifyFilter),
                                                 __UNUSED_PARAM(LPDWORD lpBytesReturned),
                                                 __UNUSED_PARAM(LPOVERLAPPED lpOverlapped),
                                                 __UNUSED_PARAM(LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)) {
    return mock();
}


WINBOOL wrap_run_realtime_CloseHandle (HANDLE hObject) {
    check_expected_ptr(hObject);

    return mock();
}

HANDLE wrap_run_realtime_CreateFile (LPCSTR lpFileName,
                                     __UNUSED_PARAM(DWORD dwDesiredAccess),
                                     __UNUSED_PARAM(DWORD dwShareMode),
                                     __UNUSED_PARAM(LPSECURITY_ATTRIBUTES lpSecurityAttributes),
                                     __UNUSED_PARAM(DWORD dwCreationDisposition),
                                     __UNUSED_PARAM(DWORD dwFlagsAndAttributes),
                                     __UNUSED_PARAM(HANDLE hTemplateFile)) {
    check_expected(lpFileName);

    return mock_type(HANDLE);
}
