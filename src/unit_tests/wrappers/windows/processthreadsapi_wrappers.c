/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "processthreadsapi_wrappers.h"
#include <stddef.h>
#include <string.h>
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

static bool create_thread_runs_routine = false;
static LPTHREAD_START_ROUTINE last_thread_routine = NULL;
static PVOID last_thread_param = NULL;

void wrap_CreateThread_run_last(void) {
    last_thread_routine(last_thread_param);
}

PVOID wrap_CreateThread_last_param(void) {
    return last_thread_param;
}

void wrap_CreateThread_reset(void) {
    create_thread_runs_routine = false;
    last_thread_routine = NULL;
    last_thread_param = NULL;
}

void wrap_CreateThread_run_routine(bool run) {
    create_thread_runs_routine = run;
}

HANDLE wrap_CreateThread(__UNUSED_PARAM(LPSECURITY_ATTRIBUTES lpThreadAttributes),
                         __UNUSED_PARAM(SIZE_T dwStackSize),
                         LPTHREAD_START_ROUTINE lpStartAddress,
                         PVOID lpParameter,
                         __UNUSED_PARAM(DWORD dwCreationFlags),
                         __UNUSED_PARAM(LPDWORD lpThreadId)) {
    last_thread_routine = lpStartAddress;
    last_thread_param = lpParameter;

    if (create_thread_runs_routine) {
        lpStartAddress(lpParameter);
    }

    return mock_type(HANDLE);
}

BOOL wrap_OpenProcessToken(__UNUSED_PARAM (HANDLE  ProcessHandle),
                           DWORD DesiredAccess,
                           PHANDLE TokenHandle) {
    check_expected(DesiredAccess);
    *TokenHandle = mock_type(HANDLE);
    return mock();
}

BOOL wrap_TerminateProcess(__UNUSED_PARAM(HANDLE hProcess),
                           __UNUSED_PARAM(UINT uExitCode)) {
    function_called();
    return mock();
}

DWORD wrap_ResumeThread(__UNUSED_PARAM(HANDLE hThread)) {
    function_called();
    return mock();
}

HANDLE wrap_CreateJobObjectW(__UNUSED_PARAM(LPSECURITY_ATTRIBUTES lpJobAttributes),
                             __UNUSED_PARAM(LPCWSTR lpName)) {
    function_called();
    return mock_type(HANDLE);
}

BOOL wrap_AssignProcessToJobObject(HANDLE hJob, __UNUSED_PARAM(HANDLE hProcess)) {
    check_expected(hJob);
    return mock();
}

BOOL wrap_TerminateJobObject(HANDLE hJob, __UNUSED_PARAM(UINT uExitCode)) {
    check_expected(hJob);
    return mock();
}

BOOL wrap_SetInformationJobObject(HANDLE hJob,
                                  JOBOBJECTINFOCLASS JobObjectInformationClass,
                                  LPVOID lpJobObjectInformation,
                                  __UNUSED_PARAM(DWORD cbJobObjectInformationLength)) {
    DWORD LimitFlags = ((JOBOBJECT_BASIC_LIMIT_INFORMATION *)lpJobObjectInformation)->LimitFlags;

    check_expected(hJob);
    check_expected(JobObjectInformationClass);
    check_expected(LimitFlags);
    return mock();
}

void expect_SetThreadPriority_call(HANDLE handle, int priority, int ret) {
    expect_value(wrap_SetThreadPriority, hThread, handle);
    expect_value(wrap_SetThreadPriority, nPriority, priority);
    will_return(wrap_SetThreadPriority, ret);
}

BOOL wrap_CreateProcessW(__UNUSED_PARAM(LPCWSTR               lpApplicationName),
                         LPWSTR                lpCommandLine,
                         __UNUSED_PARAM(LPSECURITY_ATTRIBUTES lpProcessAttributes),
                         __UNUSED_PARAM(LPSECURITY_ATTRIBUTES lpThreadAttributes),
                         __UNUSED_PARAM(BOOL                  bInheritHandles),
                         __UNUSED_PARAM(DWORD                 dwCreationFlags),
                         __UNUSED_PARAM(LPVOID                lpEnvironment),
                         __UNUSED_PARAM(LPCWSTR               lpCurrentDirectory),
                         __UNUSED_PARAM(LPSTARTUPINFOW        lpStartupInfo),
                         __UNUSED_PARAM(LPPROCESS_INFORMATION lpProcessInformation)) {
    check_expected(lpCommandLine);
    return mock();
}
