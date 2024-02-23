/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef PROCESSTHREADSAPI_WRAPPERS_H
#define PROCESSTHREADSAPI_WRAPPERS_H

#include <windows.h>

#undef OpenProcessToken
#define OpenProcessToken    wrap_OpenProcessToken
#define GetCurrentProcess   wrap_GetCurrentProcess
#define SetThreadPriority   wrap_SetThreadPriority
#define GetCurrentThread    wrap_GetCurrentThread
#define CreateThread        wrap_CreateThread
#define CreateProcessW      wrap_CreateProcessW
#undef TerminateProcess
#define TerminateProcess    wrap_TerminateProcess

WINBOOL wrap_SetThreadPriority(HANDLE hThread, int nPriority);

HANDLE wrap_GetCurrentThread(VOID);

HANDLE wrap_GetCurrentProcess(VOID);

HANDLE wrap_CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes,
                         SIZE_T dwStackSize,
                         LPTHREAD_START_ROUTINE lpStartAddress,
                         PVOID lpParameter,
                         DWORD dwCreationFlags,
                         LPDWORD lpThreadId);

BOOL wrap_OpenProcessToken(HANDLE ProcessHandle,
                           DWORD DesiredAccess,
                           PHANDLE TokenHandle);

BOOL wrap_TerminateProcess(__UNUSED_PARAM(HANDLE hProcess),
                           __UNUSED_PARAM(UINT uExitCode));

/**
 * @brief This function loads the expect and will_return calls for the wrapper of SetThreadPriority
 */
void expect_SetThreadPriority_call(HANDLE handle, int priority, int ret);

BOOL wrap_CreateProcessW(LPCWSTR               lpApplicationName,
                         LPWSTR                lpCommandLine,
                         LPSECURITY_ATTRIBUTES lpProcessAttributes,
                         LPSECURITY_ATTRIBUTES lpThreadAttributes,
                         BOOL                  bInheritHandles,
                         DWORD                 dwCreationFlags,
                         LPVOID                lpEnvironment,
                         LPCWSTR               lpCurrentDirectory,
                         LPSTARTUPINFOW        lpStartupInfo,
                         LPPROCESS_INFORMATION lpProcessInformation);
#endif
