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
#include <stdbool.h>

#undef OpenProcessToken
#define OpenProcessToken    wrap_OpenProcessToken
#define GetCurrentProcess   wrap_GetCurrentProcess
#define SetThreadPriority   wrap_SetThreadPriority
#define GetCurrentThread    wrap_GetCurrentThread
#define CreateThread        wrap_CreateThread
#define CreateProcessW      wrap_CreateProcessW
#undef TerminateProcess
#define TerminateProcess    wrap_TerminateProcess
#define ResumeThread        wrap_ResumeThread
#define CreateJobObjectW    wrap_CreateJobObjectW
#define AssignProcessToJobObject wrap_AssignProcessToJobObject
#define TerminateJobObject  wrap_TerminateJobObject
#define SetInformationJobObject wrap_SetInformationJobObject
#define CancelSynchronousIo wrap_CancelSynchronousIo

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

DWORD wrap_ResumeThread(HANDLE hThread);

HANDLE wrap_CreateJobObjectW(LPSECURITY_ATTRIBUTES lpJobAttributes, LPCWSTR lpName);

BOOL wrap_AssignProcessToJobObject(HANDLE hJob, HANDLE hProcess);

BOOL wrap_TerminateJobObject(HANDLE hJob, UINT uExitCode);

BOOL wrap_SetInformationJobObject(HANDLE hJob,
                                  JOBOBJECTINFOCLASS JobObjectInformationClass,
                                  LPVOID lpJobObjectInformation,
                                  DWORD cbJobObjectInformationLength);

BOOL wrap_CancelSynchronousIo(HANDLE hThread);

/**
 * @brief Not redirected by a macro here: wm_exec.c opts in, other users of this header keep the real call.
 */
FARPROC wrap_GetProcAddress(HMODULE hModule, LPCSTR lpProcName);

/**
 * @brief Not redirected by a macro here: wm_exec.c opts in, other users of this header keep the real call.
 *        Mocked data per call: the bytes to copy, their count and the return value.
 */
BOOL wrap_ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead,
                   LPOVERLAPPED lpOverlapped);

/**
 * @brief Makes wrap_CreateThread run the thread routine to completion before returning, instead of not
 *        running it. Reset by the test that sets it.
 */
void wrap_CreateThread_run_routine(bool run);

/**
 * @brief Runs, to completion, the routine given to the last wrap_CreateThread call. Used to let a thread that
 *        the code under test left running finish and release what it owns.
 */
void wrap_CreateThread_run_last(void);

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
