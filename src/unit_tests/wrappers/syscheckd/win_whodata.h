/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef UNIT_TEST_WRAPPERS_WIN_WHODATA
#define UNIT_TEST_WRAPPERS_WIN_WHODATA

#ifdef WIN32
#include <windows.h>

BOOL WINAPI wrap_win_whodata_OpenProcessToken(
  HANDLE  ProcessHandle,
  DWORD   DesiredAccess,
  PHANDLE TokenHandle
);

DWORD WINAPI wrap_win_whodata_GetLastError();

BOOL WINAPI wrap_win_whodata_LookupPrivilegeValue(
  LPCSTR lpSystemName,
  LPCSTR lpName,
  PLUID  lpLuid
);

WINBOOL WINAPI wrap_win_whodata_CloseHandle(HANDLE hObject);

#endif
#endif