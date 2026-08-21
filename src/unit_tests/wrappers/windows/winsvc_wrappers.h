/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef WINSVC_WRAPPERS_H
#define WINSVC_WRAPPERS_H

#include <windows.h>
#include <winsvc.h>

#undef OpenSCManager
#define OpenSCManager wrap_OpenSCManager
#undef OpenService
#define OpenService wrap_OpenService
#undef QueryServiceStatus
#define QueryServiceStatus wrap_QueryServiceStatus
#undef CloseServiceHandle
#define CloseServiceHandle wrap_CloseServiceHandle

SC_HANDLE wrap_OpenSCManager(LPCSTR lpMachineName, LPCSTR lpDatabaseName, DWORD dwDesiredAccess);

SC_HANDLE wrap_OpenService(SC_HANDLE hSCManager, LPCSTR lpServiceName, DWORD dwDesiredAccess);

WINBOOL wrap_QueryServiceStatus(SC_HANDLE hService, LPSERVICE_STATUS lpServiceStatus);

WINBOOL wrap_CloseServiceHandle(SC_HANDLE hSCObject);

/** @brief Load the full happy-path sequence for CheckServiceRunning(): a
 * valid SC manager handle, a valid service handle, and a QueryServiceStatus
 * result reporting the given state. */
void expect_CheckServiceRunning_query(DWORD current_state);

#endif
