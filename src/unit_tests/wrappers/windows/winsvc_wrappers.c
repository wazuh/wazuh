/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "winsvc_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

SC_HANDLE wrap_OpenSCManager(__attribute__((unused)) LPCSTR lpMachineName,
                             __attribute__((unused)) LPCSTR lpDatabaseName,
                             __attribute__((unused)) DWORD dwDesiredAccess) {
    return mock_type(SC_HANDLE);
}

SC_HANDLE wrap_OpenService(__attribute__((unused)) SC_HANDLE hSCManager,
                           __attribute__((unused)) LPCSTR lpServiceName,
                           __attribute__((unused)) DWORD dwDesiredAccess) {
    return mock_type(SC_HANDLE);
}

WINBOOL wrap_QueryServiceStatus(__attribute__((unused)) SC_HANDLE hService, LPSERVICE_STATUS lpServiceStatus) {
    WINBOOL ok = mock_type(WINBOOL);
    if (ok) {
        lpServiceStatus->dwCurrentState = mock_type(DWORD);
    }
    return ok;
}

WINBOOL wrap_CloseServiceHandle(__attribute__((unused)) SC_HANDLE hSCObject) {
    return mock_type(WINBOOL);
}

void expect_CheckServiceRunning_query(DWORD current_state) {
    will_return(wrap_OpenSCManager, (SC_HANDLE)0x1);
    will_return(wrap_OpenService, (SC_HANDLE)0x2);
    will_return(wrap_QueryServiceStatus, TRUE);
    will_return(wrap_QueryServiceStatus, current_state);
    will_return(wrap_CloseServiceHandle, TRUE);
    will_return(wrap_CloseServiceHandle, TRUE);
}
