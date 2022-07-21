/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef SYNCHAPI_WRAPPERS_H
#define SYNCHAPI_WRAPPERS_H

#include <windows.h>

#define Sleep wrap_Sleep
#undef CreateEvent
#define CreateEvent wrap_CreateEvent
#undef WaitForSingleObjectEx
#define WaitForSingleObjectEx wrap_WaitForSingleObjectEx

VOID wrap_Sleep(DWORD dwMilliseconds);

HANDLE wrap_CreateEvent(LPSECURITY_ATTRIBUTES lpEventAttributes,
                        WINBOOL bManualReset,
                        WINBOOL bInitialState,
                        LPCSTR lpName);

DWORD wrap_WaitForSingleObjectEx(HANDLE hHandle, DWORD dwMilliseconds, BOOL bAlertable);

#endif
