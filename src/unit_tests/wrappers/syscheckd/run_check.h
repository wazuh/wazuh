/*
 * Copyright (C) 2015-2019, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef UNIT_TEST_WRAPPERS_RUN_CHECK
#define UNIT_TEST_WRAPPERS_RUN_CHECK

#include <windows.h>

WINBOOL wrap_SetThreadPriority (HANDLE hThread, int nPriority);
HANDLE wrap_GetCurrentThread (VOID);
DWORD wrap_GetLastError (VOID);

#endif
