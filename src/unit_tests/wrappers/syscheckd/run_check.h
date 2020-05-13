/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef UNIT_TEST_WRAPPERS_RUN_CHECK
#define UNIT_TEST_WRAPPERS_RUN_CHECK

struct state_t {
    unsigned int sleep_seconds;
};

#ifdef WIN32
#include <windows.h>

WINBOOL wrap_SetThreadPriority (HANDLE hThread, int nPriority);
HANDLE wrap_GetCurrentThread (VOID);
DWORD wrap_GetLastError (VOID);
VOID wrap_Sleep (DWORD dwMilliseconds);

extern struct state_t state;
#endif

#endif
