/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef KERNEL32_WRAPPERS_WINDOWS_H
#define KERNEL32_WRAPPERS_WINDOWS_H

#include <stdbool.h>
#include <windows.h>

DWORD wrap_WaitForSingleObject(HANDLE hMutex, long value);

bool wrap_ReleaseMutex(HANDLE hMutex);

#undef WaitForSingleObject
#define WaitForSingleObject wrap_WaitForSingleObject
#undef ReleaseMutex
#define ReleaseMutex wrap_ReleaseMutex

#endif
