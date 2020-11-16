/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef SYSINFOAPI_WRAPPERS_H
#define SYSINFOAPI_WRAPPERS_H

#include <windows.h>

#define GetSystemTime wrap_GetSystemTime

VOID wrap_GetSystemTime(LPSYSTEMTIME lpSystemTime);

#endif
