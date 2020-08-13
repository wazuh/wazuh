/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef HANDLEAPI_WRAPPERS_H
#define HANDLEAPI_WRAPPERS_H

#include <windows.h>

#undef CloseHandle
#define CloseHandle wrap_CloseHandle

WINBOOL wrap_CloseHandle (HANDLE hObject);

#endif
