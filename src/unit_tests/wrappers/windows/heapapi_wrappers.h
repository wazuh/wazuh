
/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef HEAPAPI_WRAPPERS_H
#define HEAPAPI_WRAPPERS_H

#include <windows.h>

#undef win_alloc
#define win_alloc wrap_win_alloc

LPVOID wrap_win_alloc(SIZE_T size);

#endif
