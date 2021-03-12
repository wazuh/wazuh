
/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef TIMEZONEAPI_WRAPPERS_H
#define TIMEZONEAPI_WRAPPERS_H

#include <windows.h>

#define FileTimeToSystemTime wrap_FileTimeToSystemTime

WINBOOL wrap_FileTimeToSystemTime(CONST FILETIME *lpFileTime,
                                  LPSYSTEMTIME lpSystemTime);


#endif
