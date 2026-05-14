/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "sysinfoapi_wrappers.h"
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

VOID wrap_GetSystemTime(LPSYSTEMTIME lpSystemTime) {
  memcpy(lpSystemTime, mock_type(LPSYSTEMTIME), sizeof(SYSTEMTIME));
}
