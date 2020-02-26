/*
 * Copyright (C) 2015-2019, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "run_realtime.h"
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

HANDLE wrap_CreateEvent (LPSECURITY_ATTRIBUTES lpEventAttributes, WINBOOL bManualReset, WINBOOL bInitialState, LPCSTR lpName) {
    check_expected(lpEventAttributes);
    check_expected(bManualReset);
    check_expected(bInitialState);
    check_expected(lpName);

    return mock_type(HANDLE);
}
