/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "win_whodata.h"
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

BOOL WINAPI wrap_OpenProcessToken(
  __attribute__ ((unused)) HANDLE  ProcessHandle,
  DWORD   DesiredAccess,
  __attribute__ ((unused))  PHANDLE TokenHandle
) {
    check_expected(DesiredAccess);
    return mock();
}

DWORD WINAPI wrap_GetLastError() {
  return mock();
}