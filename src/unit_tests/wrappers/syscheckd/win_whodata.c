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

BOOL WINAPI wrap_win_whodata_OpenProcessToken(
  __attribute__ ((unused)) HANDLE  ProcessHandle,
  DWORD   DesiredAccess,
  PHANDLE TokenHandle
) {
    check_expected(DesiredAccess);
    *TokenHandle = mock_type(HANDLE);
    return mock();
}

DWORD WINAPI wrap_win_whodata_GetLastError() {
  return mock();
}

BOOL WINAPI wrap_win_whodata_LookupPrivilegeValue(
  __attribute__ ((unused))  LPCSTR lpSystemName,
  LPCSTR lpName,
  PLUID  lpLuid
) {
  check_expected(lpName);
  lpLuid = mock();
  return mock();
}

WINBOOL WINAPI wrap_win_whodata_CloseHandle(  __attribute__ ((unused)) HANDLE hObject) {
  return mock();
}

WINBOOL WINAPI wrap_win_whodata_AdjustTokenPrivileges(
  HANDLE TokenHandle,
  WINBOOL DisableAllPrivileges,
  __attribute__ ((unused)) PTOKEN_PRIVILEGES NewState,
  __attribute__ ((unused)) DWORD BufferLength,
  __attribute__ ((unused)) PTOKEN_PRIVILEGES PreviousState,
  __attribute__ ((unused)) PDWORD ReturnLength
) {
  check_expected(TokenHandle);
  check_expected(DisableAllPrivileges);

  return mock();
}

DWORD WINAPI wrap_win_whodata_GetNamedSecurityInfo(
  LPCSTR               pObjectName,
  SE_OBJECT_TYPE       ObjectType,
  SECURITY_INFORMATION SecurityInfo,
  __attribute__ ((unused)) PSID                 *ppsidOwner,
  __attribute__ ((unused)) PSID                 *ppsidGroup,
  __attribute__ ((unused)) PACL                 *ppDacl,
  PACL                 *ppSacl,
  PSECURITY_DESCRIPTOR *ppSecurityDescriptor
) {
  check_expected(pObjectName);
  check_expected(ObjectType);
  check_expected(SecurityInfo);
  ppSacl = mock();
  ppSecurityDescriptor = mock();
  return mock();
}
