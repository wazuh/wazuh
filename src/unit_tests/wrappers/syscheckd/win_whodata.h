/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef UNIT_TEST_WRAPPERS_WIN_WHODATA
#define UNIT_TEST_WRAPPERS_WIN_WHODATA

#ifdef WIN32
#include <windows.h>
#include <accctrl.h>

BOOL WINAPI wrap_win_whodata_OpenProcessToken(
  HANDLE  ProcessHandle,
  DWORD   DesiredAccess,
  PHANDLE TokenHandle
);

DWORD WINAPI wrap_win_whodata_GetLastError();

BOOL WINAPI wrap_win_whodata_LookupPrivilegeValue(
  LPCSTR lpSystemName,
  LPCSTR lpName,
  PLUID  lpLuid
);

WINBOOL WINAPI wrap_win_whodata_CloseHandle(HANDLE hObject);

WINBOOL WINAPI wrap_win_whodata_AdjustTokenPrivileges(
  HANDLE TokenHandle,
  WINBOOL DisableAllPrivileges,
  __attribute__ ((unused)) PTOKEN_PRIVILEGES NewState,
  __attribute__ ((unused)) DWORD BufferLength,
  __attribute__ ((unused)) PTOKEN_PRIVILEGES PreviousState,
  __attribute__ ((unused)) PDWORD ReturnLength
);

DWORD WINAPI wrap_win_whodata_GetNamedSecurityInfo(
  LPCSTR               pObjectName,
  SE_OBJECT_TYPE       ObjectType,
  SECURITY_INFORMATION SecurityInfo,
  PSID                 *ppsidOwner,
  PSID                 *ppsidGroup,
  PACL                 *ppDacl,
  PACL                 *ppSacl,
  PSECURITY_DESCRIPTOR *ppSecurityDescriptor
);

WINBOOL WINAPI wrap_win_whodata_AllocateAndInitializeSid(
  PSID_IDENTIFIER_AUTHORITY pIdentifierAuthority,
  BYTE nSubAuthorityCount,
  DWORD nSubAuthority0,
  DWORD nSubAuthority1,
  DWORD nSubAuthority2,
  DWORD nSubAuthority3,
  DWORD nSubAuthority4,
  DWORD nSubAuthority5,
  DWORD nSubAuthority6,
  DWORD nSubAuthority7,
  PSID *pSid
);

WINBOOL WINAPI wrap_win_whodata_GetAclInformation(
  __attribute__ ((unused)) PACL pAcl,
  LPVOID pAclInformation,
  DWORD nAclInformationLength,
  __attribute__ ((unused)) ACL_INFORMATION_CLASS dwAclInformationClass
);

LPVOID wrap_win_whodata_win_alloc(SIZE_T size);

WINBOOL WINAPI wrap_win_whodata_InitializeAcl(
  PACL pAcl,
  DWORD nAclLength,
  DWORD dwAclRevision
);

HLOCAL WINAPI wrap_win_whodata_LocalFree(HLOCAL hMem);
WINBOOL WINAPI wrap_win_whodata_CopySid(
  DWORD nDestinationSidLength,
  PSID pDestinationSid,
  PSID pSourceSid
);

WINBOOL WINAPI wrap_win_whodata_GetAce(
  __attribute__ ((unused)) PACL pAcl,
  __attribute__ ((unused)) DWORD dwAceIndex,
  LPVOID *pAce
);

WINBOOL WINAPI wrap_win_whodata_AddAce(
  PACL pAcl,
  __attribute__ ((unused)) DWORD dwAceRevision,
  __attribute__ ((unused)) DWORD dwStartingAceIndex,
  __attribute__ ((unused)) LPVOID pAceList,
  __attribute__ ((unused)) DWORD nAceListLength
);

DWORD WINAPI wrap_win_whodata_SetNamedSecurityInfo(
  LPSTR pObjectName,
  SE_OBJECT_TYPE ObjectType,
  SECURITY_INFORMATION SecurityInfo,
  PSID psidOwner,
  PSID psidGroup,
  PACL pDacl,
  PACL pSacl
);

LONG WINAPI wrap_win_whodata_RegOpenKeyEx(
  HKEY hKey,
  LPCSTR lpSubKey,
  DWORD ulOptions,
  REGSAM samDesired,
  PHKEY phkResult
);

LONG WINAPI wrap_win_whodata_RegQueryValueEx(
  HKEY hKey,
  LPCSTR lpValueName,
  LPDWORD lpReserved,
  LPDWORD lpType,
  LPBYTE lpData,
  LPDWORD lpcbData
);
#endif
#endif
