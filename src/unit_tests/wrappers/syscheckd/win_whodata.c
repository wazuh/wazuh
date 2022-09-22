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
#include "headers/defs.h"

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
  __attribute__ ((unused)) PLUID  lpLuid
) {
  check_expected(lpName);
  lpLuid = mock_type(PLUID);
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
  *ppSacl = mock_type(PACL);
  *ppSecurityDescriptor = mock_type(PSECURITY_DESCRIPTOR);
  return mock();
}

WINBOOL WINAPI wrap_win_whodata_AllocateAndInitializeSid(
  PSID_IDENTIFIER_AUTHORITY pIdentifierAuthority,
  BYTE nSubAuthorityCount,
  __attribute__ ((unused)) DWORD nSubAuthority0,
  __attribute__ ((unused)) DWORD nSubAuthority1,
  __attribute__ ((unused)) DWORD nSubAuthority2,
  __attribute__ ((unused)) DWORD nSubAuthority3,
  __attribute__ ((unused)) DWORD nSubAuthority4,
  __attribute__ ((unused)) DWORD nSubAuthority5,
  __attribute__ ((unused)) DWORD nSubAuthority6,
  __attribute__ ((unused)) DWORD nSubAuthority7,
  __attribute__ ((unused)) PSID *pSid
) {
  check_expected(pIdentifierAuthority);
  check_expected(nSubAuthorityCount);

  return mock();
}

WINBOOL WINAPI wrap_win_whodata_GetAclInformation(
  __attribute__ ((unused)) PACL pAcl,
  LPVOID pAclInformation,
  DWORD nAclInformationLength,
  __attribute__ ((unused)) ACL_INFORMATION_CLASS dwAclInformationClass
) {
  LPVOID acl_information = mock_type(LPVOID);

  if(acl_information != NULL)
    memcpy(pAclInformation, acl_information, nAclInformationLength);

  return mock();
}

LPVOID wrap_win_whodata_win_alloc(SIZE_T size) {
  check_expected(size);
  return mock_type(LPVOID);
}


WINBOOL WINAPI wrap_win_whodata_InitializeAcl(
  PACL pAcl,
  DWORD nAclLength,
  DWORD dwAclRevision
) {
  check_expected(pAcl);
  check_expected(nAclLength);
  check_expected(dwAclRevision);

  return mock();
}

HLOCAL WINAPI wrap_win_whodata_LocalFree(__attribute__ ((unused)) HLOCAL hMem) {
  return 0;
}

WINBOOL WINAPI wrap_win_whodata_CopySid(
  __attribute__ ((unused)) DWORD nDestinationSidLength,
  __attribute__ ((unused)) PSID pDestinationSid,
  __attribute__ ((unused)) PSID pSourceSid
) {
  return mock();
}

WINBOOL WINAPI wrap_win_whodata_GetAce(
  __attribute__ ((unused)) PACL pAcl,
  __attribute__ ((unused)) DWORD dwAceIndex,
  LPVOID *pAce
) {
  *pAce = mock_type(LPVOID);

  return mock();
}

WINBOOL WINAPI wrap_win_whodata_AddAce(
  PACL pAcl,
  __attribute__ ((unused)) DWORD dwAceRevision,
  __attribute__ ((unused)) DWORD dwStartingAceIndex,
  __attribute__ ((unused)) LPVOID pAceList,
  __attribute__ ((unused)) DWORD nAceListLength
) {
  check_expected(pAcl);

  return mock();
}

DWORD WINAPI wrap_win_whodata_SetNamedSecurityInfo(
  LPSTR pObjectName,
  SE_OBJECT_TYPE ObjectType,
  SECURITY_INFORMATION SecurityInfo,
  PSID psidOwner,
  PSID psidGroup,
  PACL pDacl,
  PACL pSacl
) {
  check_expected(pObjectName);
  check_expected(ObjectType);
  check_expected(SecurityInfo);
  check_expected(psidOwner);
  check_expected(psidGroup);
  check_expected(pDacl);
  check_expected(pSacl);

  return mock();
}

LONG WINAPI wrap_win_whodata_RegOpenKeyEx(
  HKEY hKey,
  LPCSTR lpSubKey,
  DWORD ulOptions,
  REGSAM samDesired,
  PHKEY phkResult
) {
  PHKEY key;

  check_expected(hKey);
  check_expected(lpSubKey);
  check_expected(ulOptions);
  check_expected(samDesired);

  if(key = mock_type(PHKEY), key) {
    memcpy(phkResult, key, sizeof(HKEY));
  }

  return mock();
}

LONG WINAPI wrap_win_whodata_RegQueryValueEx(
  __attribute__ ((unused)) HKEY hKey,
  LPCSTR lpValueName,
  LPDWORD lpReserved,
  LPDWORD lpType,
  LPBYTE lpData,
  LPDWORD lpcbData
) {
  LPBYTE data;

  check_expected(lpValueName);
  check_expected(lpReserved);
  check_expected(lpType);

  if(data = mock_type(LPBYTE), data) {
    memcpy(lpData, data, *lpcbData);
  }
  return mock();
}

int WINAPI wrap_win_whodata_WideCharToMultiByte(
  __attribute__((unused)) UINT CodePage,
  __attribute__((unused)) DWORD dwFlags,
  LPCWCH lpWideCharStr,
  int cchWideChar,
  LPSTR lpMultiByteStr,
  int cbMultiByte,
  __attribute__((unused)) LPCCH lpDefaultChar,
  __attribute__((unused)) LPBOOL lpUsedDefaultChar
) {
  check_expected(lpWideCharStr);
  check_expected(cchWideChar);

  if(lpMultiByteStr)
    strncpy(lpMultiByteStr, mock_type(char*), cbMultiByte);

  return mock();
}

WINBOOL WINAPI wrap_win_whodata_GetVolumePathNamesForVolumeNameW(
  LPCWSTR lpszVolumeName,
  LPWCH lpszVolumePathNames,
  DWORD cchBufferLength,
  PDWORD lpcchReturnLength
) {
  DWORD buffer_size;

  check_expected(lpszVolumeName);

  buffer_size = mock();

  if(lpszVolumePathNames && buffer_size <= cchBufferLength) {
    memcpy(lpszVolumePathNames, mock_type(LPWCH), cchBufferLength);
  }
  *lpcchReturnLength = buffer_size;

  return mock();
}

HANDLE WINAPI wrap_win_whodata_FindFirstVolumeW(
  LPWSTR lpszVolumeName,
  DWORD cchBufferLength
) {
  wcsncpy(lpszVolumeName, mock_type(wchar_t*), cchBufferLength);

  return mock_type(HANDLE);
}

WINBOOL WINAPI wrap_win_whodata_FindVolumeClose (HANDLE hFindVolume) {
  check_expected(hFindVolume);

  return mock();
}

DWORD WINAPI wrap_win_whodata_QueryDosDeviceW(
  LPCWSTR lpDeviceName,
  LPWSTR lpTargetPath,
  DWORD ucchMax
) {
  DWORD len = mock();
  check_expected(lpDeviceName);

  if(len <= ucchMax)
    memcpy(lpTargetPath, mock_type(LPWSTR), len);

  return mock();
}

WINBOOL WINAPI wrap_win_whodata_FindNextVolumeW(
  HANDLE hFindVolume,
  LPWSTR lpszVolumeName,
  DWORD cchBufferLength
) {
  check_expected(hFindVolume);

  wcsncpy(lpszVolumeName, mock_type(LPWSTR), cchBufferLength);

  return mock();
}

WINBOOL WINAPI wrap_win_whodata_EqualSid(
  __attribute__ ((unused)) PSID pSid1,
  __attribute__ ((unused)) PSID pSid2
) {
  return mock();
}

WINBOOL WINAPI wrap_win_whodata_FileTimeToSystemTime(
  CONST FILETIME *lpFileTime,
  LPSYSTEMTIME lpSystemTime
) {
  check_expected(lpFileTime);

  memcpy(lpSystemTime, mock_type(LPSYSTEMTIME), sizeof(SYSTEMTIME));

  return mock();
}

BOOL WINAPI wrap_win_whodata_DeleteAce(
  PACL  pAcl,
  DWORD dwAceIndex
){
  check_expected(pAcl);
  check_expected(dwAceIndex);

  return mock();
}

BOOL WINAPI wrap_win_whodata_EvtRender(
  EVT_HANDLE Context,
  EVT_HANDLE Fragment,
  DWORD      Flags,
  DWORD      BufferSize,
  PVOID      Buffer,
  PDWORD     BufferUsed,
  PDWORD     PropertyCount
) {
  check_expected_ptr(Context);
  check_expected_ptr(Fragment);
  check_expected(Flags);
  check_expected(BufferSize);
  PEVT_VARIANT output = mock_ptr_type(PVOID);
  *BufferUsed = mock_type(int);
  *PropertyCount = mock_type(int);
  if (output && Buffer && *BufferUsed <= BufferSize) {
    memcpy(Buffer, output, *BufferUsed);
  }

  return mock();
}

EVT_HANDLE wrap_win_whodata_EvtCreateRenderContext(
  DWORD   ValuePathsCount,
  LPCWSTR *ValuePaths,
  DWORD   Flags
) {
  check_expected(ValuePathsCount),
  check_expected_ptr(ValuePaths);
  check_expected(Flags);

  return mock_type(EVT_HANDLE);
}

EVT_HANDLE wrap_win_whodata_EvtSubscribe(
  EVT_HANDLE             Session,
  HANDLE                 SignalEvent,
  LPCWSTR                ChannelPath,
  LPCWSTR                Query,
  EVT_HANDLE             Bookmark,
  PVOID                  Context,
  EVT_SUBSCRIBE_CALLBACK Callback,
  DWORD                  Flags
) {
  check_expected_ptr(Session);
  check_expected(SignalEvent);
  check_expected(ChannelPath);
  check_expected(Query);
  check_expected(Bookmark);
  check_expected(Context);
  check_expected_ptr(Callback);
  check_expected(Flags);
  return mock_type(EVT_HANDLE);
}

int wrap_win_whodata_fprintf (FILE *__stream, const char *__format, ...) {
  char formatted_msg[OS_MAXSTR];
  va_list args;

  check_expected(__stream);

  va_start(args, __format);
  vsnprintf(formatted_msg, OS_MAXSTR, __format, args);
  va_end(args);

  check_expected(formatted_msg);

  return mock();
}

char * wrap_win_whodata_fgets (char * __s, int __n, FILE * __stream) {
  char *buffer = mock_type(char*);

  check_expected(__stream);

  if(buffer) {
    strncpy(__s, buffer, __n - 1);
    return __s;
  }
  return NULL;
}

VOID wrap_win_whodata_Sleep (DWORD dwMilliseconds) {
    check_expected(dwMilliseconds);
}

VOID WINAPI wrap_win_whodata_GetSystemTime (LPSYSTEMTIME lpSystemTime) {
  memcpy(lpSystemTime, mock_type(LPSYSTEMTIME), sizeof(SYSTEMTIME));
}

WINBOOL wrap_win_whodata_ConvertSidToStringSid(__UNUSED_PARAM(PSID Sid),LPSTR *StringSid) {
    *StringSid = mock_type(LPSTR);
    return mock();
}
