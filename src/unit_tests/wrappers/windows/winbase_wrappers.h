/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef WINBASE_WRAPPERS_H
#define WINBASE_WRAPPERS_H

#include <windows.h>

#undef  LookupPrivilegeValue
#define LookupPrivilegeValue wrap_LookupPrivilegeValue
#define LocalFree wrap_LocalFree
#undef  FormatMessage
#define FormatMessage wrap_FormatMessage
#undef  LookupAccountSid
#define LookupAccountSid wrap_LookupAccountSid
#undef  GetFileSecurity
#define GetFileSecurity wrap_GetFileSecurity
#define ReadDirectoryChangesW wrap_ReadDirectoryChangesW

DWORD wrap_FormatMessage(DWORD dwFlags,
                         LPCVOID lpSource,
                         DWORD dwMessageId,
                         DWORD dwLanguageId,
                         LPTSTR lpBuffer,
                         DWORD nSize,
                         va_list *Arguments);

HLOCAL wrap_LocalFree(HLOCAL hMem);

WINBOOL wrap_GetFileSecurity(LPCSTR lpFileName,
                             SECURITY_INFORMATION RequestedInformation,
                             PSECURITY_DESCRIPTOR pSecurityDescriptor,
                             DWORD nLength, LPDWORD lpnLengthNeeded);

WINBOOL wrap_LookupAccountSid(LPCSTR lpSystemName,
                              PSID Sid,
                              LPSTR Name,
                              LPDWORD cchName,
                              LPSTR ReferencedDomainName,
                              LPDWORD cchReferencedDomainName,
                              PSID_NAME_USE peUse);

WINBOOL wrap_ReadDirectoryChangesW(HANDLE hDirectory,
                                   LPVOID lpBuffer,
                                   DWORD nBufferLength,
                                   WINBOOL bWatchSubtree,
                                   DWORD dwNotifyFilter,
                                   LPDWORD lpBytesReturned,
                                   LPOVERLAPPED lpOverlapped,
                                   LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

BOOL wrap_LookupPrivilegeValue(LPCSTR lpSystemName,
                               LPCSTR lpName,
                               PLUID  lpLuid);

#endif
