/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "winbase_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

DWORD wrap_FormatMessage(__UNUSED_PARAM(DWORD dwFlags),
                         __UNUSED_PARAM(LPCVOID lpSource),
                         __UNUSED_PARAM(DWORD dwMessageId),
                         __UNUSED_PARAM(DWORD dwLanguageId),
                         LPTSTR lpBuffer,
                         __UNUSED_PARAM(DWORD nSize),
                         __UNUSED_PARAM(va_list *Arguments)) {
    *((LPTSTR*)lpBuffer) = mock_type(char*);
    return 0;
}

HLOCAL wrap_LocalFree(__UNUSED_PARAM(HLOCAL hMem)) {
    return NULL;
}

WINBOOL wrap_LookupAccountSid(__UNUSED_PARAM(LPCSTR lpSystemName),
                              __UNUSED_PARAM(PSID Sid),
                              LPSTR Name,
                              LPDWORD cchName,
                              LPSTR ReferencedDomainName,
                              LPDWORD cchReferencedDomainName,
                              __UNUSED_PARAM(PSID_NAME_USE peUse)) {
    if (Name != NULL) {
        strncpy(Name, mock_type(char*), *cchName);
    }
    else {
        *cchName = mock();
    }

    if (ReferencedDomainName != NULL) {
        strncpy(ReferencedDomainName, mock_type(char*), *cchReferencedDomainName);
    }
    else {
        *cchReferencedDomainName = mock();
    }

    return mock();
}

WINBOOL wrap_GetFileSecurity(LPCSTR lpFileName,
                             __UNUSED_PARAM(SECURITY_INFORMATION RequestedInformation),
                             PSECURITY_DESCRIPTOR pSecurityDescriptor,
                             DWORD nLength,
                             LPDWORD lpnLengthNeeded) {
    check_expected(lpFileName);

    if(!nLength) {
        *lpnLengthNeeded = mock();
    }
    else {
        PSECURITY_DESCRIPTOR sec_desc = mock_type(PSECURITY_DESCRIPTOR);

        if(sec_desc) {
            memcpy(pSecurityDescriptor, sec_desc, nLength);
        }
    }

    return mock();
}

WINBOOL wrap_ReadDirectoryChangesW(__UNUSED_PARAM(HANDLE hDirectory),
                                   __UNUSED_PARAM(LPVOID lpBuffer),
                                   __UNUSED_PARAM(DWORD nBufferLength),
                                   __UNUSED_PARAM(WINBOOL bWatchSubtree),
                                   __UNUSED_PARAM(DWORD dwNotifyFilter),
                                   __UNUSED_PARAM(LPDWORD lpBytesReturned),
                                   __UNUSED_PARAM(LPOVERLAPPED lpOverlapped),
                                   __UNUSED_PARAM(LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)) {
    return mock();
}

BOOL wrap_LookupPrivilegeValue(__UNUSED_PARAM(LPCSTR lpSystemName),
                               LPCSTR lpName,
                               __UNUSED_PARAM(PLUID  lpLuid)) {
    check_expected(lpName);
    lpLuid = mock_type(PLUID);
    return mock();
}
