/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "syscheck_op.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

HANDLE wrap_syscheck_op_CreateFile (LPCSTR lpFileName,
                                    __UNUSED_PARAM(DWORD dwDesiredAccess),
                                    __UNUSED_PARAM(DWORD dwShareMode),
                                    __UNUSED_PARAM(LPSECURITY_ATTRIBUTES lpSecurityAttributes),
                                    __UNUSED_PARAM(DWORD dwCreationDisposition),
                                    __UNUSED_PARAM(DWORD dwFlagsAndAttributes),
                                    __UNUSED_PARAM(HANDLE hTemplateFile)) {
    check_expected(lpFileName);

    return mock_type(HANDLE);
}

WINBOOL wrap_syscheck_op_CloseHandle (HANDLE hObject) {
    check_expected(hObject);

    return mock();
}

DWORD wrap_syscheck_op_GetLastError (VOID) {
    return mock();
}

DWORD wrap_syscheck_op_FormatMessage (__UNUSED_PARAM(DWORD dwFlags),
                                      __UNUSED_PARAM(LPCVOID lpSource),
                                      __UNUSED_PARAM(DWORD dwMessageId),
                                      __UNUSED_PARAM(DWORD dwLanguageId),
                                      LPTSTR lpBuffer,
                                      __UNUSED_PARAM(DWORD nSize),
                                      __UNUSED_PARAM(va_list *Arguments)) {
    *((LPTSTR*)lpBuffer) = mock_type(char*);
    return 0;
}

HLOCAL wrap_syscheck_op_LocalFree (__UNUSED_PARAM(HLOCAL hMem)) {
    return NULL;
}

DWORD wrap_syscheck_op_GetSecurityInfo (__UNUSED_PARAM(HANDLE handle),
                                        __UNUSED_PARAM(SE_OBJECT_TYPE ObjectType),
                                        __UNUSED_PARAM(SECURITY_INFORMATION SecurityInfo),
                                        __UNUSED_PARAM(PSID *ppsidOwner),
                                        __UNUSED_PARAM(PSID *ppsidGroup),
                                        __UNUSED_PARAM(PACL *ppDacl),
                                        __UNUSED_PARAM(PACL *ppSacl),
                                        __UNUSED_PARAM(PSECURITY_DESCRIPTOR *ppSecurityDescriptor)) {
    return mock();
}

WINBOOL wrap_syscheck_op_ConvertSidToStringSid(__UNUSED_PARAM(PSID Sid),LPSTR *StringSid) {
    *StringSid = mock_type(LPSTR);
    return mock();
}

WINBOOL wrap_syscheck_op_LookupAccountSid (__UNUSED_PARAM(LPCSTR lpSystemName),
                                           __UNUSED_PARAM(PSID Sid),
                                           LPSTR Name,
                                           LPDWORD cchName,
                                           LPSTR ReferencedDomainName,
                                           LPDWORD cchReferencedDomainName,
                                           __UNUSED_PARAM(PSID_NAME_USE peUse)) {
    if(Name != NULL)
        strncpy(Name, mock_type(char*), *cchName);
    else
        *cchName = mock();

    if(ReferencedDomainName != NULL)
        strncpy(ReferencedDomainName, mock_type(char*), *cchReferencedDomainName);
    else
        *cchReferencedDomainName = mock();

    return mock();
}

WINBOOL wrap_syscheck_op_IsValidSid (__UNUSED_PARAM(PSID pSid)) {
    return mock();
}

WINBOOL wrap_syscheck_op_GetFileSecurity (LPCSTR lpFileName,
                                          __UNUSED_PARAM(SECURITY_INFORMATION RequestedInformation),
                                          PSECURITY_DESCRIPTOR pSecurityDescriptor,
                                          DWORD nLength,
                                          LPDWORD lpnLengthNeeded) {
    check_expected(lpFileName);

    if(!nLength) {
        *lpnLengthNeeded = mock();
    } else {
        PSECURITY_DESCRIPTOR sec_desc = mock_type(PSECURITY_DESCRIPTOR);

        if(sec_desc)
            memcpy(pSecurityDescriptor, sec_desc, nLength);
    }

    return mock();
}

WINBOOL wrap_syscheck_op_GetSecurityDescriptorDacl (__UNUSED_PARAM(PSECURITY_DESCRIPTOR pSecurityDescriptor),
                                                    LPBOOL lpbDaclPresent,
                                                    PACL *pDacl,
                                                    __UNUSED_PARAM(LPBOOL lpbDaclDefaulted)) {
    *lpbDaclPresent = mock();

    if(*lpbDaclPresent == TRUE)
        *pDacl = mock_type(PACL);

    return mock();
}

WINBOOL wrap_syscheck_op_GetAclInformation (__UNUSED_PARAM(PACL pAcl),
                                            LPVOID pAclInformation,
                                            DWORD nAclInformationLength,
                                            __UNUSED_PARAM(ACL_INFORMATION_CLASS dwAclInformationClass)) {
    LPVOID acl_information = mock_type(LPVOID);

    if(acl_information != NULL)
        memcpy(pAclInformation, acl_information, nAclInformationLength);

    return mock();
}

WINBOOL wrap_syscheck_op_GetAce (__UNUSED_PARAM(PACL pAcl),
                                 __UNUSED_PARAM(DWORD dwAceIndex),
                                LPVOID *pAce) {
    *pAce = mock_type(LPVOID);

    return mock();
}

DWORD wrap_syscheck_op_GetFileAttributesA (LPCSTR lpFileName) {
    check_expected(lpFileName);

    return mock();
}
