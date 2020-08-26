/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef UNIT_TEST_WRAPPERS_SYSCHECK_OP
#define UNIT_TEST_WRAPPERS_SYSCHECK_OP

#ifdef WIN32
#include <windows.h>
#include <accctrl.h>

HANDLE wrap_syscheck_op_CreateFile (LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
WINBOOL wrap_syscheck_op_CloseHandle (HANDLE hObject);
DWORD wrap_syscheck_op_GetLastError (VOID);
DWORD wrap_syscheck_op_FormatMessage (DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId, DWORD dwLanguageId, LPTSTR lpBuffer, DWORD nSize, va_list *Arguments);
HLOCAL wrap_syscheck_op_LocalFree (HLOCAL hMem);
DWORD wrap_syscheck_op_GetSecurityInfo (HANDLE handle, SE_OBJECT_TYPE ObjectType, SECURITY_INFORMATION SecurityInfo, PSID *ppsidOwner, PSID *ppsidGroup, PACL *ppDacl, PACL *ppSacl, PSECURITY_DESCRIPTOR *ppSecurityDescriptor);
WINBOOL wrap_syscheck_op_ConvertSidToStringSid(PSID Sid,LPSTR *StringSid);
WINBOOL wrap_syscheck_op_LookupAccountSid (LPCSTR lpSystemName, PSID Sid, LPSTR Name, LPDWORD cchName, LPSTR ReferencedDomainName, LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse);
WINBOOL wrap_syscheck_op_IsValidSid (PSID pSid);
WINBOOL wrap_syscheck_op_GetFileSecurity (LPCSTR lpFileName, SECURITY_INFORMATION RequestedInformation, PSECURITY_DESCRIPTOR pSecurityDescriptor, DWORD nLength, LPDWORD lpnLengthNeeded);
WINBOOL wrap_syscheck_op_GetSecurityDescriptorDacl (PSECURITY_DESCRIPTOR pSecurityDescriptor, LPBOOL lpbDaclPresent, PACL *pDacl, LPBOOL lpbDaclDefaulted);
WINBOOL wrap_syscheck_op_GetAclInformation (PACL pAcl, LPVOID pAclInformation, DWORD nAclInformationLength, ACL_INFORMATION_CLASS dwAclInformationClass);
WINBOOL wrap_syscheck_op_GetAce (PACL pAcl, DWORD dwAceIndex, LPVOID *pAce);
DWORD wrap_syscheck_op_GetFileAttributesA (LPCSTR lpFileName);
#endif
#endif
