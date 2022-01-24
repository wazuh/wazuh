/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef SECURITYBASEAPI_WRAPPERS_H
#define SECURITYBASEAPI_WRAPPERS_H

#include <windows.h>

#define AdjustTokenPrivileges wrap_AdjustTokenPrivileges
#define AllocateAndInitializeSid wrap_AllocateAndInitializeSid
#define GetAclInformation wrap_GetAclInformation
#define InitializeAcl wrap_InitializeAcl
#define CopySid wrap_CopySid
#define GetAce wrap_GetAce
#define AddAce wrap_AddAce
#define EqualSid wrap_EqualSid
#define DeleteAce wrap_DeleteAce
#define IsValidSid wrap_IsValidSid
#define GetSecurityDescriptorDacl wrap_GetSecurityDescriptorDacl

WINBOOL wrap_IsValidSid(PSID pSid);

WINBOOL wrap_GetSecurityDescriptorDacl(PSECURITY_DESCRIPTOR pSecurityDescriptor,
                                       LPBOOL lpbDaclPresent,
                                       PACL *pDacl,
                                       LPBOOL lpbDaclDefaulted);

void expect_GetSecurityDescriptorDacl_call(int fDaclPresent, PACL *pDacl, int ret_value);

WINBOOL wrap_GetAclInformation(PACL pAcl,
                               LPVOID pAclInformation,
                               DWORD nAclInformationLength,
                               ACL_INFORMATION_CLASS dwAclInformationClass);

void expect_GetAclInformation_call(LPVOID pAclInformation, int ret_value);

WINBOOL wrap_GetAce(PACL pAcl,
                    DWORD dwAceIndex,
                    LPVOID *pAce);

void expect_GetAce_call(LPVOID *pAce, int ret_value);

WINBOOL wrap_AdjustTokenPrivileges(HANDLE TokenHandle,
                                   WINBOOL DisableAllPrivileges,
                                   PTOKEN_PRIVILEGES NewState,
                                   DWORD BufferLength,
                                   PTOKEN_PRIVILEGES PreviousState,
                                   PDWORD ReturnLength);

WINBOOL wrap_AllocateAndInitializeSid(PSID_IDENTIFIER_AUTHORITY pIdentifierAuthority,
                                      BYTE nSubAuthorityCount,
                                      DWORD nSubAuthority0,
                                      DWORD nSubAuthority1,
                                      DWORD nSubAuthority2,
                                      DWORD nSubAuthority3,
                                      DWORD nSubAuthority4,
                                      DWORD nSubAuthority5,
                                      DWORD nSubAuthority6,
                                      DWORD nSubAuthority7,
                                      PSID *pSid);

WINBOOL wrap_InitializeAcl(PACL pAcl,
                           DWORD nAclLength,
                           DWORD dwAclRevision);

WINBOOL wrap_CopySid(DWORD nDestinationSidLength,
                     PSID pDestinationSid,
                     PSID pSourceSid);

WINBOOL wrap_AddAce(PACL pAcl,
                    DWORD dwAceRevision,
                    DWORD dwStartingAceIndex,
                    LPVOID pAceList,
                    DWORD nAceListLength);

WINBOOL wrap_EqualSid(PSID pSid1,
                      PSID pSid2);

BOOL wrap_DeleteAce(PACL  pAcl,
                    DWORD dwAceIndex);

#endif
