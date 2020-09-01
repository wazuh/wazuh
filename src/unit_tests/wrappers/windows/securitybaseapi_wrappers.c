/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "securitybaseapi_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

WINBOOL wrap_IsValidSid(__UNUSED_PARAM(PSID pSid)) {
    return mock();
}

WINBOOL wrap_GetSecurityDescriptorDacl(__UNUSED_PARAM(PSECURITY_DESCRIPTOR pSecurityDescriptor),
                                       LPBOOL lpbDaclPresent,
                                       PACL *pDacl,
                                       __UNUSED_PARAM(LPBOOL lpbDaclDefaulted)) {
    *lpbDaclPresent = mock();

    if(*lpbDaclPresent == TRUE)
        *pDacl = mock_type(PACL);

    return mock();
}

WINBOOL wrap_GetAclInformation(__UNUSED_PARAM(PACL pAcl),
                               LPVOID pAclInformation,
                               DWORD nAclInformationLength,
                               __UNUSED_PARAM(ACL_INFORMATION_CLASS dwAclInformationClass)) {
    LPVOID acl_information = mock_type(LPVOID);

    if(acl_information != NULL)
        memcpy(pAclInformation, acl_information, nAclInformationLength);

    return mock();
}

WINBOOL wrap_GetAce(__UNUSED_PARAM(PACL pAcl),
                    __UNUSED_PARAM(DWORD dwAceIndex),
                    LPVOID *pAce) {
    *pAce = mock_type(LPVOID);
    return mock();
}

WINBOOL wrap_AdjustTokenPrivileges(HANDLE TokenHandle,
                                   WINBOOL DisableAllPrivileges,
                                   __UNUSED_PARAM(PTOKEN_PRIVILEGES NewState),
                                   __UNUSED_PARAM(DWORD BufferLength),
                                   __UNUSED_PARAM(PTOKEN_PRIVILEGES PreviousState),
                                   __UNUSED_PARAM(PDWORD ReturnLength)) {
    check_expected(TokenHandle);
    check_expected(DisableAllPrivileges);
    return mock();
}

WINBOOL wrap_AllocateAndInitializeSid(PSID_IDENTIFIER_AUTHORITY pIdentifierAuthority,
                                      BYTE nSubAuthorityCount,
                                      __UNUSED_PARAM(DWORD nSubAuthority0),
                                      __UNUSED_PARAM(DWORD nSubAuthority1),
                                      __UNUSED_PARAM(DWORD nSubAuthority2),
                                      __UNUSED_PARAM(DWORD nSubAuthority3),
                                      __UNUSED_PARAM(DWORD nSubAuthority4),
                                      __UNUSED_PARAM(DWORD nSubAuthority5),
                                      __UNUSED_PARAM(DWORD nSubAuthority6),
                                      __UNUSED_PARAM(DWORD nSubAuthority7),
                                      __UNUSED_PARAM(PSID *pSid)) {
    check_expected(pIdentifierAuthority);
    check_expected(nSubAuthorityCount);
    return mock();
}

WINBOOL wrap_InitializeAcl(PACL pAcl,
                           DWORD nAclLength,
                           DWORD dwAclRevision) {
    check_expected(pAcl);
    check_expected(nAclLength);
    check_expected(dwAclRevision);
    return mock();
}

WINBOOL wrap_CopySid(__UNUSED_PARAM(DWORD nDestinationSidLength),
                     __UNUSED_PARAM(PSID pDestinationSid),
                     __UNUSED_PARAM(PSID pSourceSid)) {
    return mock();
}

WINBOOL wrap_AddAce(PACL pAcl,
                    __UNUSED_PARAM(DWORD dwAceRevision),
                    __UNUSED_PARAM(DWORD dwStartingAceIndex),
                    __UNUSED_PARAM(LPVOID pAceList),
                    __UNUSED_PARAM(DWORD nAceListLength)) {
    check_expected(pAcl);
    return mock();
}

WINBOOL wrap_EqualSid(__UNUSED_PARAM(PSID pSid1),
                      __UNUSED_PARAM(PSID pSid2)) {
    return mock();
}

BOOL wrap_DeleteAce(PACL  pAcl,
                    DWORD dwAceIndex){
    check_expected(pAcl);
    check_expected(dwAceIndex);
    return mock();
}
