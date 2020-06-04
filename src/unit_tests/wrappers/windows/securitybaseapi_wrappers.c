/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
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

WINBOOL wrap_IsValidSid (__UNUSED_PARAM(PSID pSid)) {
    return mock();
}

WINBOOL wrap_GetSecurityDescriptorDacl (__UNUSED_PARAM(PSECURITY_DESCRIPTOR pSecurityDescriptor),
                                                    LPBOOL lpbDaclPresent,
                                                    PACL *pDacl,
                                                    __UNUSED_PARAM(LPBOOL lpbDaclDefaulted)) {
    *lpbDaclPresent = mock();

    if(*lpbDaclPresent == TRUE)
        *pDacl = mock_type(PACL);

    return mock();
}

WINBOOL wrap_GetAclInformation (__UNUSED_PARAM(PACL pAcl),
                                            LPVOID pAclInformation,
                                            DWORD nAclInformationLength,
                                            __UNUSED_PARAM(ACL_INFORMATION_CLASS dwAclInformationClass)) {
    LPVOID acl_information = mock_type(LPVOID);

    if(acl_information != NULL)
        memcpy(pAclInformation, acl_information, nAclInformationLength);

    return mock();
}

WINBOOL wrap_GetAce (__UNUSED_PARAM(PACL pAcl),
                                 __UNUSED_PARAM(DWORD dwAceIndex),
                                LPVOID *pAce) {
    *pAce = mock_type(LPVOID);

    return mock();
}
