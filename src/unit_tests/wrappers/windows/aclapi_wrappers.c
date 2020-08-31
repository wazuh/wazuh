/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "aclapi_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

DWORD wrap_GetSecurityInfo(__UNUSED_PARAM(HANDLE handle),
                           __UNUSED_PARAM(SE_OBJECT_TYPE ObjectType),
                           __UNUSED_PARAM(SECURITY_INFORMATION SecurityInfo),
                           __UNUSED_PARAM(PSID *ppsidOwner),
                           __UNUSED_PARAM(PSID *ppsidGroup),
                           __UNUSED_PARAM(PACL *ppDacl),
                           __UNUSED_PARAM(PACL *ppSacl),
                           __UNUSED_PARAM(PSECURITY_DESCRIPTOR *ppSecurityDescriptor)) {
    return mock();
}

DWORD wrap_GetNamedSecurityInfo(LPCSTR pObjectName,
                                SE_OBJECT_TYPE ObjectType,
                                SECURITY_INFORMATION SecurityInfo,
                                __UNUSED_PARAM(PSID *ppsidOwner),
                                __UNUSED_PARAM(PSID *ppsidGroup),
                                __UNUSED_PARAM(PACL *ppDacl),
                                PACL *ppSacl,
                                PSECURITY_DESCRIPTOR *ppSecurityDescriptor) {
    check_expected(pObjectName);
    check_expected(ObjectType);
    check_expected(SecurityInfo);
    *ppSacl = mock_type(PACL);
    *ppSecurityDescriptor = mock_type(PSECURITY_DESCRIPTOR);
    return mock();
}

DWORD wrap_SetNamedSecurityInfo(LPSTR pObjectName,
                                SE_OBJECT_TYPE ObjectType,
                                SECURITY_INFORMATION SecurityInfo,
                                PSID psidOwner,
                                PSID psidGroup,
                                PACL pDacl,
                                PACL pSacl) {
    check_expected(pObjectName);
    check_expected(ObjectType);
    check_expected(SecurityInfo);
    check_expected(psidOwner);
    check_expected(psidGroup);
    check_expected(pDacl);
    check_expected(pSacl);
    return mock();
}
