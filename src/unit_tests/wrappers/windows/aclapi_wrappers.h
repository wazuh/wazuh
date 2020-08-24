/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef ACLAPI_WRAPPERS_H
#define ACLAPI_WRAPPERS_H

#include <windows.h>
#include <accctrl.h>

#undef GetNamedSecurityInfo
#define GetNamedSecurityInfo wrap_GetNamedSecurityInfo
#undef SetNamedSecurityInfo
#define SetNamedSecurityInfo wrap_SetNamedSecurityInfo
#define GetSecurityInfo wrap_GetSecurityInfo

DWORD wrap_GetSecurityInfo(HANDLE handle,
                           SE_OBJECT_TYPE ObjectType,
                           SECURITY_INFORMATION SecurityInfo,
                           PSID *ppsidOwner,
                           PSID *ppsidGroup,
                           PACL *ppDacl,
                           PACL *ppSacl,
                           PSECURITY_DESCRIPTOR *ppSecurityDescriptor);

DWORD wrap_GetNamedSecurityInfo(LPCSTR pObjectName,
                                SE_OBJECT_TYPE ObjectType,
                                SECURITY_INFORMATION SecurityInfo,
                                PSID *ppsidOwner,
                                PSID *ppsidGroup,
                                PACL *ppDacl,
                                PACL *ppSacl,
                                PSECURITY_DESCRIPTOR *ppSecurityDescriptor);

DWORD wrap_SetNamedSecurityInfo(LPSTR pObjectName,
                                SE_OBJECT_TYPE ObjectType,
                                SECURITY_INFORMATION SecurityInfo,
                                PSID psidOwner,
                                PSID psidGroup,
                                PACL pDacl,
                                PACL pSacl);

#endif
