/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef SECURITYBASEAPI_H
#define SECURITYBASEAPI_H

#include <windows.h>

WINBOOL wrap_IsValidSid (PSID pSid);
WINBOOL wrap_GetSecurityDescriptorDacl (PSECURITY_DESCRIPTOR pSecurityDescriptor, LPBOOL lpbDaclPresent, PACL *pDacl, LPBOOL lpbDaclDefaulted);
WINBOOL wrap_GetAclInformation (PACL pAcl, LPVOID pAclInformation, DWORD nAclInformationLength, ACL_INFORMATION_CLASS dwAclInformationClass);
WINBOOL wrap_GetAce (PACL pAcl, DWORD dwAceIndex, LPVOID *pAce);

#endif
