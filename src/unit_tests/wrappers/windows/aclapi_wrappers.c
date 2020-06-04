/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
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

DWORD wrap_GetSecurityInfo (__UNUSED_PARAM(HANDLE handle),
                                        __UNUSED_PARAM(SE_OBJECT_TYPE ObjectType),
                                        __UNUSED_PARAM(SECURITY_INFORMATION SecurityInfo),
                                        __UNUSED_PARAM(PSID *ppsidOwner),
                                        __UNUSED_PARAM(PSID *ppsidGroup),
                                        __UNUSED_PARAM(PACL *ppDacl),
                                        __UNUSED_PARAM(PACL *ppSacl),
                                        __UNUSED_PARAM(PSECURITY_DESCRIPTOR *ppSecurityDescriptor)) {
    return mock();
}
