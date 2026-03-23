/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "ntsecapi_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>

NTSTATUS wrap_LsaOpenPolicy(__UNUSED_PARAM(PLSA_UNICODE_STRING    SystemName),
                            __UNUSED_PARAM(PLSA_OBJECT_ATTRIBUTES ObjectAttributes),
                            __UNUSED_PARAM(ACCESS_MASK            DesiredAccess),
                            __UNUSED_PARAM(PLSA_HANDLE            PolicyHandle)) {
    return mock();
}

NTSTATUS wrap_LsaQueryInformationPolicy(__UNUSED_PARAM(LSA_HANDLE               PolicyHandle),
                                        __UNUSED_PARAM(POLICY_INFORMATION_CLASS InformationClass),
                                        PVOID                                   *Buffer) {
    *Buffer = mock_type(PPOLICY_AUDIT_EVENTS_INFO);
    return mock();
}

BOOLEAN wrap_AuditLookupCategoryGuidFromCategoryId(__UNUSED_PARAM(POLICY_AUDIT_EVENT_TYPE AuditCategoryId),
                                                   GUID                    *pAuditCategoryGuid) {
    GUID *guid = mock_type(GUID *);
    *pAuditCategoryGuid = *guid;
    return mock();
}

BOOLEAN wrap_AuditEnumerateSubCategories(__UNUSED_PARAM(const GUID *pAuditCategoryGuid),
                                         __UNUSED_PARAM(BOOLEAN    bRetrieveAllSubCategories),
                                         __UNUSED_PARAM(GUID       **ppAuditSubCategoriesArray),
                                         PULONG                    pdwCountReturned) {
    *pdwCountReturned = mock_type(ULONG);
    return mock();
}

BOOLEAN wrap_AuditQuerySystemPolicy(__UNUSED_PARAM(const GUID                *pSubCategoryGuids),
                                    __UNUSED_PARAM(ULONG                     dwPolicyCount),
                                    PAUDIT_POLICY_INFORMATION                *ppAuditPolicy) {
    *ppAuditPolicy = mock_type(AUDIT_POLICY_INFORMATION *);
    return mock();
}

NTSTATUS wrap_LsaFreeMemory(__UNUSED_PARAM(PVOID Buffer)) {
    return 0;
}

NTSTATUS wrap_LsaClose(__UNUSED_PARAM(LSA_HANDLE ObjectHandle)) {
    return 0;
}
