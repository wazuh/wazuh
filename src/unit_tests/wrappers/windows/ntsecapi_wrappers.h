/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef NTSECAPI_WRAPPERS_H
#define NTSECAPI_WRAPPERS_H

#include <windows.h>
#include <ntsecapi.h>

#undef LsaOpenPolicy
#define LsaOpenPolicy wrap_LsaOpenPolicy
#undef LsaQueryInformationPolicy
#define LsaQueryInformationPolicy wrap_LsaQueryInformationPolicy
#undef AuditLookupCategoryGuidFromCategoryId
#define AuditLookupCategoryGuidFromCategoryId wrap_AuditLookupCategoryGuidFromCategoryId
#undef AuditEnumerateSubCategories
#define AuditEnumerateSubCategories wrap_AuditEnumerateSubCategories
#undef AuditQuerySystemPolicy
#define AuditQuerySystemPolicy wrap_AuditQuerySystemPolicy
#undef LsaFreeMemory
#define LsaFreeMemory wrap_LsaFreeMemory
#undef LsaClose
#define LsaClose wrap_LsaClose

NTSTATUS wrap_LsaOpenPolicy(PLSA_UNICODE_STRING    SystemName,
                            PLSA_OBJECT_ATTRIBUTES ObjectAttributes,
                            ACCESS_MASK            DesiredAccess,
                            PLSA_HANDLE            PolicyHandle);

NTSTATUS wrap_LsaQueryInformationPolicy(LSA_HANDLE                PolicyHandle,
                                        POLICY_INFORMATION_CLASS  InformationClass,
                                        PVOID                     *Buffer);

BOOLEAN wrap_AuditLookupCategoryGuidFromCategoryId(POLICY_AUDIT_EVENT_TYPE AuditCategoryId,
                                                   GUID                    *pAuditCategoryGuid);

BOOLEAN wrap_AuditEnumerateSubCategories(const GUID *pAuditCategoryGuid,
                                         BOOLEAN    bRetrieveAllSubCategories,
                                         GUID       **ppAuditSubCategoriesArray,
                                         PULONG     pdwCountReturned);

BOOLEAN wrap_AuditQuerySystemPolicy(const GUID                *pSubCategoryGuids,
                                    ULONG                     dwPolicyCount,
                                    PAUDIT_POLICY_INFORMATION *ppAuditPolicy);

NTSTATUS wrap_LsaFreeMemory(PVOID Buffer);

NTSTATUS wrap_LsaClose(LSA_HANDLE ObjectHandle);


#endif
