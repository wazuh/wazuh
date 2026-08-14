/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef UTF8_WINAPI_WRAPPER_WRAPPERS_H
#define UTF8_WINAPI_WRAPPER_WRAPPERS_H

#ifdef WIN32

#include "utf8_winapi_wrapper.h"

int __wrap_utf8_stat64(const char* pathname, struct _stat64* statbuf);

HANDLE __wrap_utf8_CreateFile(const char* utf8_path,
                              DWORD access,
                              DWORD share,
                              LPSECURITY_ATTRIBUTES sa,
                              DWORD creation,
                              DWORD flags,
                              HANDLE h_template);

DWORD __wrap_utf8_GetFileAttributes(const char* utf8_path);

char* __wrap_utf8_GetShortPathName(const char* utf8_path);

BOOL __wrap_utf8_GetFileSecurity(
    const char* utf8_path, SECURITY_INFORMATION si, PSECURITY_DESCRIPTOR psd, DWORD len, LPDWORD needed);

DWORD __wrap_utf8_GetNamedSecurityInfo(const char* utf8_path,
                                       SE_OBJECT_TYPE obj_type,
                                       SECURITY_INFORMATION si,
                                       PSID* owner,
                                       PSID* group,
                                       PACL* dacl,
                                       PACL* sacl,
                                       PSECURITY_DESCRIPTOR* psd);

DWORD __wrap_utf8_SetNamedSecurityInfo(const char* utf8_path,
                                       SE_OBJECT_TYPE obj_type,
                                       SECURITY_INFORMATION si,
                                       PSID owner,
                                       PSID group,
                                       PACL dacl,
                                       PACL sacl);

BOOL __wrap_utf8_LookupAccountSid(LPCSTR lpSystemName,
                                  PSID lpSid,
                                  char **lpName,
                                  LPDWORD cchName,
                                  char **lpReferencedDomainName,
                                  LPDWORD cchReferencedDomainName,
                                  PSID_NAME_USE peUse);

void expect_utf8_LookupAccountSid_call(char *name, char *domain_name, int ret_value);

#endif

#endif
