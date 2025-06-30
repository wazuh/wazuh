/*
 * Shared functions for Syscheck events decoding
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef UTF8_WINAPI_WRAPPER_H
#define UTF8_WINAPI_WRAPPER_H

#ifdef WIN32

#include <shared.h>

// clang-format off
#include <aclapi.h>
#include <winnt.h>
#include <wchar.h>
#include <stdbool.h>
// clang-format on

/// Convert utf8 to wide string
wchar_t* utf8_to_wide(const char* input);

/// Convert wide string to utf8
char *wide_to_utf8(const wchar_t *input);

/// Stat a file with utf8 path
int utf8_stat64(const char * pathname, struct _stat64 * statbuf);

/// Create a file with utf8 path
HANDLE utf8_CreateFile(const char* utf8_path,
                       DWORD access,
                       DWORD share,
                       LPSECURITY_ATTRIBUTES sa,
                       DWORD creation,
                       DWORD flags,
                       HANDLE h_template);

/// Get file attributes
DWORD utf8_GetFileAttributes(const char* utf8_path);

/// Get file security
BOOL utf8_GetFileSecurity(
    const char* utf8_path, SECURITY_INFORMATION si, PSECURITY_DESCRIPTOR psd, DWORD len, LPDWORD needed);

/// Get named file security
DWORD utf8_GetNamedSecurityInfo(const char* utf8_path,
                                SE_OBJECT_TYPE obj_type,
                                SECURITY_INFORMATION si,
                                PSID* owner,
                                PSID* group,
                                PACL* dacl,
                                PACL* sacl,
                                PSECURITY_DESCRIPTOR* psd);

/// Set named file security
DWORD utf8_SetNamedSecurityInfo(const char* utf8_path,
                                SE_OBJECT_TYPE obj_type,
                                SECURITY_INFORMATION si,
                                PSID owner,
                                PSID group,
                                PACL dacl,
                                PACL sacl);

#endif

#endif // UTF8_WINAPI_WRAPPER_H
