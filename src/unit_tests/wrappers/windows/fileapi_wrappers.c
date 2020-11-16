/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "fileapi_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

HANDLE wrap_CreateFile(LPCSTR lpFileName,
                       __UNUSED_PARAM(DWORD dwDesiredAccess),
                       __UNUSED_PARAM(DWORD dwShareMode),
                       __UNUSED_PARAM(LPSECURITY_ATTRIBUTES lpSecurityAttributes),
                       __UNUSED_PARAM(DWORD dwCreationDisposition),
                       __UNUSED_PARAM(DWORD dwFlagsAndAttributes),
                       __UNUSED_PARAM(HANDLE hTemplateFile)) {
    check_expected(lpFileName);
    return mock_type(HANDLE);
}

DWORD wrap_GetFileAttributesA(LPCSTR lpFileName) {
    check_expected(lpFileName);
    return mock();
}

WINBOOL wrap_GetVolumePathNamesForVolumeNameW(LPCWSTR lpszVolumeName,
                                              LPWCH lpszVolumePathNames,
                                              DWORD cchBufferLength,
                                              PDWORD lpcchReturnLength) {
    DWORD buffer_size;
    check_expected(lpszVolumeName);
    buffer_size = mock();

    if(lpszVolumePathNames && buffer_size <= cchBufferLength) {
        memcpy(lpszVolumePathNames, mock_type(LPWCH), cchBufferLength);
    }

    *lpcchReturnLength = buffer_size;
    return mock();
}

HANDLE wrap_FindFirstVolumeW(LPWSTR lpszVolumeName,
                             DWORD cchBufferLength) {
    wcsncpy(lpszVolumeName, mock_type(wchar_t*), cchBufferLength);
    return mock_type(HANDLE);
}

WINBOOL wrap_FindVolumeClose (HANDLE hFindVolume) {
    check_expected(hFindVolume);
    return mock();
}

DWORD wrap_QueryDosDeviceW(LPCWSTR lpDeviceName,
                           LPWSTR lpTargetPath,
                           DWORD ucchMax) {
    DWORD len = mock();
    check_expected(lpDeviceName);

    if(len <= ucchMax)
        memcpy(lpTargetPath, mock_type(LPWSTR), len);

    return mock();
}

WINBOOL wrap_FindNextVolumeW(HANDLE hFindVolume,
                             LPWSTR lpszVolumeName,
                             DWORD cchBufferLength) {
    check_expected(hFindVolume);
    wcsncpy(lpszVolumeName, mock_type(LPWSTR), cchBufferLength);
    return mock();
}
