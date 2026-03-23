/* Copyright (C) 2015, Wazuh Inc.
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
#include <stdio.h>
#include "../common.h"

HANDLE wrap_CreateFile(LPCSTR lpFileName,
                       DWORD dwDesiredAccess,
                       DWORD dwShareMode,
                       LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                       DWORD dwCreationDisposition,
                       DWORD dwFlagsAndAttributes,
                       HANDLE hTemplateFile) {
    if (test_mode) {
        check_expected(lpFileName);
        return mock_type(HANDLE);
    } else {
        return CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    }
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

DWORD wrap_QueryDosDeviceA(LPCSTR lpDeviceName,
                           LPSTR lpTargetPath,
                           DWORD ucchMax) {
    // Provide default behavior without requiring explicit mocks in every test
    // Z:, Y:, X: return network paths (typical test scenario)
    // C:, D: and others return local paths
    // This allows is_network_path() to work correctly in tests without setup overhead

    if (lpDeviceName && strlen(lpDeviceName) >= 2 && lpDeviceName[1] == ':') {
        char drive = toupper(lpDeviceName[0]);
        const char *device_path;

        // Provide realistic default device paths
        // For typical network drive letters, return network paths so tests work
        switch (drive) {
            case 'Z':
                // Z: is commonly used for network drives in tests
                device_path = "\\Device\\LanmanRedirector\\server\\share";
                break;
            case 'Y':
            case 'X':
                // Also common network drive letters
                device_path = "\\Device\\Mup\\server\\share";
                break;
            case 'D':
                device_path = "\\Device\\HarddiskVolume2";
                break;
            case 'C':
            default:
                device_path = "\\Device\\HarddiskVolume1";
                break;
        }

        size_t len = strlen(device_path);
        if (len < ucchMax) {
            strncpy(lpTargetPath, device_path, ucchMax);
            lpTargetPath[ucchMax - 1] = '\0';
            return (DWORD)len;
        }
    }

    return 0;
}

WINBOOL wrap_FindNextVolumeW(HANDLE hFindVolume,
                             LPWSTR lpszVolumeName,
                             DWORD cchBufferLength) {
    check_expected(hFindVolume);
    wcsncpy(lpszVolumeName, mock_type(LPWSTR), cchBufferLength);
    return mock();
}

BOOL wrap_GetFileTime(HANDLE     hFile,
                      LPFILETIME lpCreationTime,
                      LPFILETIME lpLastAccessTime,
                      LPFILETIME lpLastWriteTime) {
    LPFILETIME lpft;

    check_expected(hFile);
    if (lpCreationTime){
        lpft = mock_type(LPFILETIME);
        lpCreationTime->dwLowDateTime = lpft->dwLowDateTime;
        lpCreationTime->dwHighDateTime = lpft->dwHighDateTime;
    }
    if (lpLastAccessTime){
        lpft = mock_type(LPFILETIME);
        lpLastAccessTime->dwLowDateTime = lpft->dwLowDateTime;
        lpLastAccessTime->dwHighDateTime = lpft->dwHighDateTime;
    }
    if (lpLastWriteTime){
        lpft = mock_type(LPFILETIME);
        lpLastWriteTime->dwLowDateTime = lpft->dwLowDateTime;
        lpLastWriteTime->dwHighDateTime = lpft->dwHighDateTime;
    }
    return mock_type(BOOL);
}

HANDLE wrap_FindFirstFile(LPCWSTR lpFileName,  LPWIN32_FIND_DATAW lpFindFileData) {
    char *file_name;
    check_expected(lpFileName);

    file_name = mock_type(char *);
    if (file_name != NULL) {
        mbstowcs(lpFindFileData->cFileName, file_name, MAX_PATH);
        lpFindFileData->dwFileAttributes = mock_type(DWORD);
    }

    return mock_type(HANDLE);
}

BOOL wrap_FindNextFile(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData) {
    char *file_name;
    check_expected(hFindFile);
    file_name = mock_type(char *);
    if (file_name != NULL) {
        mbstowcs(lpFindFileData->cFileName, file_name, MAX_PATH);
        lpFindFileData->dwFileAttributes = mock_type(DWORD);
    }
    return mock_type(BOOL);
}

UINT wrap_GetDriveTypeA(LPCSTR lpRootPathName) {
    if (lpRootPathName == NULL) {
        // If this parameter is NULL, the function uses the root of the current directory.
        return DRIVE_FIXED;
    }

    if (strlen(lpRootPathName) == 3 && lpRootPathName[1] == ':' && lpRootPathName[2] == '\\') {
        switch (lpRootPathName[0]) {
            case 'A':
                return DRIVE_REMOVABLE;
            case 'C':
                return DRIVE_FIXED;
            case 'D':
                return DRIVE_CDROM;
            case 'R':
                return DRIVE_RAMDISK;
            case 'Z':
                return DRIVE_REMOTE;
            default:
                return DRIVE_UNKNOWN;
        }
    }

    return DRIVE_NO_ROOT_DIR;
}
