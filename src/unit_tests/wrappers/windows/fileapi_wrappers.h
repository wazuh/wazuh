/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef FILEAPI_WRAPPERS_H
#define FILEAPI_WRAPPERS_H

#include <windows.h>

#define FindFirstVolumeW wrap_FindFirstVolumeW
#define GetVolumePathNamesForVolumeNameW wrap_GetVolumePathNamesForVolumeNameW
#define FindVolumeClose wrap_FindVolumeClose
#define QueryDosDeviceW wrap_QueryDosDeviceW
#define FindNextVolumeW wrap_FindNextVolumeW
#undef  CreateFile
#define CreateFile      wrap_CreateFile
#define GetFileAttributesA wrap_GetFileAttributesA

HANDLE wrap_CreateFile(LPCSTR lpFileName,
                       DWORD dwDesiredAccess,
                       DWORD dwShareMode,
                       LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                       DWORD dwCreationDisposition,
                       DWORD dwFlagsAndAttributes,
                       HANDLE hTemplateFile);

DWORD wrap_GetFileAttributesA(LPCSTR lpFileName);

WINBOOL wrap_GetVolumePathNamesForVolumeNameW(LPCWSTR lpszVolumeName,
                                              LPWCH lpszVolumePathNames,
                                              DWORD cchBufferLength,
                                              PDWORD lpcchReturnLength);

HANDLE wrap_FindFirstVolumeW(LPWSTR lpszVolumeName,
                             DWORD cchBufferLength);

WINBOOL wrap_FindVolumeClose(HANDLE hFindVolume);

DWORD wrap_QueryDosDeviceW(LPCWSTR lpDeviceName,
                           LPWSTR lpTargetPath,
                           DWORD ucchMax);

WINBOOL wrap_FindNextVolumeW(HANDLE hFindVolume,
                             LPWSTR lpszVolumeName,
                             DWORD cchBufferLength);

#endif
