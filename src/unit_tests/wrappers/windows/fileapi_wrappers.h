/* Copyright (C) 2015, Wazuh Inc.
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
#undef  GetFileTime
#define GetFileTime      wrap_GetFileTime
#define GetFileAttributesA wrap_GetFileAttributesA
#undef FindFirstFileW
#define FindFirstFileW wrap_FindFirstFile
#undef FindNextFileW
#define FindNextFileW wrap_FindNextFile
#undef GetDriveTypeA
#define GetDriveTypeA wrap_GetDriveTypeA

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

BOOL wrap_GetFileTime(HANDLE     hFile,
                      LPFILETIME lpCreationTime,
                      LPFILETIME lpLastAccessTime,
                      LPFILETIME lpLastWriteTime);

HANDLE wrap_FindFirstFile(LPCWSTR lpFileName,  LPWIN32_FIND_DATAW lpFindFileData);

BOOL wrap_FindNextFile(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData);

UINT wrap_GetDriveTypeA(LPCSTR lpRootPathName);

#endif
