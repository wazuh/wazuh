/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <windows.h>
#include <vector>

class IIEExtensionsWrapper
{
    public:
        /// Destructor
        virtual ~IIEExtensionsWrapper() = default;

        virtual LSTATUS RegCloseKeyWrapper(HKEY hKey) = 0;

        virtual LSTATUS RegEnumValueAWrapper(
            HKEY    hKey,           // Handle to an open registry key
            DWORD   dwIndex,        // Index of the value to retrieve (0-based)
            LPSTR   lpValueName,    // Buffer for value name
            LPDWORD lpcchValueName, // Size of value name buffer (in/out)
            LPDWORD lpReserved,     // Reserved, must be NULL
            LPDWORD lpType,         // Pointer to variable that receives value type
            LPBYTE  lpData,         // Buffer for value data (can be NULL)
            LPDWORD lpcbData        // Size of data buffer (in/out, can be NULL)
        ) = 0;

        virtual LSTATUS RegQueryValueExAWrapper(
            HKEY    hKey,           // Handle to an open registry key
            LPCSTR  lpValueName,    // Name of the value to query
            LPDWORD lpReserved,     // Reserved, must be NULL
            LPDWORD lpType,         // Pointer to variable that receives value type
            LPBYTE  lpData,         // Buffer for value data (can be NULL)
            LPDWORD lpcbData        // Size of data buffer (in/out, can be NULL)
        ) = 0;

        virtual LSTATUS RegOpenKeyExAWrapper(
            HKEY   hKey,            // Handle to an open registry key
            LPCSTR lpSubKey,        // Name of the subkey to open
            DWORD  ulOptions,       // Reserved, must be 0
            REGSAM samDesired,      // Security access mask
            PHKEY  phkResult        // Pointer to variable that receives handle
        ) = 0;

        virtual LSTATUS RegEnumKeyExAWrapper(
            HKEY      hKey,               // Handle to an open registry key
            DWORD     dwIndex,            // Index of the subkey to retrieve (0-based)
            LPSTR     lpName,             // Buffer for subkey name
            LPDWORD   lpcchName,          // Size of subkey name buffer (in/out)
            LPDWORD   lpReserved,         // Reserved, must be NULL
            LPSTR     lpClass,            // Buffer for class string (can be NULL)
            LPDWORD   lpcchClass,         // Size of class buffer (in/out, can be NULL)
            PFILETIME lpftLastWriteTime   // Pointer to last write time (can be NULL)
        ) = 0;

        virtual DWORD GetFileVersionInfoSizeWWrapper(
            LPCWSTR lptstrFilename,   // Pointer to filename string
            LPDWORD lpdwHandle        // Pointer to variable to receive zero (unused)
        ) = 0;

        virtual BOOL GetFileVersionInfoWWrapper(
            LPCWSTR lptstrFilename,   // Pointer to filename string
            DWORD   dwHandle,         // Ignored, should be zero
            DWORD   dwLen,            // Length of buffer (from GetFileVersionInfoSizeW)
            LPVOID  lpData            // Pointer to buffer to receive version info
        ) = 0;

        virtual BOOL VerQueryValueWWrapper(
            LPCVOID pBlock,           // Address of buffer with version info
            LPCWSTR lpSubBlock,       // Address of value to retrieve
            LPVOID*  lplpBuffer,      // Address of buffer for version info pointer
            PUINT   puLen             // Address of version info length
        ) = 0;
};
