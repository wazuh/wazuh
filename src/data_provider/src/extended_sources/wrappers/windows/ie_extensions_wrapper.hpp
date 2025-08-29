/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include "iie_extensions_wrapper.hpp"

class IEExtensionsWrapper : public IIEExtensionsWrapper
{
    public:
        LSTATUS RegCloseKeyWrapper(HKEY hKey)
        {
            return RegCloseKey(hKey);
        }

        LSTATUS RegEnumValueAWrapper(
            HKEY    hKey,
            DWORD   dwIndex,
            LPSTR   lpValueName,
            LPDWORD lpcchValueName,
            LPDWORD lpReserved,
            LPDWORD lpType,
            LPBYTE  lpData,
            LPDWORD lpcbData
        ) override
        {
            return RegEnumValueA(hKey, dwIndex, lpValueName, lpcchValueName,
                                 lpReserved, lpType, lpData, lpcbData);
        }

        LSTATUS RegQueryValueExAWrapper(
            HKEY    hKey,
            LPCSTR  lpValueName,
            LPDWORD lpReserved,
            LPDWORD lpType,
            LPBYTE  lpData,
            LPDWORD lpcbData
        ) override
        {
            return RegQueryValueExA(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
        }

        LSTATUS RegOpenKeyExAWrapper(
            HKEY   hKey,
            LPCSTR lpSubKey,
            DWORD  ulOptions,
            REGSAM samDesired,
            PHKEY  phkResult
        ) override
        {
            return RegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired, phkResult);
        }

        LSTATUS RegEnumKeyExAWrapper(
            HKEY      hKey,
            DWORD     dwIndex,
            LPSTR     lpName,
            LPDWORD   lpcchName,
            LPDWORD   lpReserved,
            LPSTR     lpClass,
            LPDWORD   lpcchClass,
            PFILETIME lpftLastWriteTime
        ) override
        {
            return RegEnumKeyExA(hKey, dwIndex, lpName, lpcchName, lpReserved, lpClass, lpcchClass, lpftLastWriteTime);
        }

        DWORD GetFileVersionInfoSizeWWrapper(
            LPCWSTR lptstrFilename,
            LPDWORD lpdwHandle
        ) override
        {
            return ::GetFileVersionInfoSizeW(lptstrFilename, lpdwHandle);
        }

        BOOL GetFileVersionInfoWWrapper(
            LPCWSTR lptstrFilename,
            DWORD   dwHandle,
            DWORD   dwLen,
            LPVOID  lpData
        ) override
        {
            return ::GetFileVersionInfoW(lptstrFilename, dwHandle, dwLen, lpData);
        }

        BOOL VerQueryValueWWrapper(
            LPCVOID pBlock,
            LPCWSTR lpSubBlock,
            LPVOID*  lplpBuffer,
            PUINT   puLen
        ) override
        {
            return ::VerQueryValueW(pBlock, lpSubBlock, lplpBuffer, puLen);
        }
};
