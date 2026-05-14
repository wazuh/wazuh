
/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WINREG_WRAPPERS_H
#define WINREG_WRAPPERS_H

#include <windows.h>

#undef RegQueryInfoKey
#define RegQueryInfoKey wrap_RegQueryInfoKey
#undef RegQueryInfoKeyA
#define RegQueryInfoKeyA wrap_RegQueryInfoKeyA
#undef RegEnumKeyEx
#define RegEnumKeyEx wrap_RegEnumKeyEx
#undef RegEnumKeyExW
#define RegEnumKeyExW wrap_RegEnumKeyExW
#undef RegOpenKeyEx
#define RegOpenKeyEx wrap_RegOpenKeyEx
#undef RegOpenKeyExW
#define RegOpenKeyExW wrap_RegOpenKeyExW
#undef RegEnumValue
#define RegEnumValue wrap_RegEnumValue
#undef RegEnumValueW
#define RegEnumValueW wrap_RegEnumValueW
#undef RegCloseKey
#define RegCloseKey wrap_RegCloseKey
#undef RegQueryValueEx
#define RegQueryValueEx wrap_RegQueryValueEx
#undef RegGetKeySecurity
#define RegGetKeySecurity wrap_RegGetKeySecurity

LONG wrap_RegQueryInfoKey(HKEY hKey,
                          LPSTR lpClass,
                          LPDWORD lpcchClass,
                          LPDWORD lpReserved,
                          LPDWORD lpcSubKeys,
                          LPDWORD lpcbMaxSubKeyLen,
                          LPDWORD lpcbMaxClassLen,
                          LPDWORD lpcValues,
                          LPDWORD lpcbMaxValueNameLen,
                          LPDWORD lpcbMaxValueLen,
                          LPDWORD lpcbSecurityDescriptor,
                          PFILETIME lpftLastWriteTime);

void expect_RegQueryInfoKey_call(DWORD sub_keys, DWORD values, PFILETIME last_write_time, LONG return_value);

LONG wrap_RegQueryInfoKeyA(HKEY hKey,
                          LPSTR lpClass,
                          LPDWORD lpcchClass,
                          LPDWORD lpReserved,
                          LPDWORD lpcSubKeys,
                          LPDWORD lpcbMaxSubKeyLen,
                          LPDWORD lpcbMaxClassLen,
                          LPDWORD lpcValues,
                          LPDWORD lpcbMaxValueNameLen,
                          LPDWORD lpcbMaxValueLen,
                          LPDWORD lpcbSecurityDescriptor,
                          PFILETIME lpftLastWriteTime);

void expect_RegQueryInfoKeyA_call(PFILETIME last_write_time, LONG return_value);

LONG wrap_RegEnumKeyEx(HKEY hKey,
                       DWORD dwIndex,
                       LPSTR lpName,
                       LPDWORD lpcchName,
                       LPDWORD lpReserved,
                       LPSTR lpClass,
                       LPDWORD lpcchClass,
                       PFILETIME lpftLastWriteTime);

void expect_RegEnumKeyEx_call(LPSTR name, DWORD name_length, LONG return_value);

LONG wrap_RegEnumKeyExW(HKEY hKey,
                       DWORD dwIndex,
                       LPWSTR lpName,
                       LPDWORD lpcchName,
                       LPDWORD lpReserved,
                       LPWSTR lpClass,
                       LPDWORD lpcchClass,
                       PFILETIME lpftLastWriteTime);

void expect_RegEnumKeyExW_call(const wchar_t *name, LONG return_value);

LONG wrap_RegOpenKeyEx(HKEY hKey,
                       LPCSTR lpSubKey,
                       DWORD ulOptions,
                       REGSAM samDesired,
                       PHKEY phkResult);

void expect_RegOpenKeyEx_call(HKEY hKey, LPCSTR sub_key, DWORD options, REGSAM sam, PHKEY result, LONG return_value);

LONG wrap_RegOpenKeyExW(HKEY hKey,
                       LPCWSTR lpSubKey,
                       DWORD ulOptions,
                       REGSAM samDesired,
                       PHKEY phkResult);

void expect_RegOpenKeyExW_call(HKEY hKey, LPCWSTR sub_key, DWORD options, REGSAM sam, PHKEY result, LONG return_value);

LONG wrap_RegQueryValueEx(HKEY hKey,
                          LPCSTR lpValueName,
                          LPDWORD lpReserved,
                          LPDWORD lpType,
                          LPBYTE lpData,
                          LPDWORD lpcbData);

LONG wrap_RegEnumValue(HKEY hKey,
                       DWORD dwIndex,
                       LPSTR lpValueName,
                       LPDWORD lpcchValueName,
                       LPDWORD lpReserved,
                       LPDWORD lpType,
                       LPBYTE lpData,LPDWORD lpcbData);

void expect_RegEnumValue_call(LPSTR value_name, DWORD type, LPBYTE data, DWORD data_length, LONG return_value);

LONG wrap_RegEnumValueW(HKEY hKey,
                       DWORD dwIndex,
                       LPWSTR lpValueName,
                       LPDWORD lpcchValueName,
                       LPDWORD lpReserved,
                       LPDWORD lpType,
                       LPBYTE lpData,LPDWORD lpcbData);

void expect_RegEnumValueW_call(LPWSTR value_name, DWORD type, LPBYTE data, DWORD data_length, LONG return_value);

LONG wrap_RegCloseKey(HKEY hKey);

WINBOOL wrap_RegGetKeySecurity(__UNUSED_PARAM(HKEY hKey),
                               __UNUSED_PARAM(SECURITY_INFORMATION SecurityInformation),
                               __UNUSED_PARAM(PSECURITY_DESCRIPTOR pSecurityDescriptor),
                               LPDWORD lpcbSecurityDescriptor);

void expect_RegGetKeySecurity_call(LPDWORD lpcbSecurityDescriptor, int ret_value);

#endif
