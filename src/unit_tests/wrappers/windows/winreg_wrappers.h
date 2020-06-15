
/*
 * Copyright (C) 2015-2020, Wazuh Inc.
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
#undef RegEnumKeyEx
#define RegEnumKeyEx wrap_RegEnumKeyEx
#undef RegOpenKeyEx
#define RegOpenKeyEx wrap_RegOpenKeyEx
#undef RegEnumValue
#define RegEnumValue wrap_RegEnumValue
#undef RegCloseKey
#define RegCloseKey wrap_RegCloseKey
#undef RegQueryValueEx
#define RegQueryValueEx wrap_RegQueryValueEx

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

LONG wrap_RegEnumKeyEx(HKEY hKey,
                       DWORD dwIndex,
                       LPSTR lpName,
                       LPDWORD lpcchName,
                       LPDWORD lpReserved,
                       LPSTR lpClass,
                       LPDWORD lpcchClass,
                       PFILETIME lpftLastWriteTime);

LONG wrap_RegOpenKeyEx(HKEY hKey,
                       LPCSTR lpSubKey,
                       DWORD ulOptions,
                       REGSAM samDesired,
                       PHKEY phkResult);

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

LONG wrap_RegCloseKey(HKEY hKey);

#endif
