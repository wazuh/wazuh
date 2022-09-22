/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "win-registry.h"
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

LONG WINAPI wrap_RegQueryInfoKey(
    __attribute__ ((unused)) HKEY hKey,
    __attribute__ ((unused)) LPSTR lpClass,
    __attribute__ ((unused)) LPDWORD lpcchClass,
    __attribute__ ((unused)) LPDWORD lpReserved,
    LPDWORD lpcSubKeys,
    __attribute__ ((unused)) LPDWORD lpcbMaxSubKeyLen,
    __attribute__ ((unused)) LPDWORD lpcbMaxClassLen,
    LPDWORD lpcValues,
    __attribute__ ((unused)) LPDWORD lpcbMaxValueNameLen,
    __attribute__ ((unused)) LPDWORD lpcbMaxValueLen,
    __attribute__ ((unused)) LPDWORD lpcbSecurityDescriptor,
    __attribute__ ((unused)) PFILETIME lpftLastWriteTime)
{
    lpClass = mock_type(char *);
    lpcchClass = mock_type(unsigned long *);
    *lpcSubKeys = mock_type(long);
    *lpcValues = mock_type(long);
    lpftLastWriteTime = mock_type(PFILETIME);
    return mock();
}

LONG WINAPI wrap_RegEnumKeyEx(
    __attribute__ ((unused)) HKEY hKey,
    __attribute__ ((unused)) DWORD dwIndex,
    LPSTR lpName,
    LPDWORD lpcchName,
    __attribute__ ((unused)) LPDWORD lpReserved,
    __attribute__ ((unused)) LPSTR lpClass,
    __attribute__ ((unused)) LPDWORD lpcchClass,
    __attribute__ ((unused)) PFILETIME lpftLastWriteTime)
{
    strcpy(lpName, mock_ptr_type(char *));
    *lpcchName = mock_type(long);
    return mock();
}

LONG WINAPI wrap_RegOpenKeyEx(
    __attribute__ ((unused)) HKEY hKey,
    __attribute__ ((unused)) LPCSTR lpSubKey,
    __attribute__ ((unused)) DWORD ulOptions,
    __attribute__ ((unused)) REGSAM samDesired,
    __attribute__ ((unused))PHKEY phkResult)
{
    return mock();
}

LONG WINAPI wrap_RegEnumValue(
    __attribute__ ((unused)) HKEY hKey,
    __attribute__ ((unused)) DWORD dwIndex,
    LPSTR lpValueName,
    LPDWORD lpcchValueName,
    __attribute__ ((unused)) LPDWORD lpReserved,
    __attribute__ ((unused)) LPDWORD lpType,
    __attribute__ ((unused)) LPBYTE lpData,
    LPDWORD lpcbData)
{
    strcpy(lpValueName, mock_ptr_type(char *));
    *lpcchValueName = mock_type(long);
    *lpType = mock_type(long);
    *lpcbData = mock_type(long);
    const void *data = mock_ptr_type(void *);
    memcpy(lpData, data, sizeof(char) * (*lpcbData));
    return mock();
}

LONG WINAPI wrap_RegCloseKey(__attribute__ ((unused)) HKEY hKey) {
    return 0;
}