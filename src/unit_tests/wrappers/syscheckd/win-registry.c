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

LONG WINAPI wrap_RegQueryInfoKey(HKEY hKey,LPSTR lpClass,LPDWORD lpcchClass,LPDWORD lpReserved,LPDWORD lpcSubKeys,LPDWORD lpcbMaxSubKeyLen,LPDWORD lpcbMaxClassLen,LPDWORD lpcValues,LPDWORD lpcbMaxValueNameLen,LPDWORD lpcbMaxValueLen,LPDWORD lpcbSecurityDescriptor,PFILETIME lpftLastWriteTime) 
{  
    lpClass = mock();
    lpcchClass = mock();
    *lpcSubKeys = mock_type(long);
    *lpcValues = mock_type(long);
    lpftLastWriteTime = mock();
    return mock();
}

LONG WINAPI wrap_RegEnumKeyEx(HKEY hKey,DWORD dwIndex,LPSTR lpName,LPDWORD lpcchName,LPDWORD lpReserved,LPSTR lpClass,LPDWORD lpcchClass,PFILETIME lpftLastWriteTime) {
    strcpy(lpName, mock_ptr_type(char *));
    *lpcchName = mock_type(long);
    return mock();
}

LONG WINAPI wrap_RegOpenKeyEx(HKEY hKey,LPCSTR lpSubKey,DWORD ulOptions,REGSAM samDesired,PHKEY phkResult) {
    return mock();
}

LONG WINAPI wrap_RegEnumValue(HKEY hKey,DWORD dwIndex,LPSTR lpValueName,LPDWORD lpcchValueName,LPDWORD lpReserved,LPDWORD lpType,LPBYTE lpData,LPDWORD lpcbData) {
    strcpy(lpValueName, mock_ptr_type(char *));
    *lpcchValueName = mock_type(long);
    *lpType = mock_type(long);
    *lpcbData = mock_type(long);
    const void *data = mock_ptr_type(void *);
    memcpy(lpData, data, sizeof(char) * (*lpcbData));
    return mock();
}  

LONG WINAPI wrap_RegCloseKey(HKEY hKey) {
    return 0;
}