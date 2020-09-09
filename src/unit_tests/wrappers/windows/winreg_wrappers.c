/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "winreg_wrappers.h"
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

LONG wrap_RegQueryInfoKey(__UNUSED_PARAM(HKEY hKey),
                          LPSTR lpClass,
                          LPDWORD lpcchClass,
                          __UNUSED_PARAM(LPDWORD lpReserved),
                          LPDWORD lpcSubKeys,
                          __UNUSED_PARAM(LPDWORD lpcbMaxSubKeyLen),
                          __UNUSED_PARAM(LPDWORD lpcbMaxClassLen),
                          LPDWORD lpcValues,
                          __UNUSED_PARAM(LPDWORD lpcbMaxValueNameLen),
                          __UNUSED_PARAM(LPDWORD lpcbMaxValueLen),
                          __UNUSED_PARAM(LPDWORD lpcbSecurityDescriptor),
                          PFILETIME lpftLastWriteTime) {
    PFILETIME mock_file_time;
    *lpClass = mock_type(CHAR);
    *lpcchClass = mock_type(DWORD);
    *lpcSubKeys = mock_type(long);
    *lpcValues = mock_type(long);
    mock_file_time = mock_type(PFILETIME);
    lpftLastWriteTime->dwLowDateTime = mock_file_time->dwLowDateTime;
    lpftLastWriteTime->dwHighDateTime = mock_file_time->dwHighDateTime;
    return mock();
}

LONG wrap_RegEnumKeyEx(__UNUSED_PARAM(HKEY hKey),
                       __UNUSED_PARAM(DWORD dwIndex),
                       LPSTR lpName,
                       LPDWORD lpcchName,
                       __UNUSED_PARAM(LPDWORD lpReserved),
                       __UNUSED_PARAM(LPSTR lpClass),
                       __UNUSED_PARAM(LPDWORD lpcchClass),
                       __UNUSED_PARAM(PFILETIME lpftLastWriteTime)) {
    strcpy(lpName, mock_ptr_type(char *));
    *lpcchName = mock_type(long);
    return mock();
}

LONG wrap_RegOpenKeyEx(HKEY hKey,
                       LPCSTR lpSubKey,
                       DWORD ulOptions,
                       REGSAM samDesired,
                       PHKEY phkResult) {
    PHKEY key;
    check_expected(hKey);
    check_expected(lpSubKey);
    check_expected(ulOptions);
    check_expected(samDesired);
    if(key = mock_type(PHKEY), key) {
        memcpy(phkResult, key, sizeof(HKEY));
    }
    return mock();
}

LONG wrap_RegEnumValue(__UNUSED_PARAM(HKEY hKey),
                       __UNUSED_PARAM(DWORD dwIndex),
                       LPSTR lpValueName,
                       LPDWORD lpcchValueName,
                       __UNUSED_PARAM(LPDWORD lpReserved),
                       LPDWORD lpType,
                       LPBYTE lpData,
                       LPDWORD lpcbData) {
    strcpy(lpValueName, mock_ptr_type(char *));
    *lpcchValueName = mock_type(long);
    *lpType = mock_type(long);
    *lpcbData = mock_type(long);
    const void *data = mock_ptr_type(void *);
    memcpy(lpData, data, sizeof(char) * (*lpcbData));
    return mock();
}

LONG wrap_RegCloseKey(__UNUSED_PARAM(HKEY hKey)) {
    return 0;
}

LONG wrap_RegQueryValueEx(__UNUSED_PARAM(HKEY hKey),
                          LPCSTR lpValueName,
                          LPDWORD lpReserved,
                          LPDWORD lpType,
                          LPBYTE lpData,
                          LPDWORD lpcbData) {
    LPBYTE data;
    check_expected(lpValueName);
    check_expected(lpReserved);
    check_expected(lpType);
    if(data = mock_type(LPBYTE), data) {
        memcpy(lpData, data, *lpcbData);
    }
    return mock();
}
