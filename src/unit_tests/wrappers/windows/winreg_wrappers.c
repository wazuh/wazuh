/*
 * Copyright (C) 2015, Wazuh Inc.
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
                          __UNUSED_PARAM(LPSTR lpClass),
                          __UNUSED_PARAM(LPDWORD lpcchClass),
                          __UNUSED_PARAM(LPDWORD lpReserved),
                          LPDWORD lpcSubKeys,
                          __UNUSED_PARAM(LPDWORD lpcbMaxSubKeyLen),
                          __UNUSED_PARAM(LPDWORD lpcbMaxClassLen),
                          LPDWORD lpcValues,
                          LPDWORD lpcbMaxValueNameLen,
                          LPDWORD lpcbMaxValueLen,
                          __UNUSED_PARAM(LPDWORD lpcbSecurityDescriptor),
                          PFILETIME lpftLastWriteTime) {
    if (lpcSubKeys) *lpcSubKeys = mock_type(CHAR);
    if (lpcValues) *lpcValues = mock_type(DWORD);
    PFILETIME mock_file_time;
    *lpcbMaxValueNameLen = mock();
    *lpcbMaxValueLen = mock();
    mock_file_time = mock_type(PFILETIME);
    lpftLastWriteTime->dwLowDateTime = mock_file_time->dwLowDateTime;
    lpftLastWriteTime->dwHighDateTime = mock_file_time->dwHighDateTime;
    return mock();
}

void expect_RegQueryInfoKey_call(DWORD sub_keys, DWORD values, PFILETIME last_write_time, LONG return_value) {
    will_return(wrap_RegQueryInfoKey, sub_keys);
    will_return(wrap_RegQueryInfoKey, values);
    will_return(wrap_RegQueryInfoKey, 256);
    will_return(wrap_RegQueryInfoKey, 256);
    will_return(wrap_RegQueryInfoKey, last_write_time);
    will_return(wrap_RegQueryInfoKey, return_value);
}

LONG wrap_RegQueryInfoKeyA(__UNUSED_PARAM(HKEY hKey),
                          __UNUSED_PARAM(LPSTR lpClass),
                          __UNUSED_PARAM(LPDWORD lpcchClass),
                          __UNUSED_PARAM(LPDWORD lpReserved),
                          __UNUSED_PARAM(LPDWORD lpcSubKeys),
                          __UNUSED_PARAM(LPDWORD lpcbMaxSubKeyLen),
                          __UNUSED_PARAM(LPDWORD lpcbMaxClassLen),
                          __UNUSED_PARAM(LPDWORD lpcValues),
                          __UNUSED_PARAM(LPDWORD lpcbMaxValueNameLen),
                          __UNUSED_PARAM(LPDWORD lpcbMaxValueLen),
                          __UNUSED_PARAM(LPDWORD lpcbSecurityDescriptor),
                          PFILETIME lpftLastWriteTime) {
    PFILETIME mock_file_time;
    mock_file_time = mock_type(PFILETIME);
    lpftLastWriteTime->dwLowDateTime = mock_file_time->dwLowDateTime;
    lpftLastWriteTime->dwHighDateTime = mock_file_time->dwHighDateTime;
    return mock();
}

void expect_RegQueryInfoKeyA_call(PFILETIME last_write_time, LONG return_value) {
    will_return(wrap_RegQueryInfoKeyA, last_write_time);
    will_return(wrap_RegQueryInfoKeyA, return_value);
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

void expect_RegEnumKeyEx_call(LPSTR name, DWORD name_length, LONG return_value) {
    will_return(wrap_RegEnumKeyEx, name);
    will_return(wrap_RegEnumKeyEx, name_length);
    will_return(wrap_RegEnumKeyEx, return_value);
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

void expect_RegOpenKeyEx_call(HKEY hKey, LPCSTR sub_key, DWORD options, REGSAM sam, PHKEY result, LONG return_value) {
    expect_value(wrap_RegOpenKeyEx, hKey, hKey);
    expect_string(wrap_RegOpenKeyEx, lpSubKey, sub_key);
    expect_value(wrap_RegOpenKeyEx, ulOptions, options);
    expect_value(wrap_RegOpenKeyEx, samDesired, sam);
    will_return(wrap_RegOpenKeyEx, result);
    will_return(wrap_RegOpenKeyEx, return_value);
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

void expect_RegEnumValue_call(LPSTR value_name, DWORD type, LPBYTE data, DWORD data_length, LONG return_value) {
    will_return(wrap_RegEnumValue, value_name);
    will_return(wrap_RegEnumValue, strlen(value_name));
    will_return(wrap_RegEnumValue, type);
    will_return(wrap_RegEnumValue, data_length);
    will_return(wrap_RegEnumValue, data);
    will_return(wrap_RegEnumValue, return_value);
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

WINBOOL wrap_RegGetKeySecurity(__UNUSED_PARAM(HKEY hKey),
                               __UNUSED_PARAM(SECURITY_INFORMATION SecurityInformation),
                               __UNUSED_PARAM(PSECURITY_DESCRIPTOR pSecurityDescriptor),
                               LPDWORD lpcbSecurityDescriptor) {
    *lpcbSecurityDescriptor = mock();
    return mock();
}

void expect_RegGetKeySecurity_call(LPDWORD lpcbSecurityDescriptor, int ret_value) {
    will_return(wrap_RegGetKeySecurity, lpcbSecurityDescriptor);
    will_return(wrap_RegGetKeySecurity, ret_value);
}
