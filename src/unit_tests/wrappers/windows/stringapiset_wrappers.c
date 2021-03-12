/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "stringapiset_wrappers.h"
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

int wrap_WideCharToMultiByte(__UNUSED_PARAM(UINT CodePage),
                             __UNUSED_PARAM(DWORD dwFlags),
                             LPCWCH lpWideCharStr,
                             int cchWideChar,
                             LPSTR lpMultiByteStr,
                             int cbMultiByte,
                             __UNUSED_PARAM(LPCCH lpDefaultChar),
                             __UNUSED_PARAM(LPBOOL lpUsedDefaultChar)) {
    check_expected(lpWideCharStr);
    check_expected(cchWideChar);

    if(lpMultiByteStr)
        strncpy(lpMultiByteStr, mock_type(char*), cbMultiByte);

    return mock();
}
