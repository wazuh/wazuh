/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "wincrypt_wrappers.h"
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <wchar.h>
#include <softpub.h>
#include <cmocka.h>

HCERTSTORE wrap_CertOpenSystemStore(__UNUSED_PARAM(HCRYPTPROV_LEGACY hProv), LPCSTR szSubsystemProtocol) {
    check_expected(szSubsystemProtocol);
    return mock_type(HCERTSTORE);
}

PCCERT_CONTEXT wrap_CertEnumCertificatesInStore(__UNUSED_PARAM(HCERTSTORE hCertStore),
                                                __UNUSED_PARAM(PCCERT_CONTEXT pPrevCertContext)) {
    return mock_type(PCCERT_CONTEXT);
}

DWORD wrap_CertGetNameString(__UNUSED_PARAM(PCCERT_CONTEXT pCertContext),
                             __UNUSED_PARAM(DWORD dwType),
                             __UNUSED_PARAM(DWORD dwFlags),
                             __UNUSED_PARAM(void *pvTypePara),
                             LPSTR pszNameString,
                             DWORD cchNameString) {
    const char *name = mock_type(const char *);
    DWORD size = strlen(name) + 1;

    if (pszNameString && cchNameString >= size) {
        memcpy(pszNameString, name, size);
    }
    return size;
}

void expect_CertGetNameString_call(const char *name) {
    will_return(wrap_CertGetNameString, name);
    will_return(wrap_CertGetNameString, name);
}

BOOL wrap_CertCloseStore(__UNUSED_PARAM(HCERTSTORE hCertStore), __UNUSED_PARAM(DWORD dwFlags)) {
    return mock_type(BOOL);
}

BOOL wrap_CertFreeCertificateContext(PCCERT_CONTEXT pCertContext) {
    check_expected_ptr(pCertContext);
    return TRUE;
}

LONG wrap_WinVerifyTrust(__UNUSED_PARAM(HWND hwnd), __UNUSED_PARAM(GUID *pgActionID), LPVOID pWVTData) {
    WINTRUST_DATA *data = (WINTRUST_DATA *)pWVTData;

    if (data->dwStateAction == WTD_STATEACTION_CLOSE) {
        return ERROR_SUCCESS;
    }

    const wchar_t *file_path = data->pFile->pcwszFilePath;
    check_expected(file_path);
    return mock_type(LONG);
}

void expect_WinVerifyTrust_call(const wchar_t *file_path, LONG result) {
    expect_memory(wrap_WinVerifyTrust, file_path, file_path, (wcslen(file_path) + 1) * sizeof(wchar_t));
    will_return(wrap_WinVerifyTrust, result);
}

DWORD wrap_GetModuleFileNameW(__UNUSED_PARAM(HMODULE hModule), LPWSTR lpFilename, DWORD nSize) {
    const wchar_t *path = mock_type(const wchar_t *);
    DWORD length = mock_type(DWORD);

    if (length) {
        wcsncpy(lpFilename, path, nSize);
    }
    return length;
}
