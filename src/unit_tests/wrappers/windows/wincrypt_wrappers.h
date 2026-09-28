/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WINCRYPT_WRAPPERS_H
#define WINCRYPT_WRAPPERS_H

#include <windows.h>
#include <wincrypt.h>
#include <wintrust.h>

#undef CertOpenSystemStore
#define CertOpenSystemStore wrap_CertOpenSystemStore
#undef CertEnumCertificatesInStore
#define CertEnumCertificatesInStore wrap_CertEnumCertificatesInStore
#undef CertGetNameString
#define CertGetNameString wrap_CertGetNameString
#undef CertCloseStore
#define CertCloseStore wrap_CertCloseStore
#undef WinVerifyTrust
#define WinVerifyTrust wrap_WinVerifyTrust
#undef GetModuleFileNameW
#define GetModuleFileNameW wrap_GetModuleFileNameW

HCERTSTORE wrap_CertOpenSystemStore(HCRYPTPROV_LEGACY hProv, LPCSTR szSubsystemProtocol);

PCCERT_CONTEXT wrap_CertEnumCertificatesInStore(HCERTSTORE hCertStore, PCCERT_CONTEXT pPrevCertContext);

DWORD wrap_CertGetNameString(PCCERT_CONTEXT pCertContext,
                             DWORD dwType,
                             DWORD dwFlags,
                             void *pvTypePara,
                             LPSTR pszNameString,
                             DWORD cchNameString);

BOOL wrap_CertCloseStore(HCERTSTORE hCertStore, DWORD dwFlags);

LONG wrap_WinVerifyTrust(HWND hwnd, GUID *pgActionID, LPVOID pWVTData);

DWORD wrap_GetModuleFileNameW(HMODULE hModule, LPWSTR lpFilename, DWORD nSize);

void expect_CertGetNameString_call(const char *name);

void expect_WinVerifyTrust_call(const wchar_t *file_path, LONG result);

#endif
