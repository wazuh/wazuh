/*
 * Cryptography windows helper.
 * Copyright (C) 2015, Wazuh Inc.
 * November 16, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "cryptography.h"

#ifdef WIN32
#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>

DWORD verify_pe_signature(const wchar_t *path)
{
    // Get full path if path is a relative path.
    // This is needed because WinVerifyTrust only accepts full paths.
    // If path is already a full path, GetFullPathName will return the same path.

    wchar_t full_path[MAX_PATH];
    if (!GetFullPathNameW(path, MAX_PATH, full_path, NULL)) {
        merror("GetFullPathNameW failed with error %lu", GetLastError());
        return ERROR_INVALID_DATA;
    }

    DWORD last_error = ERROR_SUCCESS;
    WINTRUST_DATA WinTrustData;
    WINTRUST_FILE_INFO WinTrustFileInfo;
    GUID policy_GUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WinTrustFileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    WinTrustFileInfo.pcwszFilePath = full_path;
    WinTrustFileInfo.hFile = NULL;
    WinTrustFileInfo.pgKnownSubject = NULL;

    WinTrustData.cbStruct = sizeof(WINTRUST_DATA);
    WinTrustData.pPolicyCallbackData = NULL;
    WinTrustData.pSIPClientData = NULL;
    WinTrustData.dwUIChoice = WTD_UI_NONE;
    WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    WinTrustData.hWVTStateData = NULL;
    WinTrustData.pwszURLReference = NULL;
    WinTrustData.dwUIContext = 0;
    WinTrustData.pFile = &WinTrustFileInfo;

    DWORD status = WinVerifyTrust(NULL, &policy_GUID, &WinTrustData);

    switch (status) {
    case ERROR_SUCCESS:
        mdebug1("PE signature verification succeeded for %S", full_path);
        return ERROR_SUCCESS;
    case TRUST_E_NOSIGNATURE:
        mdebug2("No signature found for '%S'.", full_path);
        return ERROR_INVALID_DATA;
    case TRUST_E_SUBJECT_FORM_UNKNOWN:
        merror("The file '%S' is not of a recognized format.", full_path);
        return ERROR_INVALID_DATA;
    case TRUST_E_PROVIDER_UNKNOWN:
        merror("No provider found for the specified action.");
        last_error = GetLastError();
        return ERROR_INVALID_DATA;
    case TRUST_E_SUBJECT_NOT_TRUSTED:
        merror("The signature is not valid for file '%S'.", full_path);
        last_error = GetLastError();
        return ERROR_INVALID_DATA;
    default:
        last_error = GetLastError();
        merror("WinVerifyTrust returned %lX GetLastError returned %lX", status, last_error);
        return ERROR_INVALID_DATA;
    }
}

DWORD get_file_hash(const wchar_t *path, BYTE **hash, DWORD *hash_size)
{
    DWORD result = ERROR_SUCCESS;

    // Get full path if path is a relative path.
    // This is needed because CryptCATAdminCalcHashFromFileHandle only accepts full paths.
    // If path is already a full path, GetFullPathName will return the same path.
    wchar_t full_path[MAX_PATH];

    if (GetFullPathNameW(path, MAX_PATH, full_path, NULL)) {
        // Open file for hash calculation.
        HANDLE handle_file = CreateFileW(full_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

        if (handle_file != INVALID_HANDLE_VALUE) {

            // Calculate hash of the file.
            if (CryptCATAdminCalcHashFromFileHandle(handle_file, hash_size, NULL, 0)) {

                if (*hash_size == 0) {
                    result = ERROR_INVALID_DATA;
                    merror("CryptCATAdminCalcHashFromFileHandle failed with error %lu", GetLastError());
                } else {
                    os_calloc(1, *hash_size, *hash);

                    if (!CryptCATAdminCalcHashFromFileHandle(handle_file, hash_size, *hash, 0)) {
                        result = GetLastError();
                        merror("CryptCATAdminCalcHashFromFileHandle failed with error %lu", result);
                        os_free(*hash);
                    }
                }
            }
        } else {
            result = ERROR_FILE_NOT_FOUND;
            mdebug2("CreateFileW failed with error %lu path %S", GetLastError(), path);
        }
        // Close file handle.
        CloseHandle(handle_file);

    } else {
        result = ERROR_INVALID_DATA;
        merror("GetFullPathNameW failed with error %lu", GetLastError());
    }

    return result;
}

DWORD verify_hash_catalog(wchar_t *file_path)
{
    HCATADMIN catalog_administrator = NULL;
    HCATINFO catalog_context = NULL;
    GUID policy_GUID = DRIVER_ACTION_VERIFY;
    BYTE *hash = NULL;
    DWORD hash_size = 0;
    DWORD result = get_file_hash(file_path, &hash, &hash_size);

    if (ERROR_SUCCESS == result) {
        if (CryptCATAdminAcquireContext(&catalog_administrator, &policy_GUID, 0)) {
            // Search for the catalog file.
            // If the file is not signed, the function returns NULL.
            // If the file is signed, the function returns a handle to the catalog file.

            if (catalog_context = CryptCATAdminEnumCatalogFromHash(catalog_administrator, hash, hash_size, 0, NULL), catalog_context) {
                CryptCATAdminReleaseCatalogContext(catalog_administrator, catalog_context, 0);
            } else {
                result = ERROR_INVALID_DATA;
            }
            CryptCATAdminReleaseContext(catalog_administrator, 0);
        } else {
            result = GetLastError();
            merror("CryptCATAdminAcquireContext failed with error %lu", result);
        }
        os_free(hash);
    }
    return result;
}

#endif /* WIN32 */


