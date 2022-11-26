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
        break;
    case TRUST_E_NOSIGNATURE:
        last_error = GetLastError();

        if (0x800B0100 == last_error ||   // TRUST_E_NOSIGNATURE
            0x800B0003 == last_error ||   // TRUST_E_SUBJECT_FORM_UNKNOWN
            0x800B0001 == last_error) {   // TRUST_E_PROVIDER_UNKNOWN
            // The file was not signed.
            merror("No signature found for '%S'.", full_path);
        }
        else
        {
            // The signature was not valid or there was an error opening the file.
            merror("An unknown error occurred trying to verify the signature of the \"%S\" file.", full_path);
        }
        break;
    case TRUST_E_SUBJECT_FORM_UNKNOWN:
        // Trust provider does not support the form specified for the subject.
        merror("The form of file '%S' is not supported by trust provider.", full_path);
        break;
    case TRUST_E_ACTION_UNKNOWN:
        // Trust provider does not support the specified action
        merror("Provider doesn't support verify action for file '%S'.", full_path);
        break;
    case TRUST_E_PROVIDER_UNKNOWN:
        // Trust provider is not recognized on this system.
        merror("No trusted provider found for file '%S'.", full_path);
        break;
    case TRUST_E_EXPLICIT_DISTRUST:
        /*
        The hash that represents the subject or the publisher is not allowed by the admin or user.
        Signer's certificate is in the Untrusted Publishers store.
        */
        merror("The signature is present, but specifically disallowed for file '%S'.", full_path);
        break;
    case TRUST_E_SUBJECT_NOT_TRUSTED:
        // Subject failed the specified verification action.
        merror("The signature is present, but not trusted by the user for file '%S'.", full_path);
        break;
    case TRUST_E_FAIL:
        merror("The signature of file '%S' is invalid or not found.", full_path);
        break;
    case TRUST_E_BAD_DIGEST:
        // File might be corrupt.
        merror("The file '%S' or its signature is corrupt.", full_path);
        break;
    case CERT_E_EXPIRED:
        // Signer's certificate was expired.
        merror("The signature of file '%S' is expired.", full_path);
        break;
    case CERT_E_REVOKED:
        // Signer's certificate was revoked.
        merror("The signature of file '%S' was revoked.", full_path);
        break;
    case CRYPT_E_REVOKED:
        merror("The certificate or signature of file '%S' has been revoked.", full_path);
        break;
    case CERT_E_UNTRUSTEDROOT:
        // A certification chain processed correctly, but terminated in a root certificate that is not trusted by the trust provider.
        merror("The signature of file '%S' terminated in a root certificate that is not trusted.", full_path);
        break;
    case CRYPT_E_SECURITY_SETTINGS:
        /*
        The hash that represents the subject or the publisher was not explicitly trusted by the admin and the
        admin policy has disabled user trust. No signature, publisher or time stamp errors.
        */
        merror("The hash representing the subject or the publisher wasn't explicitly trusted for file '%S'.", full_path);
        break;
    case TRUST_E_SYSTEM_ERROR:
        // A system-level error occurred while verifying trust.
        merror("A system-level error occurred while verifying trust for file '%S'.", full_path);
        break;
    case TRUST_E_NO_SIGNER_CERT:
        merror("The certificate for the signer of file '%S' is invalid or not found.", full_path);
        break;
    case TRUST_E_COUNTER_SIGNER:
        merror("One of the counter signatures was not valid for file '%S'.", full_path);
        break;
    case TRUST_E_CERT_SIGNATURE:
        merror("The signature of the certificate can not be verified for file '%S'.", full_path);
        break;
    case TRUST_E_TIME_STAMP:
        merror("The timestamp signature or certificate could not be verified or is malformed for file '%S'.", full_path);
        break;
    case TRUST_E_BASIC_CONSTRAINTS:
        merror("The basic constraints of the certificate for file '%S' are invalid or missing.", full_path);
        break;
    case TRUST_E_FINANCIAL_CRITERIA:
        merror("The certificate for file '%S' does not meet or contain the Authenticode financial extensions.", full_path);
        break;
    case CERT_E_CHAINING:
        merror("The certificate chain to a trusted root authority could not be built for file '%S'.", full_path);
        break;
    case CERT_E_UNTRUSTEDTESTROOT:
        merror("The root certificate for file '%S' is a testing certificate, and policy settings disallow test certificates.", full_path);
        break;
    case CERT_E_WRONG_USAGE:
        merror("The certificate for file '%S' is not valid for the requested usage.", full_path);
        break;
    case CERT_E_INVALID_NAME:
        merror("The certificate name for file '%S' is invalid. Either the name is not included in the permitted list, or it is explicitly excluded.", full_path);
        break;
    case CERT_E_INVALID_POLICY:
        merror("The certificate policy for file '%S' is invalid.", full_path);
        break;
    case CERT_E_CRITICAL:
    case CERT_E_PURPOSE:
        merror("The certificate for file '%S' is being used for a purpose other than the purpose specified by its CA.", full_path);
        break;
    case CERT_E_VALIDITYPERIODNESTING:
        merror("The validity periods of the certification chain do not nest correctly for file '%S'.", full_path);
        break;
    case CRYPT_E_NO_REVOCATION_CHECK:
        merror("The revocation function was unable to check revocation for the certificate of file '%S'.", full_path);
        break;
    case CRYPT_E_REVOCATION_OFFLINE:
        merror("It was not possible to check revocation because the revocation server was offline for file '%S'.", full_path);
        break;
    case CERT_E_REVOCATION_FAILURE:
        merror("The revocation process could not continue, and the certificate could not be checked for file '%S'.", full_path);
        break;
    case CERT_E_CN_NO_MATCH:
        merror("The certificate's CN name does not match the passed value for file '%S'.", full_path);
        break;
    case CERT_E_ROLE:
        merror("A certificate for file '%S' that can only be used as an end-entity is being used as a CA or vice versa.", full_path);
        break;
    default:
        last_error = GetLastError();
        merror("%s WinVerifyTrust returned '%lX'. GetLastError returned '%lX'", win_strerror(last_error), status, last_error);
        status = ERROR_INVALID_DATA;
    }

    // Any hWVTStateData must be released by a call with close.
    WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policy_GUID, &WinTrustData);

    return status;
}

DWORD get_file_hash(const wchar_t *path, BYTE **hash, DWORD *hash_size)
{
    DWORD result = ERROR_SUCCESS;
    DWORD last_error = ERROR_SUCCESS;

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
                    last_error = GetLastError();
                    merror("CryptCATAdminCalcHashFromFileHandle failed because hash size is zero with error %lu: %s", last_error, win_strerror(last_error));
                } else {
                    os_calloc(1, *hash_size, *hash);

                    if (!CryptCATAdminCalcHashFromFileHandle(handle_file, hash_size, *hash, 0)) {
                        result = GetLastError();
                        merror("CryptCATAdminCalcHashFromFileHandle failed trying to calculate hash with error %lu: %s", result, win_strerror(result));
                        os_free(*hash);
                    }
                }
            } else {
                result = GetLastError();
                merror("CryptCATAdminCalcHashFromFileHandle failed trying to get the hash size with error %lu: %s", result, win_strerror(result));
            }
        } else {
            result = ERROR_FILE_NOT_FOUND;
            last_error = GetLastError();
            mdebug2("CreateFileW failed with error %lu path %S: %s", last_error, path, win_strerror(last_error));
        }
        // Close file handle.
        CloseHandle(handle_file);

    } else {
        result = ERROR_INVALID_DATA;
        last_error = GetLastError();
        merror("GetFullPathNameW failed with error %lu. %s", last_error, win_strerror(last_error));
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
            merror("CryptCATAdminAcquireContext failed with error %lu: %s", result, win_strerror(result));
        }
        os_free(hash);
    }
    return result;
}

#endif /* WIN32 */
