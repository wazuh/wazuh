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

DWORD verify_pe_signature(const wchar_t *path, char* error_message, int error_message_size)
{
    // Get full path if path is a relative path.
    // This is needed because WinVerifyTrust only accepts full paths.
    // If path is already a full path, GetFullPathName will return the same path.

    wchar_t full_path[MAX_PATH];
    int last_error = ERROR_SUCCESS;

    if (!GetFullPathNameW(path, MAX_PATH, full_path, NULL)) {
        last_error = GetLastError();
        os_snprintf(error_message,
                    error_message_size,
                    "GetFullPathNameW failed with error %lu for '%S': %s",
                    last_error, path, win_strerror(last_error));

        return ERROR_INVALID_DATA;
    }

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
        os_snprintf(error_message,
                    error_message_size,
                    "PE signature verification succeeded for %S", full_path);
        break;
    case TRUST_E_NOSIGNATURE:
        last_error = GetLastError();

        if (TRUST_E_NOSIGNATURE == last_error ||
            TRUST_E_SUBJECT_FORM_UNKNOWN == last_error ||
            TRUST_E_PROVIDER_UNKNOWN == last_error) {
            // The file was not signed.
            os_snprintf(error_message,
                        error_message_size,
                        "No signature found for '%S'.",
                        full_path);
        }
        else
        {
            // The signature was not valid or there was an error opening the file.
            os_snprintf(error_message,
                        error_message_size,
                        "An unknown error occurred trying to verify the signature of the \"%S\" file.",
                        full_path);
        }
        break;
    case TRUST_E_SUBJECT_FORM_UNKNOWN:
        // Trust provider does not support the form specified for the subject.
        os_snprintf(error_message,
                    error_message_size,
                    "The form of file '%S' is not supported by trust provider.",
                    full_path);
        break;
    case TRUST_E_ACTION_UNKNOWN:
        // Trust provider does not support the specified action
        os_snprintf(error_message,
                    error_message_size,
                    "Provider doesn't support verify action for file '%S'.",
                    full_path);
        break;
    case TRUST_E_PROVIDER_UNKNOWN:
        // Trust provider is not recognized on this system.
        os_snprintf(error_message,
                    error_message_size,
                    "No trusted provider found for file '%S'.",
                    full_path);
        break;
    case TRUST_E_EXPLICIT_DISTRUST:
        /*
        The hash that represents the subject or the publisher is not allowed by the admin or user.
        Signer's certificate is in the Untrusted Publishers store.
        */
        os_snprintf(error_message,
                    error_message_size,
                    "The signature is present, but specifically disallowed for file '%S'.",
                    full_path);
        break;
    case TRUST_E_SUBJECT_NOT_TRUSTED:
        // Subject failed the specified verification action.
        os_snprintf(error_message,
                    error_message_size,
                    "The signature is present, but not trusted by the user for file '%S'.",
                    full_path);
        break;
    case TRUST_E_FAIL:
        os_snprintf(error_message,
                    error_message_size,
                    "The signature of file '%S' is invalid or not found.",
                    full_path);
        break;
    case TRUST_E_BAD_DIGEST:
        // File might be corrupt.
        os_snprintf(error_message,
                    error_message_size,
                    "The file '%S' or its signature is corrupt.",
                    full_path);
        break;
    case CERT_E_EXPIRED:
        // Signer's certificate was expired.
        os_snprintf(error_message,
                    error_message_size,
                    "The signature of file '%S' is expired.",
                    full_path);
        break;
    case CERT_E_REVOKED:
        // Signer's certificate was revoked.
        os_snprintf(error_message,
                    error_message_size,
                    "The signature of file '%S' was revoked.",
                    full_path);
        break;
    case CRYPT_E_REVOKED:
        os_snprintf(error_message,
                    error_message_size,
                    "The certificate or signature of file '%S' has been revoked.",
                    full_path);
        break;
    case CERT_E_UNTRUSTEDROOT:
        // A certification chain processed correctly, but terminated in a root certificate that is not trusted by the
        // trust provider.
        os_snprintf(error_message,
                    error_message_size,
                    "The signature of file '%S' terminated in a root certificate that is not trusted.",
                    full_path);
        break;
    case CRYPT_E_SECURITY_SETTINGS:
        /*
        The hash that represents the subject or the publisher was not explicitly trusted by the admin and the
        admin policy has disabled user trust. No signature, publisher or time stamp errors.
        */
        os_snprintf(error_message,
                    error_message_size,
                    "The hash representing the subject or the publisher wasn't explicitly trusted for file '%S'.",
                    full_path);
        break;
    case TRUST_E_SYSTEM_ERROR:
        // A system-level error occurred while verifying trust.
        os_snprintf(error_message,
                    error_message_size,
                    "A system-level error occurred while verifying trust for file '%S'.",
                    full_path);
        break;
    case TRUST_E_NO_SIGNER_CERT:
        os_snprintf(error_message,
                    error_message_size,
                    "The certificate for the signer of file '%S' is invalid or not found.",
                    full_path);
        break;
    case TRUST_E_COUNTER_SIGNER:
        os_snprintf(error_message,
                    error_message_size,
                    "One of the counter signatures was not valid for file '%S'.",
                    full_path);
        break;
    case TRUST_E_CERT_SIGNATURE:
        os_snprintf(error_message,
                    error_message_size,
                    "The signature of the certificate can not be verified for file '%S'.",
                    full_path);
        break;
    case TRUST_E_TIME_STAMP:
        os_snprintf(error_message,
                    error_message_size,
                    "The timestamp signature or certificate could not be verified or is malformed for file '%S'.",
                    full_path);
        break;
    case TRUST_E_BASIC_CONSTRAINTS:
        os_snprintf(error_message,
                    error_message_size,
                    "The basic constraints of the certificate for file '%S' are invalid or missing.",
                    full_path);
        break;
    case TRUST_E_FINANCIAL_CRITERIA:
        os_snprintf(error_message,
                    error_message_size,
                    "The certificate for file '%S' does not meet or contain the Authenticode financial extensions.",
                    full_path);
        break;
    case CERT_E_CHAINING:
        os_snprintf(error_message,
                    error_message_size,
                    "The certificate chain to a trusted root authority could not be built for file '%S'.",
                    full_path);
        break;
    case CERT_E_UNTRUSTEDTESTROOT:
        os_snprintf(error_message,
                    error_message_size,
                    "The root certificate for file '%S' is a testing certificate, "
                    "and policy settings disallow test certificates.",
                    full_path);
        break;
    case CERT_E_WRONG_USAGE:
        os_snprintf(error_message,
                    error_message_size,
                    "The certificate for file '%S' is not valid for the requested usage.",
                    full_path);
        break;
    case CERT_E_INVALID_NAME:
        os_snprintf(error_message,
                    error_message_size,
                    "The certificate name for file '%S' is invalid. Either the name is not included in the permitted "
                    "list, or it is explicitly excluded.",
                    full_path);
        break;
    case CERT_E_INVALID_POLICY:
        os_snprintf(error_message,
                    error_message_size,
                    "The certificate policy for file '%S' is invalid.",
                    full_path);
        break;
    case CERT_E_CRITICAL:
    case CERT_E_PURPOSE:
        os_snprintf(error_message,
                    error_message_size,
                    "The certificate for file '%S' is being used for a purpose other than the purpose specified"
                    " by its CA.",
                    full_path);
        break;
    case CERT_E_VALIDITYPERIODNESTING:
        os_snprintf(error_message,
                    error_message_size,
                    "The validity periods of the certification chain do not nest correctly for file '%S'.",
                    full_path);
        break;
    case CRYPT_E_NO_REVOCATION_CHECK:
        os_snprintf(error_message,
                    error_message_size,
                    "The revocation function was unable to check revocation for the certificate of file '%S'.",
                    full_path);
        break;
    case CRYPT_E_REVOCATION_OFFLINE:
        os_snprintf(error_message,
                    error_message_size,
                    "It was not possible to check revocation because the revocation server was offline for file '%S'.",
                    full_path);
        break;
    case CERT_E_REVOCATION_FAILURE:
        os_snprintf(error_message,
                    error_message_size,
                    "The revocation process could not continue, and the certificate could not be checked for file "
                    "'%S'.",
                    full_path);
        break;
    case CERT_E_CN_NO_MATCH:
        os_snprintf(error_message,
                    error_message_size,
                    "The certificate's CN name does not match the passed value for file '%S'.",
                    full_path);
        break;
    case CERT_E_ROLE:
        os_snprintf(error_message,
                    error_message_size,
                    "A certificate for file '%S' that can only be used as an end-entity is being used as a CA or "
                    "vice versa.",
                    full_path);
        break;
    default:
        last_error = GetLastError();
        os_snprintf(error_message,
                    error_message_size,
                    "WinVerifyTrust returned '%lX' for '%S'. GetLastError returned '%lX'. %s",
                    status,
                    full_path,
                    last_error,
                    win_strerror(last_error));
        status = ERROR_INVALID_DATA;
    }

    // Any hWVTStateData must be released by a call with close.
    WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policy_GUID, &WinTrustData);

    return status;
}

DWORD get_file_hash(const wchar_t *path, BYTE **hash, DWORD *hash_size, char* error_message, int error_message_size)
{
    DWORD result = ERROR_SUCCESS;
    DWORD last_error = ERROR_SUCCESS;

    // Get full path if path is a relative path.
    // This is needed because CryptCATAdminCalcHashFromFileHandle only accepts full paths.
    // If path is already a full path, GetFullPathName will return the same path.
    wchar_t full_path[MAX_PATH];

    if (GetFullPathNameW(path, MAX_PATH, full_path, NULL)) {
        // Open file for hash calculation.
        HANDLE handle_file = CreateFileW(full_path,
                                         GENERIC_READ,
                                         FILE_SHARE_READ,
                                         NULL,
                                         OPEN_EXISTING,
                                         FILE_ATTRIBUTE_NORMAL,
                                         NULL);

        if (handle_file != INVALID_HANDLE_VALUE) {

            // Calculate hash of the file.
            if (CryptCATAdminCalcHashFromFileHandle(handle_file, hash_size, NULL, 0)) {

                if (*hash_size == 0) {
                    result = ERROR_INVALID_DATA;
                    last_error = GetLastError();
                    os_snprintf(error_message,
                                error_message_size,
                                "CryptCATAdminCalcHashFromFileHandle failed because hash size is zero with error %lu "
                                "for '%S': %s",
                                last_error,
                                full_path,
                                win_strerror(last_error));
                } else {
                    os_calloc(1, *hash_size, *hash);

                    if (!CryptCATAdminCalcHashFromFileHandle(handle_file, hash_size, *hash, 0)) {
                        result = GetLastError();
                        os_snprintf(error_message,
                                    error_message_size,
                                    "CryptCATAdminCalcHashFromFileHandle failed trying to calculate hash with error "
                                    "%lu for '%S': %s",
                                    result,
                                    full_path,
                                    win_strerror(result));
                        os_free(*hash);
                    }
                }
            } else {
                result = GetLastError();
                os_snprintf(error_message,
                            error_message_size,
                            "CryptCATAdminCalcHashFromFileHandle failed trying to get the hash size with error %lu for "
                            "'%S': %s",
                            result,
                            full_path,
                            win_strerror(result));
            }
        } else {
            result = ERROR_FILE_NOT_FOUND;
            last_error = GetLastError();
            os_snprintf(error_message,
                        error_message_size,
                        "CreateFileW failed with error %lu for '%S': %s",
                        last_error,
                        full_path,
                        win_strerror(last_error));
        }
        // Close file handle.
        CloseHandle(handle_file);

    } else {
        result = ERROR_INVALID_DATA;
        last_error = GetLastError();
        os_snprintf(error_message,
                    error_message_size,
                    "GetFullPathNameW failed with error %lu for '%S'. %s",
                    last_error,
                    path,
                    win_strerror(last_error));
    }

    return result;
}



DWORD check_ca_available() {
    // Check if the CA is available in the system.
    // If the CA is not available, the function returns some error code.
    // If the CA is available, the function returns ERROR_SUCCESS.
    DWORD result = ERROR_INVALID_DATA;
    HCERTSTORE cert_store = NULL;
    PCCERT_CONTEXT cert_context = NULL;
    char *ca_name = NULL;

    // Open the certificate store.
    cert_store = CertOpenSystemStore(0, "ROOT");
    // Check if the certificate store was opened successfully.
    if (cert_store) {
        // Get the first certificate in the store.
        cert_context = CertEnumCertificatesInStore(cert_store, NULL);

        while (cert_context) {
            // Get the certificate's CN name size.
            int req_size = CertGetNameString(cert_context,
                                             CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                             0,
                                             NULL,
                                             NULL,
                                             0);

            os_calloc(req_size, sizeof(char), ca_name);

            // Get the certificate's CN name.
            if (CertGetNameString(cert_context,
                                  CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                  0,
                                  NULL,
                                  ca_name,
                                  req_size)) {
                minfo("Checking CA '%s'", ca_name);
                // Check if the certificate's CN name matches the CA name.
                if (strncmp(ca_name, CA_NAME, sizeof(CA_NAME) - 1) == 0) {
                    result = ERROR_SUCCESS;
                    os_free(ca_name);
                    break;
                }
            }
            os_free(ca_name);
            // Get the next certificate in the store.
            cert_context = CertEnumCertificatesInStore(cert_store, cert_context);
        }

        // Close the certificate store.
        if (!CertCloseStore(cert_store, 0)) {
            merror("CertCloseStore failed with error %lu: %s", GetLastError(), win_strerror(GetLastError()));
        }
    } else {
        // Log error if the certificate store could not be opened.
        result = GetLastError();
        merror("CertOpenSystemStore failed with error %lu: %s", result, win_strerror(result));
    }


    return result;
}

DWORD verify_hash_catalog(wchar_t *file_path, char* error_message, int error_message_size)
{
    HCATADMIN catalog_administrator = NULL;
    HCATINFO catalog_context = NULL;
    GUID policy_GUID = DRIVER_ACTION_VERIFY;
    BYTE *hash = NULL;
    DWORD hash_size = 0;
    DWORD result = get_file_hash(file_path, &hash, &hash_size, error_message, error_message_size);

    if (ERROR_SUCCESS == result) {
        if (CryptCATAdminAcquireContext(&catalog_administrator, &policy_GUID, 0)) {
            // Search for the catalog file.
            // If the file is not signed, the function returns NULL.
            // If the file is signed, the function returns a handle to the catalog file.

            if (catalog_context = CryptCATAdminEnumCatalogFromHash(catalog_administrator,
                                                                   hash,
                                                                   hash_size,
                                                                   0,
                                                                   NULL), catalog_context) {
                CryptCATAdminReleaseCatalogContext(catalog_administrator, catalog_context, 0);
                os_snprintf(error_message,
                            error_message_size,
                            "Hash verification succeeded for '%S'",
                            file_path);
            } else {
                result = GetLastError();
                os_snprintf(error_message,
                            error_message_size,
                            "CryptCATAdminEnumCatalogFromHash failed with error %lu for '%S': %s",
                            result,
                            file_path,
                            win_strerror(result));
            }
            CryptCATAdminReleaseContext(catalog_administrator, 0);
        } else {
            result = GetLastError();
            os_snprintf(error_message,
                        error_message_size,
                        "CryptCATAdminAcquireContext failed with error %lu for '%S': %s",
                        result,
                        file_path,
                        win_strerror(result));
        }
        os_free(hash);
    }
    return result;
}

w_err_t verify_hash_and_pe_signature(wchar_t *file_path) {
    DWORD pe_result  = ERROR_SUCCESS;
    DWORD hash_result = ERROR_SUCCESS;
    w_err_t retval = OS_SUCCESS;
    char pe_error_message[OS_SIZE_1024] = {0};
    char hash_error_message[OS_SIZE_1024] = {0};

    pe_result = verify_pe_signature(file_path, pe_error_message, OS_SIZE_1024);

    if (ERROR_SUCCESS != pe_result) {
        hash_result = verify_hash_catalog(file_path, hash_error_message, OS_SIZE_1024);
        if (ERROR_SUCCESS != hash_result) {
            minfo("Trust verification of a module failed by using the signature method. %s", pe_error_message);
            minfo("Trust verification of a module failed by using the hash method. %s", hash_error_message);
            retval = OS_INVALID;
        } else {
            mdebug1("%s", hash_error_message);
        }
    } else {
        mdebug1("%s", pe_error_message);
    }

    return retval;
}

#endif /* WIN32 */
