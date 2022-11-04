#include "shared.h"
#include "cryptography.h"

#ifdef WIN32
#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>

int verify_pe_signature(const wchar_t *path)
{
    // Get full path if path is a relative path.
    // This is needed because WinVerifyTrust only accepts full paths.
    // If path is already a full path, GetFullPathName will return the same path.

    wchar_t fullPath[MAX_PATH];
    if (!GetFullPathNameW(path, MAX_PATH, fullPath, NULL)) {
        merror("GetFullPathNameW failed with error %lu", GetLastError());
        return ERROR_INVALID_DATA;
    }

    DWORD dwLastError;
    WINTRUST_DATA WinTrustData;
    WINTRUST_FILE_INFO WinTrustFileInfo;
    GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WinTrustFileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    WinTrustFileInfo.pcwszFilePath = fullPath;
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

    DWORD dwStatus = WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);

    switch (dwStatus) {
    case ERROR_SUCCESS:
        minfo("PE signature verification succeeded for %S", fullPath);
        return ERROR_SUCCESS;
    case TRUST_E_NOSIGNATURE:
        merror("No signature found.");
        dwLastError = GetLastError();
        return ERROR_INVALID_DATA;
    case TRUST_E_SUBJECT_FORM_UNKNOWN:
        merror("The file is not of a recognized format.");
        dwLastError = GetLastError();
        return ERROR_INVALID_DATA;
    case TRUST_E_PROVIDER_UNKNOWN:
        merror("No provider found for the specified action.");
        dwLastError = GetLastError();
        return ERROR_INVALID_DATA;
    case TRUST_E_SUBJECT_NOT_TRUSTED:
        merror("The signature is not valid.");
        dwLastError = GetLastError();
        return ERROR_INVALID_DATA;
    default:
        dwLastError = GetLastError();
        merror("WinVerifyTrust returned %lX GetLastError returned %lX", dwStatus, dwLastError);
        return ERROR_INVALID_DATA;
    }
}

int verify_catalog(const wchar_t *path)
{
    HCATADMIN hCatAdmin = NULL;
    HCATINFO hCatInfo = NULL;
    CATALOG_INFO CatInfo;
    DWORD dwFlags = 0;
    DWORD dwReserved = 0;
    BYTE bHash[OS_SIZE_128] = { 0 };
    DWORD dwHash = sizeof(bHash);

    // Get full path if path is a relative path.
    // This is needed because Verify catalog only accepts full paths.
    // If path is already a full path, GetFullPathName will return the same path.

    wchar_t fullPath[MAX_PATH];
    if (!GetFullPathNameW(path, MAX_PATH, fullPath, NULL)) {
        return ERROR_INVALID_DATA;
    }

    // Open file for hash calculation.
    HANDLE hFile = CreateFileW(fullPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return ERROR_INVALID_DATA;
    }

    // Calculate hash of the file.
    if (!CryptCATAdminCalcHashFromFileHandle(hFile, &dwHash, bHash, 0)) {
        CloseHandle(hFile);
        return ERROR_INVALID_DATA;
    }

    // Close file handle.
    CloseHandle(hFile);

    GUID WVTPolicyGUID = DRIVER_ACTION_VERIFY;
    if (!CryptCATAdminAcquireContext(&hCatAdmin, &WVTPolicyGUID, dwReserved)) {
        return ERROR_INVALID_DATA;
    }

    // Search for the catalog file.
    // If the file is not signed, the function returns NULL.
    // If the file is signed, the function returns a handle to the catalog file.
    // If the file is signed, but the catalog file is not found, the function returns INVALID_HANDLE_VALUE.

    hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, bHash, dwHash, 0, NULL);

    if (hCatInfo == NULL) {
        CryptCATAdminReleaseContext(hCatAdmin, dwReserved);
        return ERROR_INVALID_DATA;
    }

    CatInfo.cbStruct = sizeof(CATALOG_INFO);
    if (!CryptCATCatalogInfoFromContext(hCatInfo, &CatInfo, dwFlags))
    {
        CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, dwReserved);
        CryptCATAdminReleaseContext(hCatAdmin, dwReserved);
        return ERROR_INVALID_DATA;
    }

    CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, dwReserved);
    CryptCATAdminReleaseContext(hCatAdmin, dwReserved);
    return ERROR_SUCCESS;
}

#endif /* WIN32 */

