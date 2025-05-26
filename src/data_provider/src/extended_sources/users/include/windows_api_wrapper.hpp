/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include "iwindows_api_wrapper.hpp"

/// @brief Wrapper for Windows API functions used in user and registry operations.
///
/// Provides concrete implementations of the `IWindowsApiWrapper` interface by delegating
/// to native Windows API functions. This allows for easier mocking and testing.
class WindowsApiWrapper : public IWindowsApiWrapper
{
    public:
        /// @brief Wrapper for NetUserEnum API.
        /// @param servername Name of the remote server or NULL for local.
        /// @param level Information level (0, 1, etc.).
        /// @param filter Filter for user accounts (e.g., FILTER_NORMAL_ACCOUNT).
        /// @param bufptr Pointer to the buffer that receives the data.
        /// @param prefmaxlen Preferred maximum length of the returned data.
        /// @param entriesread Pointer to the number of entries read.
        /// @param totalentries Pointer to the total number of entries available.
        /// @param resume_handle Handle for continuing an existing search.
        /// @return Windows API status code.
        DWORD NetUserEnumWrapper(LPCWSTR servername, DWORD level, DWORD filter,
                                 LPBYTE* bufptr, DWORD prefmaxlen, LPDWORD entriesread,
                                 LPDWORD totalentries, LPDWORD resume_handle) override
        {
            return NetUserEnum(servername, level, filter, bufptr, prefmaxlen,
                               entriesread, totalentries, resume_handle);
        }

        /// @brief Wrapper for NetUserGetInfo API.
        /// @param servername Name of the server.
        /// @param username Name of the user.
        /// @param level Information level to retrieve.
        /// @param bufptr Pointer to the buffer that receives the data.
        /// @return Windows API status code.
        DWORD NetUserGetInfoWrapper(LPCWSTR servername, LPCWSTR username,
                                    DWORD level, LPBYTE* bufptr) override
        {
            return NetUserGetInfo(servername, username, level, bufptr);
        }

        /// @brief Wrapper for RegOpenKeyExW API.
        /// @param hKey Handle to an open registry key.
        /// @param lpSubKey Name of the subkey to open.
        /// @param ulOptions Reserved; must be 0.
        /// @param samDesired Desired access rights.
        /// @param phkResult Pointer that receives the opened key handle.
        /// @return Windows API status code.
        DWORD RegOpenKeyExWWrapper(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions,
                                   REGSAM samDesired, PHKEY phkResult) override
        {
            return RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult);
        }

        /// @brief Wrapper for RegQueryValueExW API.
        /// @param hKey Handle to an open registry key.
        /// @param lpValueName Name of the value to query.
        /// @param lpReserved Reserved; must be NULL.
        /// @param lpType Receives the type of data.
        /// @param lpData Buffer to receive the data.
        /// @param lpcbData Size of the buffer and receives actual size.
        /// @return Windows API status code.
        DWORD RegQueryValueExWWrapper(HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved,
                                      LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData) override
        {
            return RegQueryValueExW(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
        }

        /// @brief Wrapper for RegQueryInfoKeyW API.
        /// @param hKey Handle to an open registry key.
        /// @param lpClass Buffer that receives the class string.
        /// @param lpcchClass Size of the class buffer.
        /// @param lpReserved Reserved; must be NULL.
        /// @param lpcSubKeys Receives number of subkeys.
        /// @param lpcbMaxSubKeyLen Max subkey name length.
        /// @param lpcbMaxClassLen Max class string length.
        /// @param lpcValues Receives number of values.
        /// @param lpcbMaxValueNameLen Max value name length.
        /// @param lpcbMaxValueLen Max value data size.
        /// @param lpcbSecurityDescriptor Size of security descriptor.
        /// @param lpftLastWriteTime Last write time.
        /// @return Windows API status code.
        LSTATUS RegQueryInfoKeyWWrapper(
            HKEY      hKey,
            LPWSTR    lpClass,
            LPDWORD   lpcchClass,
            LPDWORD   lpReserved,
            LPDWORD   lpcSubKeys,
            LPDWORD   lpcbMaxSubKeyLen,
            LPDWORD   lpcbMaxClassLen,
            LPDWORD   lpcValues,
            LPDWORD   lpcbMaxValueNameLen,
            LPDWORD   lpcbMaxValueLen,
            LPDWORD   lpcbSecurityDescriptor,
            PFILETIME lpftLastWriteTime
        ) override
        {
            return RegQueryInfoKeyW(hKey, lpClass, lpcchClass, lpReserved,
                                    lpcSubKeys, lpcbMaxSubKeyLen, lpcbMaxClassLen,
                                    lpcValues, lpcbMaxValueNameLen, lpcbMaxValueLen, lpcbSecurityDescriptor, lpftLastWriteTime);
        }

        /// @brief Wrapper for IsValidSid.
        /// @param Sid Pointer to the SID to validate.
        /// @return true if SID is valid, false otherwise.
        bool IsValidSidWrapper(PSID Sid) override
        {
            return IsValidSid(Sid);
        }

        /// @brief Wrapper for ConvertSidToStringSidA.
        /// @param sid Pointer to the SID to convert.
        /// @param stringSid Receives the string representation.
        /// @return TRUE on success, FALSE on failure.
        BOOL ConvertSidToStringSidAWrapper(PSID sid, LPSTR* stringSid) override
        {
            return ConvertSidToStringSidA(sid, stringSid);
        }

        /// @brief Wrapper for ConvertStringSidToSidA.
        /// @param StringSid String representation of a SID.
        /// @param Sid Receives the binary SID.
        /// @return TRUE on success, FALSE on failure.
        BOOL ConvertStringSidToSidAWrapper(LPCSTR StringSid, PSID* Sid) override
        {
            return ConvertStringSidToSidA(StringSid, Sid);
        }

        /// @brief Wrapper for LookupAccountSidW.
        /// @param lpSystemName Name of the system to search.
        /// @param Sid SID to lookup.
        /// @param Name Buffer to receive the account name.
        /// @param cchName Size of the Name buffer.
        /// @param ReferencedDomainName Buffer for domain name.
        /// @param cchReferencedDomainName Size of domain buffer.
        /// @param peUse Receives SID usage.
        /// @return TRUE on success, FALSE on failure.
        BOOL LookupAccountSidWWrapper(LPCWSTR lpSystemName, PSID Sid, LPWSTR Name,
                                      LPDWORD cchName, LPWSTR ReferencedDomainName,
                                      LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse) override
        {
            return LookupAccountSidW(lpSystemName, Sid, Name, cchName, ReferencedDomainName, cchReferencedDomainName, peUse);
        }

        /// @brief Wrapper for LookupAccountNameW.
        /// @param lpSystemName Name of the system.
        /// @param lpAccountName Name of the account.
        /// @param Sid Buffer to receive the SID.
        /// @param cbSid Size of the SID buffer.
        /// @param ReferencedDomainName Buffer for domain name.
        /// @param cchReferencedDomainName Size of domain buffer.
        /// @param peUse Receives SID usage.
        /// @return true on success, false otherwise.
        bool LookupAccountNameWWrapper(LPCWSTR lpSystemName,
                                       LPCWSTR lpAccountName,
                                       PSID Sid,
                                       LPDWORD cbSid,
                                       LPWSTR ReferencedDomainName,
                                       LPDWORD cchReferencedDomainName,
                                       PSID_NAME_USE peUse) override
        {
            return LookupAccountNameW(lpSystemName, lpAccountName, Sid, cbSid,
                                      ReferencedDomainName, cchReferencedDomainName, peUse);
        }

        /// @brief Wrapper for LocalFree used to free SIDs.
        /// @param pSid Pointer to the SID to free.
        void FreeSidWrapper(LPVOID pSid) override
        {
            LocalFree(pSid);
        }

        /// @brief Wrapper for NetUserGetLocalGroups.
        /// @param servername Server name or NULL.
        /// @param username Name of the user.
        /// @param level Information level.
        /// @param flags Filter flags.
        /// @param bufptr Receives buffer with group data.
        /// @param prefmaxlen Preferred max length.
        /// @param entriesread Number of groups read.
        /// @param totalentries Total number of groups.
        /// @return Windows API status code.
        DWORD NetUserGetLocalGroupsWrapper(
            LPCWSTR servername,
            LPCWSTR username,
            DWORD level,
            DWORD flags,
            LPBYTE* bufptr,
            DWORD prefmaxlen,
            LPDWORD entriesread,
            LPDWORD totalentries) override
        {
            return NetUserGetLocalGroups(
                       servername,
                       username,
                       level,
                       flags,
                       bufptr,
                       prefmaxlen,
                       entriesread,
                       totalentries);
        }

        /// @brief Wrapper for GetSidSubAuthorityCount.
        /// @param sid Pointer to the SID.
        /// @return Pointer to the sub-authority count.
        PUCHAR GetSidSubAuthorityCountWrapper(PSID sid) override
        {
            return GetSidSubAuthorityCount(sid);
        }

        /// @brief Wrapper for GetSidSubAuthority.
        /// @param pSid Pointer to the SID.
        /// @param index Index of the sub-authority.
        /// @return Pointer to the sub-authority.
        PDWORD GetSidSubAuthorityWrapper(PSID pSid, DWORD index) override
        {
            return GetSidSubAuthority(pSid, index);
        }

        /// @brief Wrapper for RegEnumKeyW.
        /// @param hKey Registry key handle.
        /// @param index Index of the subkey to retrieve.
        /// @param lpName Buffer to receive the subkey name.
        /// @param cchName Size of the buffer.
        /// @return Windows API status code.
        LSTATUS RegEnumKeyWWrapper(HKEY hKey, DWORD index, LPWSTR lpName, DWORD cchName) override
        {
            return RegEnumKeyW(hKey, index, lpName, cchName);
        }

        /// @brief Wrapper for GetLastError.
        /// @return Last-error code for the calling thread.
        DWORD GetLastErrorWrapper() override
        {
            return GetLastError();
        }

        /// @brief Wrapper for RegCloseKey.
        /// @param hKey Handle to the registry key.
        /// @return Windows API status code.
        LSTATUS RegCloseKeyWrapper(HKEY hKey)
        {
            return RegCloseKey(hKey);
        }
};
