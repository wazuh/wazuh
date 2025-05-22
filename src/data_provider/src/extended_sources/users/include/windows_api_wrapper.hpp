#pragma once

#include "iwindows_api_wrapper.hpp"

class WindowsApiWrapper : public IWindowsApiWrapper
{
    public:
        DWORD NetUserEnumWrapper(LPCWSTR servername, DWORD level, DWORD filter,
                                 LPBYTE* bufptr, DWORD prefmaxlen, LPDWORD entriesread,
                                 LPDWORD totalentries, LPDWORD resume_handle) override
        {
            return NetUserEnum(servername, level, filter, bufptr, prefmaxlen,
                               entriesread, totalentries, resume_handle);
        }

        DWORD NetUserGetInfoWrapper(LPCWSTR servername, LPCWSTR username,
                                    DWORD level, LPBYTE* bufptr) override
        {
            return NetUserGetInfo(servername, username, level, bufptr);
        }

        DWORD RegOpenKeyExWWrapper(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions,
                                   REGSAM samDesired, PHKEY phkResult) override
        {
            return RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult);
        }

        DWORD RegQueryValueExWWrapper(HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved,
                                      LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData) override
        {
            return RegQueryValueExW(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
        }

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

        bool IsValidSidWrapper(PSID Sid) override
        {
            return IsValidSid(Sid);
        }

        BOOL ConvertSidToStringSidAWrapper(PSID sid, LPSTR* stringSid) override
        {
            return ConvertSidToStringSidA(sid, stringSid);
        }

        BOOL ConvertStringSidToSidAWrapper(LPCSTR StringSid, PSID* Sid) override
        {
            return ConvertStringSidToSidA(StringSid, Sid);
        }

        BOOL LookupAccountSidWWrapper(LPCWSTR lpSystemName, PSID Sid, LPWSTR Name,
                                      LPDWORD cchName, LPWSTR ReferencedDomainName,
                                      LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse) override
        {
            return LookupAccountSidW(lpSystemName, Sid, Name, cchName, ReferencedDomainName, cchReferencedDomainName, peUse);
        }

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

        void FreeSidWrapper(LPVOID pSid) override
        {
            LocalFree(pSid);
        }

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

        PUCHAR GetSidSubAuthorityCountWrapper(PSID sid) override
        {
            return GetSidSubAuthorityCount(sid);
        }

        PDWORD GetSidSubAuthorityWrapper(PSID pSid, DWORD index) override
        {
            return GetSidSubAuthority(pSid, index);
        }

        LSTATUS RegEnumKeyWWrapper(HKEY hKey, DWORD index, LPWSTR lpName, DWORD cchName) override
        {
            return RegEnumKeyW(hKey, index, lpName, cchName);
        }

        DWORD GetLastErrorWrapper() override
        {
            return GetLastError();
        }

        LSTATUS RegCloseKeyWrapper(HKEY hKey)
        {
            return RegCloseKey(hKey);
        }
};
