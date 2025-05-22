#pragma once

#include <windows.h>
#include <lm.h>
#include <memory>
#include <string>
#include <vector>

class IWindowsApiWrapper
{
    public:
        virtual ~IWindowsApiWrapper() = default;

        virtual DWORD NetUserEnumWrapper(LPCWSTR servername, DWORD level, DWORD filter,
                                         LPBYTE* bufptr, DWORD prefmaxlen, LPDWORD entriesread,
                                         LPDWORD totalentries, LPDWORD resume_handle) = 0;

        virtual DWORD NetUserGetInfoWrapper(LPCWSTR servername, LPCWSTR username,
                                            DWORD level, LPBYTE* bufptr) = 0;

        virtual DWORD RegOpenKeyExWWrapper(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions,
                                           REGSAM samDesired, PHKEY phkResult) = 0;

        virtual DWORD RegQueryValueExWWrapper(HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved,
                                              LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData) = 0;

        virtual LSTATUS RegQueryInfoKeyWWrapper(HKEY      hKey,
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
                                               ) = 0;

        virtual bool IsValidSidWrapper(PSID Sid) = 0;

        virtual BOOL ConvertSidToStringSidAWrapper(PSID sid, LPSTR* stringSid) = 0;

        virtual BOOL ConvertStringSidToSidAWrapper(LPCSTR StringSid, PSID* Sid) = 0;

        virtual BOOL LookupAccountSidWWrapper(LPCWSTR lpSystemName, PSID Sid, LPWSTR Name,
                                              LPDWORD cchName, LPWSTR ReferencedDomainName,
                                              LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse) = 0;

        virtual bool LookupAccountNameWWrapper(LPCWSTR lpSystemName,
                                               LPCWSTR lpAccountName,
                                               PSID Sid,
                                               LPDWORD cbSid,
                                               LPWSTR ReferencedDomainName,
                                               LPDWORD cchReferencedDomainName,
                                               PSID_NAME_USE peUse) = 0;

        virtual void FreeSidWrapper(LPVOID pSid) = 0;

        virtual DWORD NetUserGetLocalGroupsWrapper(
            LPCWSTR servername,
            LPCWSTR username,
            DWORD level,
            DWORD flags,
            LPBYTE* bufptr,
            DWORD prefmaxlen,
            LPDWORD entriesread,
            LPDWORD totalentries) = 0;

        virtual PUCHAR GetSidSubAuthorityCountWrapper(PSID sid) = 0;

        virtual PDWORD GetSidSubAuthorityWrapper(PSID pSid, DWORD index) = 0;

        virtual LSTATUS RegEnumKeyWWrapper(HKEY hKey, DWORD index, LPWSTR lpName, DWORD cchName) = 0;

        virtual DWORD GetLastErrorWrapper() = 0;
};
