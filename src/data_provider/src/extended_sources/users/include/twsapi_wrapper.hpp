#pragma once

#include "itwsapi_wrapper.hpp"


class TWSapiWrapper : public ITWSapiWrapper
{
    public:
        bool WTSEnumerateSessionsExW(HANDLE hServer, DWORD *pLevel, DWORD Filter,
            PWTS_SESSION_INFO_1W *ppSessionInfo, DWORD *pCount) override
        {
            return ::WTSEnumerateSessionsExW(hServer, pLevel, Filter, ppSessionInfo, pCount);
        }

        bool WTSQuerySessionInformationW(HANDLE hServer, DWORD SessionId, WTS_INFO_CLASS WTSInfoClass,
            LPWSTR *ppBuffer, DWORD *pBytesReturned) override
        {
            return ::WTSQuerySessionInformationW(hServer, SessionId, WTSInfoClass, ppBuffer, pBytesReturned);
        }

        void WTSFreeMemory(PVOID pMemory) override
        {
            return ::WTSFreeMemory(pMemory);
        }

        bool WTSFreeMemoryEx(WTS_TYPE_CLASS WTSTypeClass, PVOID pMemory, ULONG NumberOfEntries) override
        {
            return ::WTSFreeMemoryEx(WTSTypeClass, pMemory, NumberOfEntries);
        }

        bool LookupAccountNameW(LPCWSTR lpSystemName, LPCWSTR lpAccountName, PSID Sid,
            LPDWORD cbSid, LPWSTR ReferencedDomainName, LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse) override
        {
            return ::LookupAccountNameW(lpSystemName, lpAccountName, Sid, cbSid, ReferencedDomainName, cchReferencedDomainName, peUse);
        }

        bool ConvertSidToStringSidW(PSID Sid, LPWSTR *StringSid) override
        {
            return ::ConvertSidToStringSidW(Sid, StringSid);
        }

        bool IsValidSid(PSID pSid) override
        {
            return ::IsValidSid(pSid);
        }
};
