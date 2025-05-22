#pragma once

#include "iwinapi_wrappers.hpp"


class TWSapiWrapper : public ITWSapiWrapper
{
    public:
        bool WTSEnumerateSessionsW(HANDLE hServer, DWORD pLevel, DWORD Filter,
                                   PWTS_SESSION_INFOW* ppSessionInfo, DWORD* pCount) override
        {
            return ::WTSEnumerateSessionsW(hServer, pLevel, Filter, ppSessionInfo, pCount);
        }

        bool WTSQuerySessionInformationW(HANDLE hServer, DWORD SessionId, WTS_INFO_CLASS WTSInfoClass,
                                         LPWSTR* ppBuffer, DWORD* pBytesReturned) override
        {
            return ::WTSQuerySessionInformationW(hServer, SessionId, WTSInfoClass, ppBuffer, pBytesReturned);
        }

        void WTSFreeMemory(PVOID pMemory) override
        {
            return ::WTSFreeMemory(pMemory);
        }
};

class WinBaseApiWrapper : public IWinBaseApiWrapper
{
    public:
        virtual bool LookupAccountNameW(LPCWSTR lpSystemName,
                                        LPCWSTR lpAccountName,
                                        PSID Sid,
                                        LPDWORD cbSid,
                                        LPWSTR ReferencedDomainName,
                                        LPDWORD cchReferencedDomainName,
                                        PSID_NAME_USE peUse) override
        {
            return ::LookupAccountNameW(lpSystemName, lpAccountName, Sid, cbSid,
                                        ReferencedDomainName, cchReferencedDomainName, peUse);
        }
};

class WinSDDLWrapper : public IWinSDDLWrapper
{
    public:
        virtual bool ConvertSidToStringSidW(PSID Sid, LPWSTR* StringSid) override
        {
            return ::ConvertSidToStringSidW(Sid, StringSid);
        }
};

class WinSecurityBaseApiWrapper : public IWinSecurityBaseApiWrapper
{
    public:
        virtual bool IsValidSid(PSID pSid) override
        {
            return ::IsValidSid(pSid);
        }
};
