#pragma once

#include <winsock2.h>
#include <windows.h>
#include <wtsapi32.h>
#include <sddl.h>

class ITWSapiWrapper
{
    public:
        virtual ~ITWSapiWrapper() = default;

        virtual bool WTSEnumerateSessionsExW(HANDLE hServer,
            DWORD *pLevel,
            DWORD Filter,
            PWTS_SESSION_INFO_1W *ppSessionInfo,
            DWORD *pCount) = 0;

        virtual bool WTSQuerySessionInformationW(HANDLE hServer,
            DWORD SessionId,
            WTS_INFO_CLASS WTSInfoClass,
            LPWSTR *ppBuffer,
            DWORD *pBytesReturned) = 0;

        virtual void WTSFreeMemory(PVOID pMemory) = 0;

        virtual bool WTSFreeMemoryEx(WTS_TYPE_CLASS WTSTypeClass,
            PVOID pMemory,
            ULONG NumberOfEntries) = 0;
};

class IWinBaseApiWrapper
{
    public:
        virtual ~IWinBaseApiWrapper() = default;
        virtual bool LookupAccountNameW(LPCWSTR lpSystemName,
            LPCWSTR lpAccountName,
            PSID Sid,
            LPDWORD cbSid,
            LPWSTR ReferencedDomainName,
            LPDWORD cchReferencedDomainName,
            PSID_NAME_USE peUse) = 0;
};

class IWinSDDLWrapper
{
    public:
        virtual ~IWinSDDLWrapper() = default;
        virtual bool ConvertSidToStringSidW(PSID Sid, LPWSTR *StringSid) = 0;
};

class IWinSecurityBaseApiWrapper
{
    public:
        virtual ~IWinSecurityBaseApiWrapper() = default;
        virtual bool IsValidSid(PSID pSid) = 0;
};
