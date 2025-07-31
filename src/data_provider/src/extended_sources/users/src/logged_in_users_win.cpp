/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <iostream>
#include <ctime>

#include "logged_in_users_win.hpp"
#include "users_utils_wrapper.hpp"
#include "winapi_wrappers.hpp"
#include "encodingWindowsHelper.h"


const std::map<int, std::string> LoggedInUsersProvider::m_kSessionStates =
{
    {WTSActive, "active"},
    {WTSDisconnected, "disconnected"},
    {WTSConnected, "connected"},
    {WTSConnectQuery, "connectquery"},
    {WTSShadow, "shadow"},
    {WTSIdle, "idle"},
    {WTSListen, "listen"},
    {WTSReset, "reset"},
    {WTSDown, "down"},
    {WTSInit, "init"}
};

LoggedInUsersProvider::LoggedInUsersProvider(std::shared_ptr<ITWSapiWrapper> twsWrapper,
                                             std::shared_ptr<IWinBaseApiWrapper> winBaseWrapper, std::shared_ptr<IWinSDDLWrapper> winSddlWrapper,
                                             std::shared_ptr<IWinSecurityBaseApiWrapper> winSecurityWrapper,
                                             std::shared_ptr<IUsersHelper> usersHelperWrapper)
    : m_twsApiWrapper(std::move(twsWrapper)),
      m_winBaseWrapper(std::move(winBaseWrapper)),
      m_winSddlWrapper(std::move(winSddlWrapper)),
      m_winSecurityWrapper(std::move(winSecurityWrapper)),
      m_usersHelpersWrapper(std::move(usersHelperWrapper)) {}

LoggedInUsersProvider::LoggedInUsersProvider()
    : m_twsApiWrapper(std::make_shared<TWSapiWrapper>()),
      m_winBaseWrapper(std::make_shared<WinBaseApiWrapper>()),
      m_winSddlWrapper(std::make_shared<WinSDDLWrapper>()),
      m_winSecurityWrapper(std::make_shared<WinSecurityBaseApiWrapper>()),
      m_usersHelpersWrapper(std::make_shared<UsersHelper>()) {}

nlohmann::json LoggedInUsersProvider::collect()
{
    nlohmann::json results;
    WTS_SESSION_INFOW* pSessionInfo = nullptr;
    unsigned long count;

    auto res = m_twsApiWrapper->WTSEnumerateSessionsW(
                   WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessionInfo, &count);

    if (res == 0)
    {
        return results;
    }

    for (size_t i = 0; i < count; i++)
    {
        if (pSessionInfo[i].State != WTSActive || pSessionInfo[i].SessionId == 0)
        {
            // The only state for a user logged in is WTSActive and session 0 is the non-interactive system session
            continue;
        }

        nlohmann::json r;

        LPWSTR sessionInfo = nullptr;
        DWORD bytesRet = 0;
        res = m_twsApiWrapper->WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE,
                                                           pSessionInfo[i].SessionId,
                                                           WTSSessionInfo,
                                                           &sessionInfo,
                                                           &bytesRet);

        if (res == 0 || sessionInfo == nullptr)
        {
            std::cerr << "Error querying WTS session information (" << GetLastError() << ")" << std::endl;
            continue;
        }

        const auto wtsSession = reinterpret_cast<WTSINFOW*>(sessionInfo);
        r["user"] = Utils::EncodingWindowsHelper::wstringToStringUTF8(wtsSession->UserName);
        r["type"] = m_kSessionStates.at(pSessionInfo[i].State);
        r["tty"] = pSessionInfo[i].pWinStationName == nullptr
                   ? ""
                   : Utils::EncodingWindowsHelper::wstringToStringUTF8(pSessionInfo[i].pWinStationName);


        FILETIME utcTime = {0, 0};
        unsigned long long unixTime = 0;
        utcTime.dwLowDateTime = wtsSession->ConnectTime.LowPart;
        utcTime.dwHighDateTime = wtsSession->ConnectTime.HighPart;

        if (utcTime.dwLowDateTime != 0 || utcTime.dwHighDateTime != 0)
        {
            unixTime = filetimeToUnixtime(utcTime);
        }

        r["time"] = unixTime;

        LPWSTR clientInfo = nullptr;
        bytesRet = 0;
        res = m_twsApiWrapper->WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE,
                                                           pSessionInfo[i].SessionId,
                                                           WTSClientInfo,
                                                           &clientInfo,
                                                           &bytesRet);

        if (res == 0 || clientInfo == nullptr)
        {
            std::cerr << "Error querying WTS session information (" << GetLastError() << ")" << std::endl;
            results.push_back(r);
            WTSFreeMemory(sessionInfo);
            continue;
        }

        auto wtsClient = reinterpret_cast<WTSCLIENTA*>(clientInfo);

        if (wtsClient->ClientAddressFamily == AF_INET)
        {
            r["host"] = std::to_string(wtsClient->ClientAddress[0]) + "." +
                        std::to_string(wtsClient->ClientAddress[1]) + "." +
                        std::to_string(wtsClient->ClientAddress[2]) + "." +
                        std::to_string(wtsClient->ClientAddress[3]);
        }
        else if (wtsClient->ClientAddressFamily == AF_INET6)
        {
            // TODO: IPv6 addresses are given as an array of byte values.
            auto addr = reinterpret_cast<const char*>(wtsClient->ClientAddress);
            r["host"] = std::string(addr, CLIENTADDRESS_LENGTH);
        }
        else if (wtsClient->ClientAddressFamily == AF_UNSPEC)
        {
            LPWSTR clientName = nullptr;
            res = m_twsApiWrapper->WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE,
                                                               pSessionInfo[i].SessionId,
                                                               WTSClientName,
                                                               &clientName,
                                                               &bytesRet);

            if (res == 0 || clientName == nullptr)
            {
                std::cerr << "Error querying WTS clientName information (" << GetLastError() << ")" << std::endl;
            }
            else
            {
                r["host"] = Utils::EncodingWindowsHelper::wstringToStringUTF8(clientName);
            }

            if (clientName != nullptr)
            {
                m_twsApiWrapper->WTSFreeMemory(clientName);
            }
        }

        r["pid"] = -1;

        if (clientInfo != nullptr)
        {
            m_twsApiWrapper->WTSFreeMemory(clientInfo);
            clientInfo = nullptr;
            wtsClient = nullptr;
        }

        std::wstring domainUser = wtsSession->Domain;
        domainUser += L"\\";
        domainUser += wtsSession->UserName;
        const auto sidBuf = m_usersHelpersWrapper->getSidFromAccountName(domainUser);

        if (sessionInfo != nullptr)
        {
            m_twsApiWrapper->WTSFreeMemory(sessionInfo);
            sessionInfo = nullptr;
        }

        if (sidBuf == nullptr)
        {
            std::cerr << "Error converting username to SID" << std::endl;
            results.push_back(r);
            continue;
        }

        const auto sidStr = m_usersHelpersWrapper->psidToString(reinterpret_cast<SID*>(sidBuf.get()));
        r["sid"] = sidStr;

        const auto hivePath = "HKEY_USERS\\" + sidStr;
        r["registry_hive"] = hivePath;

        results.push_back(r);
    }

    if (pSessionInfo != nullptr)
    {
        m_twsApiWrapper->WTSFreeMemory(pSessionInfo);
        pSessionInfo = nullptr;
    }

    return results;
}

unsigned long long LoggedInUsersProvider::filetimeToUnixtime(const FILETIME& fileTime)
{
    ULARGE_INTEGER ull;
    ull.LowPart = fileTime.dwLowDateTime;
    ull.HighPart = fileTime.dwHighDateTime;

    // Convert to Unix time (seconds since 1970-01-01)
    return (ull.QuadPart - 116444736000000000ULL) / 10000000ULL;
}
