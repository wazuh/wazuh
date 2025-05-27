/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "logged_in_users_win.hpp"
#include "iwinapi_wrappers.hpp"
#include "iusers_utils_wrapper.hpp"

class MockTWSapiWrapper : public ITWSapiWrapper
{
    public:
        MOCK_METHOD(bool, WTSEnumerateSessionsW, (HANDLE hServer, DWORD pLevel, DWORD Filter,
                                                  PWTS_SESSION_INFOW* ppSessionInfo,
                                                  DWORD* pCount), (override));
        MOCK_METHOD(bool, WTSQuerySessionInformationW, (HANDLE hServer,
                                                        DWORD SessionId,
                                                        WTS_INFO_CLASS WTSInfoClass,
                                                        LPWSTR* ppBuffer,
                                                        DWORD* pBytesReturned),
                    (override));
        MOCK_METHOD(void, WTSFreeMemory, (PVOID pMemory), (override));
};

class MockWinBaseApiWrapper : public IWinBaseApiWrapper
{
    public:
        MOCK_METHOD(bool, LookupAccountNameW, (LPCWSTR lpSystemName,
                                               LPCWSTR lpAccountName,
                                               PSID Sid,
                                               LPDWORD cbSid,
                                               LPWSTR ReferencedDomainName,
                                               LPDWORD cchReferencedDomainName,
                                               PSID_NAME_USE peUse), (override));
};

class MockWinSDDLWrapper : public IWinSDDLWrapper
{
    public:
        MOCK_METHOD(bool, ConvertSidToStringSidW, (PSID Sid, LPWSTR* StringSid), (override));

};

class MockWinSecurityBaseApiWrapper : public IWinSecurityBaseApiWrapper
{
    public:
        MOCK_METHOD(bool, IsValidSid, (PSID pSid), (override));
};

class MockUsersHelper : public IUsersHelper
{
    public:
        MOCK_METHOD(std::string, getUserShell, (const std::string& sid), (override));
        MOCK_METHOD(std::vector<User>, processLocalAccounts, (std::set<std::string>& processed_sids), (override));
        MOCK_METHOD(std::vector<User>, processRoamingProfiles, (std::set<std::string>& processed_sids), (override));
        MOCK_METHOD(std::unique_ptr<BYTE[]>, getSidFromAccountName, (const std::wstring& accountNameInput), (override));
        MOCK_METHOD(std::string, psidToString, (PSID sid), (override));
};


using ::testing::_;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::DoAll;

TEST(LoggedInUsersWindowsProviderTest, CollectReturnsEmpty)
{
    auto mockTWSapiWrapper = std::make_shared<MockTWSapiWrapper>();
    auto mockedWinBaseWrapper = std::make_shared<MockWinBaseApiWrapper>();
    auto mockedWinSDDLWrapper = std::make_shared<MockWinSDDLWrapper>();
    auto mockedSecurityBaseWrapper = std::make_shared<MockWinSecurityBaseApiWrapper>();
    auto mockedUsersHelper = std::make_shared<MockUsersHelper>();

    EXPECT_CALL(*mockTWSapiWrapper, WTSEnumerateSessionsW(_, _, _, _, _)).WillOnce(Return(false));

    LoggedInUsersProvider provider(mockTWSapiWrapper, mockedWinBaseWrapper, mockedWinSDDLWrapper,
                                   mockedSecurityBaseWrapper, mockedUsersHelper);

    auto result = provider.collect();

    ASSERT_EQ(result.size(), static_cast<size_t>(0));
}

TEST(LoggedInUsersWindowsProviderTest, CollectWithAF_UNSPECAddress)
{
    auto mockTWSapiWrapper = std::make_shared<MockTWSapiWrapper>();
    auto mockedWinBaseWrapper = std::make_shared<MockWinBaseApiWrapper>();
    auto mockedWinSDDLWrapper = std::make_shared<MockWinSDDLWrapper>();
    auto mockedSecurityBaseWrapper = std::make_shared<MockWinSecurityBaseApiWrapper>();
    auto mockedUsersHelper = std::make_shared<MockUsersHelper>();

    WTS_SESSION_INFOW sessionInfo[1];
    sessionInfo[0].SessionId = 1;
    sessionInfo[0].State = WTSActive;
    sessionInfo[0].pWinStationName = const_cast<LPWSTR>(L"Console");

    auto wtsSessionInfo = std::make_unique<WTSINFOW>();
    wcscpy_s(wtsSessionInfo->UserName, L"LocalUser");
    wcscpy_s(wtsSessionInfo->Domain, L"TESTDOMAIN");
    wtsSessionInfo->ConnectTime.LowPart = 0x01234567;
    wtsSessionInfo->ConnectTime.HighPart = 0x89ABCDEF;

    auto wtsClientInfo = std::make_unique<WTSCLIENTA>();
    wtsClientInfo->ClientAddressFamily = AF_UNSPEC;
    auto clientName = const_cast<LPWSTR>(L"LOCAL");

    auto sidBuffer = std::make_unique<BYTE[]>(100);
    std::string sidString = "S-1-5-21-1234567890-1234567890-1234567890-1003";

    EXPECT_CALL(*mockTWSapiWrapper, WTSEnumerateSessionsW(_, _, _, _, _))
    .WillOnce(DoAll(
                  SetArgPointee<3>(sessionInfo),
                  SetArgPointee<4>(1),
                  Return(true)
              ));

    EXPECT_CALL(*mockTWSapiWrapper, WTSQuerySessionInformationW(_, 1, WTSSessionInfo, _, _))
    .WillOnce(DoAll(
                  SetArgPointee<3>(reinterpret_cast<LPWSTR>(wtsSessionInfo.get())),
                  Return(true)
              ));

    EXPECT_CALL(*mockTWSapiWrapper, WTSQuerySessionInformationW(_, 1, WTSClientInfo, _, _))
    .WillOnce(DoAll(
                  SetArgPointee<3>(reinterpret_cast<LPWSTR>(wtsClientInfo.get())),
                  Return(true)
              ));

    EXPECT_CALL(*mockTWSapiWrapper, WTSQuerySessionInformationW(_, 1, WTSClientName, _, _))
    .WillOnce(DoAll(
                  SetArgPointee<3>(clientName),
                  Return(true)
              ));

    EXPECT_CALL(*mockTWSapiWrapper, WTSFreeMemory(_)).Times(4);

    EXPECT_CALL(*mockedUsersHelper, getSidFromAccountName(_))
    .WillOnce(Return(testing::ByMove(std::move(sidBuffer))));

    EXPECT_CALL(*mockedUsersHelper, psidToString(_))
    .WillOnce(Return(sidString));

    LoggedInUsersProvider provider(mockTWSapiWrapper, mockedWinBaseWrapper, mockedWinSDDLWrapper,
                                   mockedSecurityBaseWrapper, mockedUsersHelper);

    auto result = provider.collect();
    ASSERT_EQ(result.size(), static_cast<size_t>(1));
    EXPECT_EQ(result[0]["user"], "LocalUser");
    EXPECT_EQ(result[0]["tty"], "Console");
    EXPECT_EQ(result[0]["host"], "LOCAL");
    EXPECT_EQ(result[0]["sid"], sidString);
    EXPECT_EQ(result[0]["registry_hive"], "HKEY_USERS\\" + sidString);
}

TEST(LoggedInUsersWindowsProviderTest, CollectWithFailedSessionInfoQuery)
{
    auto mockTWSapiWrapper = std::make_shared<MockTWSapiWrapper>();
    auto mockedWinBaseWrapper = std::make_shared<MockWinBaseApiWrapper>();
    auto mockedWinSDDLWrapper = std::make_shared<MockWinSDDLWrapper>();
    auto mockedSecurityBaseWrapper = std::make_shared<MockWinSecurityBaseApiWrapper>();
    auto mockedUsersHelper = std::make_shared<MockUsersHelper>();

    WTS_SESSION_INFOW sessionInfo[1];
    sessionInfo[0].SessionId = 1;
    sessionInfo[0].State = WTSActive;
    sessionInfo[0].pWinStationName = const_cast<LPWSTR>(L"Console");

    EXPECT_CALL(*mockTWSapiWrapper, WTSEnumerateSessionsW(_, _, _, _, _))
    .WillOnce(DoAll(
                  SetArgPointee<3>(sessionInfo),
                  SetArgPointee<4>(1),
                  Return(true)
              ));

    EXPECT_CALL(*mockTWSapiWrapper, WTSQuerySessionInformationW(_, 1, WTSSessionInfo, _, _))
    .WillOnce(Return(false));

    EXPECT_CALL(*mockTWSapiWrapper, WTSFreeMemory(_)).Times(1);

    LoggedInUsersProvider provider(mockTWSapiWrapper, mockedWinBaseWrapper, mockedWinSDDLWrapper,
                                   mockedSecurityBaseWrapper, mockedUsersHelper);

    auto result = provider.collect();

    // should have no entries due to failed WTSQuerySessionInformationW
    ASSERT_EQ(result.size(), static_cast<size_t>(0));
}

TEST(LoggedInUsersWindowsProviderTest, CollectWithOneValidSession)
{
    auto mockTWSapiWrapper = std::make_shared<MockTWSapiWrapper>();
    auto mockedWinBaseWrapper = std::make_shared<MockWinBaseApiWrapper>();
    auto mockedWinSDDLWrapper = std::make_shared<MockWinSDDLWrapper>();
    auto mockedSecurityBaseWrapper = std::make_shared<MockWinSecurityBaseApiWrapper>();
    auto mockedUsersHelper = std::make_shared<MockUsersHelper>();

    WTS_SESSION_INFOW sessionInfo[1];
    sessionInfo[0].SessionId = 1;
    sessionInfo[0].State = WTSActive;
    sessionInfo[0].pWinStationName = const_cast<LPWSTR>(L"Console");

    auto wtsSessionInfo = std::make_unique<WTSINFOW>();
    wcscpy_s(wtsSessionInfo->UserName, L"TestUser");
    wcscpy_s(wtsSessionInfo->Domain, L"TESTDOMAIN");
    wtsSessionInfo->ConnectTime.LowPart = 0x01234567;
    wtsSessionInfo->ConnectTime.HighPart = 0x89ABCDEF;

    auto wtsClientInfo = std::make_unique<WTSCLIENTA>();
    wtsClientInfo->ClientAddressFamily = AF_INET;
    wtsClientInfo->ClientAddress[0] = 192;
    wtsClientInfo->ClientAddress[1] = 168;
    wtsClientInfo->ClientAddress[2] = 1;
    wtsClientInfo->ClientAddress[3] = 100;

    auto sidBuffer = std::make_unique<BYTE[]>(100);
    std::string sidString = "S-1-5-21-1234567890-1234567890-1234567890-1001";

    EXPECT_CALL(*mockTWSapiWrapper, WTSEnumerateSessionsW(_, _, _, _, _))
    .WillOnce(DoAll(
                  SetArgPointee<3>(sessionInfo),
                  SetArgPointee<4>(1),
                  Return(true)
              ));

    EXPECT_CALL(*mockTWSapiWrapper, WTSQuerySessionInformationW(_, 1, WTSSessionInfo, _, _))
    .WillOnce(DoAll(
                  SetArgPointee<3>(reinterpret_cast<LPWSTR>(wtsSessionInfo.get())),
                  Return(true)
              ));

    EXPECT_CALL(*mockTWSapiWrapper, WTSQuerySessionInformationW(_, 1, WTSClientInfo, _, _))
    .WillOnce(DoAll(
                  SetArgPointee<3>(reinterpret_cast<LPWSTR>(wtsClientInfo.get())),
                  Return(true)
              ));

    // No need for WTSClientName query for this test

    EXPECT_CALL(*mockTWSapiWrapper, WTSFreeMemory(_)).Times(3);

    EXPECT_CALL(*mockedUsersHelper, getSidFromAccountName(_))
    .WillOnce(Return(testing::ByMove(std::move(sidBuffer))));

    EXPECT_CALL(*mockedUsersHelper, psidToString(_))
    .WillOnce(Return(sidString));

    LoggedInUsersProvider provider(mockTWSapiWrapper, mockedWinBaseWrapper, mockedWinSDDLWrapper,
                                   mockedSecurityBaseWrapper, mockedUsersHelper);

    auto result = provider.collect();

    ASSERT_EQ(result.size(), static_cast<size_t>(1));
    EXPECT_EQ(result[0]["user"], "TestUser");
    EXPECT_EQ(result[0]["tty"], "Console");
    EXPECT_EQ(result[0]["host"], "192.168.1.100");
    EXPECT_EQ(result[0]["sid"], sidString);
    EXPECT_EQ(result[0]["registry_hive"], "HKEY_USERS\\" + sidString);
}
