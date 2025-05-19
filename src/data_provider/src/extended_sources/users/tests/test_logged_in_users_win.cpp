#include "iwinapi_wrappers.hpp"
#include "logged_in_users_win.hpp"
#include "gtest/gtest.h"
#include "gmock/gmock.h"

class MockTWSapiWrapper : public ITWSapiWrapper
{
    public:
        MOCK_METHOD(bool, WTSEnumerateSessionsExW, (HANDLE hServer, DWORD *pLevel, DWORD Filter,
                                                    PWTS_SESSION_INFO_1W* ppSessionInfo,
                                                    DWORD* pCount), (override));
        MOCK_METHOD(bool, WTSQuerySessionInformationW, (HANDLE hServer,
                                                        DWORD SessionId,
                                                        WTS_INFO_CLASS WTSInfoClass,
                                                        LPWSTR* ppBuffer,
                                                        DWORD* pBytesReturned),
                                                    (override));
        MOCK_METHOD(void, WTSFreeMemory, (PVOID pMemory), (override));
        MOCK_METHOD(bool, WTSFreeMemoryEx, (WTS_TYPE_CLASS WTSTypeClass,
                                            PVOID pMemory,
                                            ULONG NumberOfEntries), (override));
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

    EXPECT_CALL(*mockTWSapiWrapper, WTSEnumerateSessionsExW(_, _, _, _, _)).WillOnce(Return(false));

    LoggedInUsersProvider provider(mockTWSapiWrapper, mockedWinBaseWrapper, mockedWinSDDLWrapper,
        mockedSecurityBaseWrapper);

    auto result = provider.collect();

    ASSERT_EQ(result.size(), 0);
}

TEST(LoggedInUsersWindowsProviderTest, CollectWithFailedConvertSidToString)
{
    // Setup
    auto mockTWSapiWrapper = std::make_shared<MockTWSapiWrapper>();
    auto mockedWinBaseWrapper = std::make_shared<MockWinBaseApiWrapper>();
    auto mockedWinSDDLWrapper = std::make_shared<MockWinSDDLWrapper>();
    auto mockedSecurityBaseWrapper = std::make_shared<MockWinSecurityBaseApiWrapper>();

    // Create test data with one active session
    WTS_SESSION_INFO_1W sessionInfo[1];
    sessionInfo[0].SessionId = 1;
    sessionInfo[0].State = WTSActive;
    sessionInfo[0].pSessionName = const_cast<LPWSTR>(L"Console");

    // Create a session info structure
    auto wtsSessionInfo = std::make_unique<WTSINFOW>();
    wcscpy_s(wtsSessionInfo->UserName, L"TestUser");
    wcscpy_s(wtsSessionInfo->Domain, L"TESTDOMAIN");
    wtsSessionInfo->ConnectTime.LowPart = 0x01234567;
    wtsSessionInfo->ConnectTime.HighPart = 0x89ABCDEF;

    // Create a client info structure for IPv4
    auto wtsClientInfo = std::make_unique<WTSCLIENTA>();
    wtsClientInfo->ClientAddressFamily = AF_INET;
    wtsClientInfo->ClientAddress[0] = 192;
    wtsClientInfo->ClientAddress[1] = 168;
    wtsClientInfo->ClientAddress[2] = 1;
    wtsClientInfo->ClientAddress[3] = 100;

    // SID buffer for the test
    auto sidBuffer = std::make_unique<BYTE[]>(100);
    std::string sidString = "S-1-5-21-1234567890-1234567890-1234567890-1001";

    EXPECT_CALL(*mockTWSapiWrapper, WTSEnumerateSessionsExW(_, _, _, _, _))
        .WillOnce(DoAll(
            SetArgPointee<3>(sessionInfo),
            SetArgPointee<4>(1),
            Return(true)
        ));

    // Succeed for WTSSessionInfo
    EXPECT_CALL(*mockTWSapiWrapper, WTSQuerySessionInformationW(_, 1, WTSSessionInfo, _, _))
        .WillOnce(DoAll(
            SetArgPointee<3>(reinterpret_cast<LPWSTR>(wtsSessionInfo.get())),
            Return(true)
        ));

    // Succeed for WTSClientInfo
    EXPECT_CALL(*mockTWSapiWrapper, WTSQuerySessionInformationW(_, 1, WTSClientInfo, _, _))
        .WillOnce(DoAll(
            SetArgPointee<3>(reinterpret_cast<LPWSTR>(wtsClientInfo.get())),
            Return(true)
        ));

    EXPECT_CALL(*mockTWSapiWrapper, WTSFreeMemory(_)).Times(2);
    EXPECT_CALL(*mockTWSapiWrapper, WTSFreeMemoryEx(WTSTypeSessionInfoLevel1, _, 1)).Times(1);

    EXPECT_CALL(*mockedWinBaseWrapper, LookupAccountNameW(nullptr, _, nullptr, _, nullptr, _, _))
        .WillOnce(DoAll(
            SetArgPointee<3>(100),
            SetArgPointee<5>(20), 
            SetArgPointee<6>(SidTypeUser),
            Return(1)
        ));

    EXPECT_CALL(*mockedWinBaseWrapper, LookupAccountNameW(nullptr, _, ::testing::NotNull(), _, ::testing::NotNull(), _, _))
        .WillOnce(DoAll(
            // Second call fills the buffer and returns success
            [&sidBuffer](LPCWSTR, LPCWSTR, PSID sid, LPDWORD sidSize, LPWSTR, LPDWORD, PSID_NAME_USE) {
                if (sid != nullptr)
                    memcpy(sid, sidBuffer.get(), *sidSize);
            },
            Return(1)
        ));

    EXPECT_CALL(*mockedSecurityBaseWrapper, IsValidSid(_))
        .WillRepeatedly(Return(TRUE));

    EXPECT_CALL(*mockedWinSDDLWrapper, ConvertSidToStringSidW(_, _))
        .WillOnce(Return(0));  // Fail

    LoggedInUsersProvider provider(mockTWSapiWrapper, mockedWinBaseWrapper, mockedWinSDDLWrapper,
        mockedSecurityBaseWrapper);

    auto result = provider.collect();

    ASSERT_EQ(result.size(), 1);
    EXPECT_EQ(result[0]["user"], "TestUser");
    EXPECT_EQ(result[0]["tty"], "Console");
    EXPECT_EQ(result[0]["host"], "192.168.1.100");
    EXPECT_EQ(result[0]["sid"], "");
    EXPECT_EQ(result[0]["registry_hive"], "HKEY_USERS\\");
}

TEST(LoggedInUsersWindowsProviderTest, CollectWithAF_UNSPECAddress)
{
    auto mockTWSapiWrapper = std::make_shared<MockTWSapiWrapper>();
    auto mockedWinBaseWrapper = std::make_shared<MockWinBaseApiWrapper>();
    auto mockedWinSDDLWrapper = std::make_shared<MockWinSDDLWrapper>();
    auto mockedSecurityBaseWrapper = std::make_shared<MockWinSecurityBaseApiWrapper>();

    WTS_SESSION_INFO_1W sessionInfo[1];
    sessionInfo[0].SessionId = 1;
    sessionInfo[0].State = WTSActive;
    sessionInfo[0].pSessionName = const_cast<LPWSTR>(L"Console");

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

    EXPECT_CALL(*mockTWSapiWrapper, WTSEnumerateSessionsExW(_, _, _, _, _))
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

    EXPECT_CALL(*mockTWSapiWrapper, WTSFreeMemory(_)).Times(3);
    EXPECT_CALL(*mockTWSapiWrapper, WTSFreeMemoryEx(WTSTypeSessionInfoLevel1, _, 1)).Times(1);

    EXPECT_CALL(*mockedWinBaseWrapper, LookupAccountNameW(nullptr, _, nullptr, _, nullptr, _, _))
        .WillOnce(DoAll(
            SetArgPointee<3>(100),
            SetArgPointee<5>(20),
            SetArgPointee<6>(SidTypeUser),
            Return(1)
        ));
        
    EXPECT_CALL(*mockedWinBaseWrapper, LookupAccountNameW(nullptr, _, ::testing::NotNull(), _, ::testing::NotNull(), _, _))
        .WillOnce(DoAll(
            [&sidBuffer](LPCWSTR, LPCWSTR, PSID sid, LPDWORD sidSize, LPWSTR, LPDWORD, PSID_NAME_USE) {
                if (sid != nullptr)
                    memcpy(sid, sidBuffer.get(), *sidSize);
            },
            Return(1)
        ));

    EXPECT_CALL(*mockedSecurityBaseWrapper, IsValidSid(_))
        .WillRepeatedly(Return(TRUE));

    EXPECT_CALL(*mockedWinSDDLWrapper, ConvertSidToStringSidW(_, _))
        .WillOnce(DoAll(
            [&sidString](PSID, LPWSTR* sidOut) {
                size_t len = sidString.length() + 1;
                *sidOut = static_cast<LPWSTR>(malloc(len * sizeof(wchar_t)));
                std::wstring wideSid(sidString.begin(), sidString.end());
                wcscpy_s(*sidOut, len, wideSid.c_str());
            },
            Return(1)
        ));

    LoggedInUsersProvider provider(mockTWSapiWrapper, mockedWinBaseWrapper, mockedWinSDDLWrapper,
        mockedSecurityBaseWrapper);

    auto result = provider.collect();
    ASSERT_EQ(result.size(), 1);
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

    WTS_SESSION_INFO_1W sessionInfo[1];
    sessionInfo[0].SessionId = 1;
    sessionInfo[0].State = WTSActive;
    sessionInfo[0].pSessionName = const_cast<LPWSTR>(L"Console");

    EXPECT_CALL(*mockTWSapiWrapper, WTSEnumerateSessionsExW(_, _, _, _, _))
        .WillOnce(DoAll(
            SetArgPointee<3>(sessionInfo),
            SetArgPointee<4>(1),
            Return(true)
        ));

    EXPECT_CALL(*mockTWSapiWrapper, WTSQuerySessionInformationW(_, 1, WTSSessionInfo, _, _))
        .WillOnce(Return(false));

    LoggedInUsersProvider provider(mockTWSapiWrapper, mockedWinBaseWrapper, mockedWinSDDLWrapper,
        mockedSecurityBaseWrapper);

    auto result = provider.collect();

    // should have no entries due to failed WTSQuerySessionInformationW
    ASSERT_EQ(result.size(), 0);
}

TEST(LoggedInUsersWindowsProviderTest, CollectWithOneValidSession)
{
    auto mockTWSapiWrapper = std::make_shared<MockTWSapiWrapper>();
    auto mockedWinBaseWrapper = std::make_shared<MockWinBaseApiWrapper>();
    auto mockedWinSDDLWrapper = std::make_shared<MockWinSDDLWrapper>();
    auto mockedSecurityBaseWrapper = std::make_shared<MockWinSecurityBaseApiWrapper>();

    WTS_SESSION_INFO_1W sessionInfo[1];
    sessionInfo[0].SessionId = 1;
    sessionInfo[0].State = WTSActive;
    sessionInfo[0].pSessionName = const_cast<LPWSTR>(L"Console");

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

    EXPECT_CALL(*mockTWSapiWrapper, WTSEnumerateSessionsExW(_, _, _, _, _))
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

    EXPECT_CALL(*mockTWSapiWrapper, WTSFreeMemory(_)).Times(2);
    EXPECT_CALL(*mockTWSapiWrapper, WTSFreeMemoryEx(WTSTypeSessionInfoLevel1, _, 1)).Times(1);

    EXPECT_CALL(*mockedWinBaseWrapper, LookupAccountNameW(nullptr, _, nullptr, _, nullptr, _, _))
        .WillOnce(DoAll(
            SetArgPointee<3>(100),
            SetArgPointee<5>(20),
            SetArgPointee<6>(SidTypeUser),
            Return(1)
        ));

    EXPECT_CALL(*mockedWinBaseWrapper, LookupAccountNameW(nullptr, _, ::testing::NotNull(), _, ::testing::NotNull(), _, _))
        .WillOnce(DoAll(
            [&sidBuffer](LPCWSTR, LPCWSTR, PSID sid, LPDWORD sidSize, LPWSTR, LPDWORD, PSID_NAME_USE) {
                if (sid != nullptr)
                    memcpy(sid, sidBuffer.get(), *sidSize);
            },
            Return(1)
        ));

    EXPECT_CALL(*mockedSecurityBaseWrapper, IsValidSid(_))
        .WillRepeatedly(Return(TRUE));

    EXPECT_CALL(*mockedWinSDDLWrapper, ConvertSidToStringSidW(_, _))
        .WillOnce(DoAll(
            [&sidString](PSID, LPWSTR* sidOut) {
                size_t len = sidString.length() + 1;
                *sidOut = static_cast<LPWSTR>(malloc(len * sizeof(wchar_t)));
                std::wstring wideSid(sidString.begin(), sidString.end());
                wcscpy_s(*sidOut, len, wideSid.c_str());
            },
            Return(1)
        ));

    LoggedInUsersProvider provider(mockTWSapiWrapper, mockedWinBaseWrapper, mockedWinSDDLWrapper,
        mockedSecurityBaseWrapper);

    auto result = provider.collect();

    ASSERT_EQ(result.size(), 1);
    EXPECT_EQ(result[0]["user"], "TestUser");
    EXPECT_EQ(result[0]["tty"], "Console");
    EXPECT_EQ(result[0]["host"], "192.168.1.100");
    EXPECT_EQ(result[0]["sid"], sidString);
    EXPECT_EQ(result[0]["registry_hive"], "HKEY_USERS\\" + sidString);
}

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
