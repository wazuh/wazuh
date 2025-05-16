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


TEST(LoggedInUsersWindowsProviderTest, CollectReturnsExpectedJson)
{
    auto mockTWSapiWrapper = std::make_shared<MockTWSapiWrapper>();
    auto mockedWinBaseWrapper = std::make_shared<MockWinBaseApiWrapper>();
    auto mockedWinSDDLWrapper = std::make_shared<MockWinSDDLWrapper>();
    auto mockedSecurityBaseWrapper = std::make_shared<MockWinSecurityBaseApiWrapper>();

    PWTS_SESSION_INFO_1W ppSessionInfo;
    DWORD pCount = 0;

    LoggedInUsersProvider provider(mockTWSapiWrapper, mockedWinBaseWrapper, mockedWinSDDLWrapper,
        mockedSecurityBaseWrapper);
    auto result = provider.collect();

    EXPECT_CALL(*mockTWSapiWrapper, WTSEnumerateSessionsExW(::testing::_, ::testing::_,
        ::testing::_, &ppSessionInfo, &pCount))
    .WillOnce(::testing::Return(false));

    ASSERT_EQ(result.size(), 0);
}

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
