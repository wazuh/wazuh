#include "itwsapi_wrapper.hpp"
#include "logged_in_users_win.hpp"
#include "gtest/gtest.h"
#include "gmock/gmock.h"

class MockTWSapiWrapper : public ITWSapiWrapper
{
    public:
        MOCK_METHOD(bool, WTSEnumerateSessionsExW, (HANDLE hServer,
                                                    DWORD* pLevel,
                                                    DWORD Filter,
                                                    PWTS_SESSION_INFO_1W* ppSessionInfo,
                                                    DWORD* pCount), (override));
        MOCK_METHOD(bool, WTSQuerySessionInformationW, (HANDLE hServer,
                                                        DWORD SessionId,
                                                        WTS_INFO_CLASS WTSInfoClass,
                                                        LPWSTR* ppBuffer,
                                                        DWORD* pBytesReturned));
        MOCK_METHOD(void, WTSFreeMemory, (PVOID pMemory));
        MOCK_METHOD(bool, WTSFreeMemoryEx, (WTS_TYPE_CLASS WTSTypeClass,
                                            PVOID pMemory,
                                            ULONG NumberOfEntries));
        MOCK_METHOD(bool, LookupAccountNameW, (LPCWSTR lpSystemName,
                                               LPCWSTR lpAccountName,
                                               PSID Sid,
                                               LPDWORD cbSid,
                                               LPWSTR ReferencedDomainName,
                                               LPDWORD cchReferencedDomainName,
                                               PSID_NAME_USE peUse));
        MOCK_METHOD(bool, ConvertSidToStringSidW, (PSID Sid, LPWSTR* StringSid));
        MOCK_METHOD(bool, IsValidSid, (PSID pSid));
};

TEST(LoggedInUsersWindowsProviderTest, CollectReturnsExpectedJson)
{
    auto mockWrapper = std::make_shared<MockTWSapiWrapper>();

    LoggedInUsersProvider provider(mockWrapper);
    auto result = provider.collect();
}

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
