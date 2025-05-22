#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "users_windows_utils_wrapper.hpp"
#include "iwindows_api_wrapper.hpp"

class MockWindowsApiWrapper : public IWindowsApiWrapper
{
    public:
        MOCK_METHOD(DWORD, NetUserEnumWrapper,
                    (LPCWSTR, DWORD, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, LPDWORD), (override));

        MOCK_METHOD(DWORD, NetUserGetInfoWrapper,
                    (LPCWSTR, LPCWSTR, DWORD, LPBYTE*), (override));

        MOCK_METHOD(DWORD, RegOpenKeyExWWrapper,
                    (HKEY, LPCWSTR, DWORD, REGSAM, PHKEY), (override));

        MOCK_METHOD(DWORD, RegQueryValueExWWrapper,
                    (HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD), (override));

        MOCK_METHOD(LSTATUS, RegQueryInfoKeyWWrapper,
                    (HKEY, LPWSTR, LPDWORD, LPDWORD, LPDWORD, LPDWORD,
                     LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, PFILETIME), (override));

        MOCK_METHOD(bool, IsValidSidWrapper, (PSID), (override));

        MOCK_METHOD(BOOL, ConvertSidToStringSidAWrapper, (PSID, LPSTR*), (override));

        MOCK_METHOD(BOOL, ConvertStringSidToSidAWrapper, (LPCSTR, PSID*), (override));

        MOCK_METHOD(BOOL, LookupAccountSidWWrapper,
                    (LPCWSTR, PSID, LPWSTR, LPDWORD, LPWSTR, LPDWORD, PSID_NAME_USE), (override));

        MOCK_METHOD(bool, LookupAccountNameWWrapper,
                    (LPCWSTR, LPCWSTR, PSID, LPDWORD, LPWSTR, LPDWORD, PSID_NAME_USE), (override));

        MOCK_METHOD(void, FreeSidWrapper, (LPVOID), (override));

        MOCK_METHOD(DWORD, NetUserGetLocalGroupsWrapper,
                    (LPCWSTR, LPCWSTR, DWORD, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD), (override));

        MOCK_METHOD(PUCHAR, GetSidSubAuthorityCountWrapper, (PSID), (override));

        MOCK_METHOD(PDWORD, GetSidSubAuthorityWrapper, (PSID, DWORD), (override));

        MOCK_METHOD(LSTATUS, RegEnumKeyWWrapper, (HKEY, DWORD, LPWSTR, DWORD), (override));

        MOCK_METHOD(DWORD, GetLastErrorWrapper, (), (override));
};

TEST(UsersHelperTest, GetUserShellReturnsDefault)
{
    auto mockApi = std::make_shared<MockWindowsApiWrapper>();
    UsersHelper helper(mockApi);

    std::string sid = "S-1-5-21-1234567890-1234567890-1234567890-1001";
    EXPECT_EQ(helper.getUserShell(sid), "C:\\Windows\\system32\\cmd.exe");
}

TEST(UsersHelperTest, ProcessLocalAccounts_SingleUser_ReturnsExpectedUser)
{
    auto mockApi = std::make_shared<MockWindowsApiWrapper>();
    UsersHelper helper(mockApi);
    std::set<std::string> processedSids;

    LPCWSTR testUsername = L"TestUser";
    LPCWSTR testComment = L"Test comment";
    PSID fakeSid = reinterpret_cast<PSID>(0xABCDEF);
    LPSTR fakeSidString = const_cast<LPSTR>("S-1-5-21-1000");
    DWORD fakeRid = 1000;

    auto usersInfo0 = new USER_INFO_0[1];
    usersInfo0[0].usri0_name = const_cast<LPWSTR>(testUsername);

    auto userInfo4 = new USER_INFO_4;
    userInfo4->usri4_name = const_cast<LPWSTR>(testUsername);
    userInfo4->usri4_comment = const_cast<LPWSTR>(testComment);
    userInfo4->usri4_user_sid = fakeSid;

    auto userInfo3 = new USER_INFO_3;
    userInfo3->usri3_primary_group_id = fakeRid;

    EXPECT_CALL(*mockApi, NetUserEnumWrapper(::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_))
    .WillOnce(::testing::DoAll(
                  ::testing::SetArgPointee<3>(reinterpret_cast<LPBYTE>(usersInfo0)),
                  ::testing::Return(NERR_Success)
              ));

    EXPECT_CALL(*mockApi, NetUserGetInfoWrapper(::testing::_, ::testing::_, ::testing::_, ::testing::_))
    .WillOnce(::testing::DoAll(
                  ::testing::SetArgPointee<3>(reinterpret_cast<LPBYTE>(userInfo4)),
                  ::testing::Return(NERR_Success)
              ));

    EXPECT_CALL(*mockApi, ConvertSidToStringSidAWrapper(fakeSid, ::testing::_))
    .WillOnce(::testing::DoAll(
                  ::testing::SetArgPointee<1>(fakeSidString),
                  ::testing::Return(TRUE)
              ));

    EXPECT_CALL(*mockApi, FreeSidWrapper(fakeSidString)).Times(1);

    BYTE subAuthCount = 2;
    EXPECT_CALL(*mockApi, GetSidSubAuthorityCountWrapper(fakeSid))
    .WillOnce(::testing::Return(&subAuthCount));

    EXPECT_CALL(*mockApi, GetSidSubAuthorityWrapper(fakeSid, 1))
    .WillOnce(::testing::Return(&fakeRid));

    EXPECT_CALL(*mockApi, NetUserGetLocalGroupsWrapper(::testing::_, testUsername, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_))
    .WillOnce(::testing::Return(ERROR_ACCESS_DENIED));

    EXPECT_CALL(*mockApi, NetUserGetInfoWrapper(::testing::_, testUsername, 3, ::testing::_))
    .WillOnce(::testing::DoAll(
                  ::testing::SetArgPointee<3>(reinterpret_cast<LPBYTE>(userInfo3)),
                  ::testing::Return(NERR_Success)
              ));

    auto users = helper.processLocalAccounts(processedSids);

    EXPECT_EQ(users.size(), size_t{1});
    const auto& user = users[0];

    EXPECT_EQ(user.username, "TestUser");
    EXPECT_EQ(user.description, "Test comment");
    EXPECT_EQ(user.uid, std::uint32_t{1000});
    EXPECT_EQ(user.gid, std::uint32_t{1000});
    EXPECT_EQ(user.sid, "S-1-5-21-1000");
    EXPECT_EQ(user.type, "local");

    delete[] usersInfo0;
    delete userInfo4;
    delete userInfo3;
}

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
