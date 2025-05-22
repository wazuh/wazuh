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
        MOCK_METHOD(LSTATUS, RegCloseKeyWrapper, (HKEY hKey), (override));
};

TEST(UsersHelperTest, GetUserShellReturnsDefault)
{
    auto mockApi = std::make_shared<MockWindowsApiWrapper>();
    UsersHelper helper(mockApi);

    std::string sid = "S-1-5-21-1234567890-1234567890-1234567890-1001";
    EXPECT_EQ(helper.getUserShell(sid), "C:\\Windows\\system32\\cmd.exe");
}

TEST(UsersHelperTest, ProcessLocalAccountsSingleUserReturnsExpectedUser)
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
                  ::testing::SetArgPointee<5>(1),
                  ::testing::SetArgPointee<6>(1),
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

    EXPECT_CALL(*mockApi, RegOpenKeyExWWrapper(::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_))
    .WillOnce(::testing::Return(ERROR_FILE_NOT_FOUND));

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

TEST(UsersHelperTest, ProcessRoamingProfilesReturnsExpectedUsers)
{
    auto mockApi = std::make_shared<MockWindowsApiWrapper>();
    UsersHelper helper(mockApi);
    std::set<std::string> processedSids = {"S-1-5-21-1234567890-1234567890-1234567890-1001"};

    HKEY fakeRootKey = reinterpret_cast<HKEY>(0x1234);
    HKEY fakeProfileKey = reinterpret_cast<HKEY>(0x5678);
    PSID fakeSid = reinterpret_cast<PSID>(0x1002);

    EXPECT_CALL(*mockApi, RegOpenKeyExWWrapper(HKEY_LOCAL_MACHINE, ::testing::StrEq(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"), 0, KEY_READ, ::testing::_))
    .WillOnce(::testing::DoAll(::testing::SetArgPointee<4>(fakeRootKey), ::testing::Return(ERROR_SUCCESS)));

    EXPECT_CALL(*mockApi, RegQueryInfoKeyWWrapper(fakeRootKey, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_,
                                                  ::testing::_))
    .WillOnce(::testing::DoAll(::testing::SetArgPointee<4>(1), ::testing::Return(ERROR_SUCCESS)));

    EXPECT_CALL(*mockApi, RegEnumKeyWWrapper(fakeRootKey, 0, ::testing::_, ::testing::_))
    .WillOnce(::testing::DoAll(
                  ::testing::Invoke([](HKEY, DWORD, LPWSTR buffer, DWORD)
    {
        wcscpy(buffer, L"S-1-5-21-1234567890-1234567890-1234567890-1002");
    }),
    ::testing::Return(ERROR_SUCCESS)));

    EXPECT_CALL(*mockApi, ConvertStringSidToSidAWrapper(::testing::StrEq("S-1-5-21-1234567890-1234567890-1234567890-1002"), ::testing::_))
    .WillOnce(::testing::DoAll(::testing::SetArgPointee<1>(fakeSid), ::testing::Return(TRUE)));

    BYTE subAuthCount = 1;
    DWORD fakeRid = 1002;
    EXPECT_CALL(*mockApi, GetSidSubAuthorityCountWrapper(fakeSid)).WillOnce(::testing::Return(&subAuthCount));
    EXPECT_CALL(*mockApi, GetSidSubAuthorityWrapper(fakeSid, 0)).WillOnce(::testing::Return(&fakeRid));

    EXPECT_CALL(*mockApi, LookupAccountSidWWrapper(nullptr, fakeSid, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_))
    .WillOnce(::testing::DoAll(
                  ::testing::Invoke([](LPCWSTR, PSID, LPWSTR name, LPDWORD, LPWSTR, LPDWORD, SID_NAME_USE*)
    {
        if (name) wcscpy(name, L"RoamingUser");
    }),
    ::testing::Return(TRUE)));

    EXPECT_CALL(*mockApi, RegOpenKeyExWWrapper(HKEY_LOCAL_MACHINE, ::testing::StrEq(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\S-1-5-21-1234567890-1234567890-1234567890-1002"), 0,
                                               KEY_READ, ::testing::_))
    .WillOnce(::testing::DoAll(::testing::SetArgPointee<4>(fakeProfileKey), ::testing::Return(ERROR_SUCCESS)));

    EXPECT_CALL(*mockApi, RegQueryInfoKeyWWrapper(fakeProfileKey, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_,
                                                  ::testing::_, ::testing::_))
    .WillOnce(::testing::DoAll(::testing::SetArgPointee<7>(1), ::testing::SetArgPointee<9>(MAX_PATH), ::testing::Return(ERROR_SUCCESS)));

    EXPECT_CALL(*mockApi, RegQueryValueExWWrapper(fakeProfileKey, ::testing::StrEq(L"ProfileImagePath"), ::testing::_, ::testing::_, ::testing::_, ::testing::_))
    .WillOnce(::testing::DoAll(
                  ::testing::Invoke([](HKEY, LPCWSTR, LPDWORD, LPDWORD type, LPBYTE data, LPDWORD)
    {
        *type = REG_SZ;
        const wchar_t* path = L"C:\\Users\\RoamingUser";
        memcpy(data, path, (wcslen(path) + 1) * sizeof(wchar_t));
    }),
    ::testing::Return(ERROR_SUCCESS)));

    wchar_t* groupName = new wchar_t[10];
    wcscpy(groupName, L"TestGroup");
    auto userGroupsBuffer = new LOCALGROUP_USERS_INFO_0[1] { { groupName } };
    EXPECT_CALL(*mockApi, NetUserGetLocalGroupsWrapper(nullptr, ::testing::StrEq(L"RoamingUser"), 0, 0, ::testing::_, MAX_PREFERRED_LENGTH, ::testing::_, ::testing::_))
    .WillOnce(::testing::DoAll(
                  ::testing::Invoke([userGroupsBuffer](LPCWSTR, LPCWSTR, DWORD, DWORD, LPBYTE * buffer, DWORD, LPDWORD, LPDWORD)
    {
        *buffer = reinterpret_cast<LPBYTE>(userGroupsBuffer);
        return NERR_Success;
    }),
    ::testing::Return(NERR_Success)));

    auto userInfo = new USER_INFO_3{};
    userInfo->usri3_primary_group_id = 1002;
    EXPECT_CALL(*mockApi, NetUserGetInfoWrapper(nullptr, ::testing::StrEq(L"RoamingUser"), ::testing::_, ::testing::_))
    .WillOnce(::testing::DoAll(
                  ::testing::Invoke([userInfo](LPCWSTR, LPCWSTR, DWORD, LPBYTE * buffer)
    {
        *buffer = reinterpret_cast<LPBYTE>(userInfo);
        return NERR_Success;
    }),
    ::testing::Return(NERR_Success)));

    EXPECT_CALL(*mockApi, RegCloseKeyWrapper(fakeRootKey)).Times(1);
    EXPECT_CALL(*mockApi, RegCloseKeyWrapper(fakeProfileKey)).Times(1);
    EXPECT_CALL(*mockApi, FreeSidWrapper(fakeSid)).Times(1);

    auto users = helper.processRoamingProfiles(processedSids);

    ASSERT_EQ(users.size(), size_t{1});
    EXPECT_EQ(users[0].username, "RoamingUser");
    EXPECT_EQ(users[0].uid, std::uint32_t{1002});
    EXPECT_EQ(users[0].gid, std::uint32_t{1002});
    EXPECT_EQ(users[0].directory, "C:\\Users\\RoamingUser");

    delete[] userGroupsBuffer;
    delete userInfo;
}
