/* Copyright (C) Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "users_utils_wrapper.hpp"
#include "iwindows_api_wrapper.hpp"
#include "users_windows.hpp"

namespace
{
    // The code under test frees NetAPI buffers with NetApiBufferFree and SID strings with LocalFree,
    // so the mocks allocate them the same way
    template<typename T>
    T* netApiBuffer(DWORD count = 1)
    {
        LPVOID buffer = nullptr;
        NetApiBufferAllocate(static_cast<DWORD>(sizeof(T) * count), &buffer);
        memset(buffer, 0, sizeof(T) * count);
        return static_cast<T*>(buffer);
    }

    LPWSTR localString(const std::wstring& value)
    {
        auto buffer = static_cast<LPWSTR>(LocalAlloc(LMEM_FIXED, (value.size() + 1) * sizeof(wchar_t)));
        wcscpy(buffer, value.c_str());
        return buffer;
    }
} // namespace

class MockWindowsApiWrapper : public IWindowsApiWrapper
{
    public:
        MOCK_METHOD(DWORD, NetUserEnumWrapper,
                    (LPCWSTR, DWORD, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, LPDWORD), (override));
        MOCK_METHOD(DWORD, NetLocalGroupEnumWrapper,
                    (LPCWSTR, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, LPDWORD), (override));
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
        MOCK_METHOD(bool, ConvertSidToStringSidWWrapper, (PSID, LPWSTR*), (override));
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

class UsersHelperTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            // Reset cache before each test to avoid memory accumulation
            UsersHelper::resetCache();
            UsersHelper::resetPasswordChangeHistory();
        }
};

TEST_F(UsersHelperTest, GetUserShellReturnsDefault)
{
    auto mockApi = std::make_shared<MockWindowsApiWrapper>();
    UsersHelper helper(mockApi);

    std::string sid = "S-1-5-21-1234567890-1234567890-1234567890-1001";
    EXPECT_EQ(helper.getUserShell(sid), "C:\\Windows\\system32\\cmd.exe");
}

TEST_F(UsersHelperTest, ProcessLocalAccountsSingleUserReturnsExpectedUser)
{
    auto mockApi = std::make_shared<MockWindowsApiWrapper>();
    std::set<std::string> processedSids;

    LPCWSTR testUsername = L"TestUser";
    LPCWSTR testFullName = L"Test Full Name";
    LPCWSTR testComment = L"Test comment";
    constexpr std::time_t now = 1'800'000'000;
    constexpr DWORD passwordAge = 3600;
    UsersHelper helper(mockApi, [] { return now; });
    PSID fakeSid = reinterpret_cast<PSID>(0xABCDEF);
    std::string sidString = "S-1-5-21-1000";
    DWORD fakeRid = 1000;

    auto usersInfo0 = netApiBuffer<USER_INFO_0>();
    usersInfo0[0].usri0_name = const_cast<LPWSTR>(testUsername);

    auto userInfo4 = netApiBuffer<USER_INFO_4>();
    userInfo4->usri4_name = const_cast<LPWSTR>(testUsername);
    userInfo4->usri4_full_name = const_cast<LPWSTR>(testFullName);
    userInfo4->usri4_comment = const_cast<LPWSTR>(testComment);
    userInfo4->usri4_password_age = passwordAge;
    userInfo4->usri4_user_sid = fakeSid;

    auto userInfo3 = netApiBuffer<USER_INFO_3>();
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

    EXPECT_CALL(*mockApi, ConvertSidToStringSidWWrapper(fakeSid, ::testing::_))
    .WillOnce(::testing::DoAll(
                  [&sidString](PSID, LPWSTR * sidOut)
    {
        *sidOut = localString(std::wstring(sidString.begin(), sidString.end()));
    },
    ::testing::Return(1)));

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

    // getRoamingProfileSids() is called first - mock it to return empty (FILE_NOT_FOUND)
    HKEY fakeProfileListKey = reinterpret_cast<HKEY>(0x9999);
    EXPECT_CALL(*mockApi, RegOpenKeyExWWrapper(HKEY_LOCAL_MACHINE, ::testing::StrEq(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"), 0, KEY_READ, ::testing::_))
    .WillOnce(::testing::DoAll(::testing::SetArgPointee<4>(fakeProfileListKey), ::testing::Return(ERROR_SUCCESS)));

    EXPECT_CALL(*mockApi, RegQueryInfoKeyWWrapper(fakeProfileListKey, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_,
                                                  ::testing::_, ::testing::_))
    .WillOnce(::testing::DoAll(::testing::SetArgPointee<4>(0), ::testing::Return(ERROR_SUCCESS)));

    EXPECT_CALL(*mockApi, RegCloseKeyWrapper(fakeProfileListKey))
    .WillOnce(::testing::Return(ERROR_SUCCESS));

    // getUserHomeDir() calls RegOpenKeyExWWrapper for each user
    EXPECT_CALL(*mockApi, RegOpenKeyExWWrapper(HKEY_LOCAL_MACHINE, ::testing::HasSubstr(L"ProfileList\\S-1-5-21-1000"), 0, KEY_READ, ::testing::_))
    .WillOnce(::testing::Return(ERROR_FILE_NOT_FOUND));

    auto users = helper.processLocalAccounts(processedSids);

    EXPECT_EQ(users.size(), size_t{1});
    const auto& user = users[0];

    EXPECT_EQ(user.username, "TestUser");
    EXPECT_EQ(user.full_name, "Test Full Name");
    EXPECT_EQ(user.description, "Test comment");
    EXPECT_EQ(user.password_last_change, std::uint64_t{now - passwordAge});
    EXPECT_EQ(user.uid, std::uint32_t{1000});
    EXPECT_EQ(user.gid, std::uint32_t{1000});
    EXPECT_EQ(user.sid, "S-1-5-21-1000");
    EXPECT_EQ(user.type, "local");
}

TEST_F(UsersHelperTest, ProcessRoamingProfilesReturnsExpectedUsers)
{
    auto mockApi = std::make_shared<MockWindowsApiWrapper>();
    constexpr std::time_t now = 1'800'000'000;
    constexpr DWORD passwordAge = 7200;
    UsersHelper helper(mockApi, [] { return now; });
    std::set<std::string> processedSids = {"S-1-5-21-1234567890-1234567890-1234567890-1001"};

    HKEY fakeRootKey = reinterpret_cast<HKEY>(0x1234);
    HKEY fakeProfileKey = reinterpret_cast<HKEY>(0x5678);
    PSID fakeSid = reinterpret_cast<PSID>(0x1002);

    // Call getRoamingProfileSids()
    EXPECT_CALL(*mockApi, RegOpenKeyExWWrapper(HKEY_LOCAL_MACHINE, ::testing::StrEq(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"), 0, KEY_READ, ::testing::_))
    .WillOnce(::testing::DoAll(::testing::SetArgPointee<4>(fakeRootKey), ::testing::Return(ERROR_SUCCESS)));

    EXPECT_CALL(*mockApi, RegQueryInfoKeyWWrapper(fakeRootKey, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_,
                                                  ::testing::_))
    .WillOnce(::testing::DoAll(::testing::SetArgPointee<4>(1), ::testing::Return(ERROR_SUCCESS)));

    EXPECT_CALL(*mockApi, RegEnumKeyWWrapper(fakeRootKey, 0, ::testing::_, ::testing::_))
    .WillOnce(::testing::DoAll(
                  ::testing::Invoke([](HKEY, DWORD, LPWSTR buffer, DWORD length)
    {
        const wchar_t* sid = L"S-1-5-21-1234567890-1234567890-1234567890-1002";
        wcsncpy(buffer, sid, length);
        buffer[length - 1] = L'\0';
    }),
    ::testing::Return(ERROR_SUCCESS)));

    // All subsequent calls return ERROR_NO_MORE_ITEMS to stop iteration
    EXPECT_CALL(*mockApi, RegEnumKeyWWrapper(fakeRootKey, ::testing::Ge(1), ::testing::_, ::testing::_))
    .WillRepeatedly(::testing::Return(ERROR_NO_MORE_ITEMS));

    // RegCloseKeyWrapper may be called by RAII destructors
    EXPECT_CALL(*mockApi, RegCloseKeyWrapper(::testing::_))
    .Times(::testing::AtLeast(0))
    .WillRepeatedly(::testing::Return(ERROR_SUCCESS));

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

    auto userGroupsBuffer = netApiBuffer<LOCALGROUP_USERS_INFO_0>();
    userGroupsBuffer[0].lgrui0_name = const_cast<LPWSTR>(L"TestGroup");
    EXPECT_CALL(*mockApi, NetUserGetLocalGroupsWrapper(nullptr, ::testing::StrEq(L"RoamingUser"), 0, 0, ::testing::_, MAX_PREFERRED_LENGTH, ::testing::_, ::testing::_))
    .WillOnce(::testing::DoAll(
                  ::testing::Invoke([userGroupsBuffer](LPCWSTR, LPCWSTR, DWORD, DWORD, LPBYTE * buffer, DWORD, LPDWORD, LPDWORD)
    {
        *buffer = reinterpret_cast<LPBYTE>(userGroupsBuffer);
        return NERR_Success;
    }),
    ::testing::Return(NERR_Success)));

    PSID accountSid = reinterpret_cast<PSID>(0x2002);
    auto userInfo = netApiBuffer<USER_INFO_4>();
    userInfo->usri4_full_name = const_cast<LPWSTR>(L"Roaming Full Name");
    userInfo->usri4_comment = const_cast<LPWSTR>(L"Comment for RoamingUser");
    userInfo->usri4_password_age = passwordAge;
    userInfo->usri4_user_sid = accountSid;
    EXPECT_CALL(*mockApi, NetUserGetInfoWrapper(nullptr, ::testing::StrEq(L"RoamingUser"), 4, ::testing::_))
    .WillOnce(::testing::DoAll(
                  ::testing::Invoke([userInfo](LPCWSTR, LPCWSTR, DWORD, LPBYTE * buffer)
    {
        *buffer = reinterpret_cast<LPBYTE>(userInfo);
        return NERR_Success;
    }),
    ::testing::Return(NERR_Success)));
    EXPECT_CALL(*mockApi, ConvertSidToStringSidWWrapper(accountSid, ::testing::_))
    .WillOnce(::testing::DoAll(
                  ::testing::Invoke([](PSID, LPWSTR * sidOut)
    {
        *sidOut = localString(L"S-1-5-21-1234567890-1234567890-1234567890-1002");
    }),
    ::testing::Return(true)));

    EXPECT_CALL(*mockApi, RegCloseKeyWrapper(fakeRootKey)).Times(1);
    EXPECT_CALL(*mockApi, RegCloseKeyWrapper(fakeProfileKey)).Times(1);
    EXPECT_CALL(*mockApi, FreeSidWrapper(fakeSid)).Times(1);

    auto users = helper.processRoamingProfiles(processedSids);

    ASSERT_EQ(users.size(), size_t{1});
    EXPECT_EQ(users[0].username, "RoamingUser");
    EXPECT_EQ(users[0].uid, std::uint32_t{1002});
    EXPECT_EQ(users[0].gid, std::uint32_t{1002});
    EXPECT_EQ(users[0].directory, "C:\\Users\\RoamingUser");
    EXPECT_EQ(users[0].full_name, "Roaming Full Name");
    EXPECT_EQ(users[0].description, "Comment for RoamingUser");
    EXPECT_EQ(users[0].password_last_change, std::uint64_t{now - passwordAge});
}

TEST_F(UsersHelperTest, ProcessRoamingProfilesWithoutUserInfoLeavesFullNameAndPasswordLastChangeEmpty)
{
    auto mockApi = std::make_shared<MockWindowsApiWrapper>();
    UsersHelper helper(mockApi, [] { return 1'800'000'000; });
    std::set<std::string> processedSids;

    HKEY fakeRootKey = reinterpret_cast<HKEY>(0x1234);
    PSID fakeSid = reinterpret_cast<PSID>(0x1003);
    BYTE subAuthCount = 1;
    DWORD fakeRid = 1003;

    EXPECT_CALL(*mockApi, RegOpenKeyExWWrapper(HKEY_LOCAL_MACHINE, ::testing::StrEq(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"), 0, KEY_READ, ::testing::_))
    .WillOnce(::testing::DoAll(::testing::SetArgPointee<4>(fakeRootKey), ::testing::Return(ERROR_SUCCESS)));
    EXPECT_CALL(*mockApi, RegOpenKeyExWWrapper(HKEY_LOCAL_MACHINE, ::testing::HasSubstr(L"ProfileList\\S-1-5-21-1003"), 0, KEY_READ, ::testing::_))
    .WillOnce(::testing::Return(ERROR_FILE_NOT_FOUND));
    EXPECT_CALL(*mockApi, RegQueryInfoKeyWWrapper(fakeRootKey, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_,
                                                  ::testing::_, ::testing::_))
    .WillOnce(::testing::DoAll(::testing::SetArgPointee<4>(1), ::testing::Return(ERROR_SUCCESS)));
    EXPECT_CALL(*mockApi, RegEnumKeyWWrapper(fakeRootKey, 0, ::testing::_, ::testing::_))
    .WillOnce(::testing::DoAll(
                  ::testing::Invoke([](HKEY, DWORD, LPWSTR buffer, DWORD length)
    {
        wcsncpy(buffer, L"S-1-5-21-1003", length);
        buffer[length - 1] = L'\0';
    }),
    ::testing::Return(ERROR_SUCCESS)));
    EXPECT_CALL(*mockApi, RegCloseKeyWrapper(::testing::_)).WillRepeatedly(::testing::Return(ERROR_SUCCESS));
    EXPECT_CALL(*mockApi, ConvertStringSidToSidAWrapper(::testing::StrEq("S-1-5-21-1003"), ::testing::_))
    .WillOnce(::testing::DoAll(::testing::SetArgPointee<1>(fakeSid), ::testing::Return(TRUE)));
    EXPECT_CALL(*mockApi, GetSidSubAuthorityCountWrapper(fakeSid)).WillOnce(::testing::Return(&subAuthCount));
    EXPECT_CALL(*mockApi, GetSidSubAuthorityWrapper(fakeSid, 0)).WillOnce(::testing::Return(&fakeRid));
    EXPECT_CALL(*mockApi, LookupAccountSidWWrapper(nullptr, fakeSid, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_))
    .WillOnce(::testing::DoAll(
                  ::testing::Invoke([](LPCWSTR, PSID, LPWSTR name, LPDWORD, LPWSTR, LPDWORD, SID_NAME_USE*)
    {
        if (name) wcscpy(name, L"SystemLikeUser");
    }),
    ::testing::Return(TRUE)));
    EXPECT_CALL(*mockApi, NetUserGetLocalGroupsWrapper(::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_))
    .WillOnce(::testing::Return(ERROR_ACCESS_DENIED));
    // Level 3 (primary group) and level 4 (full name, password age) both fail
    EXPECT_CALL(*mockApi, NetUserGetInfoWrapper(nullptr, ::testing::StrEq(L"SystemLikeUser"), 3, ::testing::_))
    .WillOnce(::testing::Return(NERR_UserNotFound));
    EXPECT_CALL(*mockApi, NetUserGetInfoWrapper(nullptr, ::testing::StrEq(L"SystemLikeUser"), 4, ::testing::_))
    .WillOnce(::testing::Return(NERR_UserNotFound));
    EXPECT_CALL(*mockApi, FreeSidWrapper(fakeSid)).Times(1);

    auto users = helper.processRoamingProfiles(processedSids);

    ASSERT_EQ(users.size(), size_t{1});
    EXPECT_EQ(users[0].username, "SystemLikeUser");
    EXPECT_EQ(users[0].gid, std::uint32_t{1003});
    EXPECT_TRUE(users[0].full_name.empty());
    EXPECT_EQ(users[0].password_last_change, std::uint64_t{0});
}

TEST_F(UsersHelperTest, ProcessRoamingProfilesIgnoresLocalAccountWithTheSameName)
{
    auto mockApi = std::make_shared<MockWindowsApiWrapper>();
    UsersHelper helper(mockApi, [] { return 1'800'000'000; });
    std::set<std::string> processedSids;

    HKEY fakeRootKey = reinterpret_cast<HKEY>(0x1234);
    PSID fakeSid = reinterpret_cast<PSID>(0x1004);
    PSID localAccountSid = reinterpret_cast<PSID>(0x2004);
    BYTE subAuthCount = 1;
    DWORD fakeRid = 1004;

    EXPECT_CALL(*mockApi, RegOpenKeyExWWrapper(HKEY_LOCAL_MACHINE, ::testing::StrEq(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"), 0, KEY_READ, ::testing::_))
    .WillOnce(::testing::DoAll(::testing::SetArgPointee<4>(fakeRootKey), ::testing::Return(ERROR_SUCCESS)));
    EXPECT_CALL(*mockApi, RegOpenKeyExWWrapper(HKEY_LOCAL_MACHINE, ::testing::HasSubstr(L"ProfileList\\S-1-5-21-1004"), 0, KEY_READ, ::testing::_))
    .WillOnce(::testing::Return(ERROR_FILE_NOT_FOUND));
    EXPECT_CALL(*mockApi, RegQueryInfoKeyWWrapper(fakeRootKey, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_,
                                                  ::testing::_, ::testing::_))
    .WillOnce(::testing::DoAll(::testing::SetArgPointee<4>(1), ::testing::Return(ERROR_SUCCESS)));
    EXPECT_CALL(*mockApi, RegEnumKeyWWrapper(fakeRootKey, 0, ::testing::_, ::testing::_))
    .WillOnce(::testing::DoAll(
                  ::testing::Invoke([](HKEY, DWORD, LPWSTR buffer, DWORD length)
    {
        wcsncpy(buffer, L"S-1-5-21-1004", length);
        buffer[length - 1] = L'\0';
    }),
    ::testing::Return(ERROR_SUCCESS)));
    EXPECT_CALL(*mockApi, RegCloseKeyWrapper(::testing::_)).WillRepeatedly(::testing::Return(ERROR_SUCCESS));
    EXPECT_CALL(*mockApi, ConvertStringSidToSidAWrapper(::testing::StrEq("S-1-5-21-1004"), ::testing::_))
    .WillOnce(::testing::DoAll(::testing::SetArgPointee<1>(fakeSid), ::testing::Return(TRUE)));
    EXPECT_CALL(*mockApi, GetSidSubAuthorityCountWrapper(fakeSid)).WillOnce(::testing::Return(&subAuthCount));
    EXPECT_CALL(*mockApi, GetSidSubAuthorityWrapper(fakeSid, 0)).WillOnce(::testing::Return(&fakeRid));
    EXPECT_CALL(*mockApi, LookupAccountSidWWrapper(nullptr, fakeSid, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_))
    .WillOnce(::testing::DoAll(
                  ::testing::Invoke([](LPCWSTR, PSID, LPWSTR name, LPDWORD, LPWSTR, LPDWORD, SID_NAME_USE*)
    {
        if (name) wcscpy(name, L"bob");
    }),
    ::testing::Return(TRUE)));
    EXPECT_CALL(*mockApi, NetUserGetLocalGroupsWrapper(::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_))
    .WillOnce(::testing::Return(ERROR_ACCESS_DENIED));
    EXPECT_CALL(*mockApi, NetUserGetInfoWrapper(nullptr, ::testing::StrEq(L"bob"), 3, ::testing::_))
    .WillOnce(::testing::Return(NERR_UserNotFound));

    // The local account "bob" answers the lookup by name, but it is not the profile's account
    auto localAccount = netApiBuffer<USER_INFO_4>();
    localAccount->usri4_full_name = const_cast<LPWSTR>(L"Local Bob");
    localAccount->usri4_comment = const_cast<LPWSTR>(L"Local comment");
    localAccount->usri4_password_age = 3600;
    localAccount->usri4_user_sid = localAccountSid;
    EXPECT_CALL(*mockApi, NetUserGetInfoWrapper(nullptr, ::testing::StrEq(L"bob"), 4, ::testing::_))
    .WillOnce(::testing::DoAll(::testing::SetArgPointee<3>(reinterpret_cast<LPBYTE>(localAccount)), ::testing::Return(NERR_Success)));
    EXPECT_CALL(*mockApi, ConvertSidToStringSidWWrapper(localAccountSid, ::testing::_))
    .WillOnce(::testing::DoAll(
                  ::testing::Invoke([](PSID, LPWSTR * sidOut)
    {
        *sidOut = localString(L"S-1-5-21-2004");
    }),
    ::testing::Return(true)));
    EXPECT_CALL(*mockApi, FreeSidWrapper(fakeSid)).Times(1);

    auto users = helper.processRoamingProfiles(processedSids);

    ASSERT_EQ(users.size(), size_t{1});
    EXPECT_EQ(users[0].username, "bob");
    EXPECT_TRUE(users[0].full_name.empty());
    EXPECT_TRUE(users[0].description.empty());
    EXPECT_EQ(users[0].password_last_change, std::uint64_t{0});
}

TEST_F(UsersHelperTest, RoamingProfileKeepsItsPasswordHistoryWhenTheLookupFails)
{
    auto mockApi = std::make_shared<MockWindowsApiWrapper>();
    std::time_t now = 1'800'000'000;
    UsersHelper helper(mockApi, [&now] { return now; });
    bool lookupFails = false;

    HKEY fakeRootKey = reinterpret_cast<HKEY>(0x1234);
    PSID fakeSid = reinterpret_cast<PSID>(0x1005);
    BYTE subAuthCount = 1;
    DWORD fakeRid = 1005;

    // A complete local enumeration with no accounts, so the history is pruned after each scan
    EXPECT_CALL(*mockApi, NetUserEnumWrapper(::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_))
    .WillRepeatedly(::testing::Invoke([](LPCWSTR, DWORD, DWORD, LPBYTE * buffer, DWORD, LPDWORD read, LPDWORD total, LPDWORD)
    {
        *buffer = reinterpret_cast<LPBYTE>(netApiBuffer<USER_INFO_0>());
        *read = 0;
        *total = 0;
        return static_cast<NET_API_STATUS>(NERR_Success);
    }));
    EXPECT_CALL(*mockApi, RegOpenKeyExWWrapper(HKEY_LOCAL_MACHINE, ::testing::StrEq(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"), 0, KEY_READ, ::testing::_))
    .WillRepeatedly(::testing::DoAll(::testing::SetArgPointee<4>(fakeRootKey), ::testing::Return(ERROR_SUCCESS)));
    EXPECT_CALL(*mockApi, RegOpenKeyExWWrapper(HKEY_LOCAL_MACHINE, ::testing::HasSubstr(L"ProfileList\\S-1-5-21-1005"), 0, KEY_READ, ::testing::_))
    .WillRepeatedly(::testing::Return(ERROR_FILE_NOT_FOUND));
    EXPECT_CALL(*mockApi, RegQueryInfoKeyWWrapper(fakeRootKey, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_,
                                                  ::testing::_, ::testing::_))
    .WillRepeatedly(::testing::DoAll(::testing::SetArgPointee<4>(1), ::testing::Return(ERROR_SUCCESS)));
    EXPECT_CALL(*mockApi, RegEnumKeyWWrapper(fakeRootKey, 0, ::testing::_, ::testing::_))
    .WillRepeatedly(::testing::DoAll(
                        ::testing::Invoke([](HKEY, DWORD, LPWSTR buffer, DWORD length)
    {
        wcsncpy(buffer, L"S-1-5-21-1005", length);
        buffer[length - 1] = L'\0';
    }),
    ::testing::Return(ERROR_SUCCESS)));
    EXPECT_CALL(*mockApi, RegCloseKeyWrapper(::testing::_)).WillRepeatedly(::testing::Return(ERROR_SUCCESS));
    EXPECT_CALL(*mockApi, ConvertStringSidToSidAWrapper(::testing::StrEq("S-1-5-21-1005"), ::testing::_))
    .WillRepeatedly(::testing::DoAll(::testing::SetArgPointee<1>(fakeSid), ::testing::Return(TRUE)));
    EXPECT_CALL(*mockApi, GetSidSubAuthorityCountWrapper(fakeSid)).WillRepeatedly(::testing::Return(&subAuthCount));
    EXPECT_CALL(*mockApi, GetSidSubAuthorityWrapper(fakeSid, 0)).WillRepeatedly(::testing::Return(&fakeRid));
    EXPECT_CALL(*mockApi, LookupAccountSidWWrapper(nullptr, fakeSid, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_))
    .WillRepeatedly(::testing::DoAll(
                        ::testing::Invoke([](LPCWSTR, PSID, LPWSTR name, LPDWORD, LPWSTR, LPDWORD, SID_NAME_USE*)
    {
        if (name) wcscpy(name, L"carol");
    }),
    ::testing::Return(TRUE)));
    EXPECT_CALL(*mockApi, NetUserGetLocalGroupsWrapper(::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_))
    .WillRepeatedly(::testing::Return(ERROR_ACCESS_DENIED));
    EXPECT_CALL(*mockApi, NetUserGetInfoWrapper(nullptr, ::testing::StrEq(L"carol"), 3, ::testing::_))
    .WillRepeatedly(::testing::Return(NERR_UserNotFound));
    EXPECT_CALL(*mockApi, NetUserGetInfoWrapper(nullptr, ::testing::StrEq(L"carol"), 4, ::testing::_))
    .WillRepeatedly(::testing::Invoke([&lookupFails, fakeSid](LPCWSTR, LPCWSTR, DWORD, LPBYTE * buffer)
    {
        if (lookupFails)
        {
            return static_cast<NET_API_STATUS>(NERR_InternalError);
        }

        auto userInfo4 = netApiBuffer<USER_INFO_4>();
        userInfo4->usri4_full_name = const_cast<LPWSTR>(L"Carol");
        userInfo4->usri4_comment = const_cast<LPWSTR>(L"");
        userInfo4->usri4_password_age = 3600;
        userInfo4->usri4_user_sid = fakeSid;
        *buffer = reinterpret_cast<LPBYTE>(userInfo4);
        return static_cast<NET_API_STATUS>(NERR_Success);
    }));
    EXPECT_CALL(*mockApi, ConvertSidToStringSidWWrapper(fakeSid, ::testing::_))
    .WillRepeatedly(::testing::DoAll(
                        ::testing::Invoke([](PSID, LPWSTR * sidOut)
    {
        *sidOut = localString(L"S-1-5-21-1005");
    }),
    ::testing::Return(true)));
    EXPECT_CALL(*mockApi, FreeSidWrapper(fakeSid)).Times(::testing::AnyNumber());

    auto collect = [&helper]()
    {
        UsersHelper::resetCache();
        std::set<std::string> processedSids;
        auto users = helper.processRoamingProfiles(processedSids);
        EXPECT_EQ(users.size(), size_t{1});
        return users.at(0).password_last_change;
    };

    EXPECT_EQ(collect(), std::uint64_t{1'800'000'000 - 3600});

    // One scan where the lookup fails reports no date
    lookupFails = true;
    EXPECT_EQ(collect(), std::uint64_t{0});

    // Back with a one second shift: the previous value is still there to absorb it
    lookupFails = false;
    now += 1;
    EXPECT_EQ(collect(), std::uint64_t{1'800'000'000 - 3600});
}

// Single local user whose password age and the clock are driven by the test
class PasswordLastChangeTest : public UsersHelperTest
{
    protected:
        static constexpr std::time_t s_start = 1'800'000'000;

        void SetUp() override
        {
            UsersHelperTest::SetUp();
            mockApi = std::make_shared<MockWindowsApiWrapper>();
            helper = std::make_unique<UsersHelper>(mockApi, [this] { return now; });
            fakeSid = reinterpret_cast<PSID>(0xABCDEF);

            EXPECT_CALL(*mockApi, NetUserEnumWrapper(::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_))
            .WillRepeatedly(::testing::Invoke([](LPCWSTR, DWORD, DWORD, LPBYTE * buffer, DWORD, LPDWORD read, LPDWORD total, LPDWORD)
            {
                auto usersInfo0 = netApiBuffer<USER_INFO_0>();
                usersInfo0[0].usri0_name = const_cast<LPWSTR>(L"TestUser");
                *buffer = reinterpret_cast<LPBYTE>(usersInfo0);
                *read = 1;
                *total = 1;
                return NERR_Success;
            }));
            EXPECT_CALL(*mockApi, NetUserGetInfoWrapper(::testing::_, ::testing::_, 4, ::testing::_))
            .WillRepeatedly(::testing::Invoke([this](LPCWSTR, LPCWSTR, DWORD, LPBYTE * buffer)
            {
                auto userInfo4 = netApiBuffer<USER_INFO_4>();
                userInfo4->usri4_name = const_cast<LPWSTR>(L"TestUser");
                userInfo4->usri4_full_name = const_cast<LPWSTR>(L"Test Full Name");
                userInfo4->usri4_comment = const_cast<LPWSTR>(L"Test comment");
                userInfo4->usri4_user_sid = fakeSid;
                userInfo4->usri4_password_age = passwordAge;
                *buffer = reinterpret_cast<LPBYTE>(userInfo4);
                return NERR_Success;
            }));
            EXPECT_CALL(*mockApi, NetUserGetInfoWrapper(::testing::_, ::testing::_, 3, ::testing::_))
            .WillRepeatedly(::testing::Invoke([this](LPCWSTR, LPCWSTR, DWORD, LPBYTE * buffer)
            {
                auto userInfo3 = netApiBuffer<USER_INFO_3>();
                userInfo3->usri3_primary_group_id = fakeRid;
                *buffer = reinterpret_cast<LPBYTE>(userInfo3);
                return NERR_Success;
            }));
            EXPECT_CALL(*mockApi, GetSidSubAuthorityCountWrapper(fakeSid)).WillRepeatedly(::testing::Return(&subAuthCount));
            EXPECT_CALL(*mockApi, GetSidSubAuthorityWrapper(fakeSid, 1)).WillRepeatedly(::testing::Return(&fakeRid));
            EXPECT_CALL(*mockApi, NetUserGetLocalGroupsWrapper(::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_))
            .WillRepeatedly(::testing::Return(ERROR_ACCESS_DENIED));
            EXPECT_CALL(*mockApi, RegOpenKeyExWWrapper(::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_))
            .WillRepeatedly(::testing::Return(ERROR_FILE_NOT_FOUND));
        }

        // Makes the SID string conversion succeed with the given SID, or fail when it is null
        void setSidString(const wchar_t* sidString)
        {
            EXPECT_CALL(*mockApi, ConvertSidToStringSidWWrapper(fakeSid, ::testing::_))
            .WillRepeatedly(::testing::Invoke([sidString](PSID, LPWSTR * sidOut)
            {
                if (sidString == nullptr)
                {
                    return false;
                }

                *sidOut = localString(sidString);
                return true;
            }));
        }

        // Forces a cache refresh and returns the collected user
        User collect()
        {
            UsersHelper::resetCache();
            std::set<std::string> processedSids;
            auto users = helper->processLocalAccounts(processedSids);
            EXPECT_EQ(users.size(), size_t{1});
            return users.at(0);
        }

        std::shared_ptr<MockWindowsApiWrapper> mockApi;
        std::unique_ptr<UsersHelper> helper;
        std::time_t now{s_start};
        DWORD passwordAge{3600};
        PSID fakeSid{nullptr};
        BYTE subAuthCount{2};
        DWORD fakeRid{1000};
};

TEST_F(PasswordLastChangeTest, IgnoresOneSecondJitterAndReportsRealChanges)
{
    setSidString(L"S-1-5-21-1000");

    const auto initial = collect().password_last_change;
    EXPECT_EQ(initial, std::uint64_t{s_start - 3600});

    // Same password one second later: the truncated age differs by one second, the value must not
    now += 1;
    EXPECT_EQ(collect().password_last_change, initial);

    // Password changed: the new value goes through
    now += 100;
    passwordAge = 5;
    EXPECT_EQ(collect().password_last_change, std::uint64_t{s_start + 101 - 5});
}

TEST_F(PasswordLastChangeTest, ToleranceBoundaryIsInclusive)
{
    setSidString(L"S-1-5-21-1000");

    const auto initial = collect().password_last_change;

    // A two second shift is still jitter
    now += 2;
    EXPECT_EQ(collect().password_last_change, initial);

    // A three second shift is reported
    now += 1;
    EXPECT_EQ(collect().password_last_change, std::uint64_t{s_start + 3 - 3600});
}

TEST_F(PasswordLastChangeTest, EmptySidReportsZeroOnEveryScan)
{
    setSidString(nullptr);

    EXPECT_EQ(collect().password_last_change, std::uint64_t{0});

    now += 1;
    EXPECT_EQ(collect().password_last_change, std::uint64_t{0});
}

TEST_F(PasswordLastChangeTest, HistoryOfRemovedAccountIsDropped)
{
    setSidString(L"S-1-5-21-1000");
    EXPECT_EQ(collect().password_last_change, std::uint64_t{s_start - 3600});

    // The account is gone from one complete enumeration, so its previous value is dropped
    setSidString(L"S-1-5-21-2000");
    collect();

    // Back with a one second shift: computed again instead of reusing the dropped value
    setSidString(L"S-1-5-21-1000");
    now += 1;
    EXPECT_EQ(collect().password_last_change, std::uint64_t{s_start + 1 - 3600});
}

TEST_F(PasswordLastChangeTest, NeverSetPasswordReportsZeroOnEveryScan)
{
    setSidString(L"S-1-5-21-1000");
    passwordAge = 0;

    EXPECT_EQ(collect().password_last_change, std::uint64_t{0});

    now += 60;
    EXPECT_EQ(collect().password_last_change, std::uint64_t{0});
}

// test_logged_in_users_win.cpp, linked into the same binary, has its own MockUsersHelper
namespace
{
    class MockUsersHelper : public IUsersHelper
    {
        public:
            MOCK_METHOD(std::string, getUserShell, (const std::string&), (override));
            MOCK_METHOD(std::vector<User>, processLocalAccounts, (std::set<std::string>&), (override));
            MOCK_METHOD(std::vector<User>, processRoamingProfiles, (std::set<std::string>&), (override));
            MOCK_METHOD(std::unique_ptr<BYTE[]>, getSidFromAccountName, (const std::wstring&), (override));
            MOCK_METHOD(std::string, psidToString, (PSID), (override));
            MOCK_METHOD(DWORD, getRidFromSid, (PSID), (override));
    };
} // namespace

TEST(UsersProviderTest, CollectReportsFullNameDescriptionAndPasswordLastChange)
{
    auto mockHelper = std::make_shared<MockUsersHelper>();

    User user;
    user.uid = 1000;
    user.gid = 1000;
    user.sid = "S-1-5-21-1000";
    user.username = "TestUser";
    user.full_name = "Test Full Name";
    user.description = "Test comment";
    user.type = "local";
    user.password_last_change = 1'799'996'400;

    EXPECT_CALL(*mockHelper, processLocalAccounts(::testing::_)).WillOnce(::testing::Return(std::vector<User> {user}));
    EXPECT_CALL(*mockHelper, processRoamingProfiles(::testing::_)).WillOnce(::testing::Return(std::vector<User> {}));
    EXPECT_CALL(*mockHelper, getUserShell(::testing::_)).WillOnce(::testing::Return("C:\\Windows\\system32\\cmd.exe"));

    UsersProvider provider(mockHelper);
    const auto result = provider.collect();

    ASSERT_EQ(result.size(), size_t{1});
    EXPECT_EQ(result[0].at("username"), "TestUser");
    EXPECT_EQ(result[0].at("full_name"), "Test Full Name");
    EXPECT_EQ(result[0].at("description"), "Test comment");
    EXPECT_EQ(result[0].at("password_last_change"), std::uint64_t{1'799'996'400});
}
