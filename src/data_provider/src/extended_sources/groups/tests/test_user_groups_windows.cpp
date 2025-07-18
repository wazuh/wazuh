/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <gmock/gmock-matchers.h>
#include "iusers_utils_wrapper.hpp"
#include "iwindows_api_wrapper.hpp"
#include "user_groups_windows.hpp"
#include "encodingWindowsHelper.h"

class MockWindowsApiWrapper : public IWindowsApiWrapper
{
    public:
        MOCK_METHOD(DWORD, NetUserEnumWrapper, (LPCWSTR, DWORD, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, LPDWORD), (override));
        MOCK_METHOD(DWORD, NetLocalGroupEnumWrapper, (LPCWSTR, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, LPDWORD), (override));
        MOCK_METHOD(DWORD, NetUserGetInfoWrapper, (LPCWSTR, LPCWSTR, DWORD, LPBYTE*), (override));
        MOCK_METHOD(DWORD, RegOpenKeyExWWrapper, (HKEY, LPCWSTR, DWORD, REGSAM, PHKEY), (override));
        MOCK_METHOD(DWORD, RegQueryValueExWWrapper, (HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD), (override));
        MOCK_METHOD(LSTATUS, RegQueryInfoKeyWWrapper, (HKEY, LPWSTR, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, PFILETIME), (override));
        MOCK_METHOD(bool, IsValidSidWrapper, (PSID), (override));
        MOCK_METHOD(BOOL, ConvertSidToStringSidAWrapper, (PSID, LPSTR*), (override));
        MOCK_METHOD(bool, ConvertSidToStringSidWWrapper, (PSID, LPWSTR*), (override));
        MOCK_METHOD(BOOL, ConvertStringSidToSidAWrapper, (LPCSTR, PSID*), (override));
        MOCK_METHOD(BOOL, LookupAccountSidWWrapper, (LPCWSTR, PSID, LPWSTR, LPDWORD, LPWSTR, LPDWORD, PSID_NAME_USE), (override));
        MOCK_METHOD(bool, LookupAccountNameWWrapper, (LPCWSTR, LPCWSTR, PSID, LPDWORD, LPWSTR, LPDWORD, PSID_NAME_USE), (override));
        MOCK_METHOD(void, FreeSidWrapper, (LPVOID), (override));
        MOCK_METHOD(DWORD, NetUserGetLocalGroupsWrapper, (LPCWSTR, LPCWSTR, DWORD, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD), (override));
        MOCK_METHOD(PUCHAR, GetSidSubAuthorityCountWrapper, (PSID), (override));
        MOCK_METHOD(PDWORD, GetSidSubAuthorityWrapper, (PSID, DWORD), (override));
        MOCK_METHOD(LSTATUS, RegEnumKeyWWrapper, (HKEY, DWORD, LPWSTR, DWORD), (override));
        MOCK_METHOD(DWORD, GetLastErrorWrapper, (), (override));
        MOCK_METHOD(LSTATUS, RegCloseKeyWrapper, (HKEY hKey), (override));

};

class MockUsersHelper : public IUsersHelper
{
    public:
        MOCK_METHOD(std::string, getUserShell, (const std::string&), (override));
        MOCK_METHOD(std::unique_ptr<BYTE[]>, getSidFromAccountName, (const std::wstring&), (override));
        MOCK_METHOD(std::string, psidToString, (PSID), (override));
        MOCK_METHOD(DWORD, getRidFromSid, (PSID), (override));
        MOCK_METHOD(std::vector<User>, processRoamingProfiles, (std::set<std::string>&), (override));
        MOCK_METHOD(std::vector<User>, processLocalAccounts, (std::set<std::string>&), (override));
};

class MockGroupsHelper : public IGroupsHelper
{
    public:
        MOCK_METHOD(std::vector<Group>, processLocalGroups, (), (override));
};

class UserGroupsProviderTest : public ::testing::Test
{
    protected:
        std::shared_ptr<MockWindowsApiWrapper> winapiWrapper;
        std::shared_ptr<MockUsersHelper> usersHelper;
        std::shared_ptr<MockGroupsHelper> groupsHelper;
        std::unique_ptr<UserGroupsProvider> provider;

        void SetUp() override
        {
            winapiWrapper = std::make_shared<MockWindowsApiWrapper>();
            usersHelper = std::make_shared<MockUsersHelper>();
            groupsHelper = std::make_shared<MockGroupsHelper>();
            provider = std::make_unique<UserGroupsProvider>(winapiWrapper, usersHelper, groupsHelper);
        }
};

static auto ReturnGroups(const std::vector<std::wstring>& groupNames)
{
    return [groupNames](LPCWSTR, LPCWSTR, DWORD, DWORD, LPBYTE * buf, DWORD, LPDWORD ng, LPDWORD tg)
    {
        auto namesCopy = std::make_shared<std::vector<std::wstring>>(groupNames);
        auto bufferPtr = std::make_shared<std::vector<LOCALGROUP_USERS_INFO_0>>();

        for (const auto& name : *namesCopy)
        {
            LOCALGROUP_USERS_INFO_0 entry{};
            entry.lgrui0_name = const_cast<LPWSTR>(name.c_str());
            bufferPtr->push_back(entry);
        }

        *buf = reinterpret_cast<LPBYTE>(bufferPtr->data());
        *ng = static_cast<DWORD>(bufferPtr->size());
        *tg = static_cast<DWORD>(bufferPtr->size());

        static std::vector<std::shared_ptr<void>> guard;
        guard.push_back(namesCopy);
        guard.push_back(bufferPtr);

        return NERR_Success;
    };
}

TEST_F(UserGroupsProviderTest, CollectNoGroupsForUserReturnsEmpty)
{
    std::set<std::string> sids;
    User testUser
    {
        .generation = 0,
        .uid = 1001,
        .gid = 0,
        .sid = "",
        .username = "user1",
        .description = "",
        .type = "",
        .directory = ""
    };
    std::vector<User> localUsers{ testUser };

    std::vector<Group> localGroups{};

    EXPECT_CALL(*usersHelper, processLocalAccounts(::testing::_)).WillOnce(::testing::Return(localUsers));
    EXPECT_CALL(*groupsHelper, processLocalGroups()).WillOnce(::testing::Return(localGroups));
    EXPECT_CALL(*winapiWrapper, NetUserGetLocalGroupsWrapper(
                    ::testing::_, ::testing::StrEq(L"user1"), 0, 1, ::testing::_, MAX_PREFERRED_LENGTH, ::testing::_, ::testing::_))
    .WillOnce(::testing::Return(NERR_Success));

    auto result = provider->collect({});

    EXPECT_TRUE(result.empty());
}

TEST_F(UserGroupsProviderTest, CollectUserWithValidGroupReturnsGroupInfo)
{
    std::set<std::string> sids;
    User testUser
    {
        .generation = 0,
        .uid = 1001,
        .gid = 0,
        .sid = "",
        .username = "user1",
        .description = "",
        .type = "",
        .directory = ""
    };
    std::vector<User> localUsers{ testUser };
    Group testGroup
    {
        .generation = 0,
        .gid = 2001,
        .sid = "",
        .groupname = "Admins",
        .comment = ""
    };
    std::vector<Group> localGroups{ testGroup };

    EXPECT_CALL(*usersHelper, processLocalAccounts(::testing::_)).WillOnce(::testing::Return(localUsers));
    EXPECT_CALL(*groupsHelper, processLocalGroups()).WillOnce(::testing::Return(localGroups));

    auto groupName = L"Admins";
    auto buffer = std::make_unique<LOCALGROUP_USERS_INFO_0[]>(1);
    buffer[0].lgrui0_name = const_cast<LPWSTR>(groupName);

    DWORD numGroups = 1;
    DWORD totalGroups = 1;

    EXPECT_CALL(*winapiWrapper, NetUserGetLocalGroupsWrapper(
                    ::testing::_, ::testing::StrEq(L"user1"), 0, 1, ::testing::_, MAX_PREFERRED_LENGTH, ::testing::_, ::testing::_))
    .WillOnce([&](LPCWSTR, LPCWSTR, DWORD, DWORD, LPBYTE * buf, DWORD, LPDWORD ng, LPDWORD tg)
    {
        *buf = reinterpret_cast<LPBYTE>(buffer.get());
        *ng = numGroups;
        *tg = totalGroups;
        return NERR_Success;
    });

    auto result = provider->collect({});

    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0]["uid"], 1001);
    EXPECT_EQ(result[0]["gid"], 2001);
}

TEST_F(UserGroupsProviderTest, CollectWithSpecificUidReturnsFilteredResults)
{
    std::set<std::string> sids;

    User user1{}, user2{};
    user1.uid = 1001;
    user1.username = "user1";
    user2.uid = 1002;
    user2.username = "user2";
    std::vector<User> localUsers{ user1, user2 };

    Group group1{};
    group1.gid = 2001;
    group1.groupname = "Admins";
    std::vector<Group> localGroups{ group1 };

    EXPECT_CALL(*usersHelper, processLocalAccounts(::testing::_)).WillOnce(::testing::Return(localUsers));
    EXPECT_CALL(*groupsHelper, processLocalGroups()).WillOnce(::testing::Return(localGroups));

    // Expect calls for user1
    static LOCALGROUP_USERS_INFO_0 buffer[1];
    static std::wstring groupName = L"Admins";
    buffer[0].lgrui0_name = const_cast<LPWSTR>(groupName.c_str());

    EXPECT_CALL(*winapiWrapper,
                NetUserGetLocalGroupsWrapper(::testing::_, ::testing::StrEq(L"user1"),
                                             0, 1, ::testing::_, MAX_PREFERRED_LENGTH, ::testing::_, ::testing::_))
    .WillOnce([&](LPCWSTR, LPCWSTR, DWORD, DWORD, LPBYTE * buf, DWORD, LPDWORD ng, LPDWORD tg)
    {
        *buf = reinterpret_cast<LPBYTE>(buffer);
        *ng = 1;
        *tg = 1;
        return NERR_Success;
    });

    // No calls for user2
    EXPECT_CALL(*winapiWrapper,
                NetUserGetLocalGroupsWrapper(::testing::_, ::testing::StrEq(L"user2"),
                                             0, 1, ::testing::_, MAX_PREFERRED_LENGTH, ::testing::_, ::testing::_))
    .Times(0);

    auto result = provider->collect({1001});

    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0]["uid"], 1001);
    EXPECT_EQ(result[0]["gid"], 2001);
}

TEST_F(UserGroupsProviderTest, CollectIgnoresSystemUsers)
{
    std::set<std::string> sids;

    User systemUser1{}, systemUser2{}, systemUser3{}, regularUser{};
    systemUser1.uid = 1;
    systemUser1.username = "LOCAL SERVICE";
    systemUser2.uid = 2;
    systemUser2.username = "SYSTEM";
    systemUser3.uid = 3;
    systemUser3.username = "NETWORK SERVICE";
    regularUser.uid = 1001;
    regularUser.username = "regular_user";
    std::vector<User> localUsers{ systemUser1, systemUser2, systemUser3, regularUser };

    Group testGroup{};
    testGroup.gid = 2001;
    testGroup.groupname = "Users";
    std::vector<Group> localGroups{ testGroup };

    EXPECT_CALL(*usersHelper, processLocalAccounts(::testing::_)).WillOnce(::testing::Return(localUsers));
    EXPECT_CALL(*groupsHelper, processLocalGroups()).WillOnce(::testing::Return(localGroups));

    // Expect calls only for regular_user
    auto buffer = std::make_unique<LOCALGROUP_USERS_INFO_0[]>(1);
    buffer[0].lgrui0_name = const_cast<LPWSTR>(L"Users");
    EXPECT_CALL(*winapiWrapper, NetUserGetLocalGroupsWrapper(
                    ::testing::_, ::testing::StrEq(L"regular_user"), 0, 1, ::testing::_, MAX_PREFERRED_LENGTH, ::testing::_, ::testing::_))
    .WillOnce([&](LPCWSTR, LPCWSTR, DWORD, DWORD, LPBYTE * buf, DWORD, LPDWORD ng, LPDWORD tg)
    {
        *buf = reinterpret_cast<LPBYTE>(buffer.get());
        *ng = 1;
        *tg = 1;
        return NERR_Success;
    });

    auto result = provider->collect({});

    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0]["uid"], 1001);
    EXPECT_EQ(result[0]["gid"], 2001);
}

TEST_F(UserGroupsProviderTest, CollectHandlesNetUserGetLocalGroupsFailure)
{
    std::set<std::string> sids;

    User user1{}, user2{};
    user1.uid = 1001;
    user1.username = "user1";
    user2.uid = 1002;
    user2.username = "user2";
    std::vector<User> localUsers{ user1, user2 };

    Group testGroup{};
    testGroup.gid = 2001;
    testGroup.groupname = "Admins";
    std::vector<Group> localGroups{ testGroup };

    EXPECT_CALL(*usersHelper, processLocalAccounts(::testing::_)).WillOnce(::testing::Return(localUsers));
    EXPECT_CALL(*groupsHelper, processLocalGroups()).WillOnce(::testing::Return(localGroups));

    // user1 fails NetUserGetLocalGroupsWrapper
    EXPECT_CALL(*winapiWrapper, NetUserGetLocalGroupsWrapper(
                    ::testing::_, ::testing::StrEq(L"user1"), 0, 1, ::testing::_, MAX_PREFERRED_LENGTH, ::testing::_, ::testing::_))
    .WillOnce(::testing::Return(ERROR_ACCESS_DENIED)); // Simulate failure

    // user2 succeeds
    auto buffer2 = std::make_unique<LOCALGROUP_USERS_INFO_0[]>(1);
    buffer2[0].lgrui0_name = const_cast<LPWSTR>(L"Admins");
    EXPECT_CALL(*winapiWrapper, NetUserGetLocalGroupsWrapper(
                    ::testing::_, ::testing::StrEq(L"user2"), 0, 1, ::testing::_, MAX_PREFERRED_LENGTH, ::testing::_, ::testing::_))
    .WillOnce([&](LPCWSTR, LPCWSTR, DWORD, DWORD, LPBYTE * buf, DWORD, LPDWORD ng, LPDWORD tg)
    {
        *buf = reinterpret_cast<LPBYTE>(buffer2.get());
        *ng = 1;
        *tg = 1;
        return NERR_Success;
    });

    auto result = provider->collect({});

    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0]["uid"], 1002);
    EXPECT_EQ(result[0]["gid"], 2001);
}

TEST_F(UserGroupsProviderTest, CollectHandlesGroupNotFound)
{
    std::set<std::string> sids;

    User testUser{};
    testUser.uid = 1001;
    testUser.username = "user1";
    std::vector<User> localUsers{ testUser };

    // Group returned by NetUserGetLocalGroupsWrapper, but not in localGroups
    Group testGroupInApiCall{};
    testGroupInApiCall.gid = 9999;
    testGroupInApiCall.groupname = "NonExistentGroup";
    std::vector<Group> localGroups{}; // Empty, so NonExistentGroup won't be found

    EXPECT_CALL(*usersHelper, processLocalAccounts(::testing::_)).WillOnce(::testing::Return(localUsers));
    EXPECT_CALL(*groupsHelper, processLocalGroups()).WillOnce(::testing::Return(localGroups));

    auto groupName = L"NonExistentGroup";
    auto buffer = std::make_unique<LOCALGROUP_USERS_INFO_0[]>(1);
    buffer[0].lgrui0_name = const_cast<LPWSTR>(groupName);

    DWORD numGroups = 1;
    DWORD totalGroups = 1;

    EXPECT_CALL(*winapiWrapper, NetUserGetLocalGroupsWrapper(
                    ::testing::_, ::testing::StrEq(L"user1"), 0, 1, ::testing::_, MAX_PREFERRED_LENGTH, ::testing::_, ::testing::_))
    .WillOnce([&](LPCWSTR, LPCWSTR, DWORD, DWORD, LPBYTE * buf, DWORD, LPDWORD ng, LPDWORD tg)
    {
        *buf = reinterpret_cast<LPBYTE>(buffer.get());
        *ng = numGroups;
        *tg = totalGroups;
        return NERR_Success;
    });

    auto result = provider->collect({});

    EXPECT_TRUE(result.empty());
}

TEST_F(UserGroupsProviderTest, GetGroupNamesByUidSingleUid)
{
    User testUser{};
    testUser.uid = 1000;
    testUser.username = "testuser";
    std::vector<User> localUsers = { testUser };

    Group group1{};
    group1.gid = 100;
    group1.groupname = "groupA";
    Group group2{};
    group2.gid = 101;
    group2.groupname = "groupB";
    std::vector<Group> localGroups = { group1, group2 };

    EXPECT_CALL(*usersHelper, processLocalAccounts(::testing::_))
    .WillOnce(::testing::Return(localUsers));

    EXPECT_CALL(*groupsHelper, processLocalGroups())
    .WillOnce(::testing::Return(localGroups));

    static std::wstring gA = L"groupA";
    static std::wstring gB = L"groupB";
    auto buffer = std::make_unique<LOCALGROUP_USERS_INFO_0[]>(2);
    buffer[0].lgrui0_name = const_cast<LPWSTR>(gA.c_str());
    buffer[1].lgrui0_name = const_cast<LPWSTR>(gB.c_str());

    EXPECT_CALL(*winapiWrapper,
                NetUserGetLocalGroupsWrapper(::testing::_, ::testing::StrEq(L"testuser"),
                                             0, 1, ::testing::_, MAX_PREFERRED_LENGTH,
                                             ::testing::_, ::testing::_))
    .WillOnce([&](LPCWSTR, LPCWSTR, DWORD, DWORD, LPBYTE * buf,
                  DWORD, LPDWORD ng, LPDWORD tg)
    {
        *buf = reinterpret_cast<LPBYTE>(buffer.get());
        *ng  = 2;
        *tg  = 2;
        return NERR_Success;
    });

    auto result = provider->getGroupNamesByUid({1000});

    EXPECT_THAT(result.get<std::vector<std::string>>(),
                ::testing::UnorderedElementsAre("groupA", "groupB"));
}

TEST_F(UserGroupsProviderTest, GetGroupNamesByUidMultipleUids)
{
    User user1{}, user2{};
    user1.uid = 1000;
    user1.username = "user1";
    user2.uid = 1001;
    user2.username = "user2";
    std::vector<User> localUsers = { user1, user2 };

    Group group1{}, group2{}, group3{};
    group1.gid = 100;
    group1.groupname = "groupA";
    group2.gid = 101;
    group2.groupname = "groupB";
    group3.gid = 102;
    group3.groupname = "groupC";
    std::vector<Group> localGroups = { group1, group2, group3 };

    EXPECT_CALL(*usersHelper, processLocalAccounts(::testing::_))
    .WillOnce(::testing::Return(localUsers));

    EXPECT_CALL(*groupsHelper, processLocalGroups())
    .WillOnce(::testing::Return(localGroups));

    static std::wstring gA = L"groupA";
    static std::wstring gB = L"groupB";
    auto buffer1 = std::make_unique<LOCALGROUP_USERS_INFO_0[]>(2);
    buffer1[0].lgrui0_name = const_cast<LPWSTR>(gA.c_str());
    buffer1[1].lgrui0_name = const_cast<LPWSTR>(gB.c_str());

    EXPECT_CALL(*winapiWrapper,
                NetUserGetLocalGroupsWrapper(::testing::_, ::testing::StrEq(L"user1"),
                                             0, 1, ::testing::_, MAX_PREFERRED_LENGTH,
                                             ::testing::_, ::testing::_))
    .WillOnce([&](LPCWSTR, LPCWSTR, DWORD, DWORD, LPBYTE * buf,
                  DWORD, LPDWORD ng, LPDWORD tg)
    {
        *buf = reinterpret_cast<LPBYTE>(buffer1.get());
        *ng  = 2;
        *tg  = 2;
        return NERR_Success;
    });

    static std::wstring gC = L"groupC";
    auto buffer2 = std::make_unique<LOCALGROUP_USERS_INFO_0[]>(2);
    buffer2[0].lgrui0_name = const_cast<LPWSTR>(gB.c_str());
    buffer2[1].lgrui0_name = const_cast<LPWSTR>(gC.c_str());

    EXPECT_CALL(*winapiWrapper,
                NetUserGetLocalGroupsWrapper(::testing::_, ::testing::StrEq(L"user2"),
                                             0, 1, ::testing::_, MAX_PREFERRED_LENGTH,
                                             ::testing::_, ::testing::_))
    .WillOnce([&](LPCWSTR, LPCWSTR, DWORD, DWORD, LPBYTE * buf,
                  DWORD, LPDWORD ng, LPDWORD tg)
    {
        *buf = reinterpret_cast<LPBYTE>(buffer2.get());
        *ng  = 2;
        *tg  = 2;
        return NERR_Success;
    });

    auto result = provider->getGroupNamesByUid({1000, 1001});

    EXPECT_THAT(result["1000"].get<std::vector<std::string>>(),
                ::testing::UnorderedElementsAre("groupA", "groupB"));

    EXPECT_THAT(result["1001"].get<std::vector<std::string>>(),
                ::testing::UnorderedElementsAre("groupB", "groupC"));
}

TEST_F(UserGroupsProviderTest, GetGroupNamesByUidAllUsers)
{
    User user1{}, user2{};
    user1.uid = 1000;
    user1.username = "user1";
    user2.uid = 1001;
    user2.username = "user2";
    std::vector<User> localUsers = { user1, user2 };

    Group group1{}, group2{}, group3{};
    group1.gid = 100;
    group1.groupname = "groupA";
    group2.gid = 101;
    group2.groupname = "groupB";
    group3.gid = 102;
    group3.groupname = "groupC";
    std::vector<Group> localGroups = { group1, group2, group3 };

    EXPECT_CALL(*usersHelper, processLocalAccounts(::testing::_))
    .WillOnce(::testing::Return(localUsers));

    EXPECT_CALL(*groupsHelper, processLocalGroups())
    .WillOnce(::testing::Return(localGroups));

    static std::wstring gA = L"groupA";
    static std::wstring gB = L"groupB";
    static std::wstring gC = L"groupC";

    auto buffer1 = std::make_unique<LOCALGROUP_USERS_INFO_0[]>(2);
    buffer1[0].lgrui0_name = const_cast<LPWSTR>(gA.c_str());
    buffer1[1].lgrui0_name = const_cast<LPWSTR>(gB.c_str());

    EXPECT_CALL(*winapiWrapper,
                NetUserGetLocalGroupsWrapper(::testing::_, ::testing::StrEq(L"user1"),
                                             0, 1, ::testing::_, MAX_PREFERRED_LENGTH,
                                             ::testing::_, ::testing::_))
    .WillOnce([&](LPCWSTR, LPCWSTR, DWORD, DWORD, LPBYTE * buf,
                  DWORD, LPDWORD ng, LPDWORD tg)
    {
        *buf = reinterpret_cast<LPBYTE>(buffer1.get());
        *ng  = 2;
        *tg  = 2;
        return NERR_Success;
    });

    auto buffer2 = std::make_unique<LOCALGROUP_USERS_INFO_0[]>(2);
    buffer2[0].lgrui0_name = const_cast<LPWSTR>(gB.c_str());
    buffer2[1].lgrui0_name = const_cast<LPWSTR>(gC.c_str());

    EXPECT_CALL(*winapiWrapper,
                NetUserGetLocalGroupsWrapper(::testing::_, ::testing::StrEq(L"user2"),
                                             0, 1, ::testing::_, MAX_PREFERRED_LENGTH,
                                             ::testing::_, ::testing::_))
    .WillOnce([&](LPCWSTR, LPCWSTR, DWORD, DWORD, LPBYTE * buf,
                  DWORD, LPDWORD ng, LPDWORD tg)
    {
        *buf = reinterpret_cast<LPBYTE>(buffer2.get());
        *ng  = 2;
        *tg  = 2;
        return NERR_Success;
    });

    auto result = provider->getGroupNamesByUid({});

    EXPECT_THAT(result["1000"].get<std::vector<std::string>>(),
                ::testing::UnorderedElementsAre("groupA", "groupB"));

    EXPECT_THAT(result["1001"].get<std::vector<std::string>>(),
                ::testing::UnorderedElementsAre("groupB", "groupC"));
}

TEST_F(UserGroupsProviderTest, GetUserNamesByGidSingleGid)
{
    User user1{}, user2{};
    user1.uid = 1000;
    user1.username = "alice";
    user2.uid = 1001;
    user2.username = "bob";
    std::vector<User> users = { user1, user2 };

    Group group{};
    group.gid = 200;
    group.groupname = "developers";
    std::vector<Group> groups = { group };

    EXPECT_CALL(*usersHelper, processLocalAccounts(::testing::_))
    .WillOnce(::testing::Return(users));

    EXPECT_CALL(*groupsHelper, processLocalGroups())
    .WillOnce(::testing::Return(groups));

    EXPECT_CALL(*winapiWrapper, NetUserGetLocalGroupsWrapper(::testing::_, ::testing::StrEq(L"alice"), 0, 1, ::testing::_, MAX_PREFERRED_LENGTH, ::testing::_, ::testing::_))
    .WillOnce(ReturnGroups({ L"developers" }));

    EXPECT_CALL(*winapiWrapper, NetUserGetLocalGroupsWrapper(::testing::_, ::testing::StrEq(L"bob"), 0, 1, ::testing::_, MAX_PREFERRED_LENGTH, ::testing::_, ::testing::_))
    .WillOnce(ReturnGroups({}));

    auto result = provider->getUserNamesByGid({200});

    EXPECT_THAT(result.get<std::vector<std::string>>(),
                ::testing::UnorderedElementsAre("alice"));
}

TEST_F(UserGroupsProviderTest, GetUserNamesByGidMultipleGids)
{
    User user1{}, user2{};
    user1.uid = 1000;
    user1.username = "alice";
    user2.uid = 1001;
    user2.username = "bob";
    std::vector<User> users = { user1, user2 };

    Group group1{}, group2{};
    group1.gid = 200;
    group1.groupname = "developers";
    group2.gid = 201;
    group2.groupname = "admins";
    std::vector<Group> groups = { group1, group2 };

    EXPECT_CALL(*usersHelper, processLocalAccounts(::testing::_))
    .WillOnce(::testing::Return(users));
    EXPECT_CALL(*groupsHelper, processLocalGroups())
    .WillOnce(::testing::Return(groups));

    EXPECT_CALL(*winapiWrapper, NetUserGetLocalGroupsWrapper(::testing::_, ::testing::StrEq(L"alice"), 0, 1, ::testing::_, MAX_PREFERRED_LENGTH, ::testing::_, ::testing::_))
    .WillOnce(ReturnGroups({ L"developers", L"admins" }));

    EXPECT_CALL(*winapiWrapper, NetUserGetLocalGroupsWrapper(::testing::_, ::testing::StrEq(L"bob"), 0, 1, ::testing::_, MAX_PREFERRED_LENGTH, ::testing::_, ::testing::_))
    .WillOnce(ReturnGroups({ L"admins" }));

    auto result = provider->getUserNamesByGid({200, 201});

    EXPECT_THAT(result["200"].get<std::vector<std::string>>(),
                ::testing::UnorderedElementsAre("alice"));
    EXPECT_THAT(result["201"].get<std::vector<std::string>>(),
                ::testing::UnorderedElementsAre("alice", "bob"));
}

TEST_F(UserGroupsProviderTest, GetUserNamesByGidAllGroups)
{
    User user1{}, user2{};
    user1.uid = 1000;
    user1.username = "alice";
    user2.uid = 1001;
    user2.username = "bob";
    std::vector<User> users = { user1, user2 };

    Group group1{}, group2{};
    group1.gid = 200;
    group1.groupname = "developers";
    group2.gid = 201;
    group2.groupname = "admins";
    std::vector<Group> groups = { group1, group2 };

    EXPECT_CALL(*usersHelper, processLocalAccounts(::testing::_))
    .WillOnce(::testing::Return(users));
    EXPECT_CALL(*groupsHelper, processLocalGroups())
    .WillOnce(::testing::Return(groups));

    EXPECT_CALL(*winapiWrapper, NetUserGetLocalGroupsWrapper(::testing::_, ::testing::StrEq(L"alice"), 0, 1, ::testing::_, MAX_PREFERRED_LENGTH, ::testing::_, ::testing::_))
    .WillOnce(ReturnGroups({ L"developers", L"admins" }));

    EXPECT_CALL(*winapiWrapper, NetUserGetLocalGroupsWrapper(::testing::_, ::testing::StrEq(L"bob"), 0, 1, ::testing::_, MAX_PREFERRED_LENGTH, ::testing::_, ::testing::_))
    .WillOnce(ReturnGroups({ L"admins" }));

    auto result = provider->getUserNamesByGid({});

    EXPECT_THAT(result["200"].get<std::vector<std::string>>(),
                ::testing::UnorderedElementsAre("alice"));
    EXPECT_THAT(result["201"].get<std::vector<std::string>>(),
                ::testing::UnorderedElementsAre("alice", "bob"));
}
