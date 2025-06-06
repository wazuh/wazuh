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
#include "igroup_wrapper.hpp"
#include "ipasswd_wrapper.hpp"
#include "isystem_wrapper.hpp"
#include "user_groups_linux.hpp"

class MockGroupWrapper : public IGroupWrapperLinux
{
    public:
        MOCK_METHOD(int, getgrgid_r, (gid_t gid, struct group* grp, char* buf, size_t buflen, struct group** result), (const, override));
        MOCK_METHOD(int, getgrent_r, (struct group* grp, char* buf, size_t buflen, struct group** result), (const, override));
        MOCK_METHOD(struct group*, getgrent, (), (const, override));
        MOCK_METHOD(void, setgrent, (), (const, override));
        MOCK_METHOD(void, endgrent, (), (const, override));
        MOCK_METHOD(int, getgrouplist, (const char* user, gid_t group, gid_t* groups, int* ngroups), (const, override));
};

class MockPasswdWrapper : public IPasswdWrapperLinux
{
    public:
        MOCK_METHOD(int, fgetpwent_r, (FILE* stream, struct passwd* pwd, char* buf, size_t buflen, struct passwd** result), (override));
        MOCK_METHOD(int, getpwuid_r, (uid_t uid, struct passwd* pwd, char* buf, size_t buflen, struct passwd** result), (override));
        MOCK_METHOD(int, getpwent_r, (struct passwd* pwd, char* buf, size_t buflen, struct passwd** result), (override));
        MOCK_METHOD(struct passwd*, getpwent, (), (override));
        MOCK_METHOD(void, setpwent, (), (override));
        MOCK_METHOD(void, endpwent, (), (override));
        MOCK_METHOD(int, getpwnam_r, (const char* name, struct passwd* pwd, char* buf, size_t buflen, struct passwd** result), (override));
};

class MockSystemWrapper : public ISystemWrapper
{
    public:
        MOCK_METHOD(long, sysconf, (int name), (const, override));
        MOCK_METHOD(FILE*, fopen, (const char* filename, const char* mode), (override));
        MOCK_METHOD(int, fclose, (FILE* stream), (override));
        MOCK_METHOD(char*, strerror, (int errnum), (override));
};

using ::testing::_;
using ::testing::Return;
using ::testing::DoAll;
using ::testing::SetArgPointee;
using ::testing::SetArrayArgument;
using ::testing::Invoke;
using ::testing::NiceMock;
using ::testing::InSequence;
using ::testing::StrEq;

TEST(UserGroupsProviderTest, CollectWithSpecificUid)
{
    auto mockGroup = std::make_shared<MockGroupWrapper>();
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockSys = std::make_shared<MockSystemWrapper>();

    const uid_t testUid = 1001;
    const gid_t testGid = 2001;
    const char* username = "testuser";

    EXPECT_CALL(*mockSys, sysconf(_SC_GETPW_R_SIZE_MAX))
    .WillOnce(Return(1024));

    EXPECT_CALL(*mockPasswd, getpwuid_r(testUid, _, _, _, _))
    .WillOnce(Invoke([&](uid_t, struct passwd * pwd, char*, size_t, struct passwd** result)
    {
        pwd->pw_name = const_cast<char*>(username);
        pwd->pw_uid = testUid;
        pwd->pw_gid = testGid;
        *result = pwd;
        return 0;
    }));

    EXPECT_CALL(*mockGroup, getgrouplist(username, testGid, _, _))
    .WillOnce(Invoke([](const char*, gid_t, gid_t * groups, int* ngroups)
    {
        groups[0] = 2001;
        groups[1] = 2002;
        *ngroups = 2;
        return 2;
    }));

    UserGroupsProvider provider(mockGroup, mockPasswd, mockSys);

    auto result = provider.collect({testUid});

    ASSERT_EQ(result.size(), static_cast<decltype(result.size())>(2));
    EXPECT_EQ(result[0]["uid"], testUid);
    EXPECT_EQ(result[0]["gid"], 2001);
    EXPECT_EQ(result[1]["uid"], testUid);
    EXPECT_EQ(result[1]["gid"], 2002);
}

TEST(UserGroupsProviderTest, CollectAllUserGroups)
{
    auto mockGroup = std::make_shared<MockGroupWrapper>();
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockSys = std::make_shared<MockSystemWrapper>();
    UserGroupsProvider provider(mockGroup, mockPasswd, mockSys);

    struct passwd user1;
    struct passwd user2;

    const char* user1Name = "user1";
    const uid_t user1Uid = 1001;
    const gid_t user1Gid = 100;

    const char* user2Name = "user2";
    const uid_t user2Uid = 1002;
    const gid_t user2Gid = 200;

    EXPECT_CALL(*mockSys, sysconf(_SC_GETPW_R_SIZE_MAX))
    .WillOnce(Return(1024));

    EXPECT_CALL(*mockPasswd, setpwent());

    {
        InSequence seq;

        EXPECT_CALL(*mockPasswd, getpwent_r(_, _, _, _))
        .WillOnce(Invoke([&](struct passwd * pwd, char* /* buf */, size_t /* buflen */, struct passwd** pwdResult)
        {
            user1.pw_name = const_cast<char*>(user1Name);
            user1.pw_uid = user1Uid;
            user1.pw_gid = user1Gid;
            *pwd = user1;
            *pwdResult = &user1;
            return 0;
        }));

        EXPECT_CALL(*mockPasswd, getpwent_r(_, _, _, _))
        .WillOnce(Invoke([&](struct passwd * pwd, char* /* buf */, size_t /* buflen */, struct passwd** pwdResult)
        {
            user2.pw_name = const_cast<char*>(user2Name);
            user2.pw_uid = user2Uid;
            user2.pw_gid = user2Gid;
            *pwd = user2;
            *pwdResult = &user2;
            return 0;
        }));

        EXPECT_CALL(*mockPasswd, getpwent_r(_, _, _, _))
        .WillOnce(Invoke([](struct passwd*, char*, size_t, struct passwd** pwdResult)
        {
            *pwdResult = nullptr;
            return 0;
        }));
    }

    EXPECT_CALL(*mockGroup, getgrouplist(StrEq(user1Name), user1Gid, _, _))
    .WillOnce(Invoke([](const char*, gid_t, gid_t * groups, int* ngroups)
    {
        groups[0] = 101;
        groups[1] = 102;
        *ngroups = 2;
        return 2;
    }));

    EXPECT_CALL(*mockGroup, getgrouplist(StrEq(user2Name), user2Gid, _, _))
    .WillOnce(Invoke([](const char*, gid_t, gid_t * groups, int* ngroups)
    {
        groups[0] = 201;
        groups[1] = 202;
        *ngroups = 2;
        return 2;
    }));

    EXPECT_CALL(*mockPasswd, endpwent());

    nlohmann::json results = provider.collect();

    ASSERT_EQ(results.size(), static_cast<decltype(results.size())>(4)); // 2 users * 2 groups

    std::set<std::tuple<uid_t, gid_t>> expected =
    {
        {user1Uid, 101}, {user1Uid, 102},
        {user2Uid, 201}, {user2Uid, 202}
    };

    for (const auto& entry : results)
    {
        uid_t uid = entry["uid"];
        gid_t gid = entry["gid"];
        ASSERT_TRUE(expected.count({uid, gid})) << "Unexpected pair: uid=" << uid << ", gid=" << gid;
    }
}

TEST(UserGroupsProviderTest, getUserNamesByGidAllGroups)
{

    auto mockGroup = std::make_shared<MockGroupWrapper>();
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockSys = std::make_shared<MockSystemWrapper>();

    EXPECT_CALL(*mockSys, sysconf(_SC_GETPW_R_SIZE_MAX)).WillOnce(testing::Return(1024));

    group group1 = {};
    char* members1[] = {strdup("alice"), strdup("bob"), nullptr};
    group1.gr_gid = 1000;
    group1.gr_mem = members1;

    group* group1Ptr = &group1;

    EXPECT_CALL(*mockGroup, setgrent());
    EXPECT_CALL(*mockGroup, getgrent()).WillOnce(testing::Return(group1Ptr)).WillOnce(testing::Return(nullptr));
    EXPECT_CALL(*mockGroup, endgrent());

    passwd user1 = {};
    user1.pw_gid = 1000;
    user1.pw_name = strdup("charlie");

    passwd* user1Ptr = &user1;

    EXPECT_CALL(*mockPasswd, setpwent());
    EXPECT_CALL(*mockPasswd, getpwent()).WillOnce(testing::Return(user1Ptr)).WillOnce(testing::Return(nullptr));
    EXPECT_CALL(*mockPasswd, endpwent());

    UserGroupsProvider provider(mockGroup, mockPasswd, mockSys);

    auto result = provider.getUserNamesByGid({});

    nlohmann::json expected = {{"1000", {"alice", "bob", "charlie"}}};

    EXPECT_EQ(result, expected);

    for (char** p = members1; *p != nullptr; ++p)
    {
        free(*p);
    }

    free(user1.pw_name);
}

TEST(UserGroupsProviderTest, getUserNamesByGidSingleGid)
{
    auto mockGroup = std::make_shared<MockGroupWrapper>();
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockSys = std::make_shared<MockSystemWrapper>();

    EXPECT_CALL(*mockSys, sysconf(_SC_GETPW_R_SIZE_MAX)).WillOnce(testing::Return(1024));

    gid_t gid = 2000;
    auto groupBuf = std::make_unique<char[]>(1024);
    group group2 = {};
    char* members2[] = {strdup("dave"), nullptr};
    group2.gr_gid = gid;
    group2.gr_mem = members2;

    EXPECT_CALL(*mockGroup, getgrgid_r(gid, testing::_, testing::_, testing::_, testing::_))
    .WillOnce(
        [&](gid_t, group * g, char*, size_t, group** result)
    {
        *g = group2;
        *result = g;
        return 0;
    });

    passwd user2 = {};
    user2.pw_gid = gid;
    user2.pw_name = strdup("emma");

    passwd* user2Ptr = &user2;

    EXPECT_CALL(*mockPasswd, setpwent());
    EXPECT_CALL(*mockPasswd, getpwent()).WillOnce(testing::Return(user2Ptr)).WillOnce(testing::Return(nullptr));
    EXPECT_CALL(*mockPasswd, endpwent());

    UserGroupsProvider provider {mockGroup, mockPasswd, mockSys};

    auto result = provider.getUserNamesByGid({gid});

    nlohmann::json expected = {"dave", "emma"};
    EXPECT_EQ(result, expected);

    for (char** p = members2; *p != nullptr; ++p)
    {
        free(*p);
    }

    free(user2.pw_name);
}

TEST(UserGroupsProviderTest, getUserNamesByGidMultipleGids)
{
    auto mockGroup = std::make_shared<MockGroupWrapper>();
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockSys = std::make_shared<MockSystemWrapper>();

    EXPECT_CALL(*mockSys, sysconf(_SC_GETPW_R_SIZE_MAX)).WillOnce(testing::Return(1024));

    const gid_t gid1 = 3000;
    const gid_t gid2 = 4000;

    group grp1 = {};
    char* members1[] = {strdup("user1"), nullptr};
    grp1.gr_gid = gid1;
    grp1.gr_mem = members1;

    group grp2 = {};
    char* members2[] = {strdup("user2"), nullptr};
    grp2.gr_gid = gid2;
    grp2.gr_mem = members2;

    EXPECT_CALL(*mockGroup, getgrgid_r(gid1, testing::_, testing::_, testing::_, testing::_))
    .WillOnce(
        [&](gid_t, group * g, char*, size_t, group** result)
    {
        *g = grp1;
        *result = g;
        return 0;
    });

    EXPECT_CALL(*mockGroup, getgrgid_r(gid2, testing::_, testing::_, testing::_, testing::_))
    .WillOnce(
        [&](gid_t, group * g, char*, size_t, group** result)
    {
        *g = grp2;
        *result = g;
        return 0;
    });

    passwd pwd1 = {};
    pwd1.pw_gid = gid1;
    pwd1.pw_name = strdup("user3");

    passwd pwd2 = {};
    pwd2.pw_gid = gid2;
    pwd2.pw_name = strdup("user4");

    EXPECT_CALL(*mockPasswd, setpwent());
    EXPECT_CALL(*mockPasswd, getpwent())
    .WillOnce(testing::Return(&pwd1))
    .WillOnce(testing::Return(&pwd2))
    .WillOnce(testing::Return(nullptr));
    EXPECT_CALL(*mockPasswd, endpwent());

    UserGroupsProvider provider {mockGroup, mockPasswd, mockSys};

    std::set<gid_t> gids = {gid1, gid2};
    auto result = provider.getUserNamesByGid(gids);

    nlohmann::json expected = {{"3000", {"user1", "user3"}}, {"4000", {"user2", "user4"}}};

    EXPECT_EQ(result, expected);

    for (char** p = members1; *p != nullptr; ++p)
    {
        free(*p);
    }

    for (char** p = members2; *p != nullptr; ++p)
    {
        free(*p);
    }

    free(pwd1.pw_name);
    free(pwd2.pw_name);
}
