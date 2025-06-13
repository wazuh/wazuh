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
#include "iopen_directory_utils_wrapper.hpp"
#include "user_groups_darwin.hpp"
#include "json.hpp"

using ::testing::Return;
using ::testing::_;
using ::testing::DoAll;
using ::testing::SetArgPointee;
using ::testing::Invoke;

class MockGroupWrapper : public IGroupWrapperDarwin
{
    public:
        MOCK_METHOD(struct group*, getgrgid, (gid_t gid), (const, override));
        MOCK_METHOD(struct group*, getgrnam, (const char* name), (const, override));
        MOCK_METHOD(int, getgrouplist, (const char* user, gid_t group, gid_t* groups, int* ngroups), (const, override));
        MOCK_METHOD(int, getgroupcount, (const char* user, gid_t group), (const, override));
};

class MockPasswdWrapper : public IPasswdWrapperDarwin
{
    public:
        MOCK_METHOD(void, setpwent, (), (override));
        MOCK_METHOD(void, endpwent, (), (override));
        MOCK_METHOD(struct passwd*, getpwent, (), (override));
        MOCK_METHOD(struct passwd*, getpwuid, (uid_t uid), (override));
        MOCK_METHOD(struct passwd*, getpwnam, (const char* name), (override));
};

class MockODUtilsWrapper : public IODUtilsWrapper
{
        using StringBoolMap = std::map<std::string, bool>;

    public:
        MOCK_METHOD(void,
                    genEntries,
                    (const std::string& recordType, const std::string* record, StringBoolMap& usernames),
                    (override));
        MOCK_METHOD(void, genAccountPolicyData, (const std::string& uid, nlohmann::json& policyData), (override));
};

struct passwd* createFakePasswd(const char* name, uid_t uid, gid_t gid)
{
    auto* pwd = new passwd();
    pwd->pw_name = strdup(name);
    pwd->pw_uid = uid;
    pwd->pw_gid = gid;
    return pwd;
}

TEST(UserGroupsProviderTest, CollectWithUIDReturnsExpectedGroups)
{
    auto mockGroup = std::make_shared<MockGroupWrapper>();
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockODWrapper = std::make_shared<MockODUtilsWrapper>();
    UserGroupsProvider provider(mockGroup, mockPasswd, mockODWrapper);

    uid_t testUid = 1000;
    gid_t testGid = 2000;
    const char* username = "testuser";

    passwd* fakePwd = createFakePasswd(username, testUid, testGid);
    EXPECT_CALL(*mockPasswd, getpwuid(testUid)).WillOnce(Return(fakePwd));

    EXPECT_CALL(*mockGroup, getgroupcount(::testing::StrEq("testuser"), testGid))
    .WillOnce(Return(2));

    EXPECT_CALL(*mockGroup, getgrouplist(::testing::StrEq("testuser"), testGid, _, _))
    .WillOnce(Invoke([](const std::string&, gid_t, gid_t * groups, int* /*ngroups*/)
    {
        groups[0] = 2000;
        groups[1] = 3000;
        return 0;
    }));

    std::set<uid_t> uids = {testUid};
    nlohmann::json result = provider.collect(uids);

    ASSERT_EQ(result.size(), static_cast<decltype(result.size())>(2));
    EXPECT_EQ(result[0]["uid"], testUid);
    EXPECT_EQ(result[0]["gid"], 2000);
    EXPECT_EQ(result[1]["gid"], 3000);

    free(fakePwd->pw_name);
    delete fakePwd;
}

TEST(UserGroupsProviderTest, CollectWithoutUID_ReturnsExpectedGroups)
{
    auto mockGroup = std::make_shared<MockGroupWrapper>();
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockODWrapper = std::make_shared<MockODUtilsWrapper>();
    UserGroupsProvider provider(mockGroup, mockPasswd, mockODWrapper);

    const char* username = "testuser";
    uid_t testUid = 1001;
    gid_t testGid = 3001;

    std::map<std::string, bool> fakeUsers = {{username, true}};

    EXPECT_CALL(*mockODWrapper, genEntries("dsRecTypeStandard:Users", nullptr, _))
    .WillOnce(Invoke([&fakeUsers](const std::string&, const void*, std::map<std::string, bool>& output)
    {
        output = fakeUsers;
    }));

    passwd* fakePwd = createFakePasswd(username, testUid, testGid);
    EXPECT_CALL(*mockPasswd, getpwnam(::testing::StrEq(username))).WillOnce(Return(fakePwd));

    EXPECT_CALL(*mockGroup, getgroupcount(::testing::StrEq(username), testGid))
    .WillOnce(Return(1));

    EXPECT_CALL(*mockGroup, getgrouplist(::testing::StrEq(username), testGid, _, _))
    .WillOnce(Invoke([](const std::string&, gid_t, gid_t * groups, int* /*ngroups*/)
    {
        groups[0] = 3001;
        return 0;
    }));

    std::set<uid_t> emptyUids;
    nlohmann::json result = provider.collect(emptyUids);

    ASSERT_EQ(result.size(), static_cast<decltype(result.size())>(1));
    EXPECT_EQ(result[0]["uid"], testUid);
    EXPECT_EQ(result[0]["gid"], 3001);

    free(fakePwd->pw_name);
    delete fakePwd;
}

TEST(UserGroupsProviderTest, GetUserNamesByGidSingleGidReturnsCorrectUsernames)
{
    auto mockGroup = std::make_shared<MockGroupWrapper>();
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockODWrapper = std::make_shared<MockODUtilsWrapper>();
    UserGroupsProvider provider(mockGroup, mockPasswd, mockODWrapper);

    const char* username = "testuser";
    uid_t uid = 1000;
    gid_t primaryGid = 2000;
    gid_t extraGid = 3000;
    std::set<gid_t> targetGids = {extraGid};

    std::map<std::string, bool> fakeUsers = {{username, true}};
    passwd* fakePwd = createFakePasswd(username, uid, primaryGid);

    EXPECT_CALL(*mockODWrapper, genEntries("dsRecTypeStandard:Users", nullptr, _))
    .WillOnce(Invoke([&fakeUsers](const std::string&, const void*, std::map<std::string, bool>& out)
    {
        out = fakeUsers;
    }));

    EXPECT_CALL(*mockPasswd, getpwnam(::testing::StrEq(username)))
    .WillOnce(Return(fakePwd));

    EXPECT_CALL(*mockGroup, getgroupcount(::testing::StrEq(username), primaryGid))
    .WillOnce(Return(2));

    EXPECT_CALL(*mockGroup, getgrouplist(::testing::StrEq(username), primaryGid, _, _))
    .WillOnce(Invoke([ = ](const char*, gid_t, gid_t * groups, int*)
    {
        groups[0] = primaryGid;
        groups[1] = extraGid;
        return 0;
    }));

    nlohmann::json result = provider.getUserNamesByGid(targetGids);

    ASSERT_TRUE(result.is_array());
    ASSERT_EQ(result.size(), static_cast<decltype(result.size())>(1));
    EXPECT_EQ(result[0], username);

    free(fakePwd->pw_name);
    delete fakePwd;
}

TEST(UserGroupsProviderTest, GetUserNamesByGidMultipleGidsReturnsGroupedUsernames)
{
    auto mockGroup = std::make_shared<MockGroupWrapper>();
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockODWrapper = std::make_shared<MockODUtilsWrapper>();
    UserGroupsProvider provider(mockGroup, mockPasswd, mockODWrapper);

    const char* username = "testuser";
    uid_t uid = 1000;
    gid_t gid1 = 2000;
    gid_t gid2 = 3000;
    std::set<gid_t> gids = {gid1, gid2};

    std::map<std::string, bool> fakeUsers = {{username, true}};
    passwd* fakePwd = createFakePasswd(username, uid, gid1);

    EXPECT_CALL(*mockODWrapper, genEntries("dsRecTypeStandard:Users", nullptr, _))
    .WillOnce(Invoke([&fakeUsers](const std::string&, const void*, std::map<std::string, bool>& out)
    {
        out = fakeUsers;
    }));

    EXPECT_CALL(*mockPasswd, getpwnam(::testing::StrEq(username)))
    .WillOnce(Return(fakePwd));

    EXPECT_CALL(*mockGroup, getgroupcount(::testing::StrEq(username), gid1))
    .WillOnce(Return(2));

    EXPECT_CALL(*mockGroup, getgrouplist(::testing::StrEq(username), gid1, testing::NotNull(), _))
    .WillOnce(Invoke([ = ](const char*, gid_t, gid_t * groups, int* ngroups)
    {
        if (*ngroups >= 2)
        {
            groups[0] = gid1;
            groups[1] = gid2;
            *ngroups = 2;
            return 0;
        }

        return -1;
    }));

    auto result = provider.getUserNamesByGid(gids);

    ASSERT_TRUE(result.is_object());
    EXPECT_TRUE(result.contains(std::to_string(gid1)));
    EXPECT_TRUE(result.contains(std::to_string(gid2)));
    EXPECT_THAT(result[std::to_string(gid1)], ::testing::Contains(username));
    EXPECT_THAT(result[std::to_string(gid2)], ::testing::Contains(username));

    free(fakePwd->pw_name);
    delete fakePwd;
}

TEST(UserGroupsProviderTest, GetUserNamesByGid_NoMatch_ReturnsEmpty)
{
    auto mockGroup = std::make_shared<MockGroupWrapper>();
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockODWrapper = std::make_shared<MockODUtilsWrapper>();
    UserGroupsProvider provider(mockGroup, mockPasswd, mockODWrapper);

    std::map<std::string, bool> emptyUsers;
    EXPECT_CALL(*mockODWrapper, genEntries("dsRecTypeStandard:Users", nullptr, _))
    .WillOnce(Invoke([&emptyUsers](const std::string&, const void*, std::map<std::string, bool>& out)
    {
        out = emptyUsers;
    }));

    auto result = provider.getUserNamesByGid({1234});
    ASSERT_TRUE(result.empty());
}

TEST(UserGroupsProviderTest, GetGroupNamesByUidSingleUidReturnsGroupNames)
{
    auto mockGroup = std::make_shared<MockGroupWrapper>();
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockODWrapper = std::make_shared<MockODUtilsWrapper>();
    UserGroupsProvider provider(mockGroup, mockPasswd, mockODWrapper);

    const char* username = "testuser";
    uid_t uid = 1001;
    gid_t primaryGid = 2001;
    gid_t extraGid = 3001;
    std::set<uid_t> targetUids = {uid};

    passwd* fakePwd = createFakePasswd(username, uid, primaryGid);

    EXPECT_CALL(*mockPasswd, getpwuid(uid))
    .WillOnce(Return(fakePwd));

    EXPECT_CALL(*mockGroup, getgroupcount(::testing::StrEq(username), primaryGid))
    .WillOnce(Return(2));

    EXPECT_CALL(*mockGroup, getgrouplist(::testing::StrEq(username), primaryGid, _, _))
    .WillOnce(Invoke([ = ](const char*, gid_t, gid_t * groups, int*)
    {
        groups[0] = primaryGid;
        groups[1] = extraGid;
        return 0;
    }));

    struct group* fakeGroup1 = new group();
    fakeGroup1->gr_name = strdup("staff");

    struct group* fakeGroup2 = new group();
    fakeGroup2->gr_name = strdup("dev");

    EXPECT_CALL(*mockGroup, getgrgid(primaryGid)).WillOnce(Return(fakeGroup1));
    EXPECT_CALL(*mockGroup, getgrgid(extraGid)).WillOnce(Return(fakeGroup2));

    nlohmann::json result = provider.getGroupNamesByUid(targetUids);

    ASSERT_TRUE(result.is_array());
    ASSERT_EQ(result.size(), static_cast<decltype(result.size())>(2));
    EXPECT_THAT(result, ::testing::UnorderedElementsAre("staff", "dev"));

    free(fakePwd->pw_name);
    delete fakePwd;
    free(fakeGroup1->gr_name);
    free(fakeGroup1);
    free(fakeGroup2->gr_name);
    delete fakeGroup2;
}

TEST(UserGroupsProviderTest, GetGroupNamesByUidMultipleUidsReturnsGroupedNames)
{
    auto mockGroup = std::make_shared<MockGroupWrapper>();
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockODWrapper = std::make_shared<MockODUtilsWrapper>();
    UserGroupsProvider provider(mockGroup, mockPasswd, mockODWrapper);

    const char* user1 = "user1";
    const char* user2 = "user2";
    uid_t uid1 = 5001;
    uid_t uid2 = 5002;
    gid_t gid1 = 3001;
    gid_t gid2 = 3002;

    auto* pwd1 = createFakePasswd(user1, uid1, gid1);
    auto* pwd2 = createFakePasswd(user2, uid2, gid2);

    EXPECT_CALL(*mockPasswd, getpwuid(uid1)).WillOnce(Return(pwd1));
    EXPECT_CALL(*mockPasswd, getpwuid(uid2)).WillOnce(Return(pwd2));

    EXPECT_CALL(*mockGroup, getgroupcount(::testing::StrEq(user1), gid1)).WillOnce(Return(1));
    EXPECT_CALL(*mockGroup, getgroupcount(::testing::StrEq(user2), gid2)).WillOnce(Return(1));

    EXPECT_CALL(*mockGroup, getgrouplist(::testing::StrEq(user1), gid1, _, _))
    .WillOnce(Invoke([ = ](const char*, gid_t, gid_t * groups, int*)
    {
        groups[0] = gid1;
        return 0;
    }));

    EXPECT_CALL(*mockGroup, getgrouplist(::testing::StrEq(user2), gid2, _, _))
    .WillOnce(Invoke([ = ](const char*, gid_t, gid_t * groups, int*)
    {
        groups[0] = gid2;
        return 0;
    }));

    struct group* grp1 = new group();
    grp1->gr_name = strdup("staff");

    struct group* grp2 = new group();
    grp2->gr_name = strdup("admin");

    EXPECT_CALL(*mockGroup, getgrgid(gid1)).WillOnce(Return(grp1));
    EXPECT_CALL(*mockGroup, getgrgid(gid2)).WillOnce(Return(grp2));

    std::set<uid_t> uids = {uid1, uid2};
    auto result = provider.getGroupNamesByUid(uids);

    ASSERT_TRUE(result.is_object());
    EXPECT_EQ(result[std::to_string(uid1)][0], "staff");
    EXPECT_EQ(result[std::to_string(uid2)][0], "admin");

    free(pwd1->pw_name);
    delete pwd1;
    free(pwd2->pw_name);
    delete pwd2;
    free(grp1->gr_name);
    delete grp1;
    free(grp2->gr_name);
    delete grp2;
}

TEST(UserGroupsProviderTest, GetGroupNamesByUidInvalidUIDReturnsEmpty)
{
    auto mockGroup = std::make_shared<MockGroupWrapper>();
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockODWrapper = std::make_shared<MockODUtilsWrapper>();
    UserGroupsProvider provider(mockGroup, mockPasswd, mockODWrapper);

    uid_t invalidUid = 9999;
    EXPECT_CALL(*mockPasswd, getpwuid(invalidUid)).WillOnce(Return(nullptr));

    auto result = provider.getGroupNamesByUid({invalidUid});
    ASSERT_TRUE(result.empty());
}
