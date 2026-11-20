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
#include "igroup_wrapper.hpp"
#include "ipasswd_wrapper.hpp"
#include "iopen_directory_utils_wrapper.hpp"
#include "iuuid_wrapper.hpp"
#include "user_groups_darwin.hpp"
#include "json.hpp"

using ::testing::Return;
using ::testing::_;
using ::testing::DoAll;
using ::testing::SetArgPointee;
using ::testing::Invoke;
using ::testing::NiceMock;

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
        using GroupMembersMap = std::map<std::string, ODGroupMembers>;

        using StringBoolMap = std::map<std::string, bool>;
        using StringJsonMap = std::map<std::string, nlohmann::json>;

    public:
        MOCK_METHOD(void,
                    genEntries,
                    (const std::string& recordType, const std::string* record, StringBoolMap& usernames),
                    (override));
        MOCK_METHOD(void, genAccountPolicyData, (const std::string& uid, nlohmann::json& policyData), (override));
        MOCK_METHOD(void, genPasswordData, (StringJsonMap& passwordData), (override));
        MOCK_METHOD(bool, genDisabledUsers, (std::set<std::string>& disabledUsers), (override));
        MOCK_METHOD(bool, genGroupMembers, (GroupMembersMap& membersByGroup), (override));
};

class MockUUIDWrapper : public IUUIDWrapper
{
    public:
        MOCK_METHOD(void, uidToUUID, (uid_t uid, uuid_t& uuid), (override));
        MOCK_METHOD(void, gidToUUID, (gid_t gid, uuid_t& uuid), (override));
        MOCK_METHOD(void, uuidToString, (const uuid_t& uuid, uuid_string_t& str), (override));
};

// Answers the directory read the provider does once: each added user is listed by name in one
// group per extra gid, named "g<gid>". Nothing else is listed, so nested groups never appear.
class DirectGroupsStub
{
    public:
        DirectGroupsStub(MockGroupWrapper& group, MockODUtilsWrapper& od)
        {
            EXPECT_CALL(od, genGroupMembers(_)).WillOnce(Invoke([this](std::map<std::string, ODGroupMembers>& out)
            {
                out = m_members;
                return true;
            }));
            EXPECT_CALL(group, getgrnam(_)).WillRepeatedly(Invoke([this](const char* name) -> struct group*
            {
                auto it = m_groups.find(name);
                return it == m_groups.end() ? nullptr : &it->second;
            }));
        }

        ~DirectGroupsStub()
        {
            for (auto& entry : m_groups)
            {
                free(entry.second.gr_name);
            }
        }

        void add(const std::string& user, const std::vector<gid_t>& extraGids)
        {
            for (const auto gid : extraGids)
            {
                const auto name = "g" + std::to_string(gid);
                m_members[name].names.insert(user);
                m_groups.try_emplace(name);
                m_groups[name].gr_gid = gid;
                m_groups[name].gr_name = strdup(name.c_str());
            }
        }

    private:
        std::map<std::string, ODGroupMembers> m_members;
        std::map<std::string, struct group> m_groups;
};

// Test fixture to ensure cache is reset before each test
class UserGroupsProviderDarwinTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            UserGroupsProvider::resetCache();
        }
};

struct passwd* createFakePasswd(const char* name, uid_t uid, gid_t gid)
{
    auto* pwd = new passwd();
    pwd->pw_name = strdup(name);
    pwd->pw_uid = uid;
    pwd->pw_gid = gid;
    return pwd;
}

TEST_F(UserGroupsProviderDarwinTest, CollectWithUIDReturnsExpectedGroups)
{
    auto mockGroup = std::make_shared<MockGroupWrapper>();
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockODWrapper = std::make_shared<MockODUtilsWrapper>();
    auto mockUuid = std::make_shared<NiceMock<MockUUIDWrapper>>();
    UserGroupsProvider provider(mockGroup, mockPasswd, mockODWrapper, mockUuid);
    DirectGroupsStub stub(*mockGroup, *mockODWrapper);

    uid_t testUid = 1000;
    gid_t testGid = 2000;
    const char* username = "testuser";

    passwd* fakePwd = createFakePasswd(username, testUid, testGid);
    EXPECT_CALL(*mockPasswd, getpwuid(testUid)).WillOnce(Return(fakePwd));

    stub.add("testuser", {2000, 3000});

    std::set<uid_t> uids = {testUid};
    nlohmann::json result = provider.collect(uids);

    ASSERT_EQ(result.size(), static_cast<decltype(result.size())>(2));
    EXPECT_EQ(result[0]["uid"], testUid);
    EXPECT_EQ(result[0]["gid"], 2000);
    EXPECT_EQ(result[1]["gid"], 3000);

    free(fakePwd->pw_name);
    delete fakePwd;
}

TEST_F(UserGroupsProviderDarwinTest, CollectWithoutUID_ReturnsExpectedGroups)
{
    auto mockGroup = std::make_shared<MockGroupWrapper>();
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockODWrapper = std::make_shared<MockODUtilsWrapper>();
    auto mockUuid = std::make_shared<NiceMock<MockUUIDWrapper>>();
    UserGroupsProvider provider(mockGroup, mockPasswd, mockODWrapper, mockUuid);
    DirectGroupsStub stub(*mockGroup, *mockODWrapper);

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

    stub.add(username, {3001});

    std::set<uid_t> emptyUids;
    nlohmann::json result = provider.collect(emptyUids);

    ASSERT_EQ(result.size(), static_cast<decltype(result.size())>(1));
    EXPECT_EQ(result[0]["uid"], testUid);
    EXPECT_EQ(result[0]["gid"], 3001);

    free(fakePwd->pw_name);
    delete fakePwd;
}

TEST_F(UserGroupsProviderDarwinTest, GetUserNamesByGidSingleGidReturnsCorrectUsernames)
{
    auto mockGroup = std::make_shared<MockGroupWrapper>();
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockODWrapper = std::make_shared<MockODUtilsWrapper>();
    auto mockUuid = std::make_shared<NiceMock<MockUUIDWrapper>>();
    UserGroupsProvider provider(mockGroup, mockPasswd, mockODWrapper, mockUuid);
    DirectGroupsStub stub(*mockGroup, *mockODWrapper);

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

    stub.add(username, {extraGid});

    nlohmann::json result = provider.getUserNamesByGid(targetGids);

    ASSERT_TRUE(result.is_array());
    ASSERT_EQ(result.size(), static_cast<decltype(result.size())>(1));
    EXPECT_EQ(result[0], username);

    free(fakePwd->pw_name);
    delete fakePwd;
}

TEST_F(UserGroupsProviderDarwinTest, GetUserNamesByGidMultipleGidsReturnsGroupedUsernames)
{
    auto mockGroup = std::make_shared<MockGroupWrapper>();
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockODWrapper = std::make_shared<MockODUtilsWrapper>();
    auto mockUuid = std::make_shared<NiceMock<MockUUIDWrapper>>();
    UserGroupsProvider provider(mockGroup, mockPasswd, mockODWrapper, mockUuid);
    DirectGroupsStub stub(*mockGroup, *mockODWrapper);

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

    stub.add(username, {gid2});

    auto result = provider.getUserNamesByGid(gids);

    ASSERT_TRUE(result.is_object());
    EXPECT_TRUE(result.contains(std::to_string(gid1)));
    EXPECT_TRUE(result.contains(std::to_string(gid2)));
    EXPECT_THAT(result[std::to_string(gid1)], ::testing::Contains(username));
    EXPECT_THAT(result[std::to_string(gid2)], ::testing::Contains(username));

    free(fakePwd->pw_name);
    delete fakePwd;
}

TEST_F(UserGroupsProviderDarwinTest, GetUserNamesByGid_NoMatch_ReturnsEmpty)
{
    auto mockGroup = std::make_shared<MockGroupWrapper>();
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockODWrapper = std::make_shared<MockODUtilsWrapper>();
    auto mockUuid = std::make_shared<NiceMock<MockUUIDWrapper>>();
    UserGroupsProvider provider(mockGroup, mockPasswd, mockODWrapper, mockUuid);

    std::map<std::string, bool> emptyUsers;
    EXPECT_CALL(*mockODWrapper, genEntries("dsRecTypeStandard:Users", nullptr, _))
    .WillOnce(Invoke([&emptyUsers](const std::string&, const void*, std::map<std::string, bool>& out)
    {
        out = emptyUsers;
    }));

    auto result = provider.getUserNamesByGid({1234});
    ASSERT_TRUE(result.empty());
}

TEST_F(UserGroupsProviderDarwinTest, GetGroupNamesByUidSingleUidReturnsGroupNames)
{
    auto mockGroup = std::make_shared<MockGroupWrapper>();
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockODWrapper = std::make_shared<MockODUtilsWrapper>();
    auto mockUuid = std::make_shared<NiceMock<MockUUIDWrapper>>();
    UserGroupsProvider provider(mockGroup, mockPasswd, mockODWrapper, mockUuid);
    DirectGroupsStub stub(*mockGroup, *mockODWrapper);

    const char* username = "testuser";
    uid_t uid = 1001;
    gid_t primaryGid = 2001;
    gid_t extraGid = 3001;
    std::set<uid_t> targetUids = {uid};

    passwd* fakePwd = createFakePasswd(username, uid, primaryGid);

    EXPECT_CALL(*mockPasswd, getpwuid(uid))
    .WillOnce(Return(fakePwd));

    stub.add(username, {extraGid});

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

TEST_F(UserGroupsProviderDarwinTest, GetGroupNamesByUidMultipleUidsReturnsGroupedNames)
{
    auto mockGroup = std::make_shared<MockGroupWrapper>();
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockODWrapper = std::make_shared<MockODUtilsWrapper>();
    auto mockUuid = std::make_shared<NiceMock<MockUUIDWrapper>>();
    UserGroupsProvider provider(mockGroup, mockPasswd, mockODWrapper, mockUuid);
    DirectGroupsStub stub(*mockGroup, *mockODWrapper);

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

    stub.add(user1, {});
    stub.add(user2, {});

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

TEST_F(UserGroupsProviderDarwinTest, GetGroupNamesByUidInvalidUIDReturnsEmpty)
{
    auto mockGroup = std::make_shared<MockGroupWrapper>();
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockODWrapper = std::make_shared<MockODUtilsWrapper>();
    auto mockUuid = std::make_shared<NiceMock<MockUUIDWrapper>>();
    UserGroupsProvider provider(mockGroup, mockPasswd, mockODWrapper, mockUuid);

    uid_t invalidUid = 9999;
    EXPECT_CALL(*mockPasswd, getpwuid(invalidUid)).WillOnce(Return(nullptr));

    auto result = provider.getGroupNamesByUid({invalidUid});
    ASSERT_TRUE(result.empty());
}

namespace
{
    // One account whose groups come from a directory the test scripts, read by a fresh provider.
    struct DirectoryCase
    {
        std::shared_ptr<MockGroupWrapper> group = std::make_shared<MockGroupWrapper>();
        std::shared_ptr<MockPasswdWrapper> passwd = std::make_shared<MockPasswdWrapper>();
        std::shared_ptr<MockODUtilsWrapper> od = std::make_shared<MockODUtilsWrapper>();
        std::shared_ptr<NiceMock<MockUUIDWrapper>> uuid = std::make_shared<NiceMock<MockUUIDWrapper>>();
        struct passwd account {};
        struct group share {};

        DirectoryCase()
        {
            account.pw_name = const_cast<char*>("member");
            account.pw_uid = 600;
            account.pw_gid = 20;
            share.gr_gid = 5000;
            share.gr_name = const_cast<char*>("share");
            EXPECT_CALL(*passwd, getpwuid(600)).WillRepeatedly(Return(&account));
            EXPECT_CALL(*group, getgrnam(::testing::StrEq("share"))).WillRepeatedly(Return(&share));
            EXPECT_CALL(*group, getgrouplist(_, _, _, _)).Times(0);
        }

        nlohmann::json collect()
        {
            UserGroupsProvider::resetCache();
            UserGroupsProvider provider(group, passwd, od, uuid);
            return provider.collect({600});
        }
    };
}

TEST_F(UserGroupsProviderDarwinTest, GroupThatOnlyNestsAnotherGroupIsNotReported)
{
    DirectoryCase env;
    EXPECT_CALL(*env.od, genGroupMembers(_)).WillOnce(Invoke([](std::map<std::string, ODGroupMembers>& out)
    {
        // "share" nests `everyone` in the directory, so it does not list `member` itself.
        out["share"] = {};
        return true;
    }));

    const auto result = env.collect();

    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0]["gid"], 20);
}

TEST_F(UserGroupsProviderDarwinTest, MemberListedOnlyByGuidIsReported)
{
    DirectoryCase env;
    EXPECT_CALL(*env.uuid, uuidToString(_, _)).WillRepeatedly(Invoke([](const uuid_t&, uuid_string_t& str)
    {
        strlcpy(str, "abcdefab-cdef-abcd-efab-cdef00000001", sizeof(uuid_string_t));
    }));
    EXPECT_CALL(*env.od, genGroupMembers(_)).WillOnce(Invoke([](std::map<std::string, ODGroupMembers>& out)
    {
        out["share"].uuids.insert("ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000001");
        return true;
    }));

    const auto result = env.collect();

    ASSERT_EQ(result.size(), 2u);
    EXPECT_EQ(result[0]["gid"], 20);
    EXPECT_EQ(result[1]["gid"], 5000);
}

TEST_F(UserGroupsProviderDarwinTest, PrimaryGroupComesFirstThenAscendingGidsWithoutRepeats)
{
    auto mockGroup = std::make_shared<MockGroupWrapper>();
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockODWrapper = std::make_shared<MockODUtilsWrapper>();
    auto mockUuid = std::make_shared<NiceMock<MockUUIDWrapper>>();
    UserGroupsProvider provider(mockGroup, mockPasswd, mockODWrapper, mockUuid);
    DirectGroupsStub stub(*mockGroup, *mockODWrapper);

    passwd* fakePwd = createFakePasswd("testuser", 700, 500);
    EXPECT_CALL(*mockPasswd, getpwuid(700)).WillOnce(Return(fakePwd));
    stub.add("testuser", {900, 300, 300, 500});

    const auto result = provider.collect({700});

    ASSERT_EQ(result.size(), 3u);
    EXPECT_EQ(result[0]["gid"], 500);
    EXPECT_EQ(result[1]["gid"], 300);
    EXPECT_EQ(result[2]["gid"], 900);

    free(fakePwd->pw_name);
    delete fakePwd;
}

TEST_F(UserGroupsProviderDarwinTest, UnreadableDirectoryReportsNoGroupsAndIsNotCached)
{
    DirectoryCase env;
    EXPECT_CALL(*env.od, genGroupMembers(_))
    .WillOnce(Return(false))
    .WillOnce(Invoke([](std::map<std::string, ODGroupMembers>& out)
    {
        out["share"].names.insert("member");
        return true;
    }));

    EXPECT_TRUE(env.collect().empty());

    // The failed scan left nothing behind: the next one reads the directory again.
    EXPECT_EQ(env.collect().size(), 2u);
}

TEST_F(UserGroupsProviderDarwinTest, EffectiveGroupNamesIncludeGroupsReachedThroughNesting)
{
    auto mockGroup = std::make_shared<MockGroupWrapper>();
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockODWrapper = std::make_shared<MockODUtilsWrapper>();
    auto mockUuid = std::make_shared<NiceMock<MockUUIDWrapper>>();
    UserGroupsProvider provider(mockGroup, mockPasswd, mockODWrapper, mockUuid);

    passwd* fakePwd = createFakePasswd("member", 800, 20);
    EXPECT_CALL(*mockPasswd, getpwuid(800)).WillOnce(Return(fakePwd));
    EXPECT_CALL(*mockGroup, getgroupcount(::testing::StrEq("member"), 20)).WillOnce(Return(2));
    // The second gid is a group the account reaches only because another group nests into it.
    EXPECT_CALL(*mockGroup, getgrouplist(::testing::StrEq("member"), 20, _, _))
    .WillOnce(Invoke([](const char*, gid_t, gid_t * groups, int*)
    {
        groups[0] = 20;
        groups[1] = 80;
        return 0;
    }));

    struct group staff {};
    staff.gr_name = const_cast<char*>("staff");
    struct group admin {};
    admin.gr_name = const_cast<char*>("admin");
    EXPECT_CALL(*mockGroup, getgrgid(20)).WillOnce(Return(&staff));
    EXPECT_CALL(*mockGroup, getgrgid(80)).WillOnce(Return(&admin));

    EXPECT_THAT(provider.getEffectiveGroupNamesByUid(800), ::testing::UnorderedElementsAre("staff", "admin"));

    free(fakePwd->pw_name);
    delete fakePwd;
}

TEST_F(UserGroupsProviderDarwinTest, EffectiveGroupNamesOfUnknownUidAreEmpty)
{
    auto mockGroup = std::make_shared<MockGroupWrapper>();
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockODWrapper = std::make_shared<MockODUtilsWrapper>();
    auto mockUuid = std::make_shared<NiceMock<MockUUIDWrapper>>();
    UserGroupsProvider provider(mockGroup, mockPasswd, mockODWrapper, mockUuid);

    EXPECT_CALL(*mockPasswd, getpwuid(9999)).WillOnce(Return(nullptr));

    EXPECT_TRUE(provider.getEffectiveGroupNamesByUid(9999).empty());
}
