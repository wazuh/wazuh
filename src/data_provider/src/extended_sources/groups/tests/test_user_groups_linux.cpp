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
#include <algorithm>
#include <functional>
#include <cerrno>
#include <string>
#include <vector>
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

class UserGroupsProviderLinuxTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            UserGroupsProvider::resetCache();
        }
};

namespace
{
    // getpwent_r() stub that hands out the given (name, uid, gid) entries in order and then ends.
    struct PasswdEntry
    {
        const char* name;
        uid_t uid;
        gid_t gid;
    };

    auto enumerate(const std::vector<PasswdEntry>& entries)
    {
        auto next = std::make_shared<size_t>(0);
        return [entries, next](struct passwd * pwd, char*, size_t, struct passwd** result)
        {
            if (*next >= entries.size())
            {
                *result = nullptr;
                return ENOENT;
            }

            const auto& entry = entries[(*next)++];
            pwd->pw_name = const_cast<char*>(entry.name);
            pwd->pw_uid = entry.uid;
            pwd->pw_gid = entry.gid;
            *result = pwd;
            return 0;
        };
    }

    struct GroupEntry
    {
        std::string name;
        gid_t gid;
        std::vector<std::string> members;
        // getgrent_r() answers ERANGE for this entry while the buffer is smaller than this.
        size_t requiredBuf {0};
    };

    // getgrouplist() stub for a user the group database adds nothing to: only the primary group.
    int primaryOnly(const char*, gid_t gid, gid_t* groups, int* ngroups)
    {
        groups[0] = gid;
        *ngroups = 1;
        return 1;
    }

    // Group database served through setgrent()/getgrent()/endgrent(). It owns the memory the
    // returned entries point to, so it has to outlive the provider call.
    class GroupDb
    {
        public:
            explicit GroupDb(std::vector<GroupEntry> entries)
                : m_entries(std::move(entries))
            {
                for (auto& entry : m_entries)
                {
                    std::vector<char*> members;

                    for (auto& member : entry.members)
                    {
                        members.push_back(member.data());
                    }

                    members.push_back(nullptr);
                    m_members.push_back(std::move(members));
                }

                for (size_t i = 0; i < m_entries.size(); ++i)
                {
                    struct group grp {};
                    grp.gr_name = m_entries[i].name.data();
                    grp.gr_gid = m_entries[i].gid;
                    grp.gr_mem = m_members[i].data();
                    m_groups.push_back(grp);
                }
            }

            // Exactly one enumeration is expected. getgrouplist(), asked only about users no
            // group lists, answers with the primary group alone unless a test says otherwise.
            void expectOneEnumeration(MockGroupWrapper& mock)
            {
                EXPECT_CALL(mock, setgrent()).Times(1);
                EXPECT_CALL(mock, endgrent()).Times(1);
                EXPECT_CALL(mock, getgrent_r(_, _, _, _))
                .WillRepeatedly(Invoke([this](struct group * grp, char*, size_t buflen, struct group** result)
                {
                    if (m_next >= m_groups.size())
                    {
                        *result = nullptr;
                        return ENOENT;
                    }

                    if (buflen < m_entries[m_next].requiredBuf)
                    {
                        *result = nullptr;
                        return ERANGE;
                    }

                    *grp = m_groups[m_next++];
                    *result = grp;
                    return 0;
                }));
                EXPECT_CALL(mock, getgrent()).Times(0);
                EXPECT_CALL(mock, getgrouplist(_, _, _, _)).WillRepeatedly(Invoke(primaryOnly));
            }

        private:
            std::vector<GroupEntry> m_entries;
            std::vector<std::vector<char*>> m_members;
            std::vector<struct group> m_groups;
            size_t m_next {0};
    };
}

TEST_F(UserGroupsProviderLinuxTest, CollectWithSpecificUid)
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

    GroupDb groupDb({{"testgroup", 2001, {}}, {"othergroup", 2002, {username}}});
    groupDb.expectOneEnumeration(*mockGroup);

    UserGroupsProvider provider(mockGroup, mockPasswd, mockSys);

    auto result = provider.collect({testUid});

    ASSERT_EQ(result.size(), static_cast<decltype(result.size())>(2));
    EXPECT_EQ(result[0]["uid"], testUid);
    EXPECT_EQ(result[0]["gid"], 2001);
    EXPECT_EQ(result[1]["uid"], testUid);
    EXPECT_EQ(result[1]["gid"], 2002);
}

TEST_F(UserGroupsProviderLinuxTest, CollectAllUserGroups)
{
    auto mockGroup = std::make_shared<MockGroupWrapper>();
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockSys = std::make_shared<MockSystemWrapper>();
    UserGroupsProvider provider(mockGroup, mockPasswd, mockSys);

    struct passwd user1 {};
    struct passwd user2 {};

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

    GroupDb groupDb({{"g101", 101, {user1Name}}, {"g102", 102, {user1Name}},
        {"g201", 201, {user2Name}}, {"g202", 202, {user2Name}}});
    groupDb.expectOneEnumeration(*mockGroup);

    EXPECT_CALL(*mockPasswd, endpwent());

    nlohmann::json results = provider.collect();

    ASSERT_EQ(results.size(), static_cast<decltype(results.size())>(6)); // 2 users * (primary + 2 groups)

    std::set<std::tuple<uid_t, gid_t>> expected =
    {
        {user1Uid, user1Gid}, {user1Uid, 101}, {user1Uid, 102},
        {user2Uid, user2Gid}, {user2Uid, 201}, {user2Uid, 202}
    };

    for (const auto& entry : results)
    {
        uid_t uid = entry["uid"];
        gid_t gid = entry["gid"];
        ASSERT_TRUE(expected.count({uid, gid})) << "Unexpected pair: uid=" << uid << ", gid=" << gid;
    }
}

TEST_F(UserGroupsProviderLinuxTest, getUserNamesByGidAllGroups)
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

TEST_F(UserGroupsProviderLinuxTest, getUserNamesByGidSingleGid)
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

TEST_F(UserGroupsProviderLinuxTest, getUserNamesByGidMultipleGids)
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

// A gid shared by several users must cost one group lookup for the whole call, not one
// per user that belongs to it. On a host whose group database is served by a network
// directory, each lookup is a round trip, so the call count is the property under test.
// Names of the groups the enumeration returned are taken from it: no gid is looked up again.
TEST_F(UserGroupsProviderLinuxTest, getGroupNamesByUidTakesNamesFromGroupEnumeration)
{
    auto mockGroup = std::make_shared<MockGroupWrapper>();
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockSys = std::make_shared<MockSystemWrapper>();

    const uid_t uidA = 1001;
    const uid_t uidB = 1002;
    const char* nameA = "usera";
    const char* nameB = "userb";
    const gid_t sharedGid1 = 100;
    const gid_t sharedGid2 = 101;

    EXPECT_CALL(*mockSys, sysconf(_SC_GETPW_R_SIZE_MAX)).WillOnce(Return(1024));
    EXPECT_CALL(*mockSys, sysconf(_SC_GETGR_R_SIZE_MAX)).WillOnce(Return(1024));

    EXPECT_CALL(*mockPasswd, setpwent());
    EXPECT_CALL(*mockPasswd, getpwent_r(_, _, _, _))
    .WillRepeatedly(Invoke(enumerate({{nameA, uidA, sharedGid1}, {nameB, uidB, sharedGid1}})));
    EXPECT_CALL(*mockPasswd, endpwent());

    GroupDb groupDb({{"groupone", sharedGid1, {}}, {"grouptwo", sharedGid2, {nameA, nameB}}});
    groupDb.expectOneEnumeration(*mockGroup);
    EXPECT_CALL(*mockGroup, getgrgid_r(_, _, _, _, _)).Times(0);

    UserGroupsProvider provider(mockGroup, mockPasswd, mockSys);

    auto result = provider.getGroupNamesByUid({uidA, uidB});

    ASSERT_TRUE(result.is_object());
    EXPECT_EQ(result[std::to_string(uidA)], nlohmann::json::array({"groupone", "grouptwo"}));
    EXPECT_EQ(result[std::to_string(uidB)], nlohmann::json::array({"groupone", "grouptwo"}));
}

// A gid the group database cannot resolve must also be looked up only once. Without
// memoising the failures, an unresolvable gid shared by many users costs a lookup per
// user, which is the case that hurts most on a directory-backed host.
TEST_F(UserGroupsProviderLinuxTest, getGroupNamesByUidRetriesUnresolvableGidOnlyOnce)
{
    auto mockGroup = std::make_shared<MockGroupWrapper>();
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockSys = std::make_shared<MockSystemWrapper>();

    const uid_t uidA = 1001;
    const uid_t uidB = 1002;
    const char* nameA = "usera";
    const char* nameB = "userb";
    const gid_t missingGid = 500;

    EXPECT_CALL(*mockSys, sysconf(_SC_GETPW_R_SIZE_MAX)).WillOnce(Return(1024));
    EXPECT_CALL(*mockSys, sysconf(_SC_GETGR_R_SIZE_MAX)).WillOnce(Return(1024));

    EXPECT_CALL(*mockPasswd, setpwent());
    EXPECT_CALL(*mockPasswd, getpwent_r(_, _, _, _))
    .WillRepeatedly(Invoke(enumerate({{nameA, uidA, missingGid}, {nameB, uidB, missingGid}})));
    EXPECT_CALL(*mockPasswd, endpwent());

    // The primary gid of both users is not in the group database.
    GroupDb groupDb({});
    groupDb.expectOneEnumeration(*mockGroup);

    EXPECT_CALL(*mockGroup, getgrgid_r(missingGid, _, _, _, _))
    .Times(1)
    .WillOnce(Invoke([](gid_t, struct group*, char*, size_t, struct group** result)
    {
        *result = nullptr;
        return 0;
    }));

    UserGroupsProvider provider(mockGroup, mockPasswd, mockSys);

    auto result = provider.getGroupNamesByUid({uidA, uidB});

    // An unresolvable gid contributes no name, exactly as before.
    ASSERT_TRUE(result.is_object());
    EXPECT_EQ(result[std::to_string(uidA)], nlohmann::json::array());
    EXPECT_EQ(result[std::to_string(uidB)], nlohmann::json::array());
}

// The single uid call returns a bare array of names, and callers depend on that shape.
// Batching several uids into one call must not change it.
TEST_F(UserGroupsProviderLinuxTest, getGroupNamesByUidKeepsArrayShapeForOneUid)
{
    auto mockGroup = std::make_shared<MockGroupWrapper>();
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockSys = std::make_shared<MockSystemWrapper>();

    const uid_t uid = 1001;
    const gid_t gid = 100;
    const char* name = "usera";

    EXPECT_CALL(*mockSys, sysconf(_SC_GETPW_R_SIZE_MAX)).WillOnce(Return(1024));
    EXPECT_CALL(*mockSys, sysconf(_SC_GETGR_R_SIZE_MAX)).WillOnce(Return(1024));

    EXPECT_CALL(*mockPasswd, getpwuid_r(uid, _, _, _, _))
    .WillOnce(Invoke([&](uid_t, struct passwd * pwd, char*, size_t, struct passwd** result)
    {
        pwd->pw_name = const_cast<char*>(name);
        pwd->pw_uid = uid;
        pwd->pw_gid = gid;
        *result = pwd;
        return 0;
    }));

    GroupDb groupDb({{"groupone", gid, {}}});
    groupDb.expectOneEnumeration(*mockGroup);

    UserGroupsProvider provider(mockGroup, mockPasswd, mockSys);

    auto result = provider.getGroupNamesByUid({uid});

    ASSERT_TRUE(result.is_array());
    EXPECT_EQ(result, nlohmann::json::array({"groupone"}));
}

// A failed lookup, as opposed to an authoritative "no such group", may be transient when the
// group database is served over the network. It must not be remembered for the rest of the
// scan, so a later user belonging to the same gid attempts it again.
TEST_F(UserGroupsProviderLinuxTest, getGroupNamesByUidRetriesGidAfterAFailedLookup)
{
    auto mockGroup = std::make_shared<MockGroupWrapper>();
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockSys = std::make_shared<MockSystemWrapper>();

    const uid_t uidA = 1001;
    const uid_t uidB = 1002;
    const char* nameA = "usera";
    const char* nameB = "userb";
    const gid_t flakyGid = 700;

    EXPECT_CALL(*mockSys, sysconf(_SC_GETPW_R_SIZE_MAX)).WillOnce(Return(1024));
    EXPECT_CALL(*mockSys, sysconf(_SC_GETGR_R_SIZE_MAX)).WillOnce(Return(1024));

    EXPECT_CALL(*mockPasswd, setpwent());
    EXPECT_CALL(*mockPasswd, getpwent_r(_, _, _, _))
    .WillRepeatedly(Invoke(enumerate({{nameA, uidA, flakyGid}, {nameB, uidB, flakyGid}})));
    EXPECT_CALL(*mockPasswd, endpwent());

    // The primary gid of both users is not in the group database.
    GroupDb groupDb({});
    groupDb.expectOneEnumeration(*mockGroup);

    // First attempt fails with an error, second succeeds. Memoising the failure would make
    // this a single call and lose the name for both users.
    {
        InSequence seq;

        EXPECT_CALL(*mockGroup, getgrgid_r(flakyGid, _, _, _, _))
        .WillOnce(Invoke([](gid_t, struct group*, char*, size_t, struct group** result)
        {
            *result = nullptr;
            return EIO;
        }));

        EXPECT_CALL(*mockGroup, getgrgid_r(flakyGid, _, _, _, _))
        .WillOnce(Invoke([](gid_t, struct group * grp, char*, size_t, struct group** result)
        {
            grp->gr_name = const_cast<char*>("flakygroup");
            *result = grp;
            return 0;
        }));
    }

    UserGroupsProvider provider(mockGroup, mockPasswd, mockSys);

    auto result = provider.getGroupNamesByUid({uidA, uidB});

    ASSERT_TRUE(result.is_object());
    // The user whose lookup failed reports no name, the retry recovers it for the other.
    EXPECT_EQ(result[std::to_string(uidA)], nlohmann::json::array());
    EXPECT_EQ(result[std::to_string(uidB)], nlohmann::json::array({"flakygroup"}));
}

// Several uids are resolved with one passwd enumeration, not one getpwuid_r() per uid: on a
// directory-backed host each of those lookups can be a round trip once the cache has expired.
TEST_F(UserGroupsProviderLinuxTest, getGroupNamesByUidResolvesUidsWithOneEnumeration)
{
    auto mockGroup = std::make_shared<MockGroupWrapper>();
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockSys = std::make_shared<MockSystemWrapper>();

    EXPECT_CALL(*mockSys, sysconf(_SC_GETPW_R_SIZE_MAX)).WillOnce(Return(1024));
    EXPECT_CALL(*mockSys, sysconf(_SC_GETGR_R_SIZE_MAX)).WillOnce(Return(1024));

    EXPECT_CALL(*mockPasswd, setpwent());
    EXPECT_CALL(*mockPasswd, getpwent_r(_, _, _, _))
    .WillRepeatedly(Invoke(enumerate({{"other", 999, 999}, {"usera", 1001, 100}, {"userb", 1002, 101}})));
    EXPECT_CALL(*mockPasswd, endpwent());
    EXPECT_CALL(*mockPasswd, getpwuid_r(_, _, _, _, _)).Times(0);

    GroupDb groupDb({{"groupa", 100, {}}, {"groupb", 101, {}}, {"othergroup", 999, {}}});
    groupDb.expectOneEnumeration(*mockGroup);
    EXPECT_CALL(*mockGroup, getgrgid_r(_, _, _, _, _)).Times(0);

    UserGroupsProvider provider(mockGroup, mockPasswd, mockSys);

    auto result = provider.getGroupNamesByUid({1001, 1002});

    // An enumerated account that was not asked for is not reported.
    ASSERT_TRUE(result.is_object());
    EXPECT_EQ(result.size(), 2u);
    EXPECT_EQ(result["1001"], nlohmann::json::array({"groupa"}));
    EXPECT_EQ(result["1002"], nlohmann::json::array({"groupb"}));
}

// A uid the enumeration does not return, as with a directory that does not enumerate its
// accounts, is still resolved with getpwuid_r(), and only that one. Its primary group, not in
// the group enumeration either, is looked up by gid.
TEST_F(UserGroupsProviderLinuxTest, getGroupNamesByUidLooksUpUidsMissingFromEnumeration)
{
    auto mockGroup = std::make_shared<MockGroupWrapper>();
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockSys = std::make_shared<MockSystemWrapper>();

    EXPECT_CALL(*mockSys, sysconf(_SC_GETPW_R_SIZE_MAX)).WillOnce(Return(1024));
    EXPECT_CALL(*mockSys, sysconf(_SC_GETGR_R_SIZE_MAX)).WillOnce(Return(1024));

    EXPECT_CALL(*mockPasswd, setpwent());
    EXPECT_CALL(*mockPasswd, getpwent_r(_, _, _, _)).WillRepeatedly(Invoke(enumerate({{"localuser", 1001, 100}})));
    EXPECT_CALL(*mockPasswd, endpwent());
    EXPECT_CALL(*mockPasswd, getpwuid_r(1001, _, _, _, _)).Times(0);
    EXPECT_CALL(*mockPasswd, getpwuid_r(5000, _, _, _, _))
    .WillOnce(Invoke([](uid_t, struct passwd * pwd, char*, size_t, struct passwd** result)
    {
        pwd->pw_name = const_cast<char*>("diruser");
        pwd->pw_uid = 5000;
        pwd->pw_gid = 500;
        *result = pwd;
        return 0;
    }));

    GroupDb groupDb({{"localgroup", 100, {}}});
    groupDb.expectOneEnumeration(*mockGroup);
    EXPECT_CALL(*mockGroup, getgrgid_r(100, _, _, _, _)).Times(0);
    EXPECT_CALL(*mockGroup, getgrgid_r(500, _, _, _, _))
    .WillOnce(Invoke([](gid_t, struct group * grp, char*, size_t, struct group** result)
    {
        grp->gr_name = const_cast<char*>("dirgroup");
        *result = grp;
        return 0;
    }));

    UserGroupsProvider provider(mockGroup, mockPasswd, mockSys);

    auto result = provider.getGroupNamesByUid({1001, 5000});

    ASSERT_TRUE(result.is_object());
    EXPECT_EQ(result["1001"], nlohmann::json::array({"localgroup"}));
    EXPECT_EQ(result["5000"], nlohmann::json::array({"dirgroup"}));
}

// Two passwd entries with the same uid: the first one wins, as it does with getpwuid_r().
TEST_F(UserGroupsProviderLinuxTest, getGroupNamesByUidUsesFirstEntryOfDuplicateUid)
{
    auto mockGroup = std::make_shared<MockGroupWrapper>();
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockSys = std::make_shared<MockSystemWrapper>();

    EXPECT_CALL(*mockSys, sysconf(_SC_GETPW_R_SIZE_MAX)).WillOnce(Return(1024));
    EXPECT_CALL(*mockSys, sysconf(_SC_GETGR_R_SIZE_MAX)).WillOnce(Return(1024));

    EXPECT_CALL(*mockPasswd, setpwent());
    EXPECT_CALL(*mockPasswd, getpwent_r(_, _, _, _))
    .WillRepeatedly(Invoke(enumerate({{"first", 1001, 100}, {"other", 1002, 100}, {"second", 1001, 200}})));
    EXPECT_CALL(*mockPasswd, endpwent());
    EXPECT_CALL(*mockPasswd, getpwuid_r(_, _, _, _, _)).Times(0);

    GroupDb groupDb({{"groupone", 100, {}}, {"grouptwo", 200, {}}, {"secondonly", 300, {"second"}}});
    groupDb.expectOneEnumeration(*mockGroup);

    UserGroupsProvider provider(mockGroup, mockPasswd, mockSys);

    auto result = provider.getGroupNamesByUid({1001, 1002});

    ASSERT_TRUE(result.is_object());
    EXPECT_EQ(result["1001"], nlohmann::json::array({"groupone"}));
    EXPECT_EQ(result["1002"], nlohmann::json::array({"groupone"}));
}

// Membership comes from one group enumeration for all users, with the primary group first and
// the rest by ascending gid whatever order the enumeration returns them in. A group that lists
// the user under its primary gid, or twice, or under a second entry sharing a gid, adds nothing.
TEST_F(UserGroupsProviderLinuxTest, getGroupNamesByUidReadsMembershipFromOneGroupEnumeration)
{
    auto mockGroup = std::make_shared<MockGroupWrapper>();
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockSys = std::make_shared<MockSystemWrapper>();

    EXPECT_CALL(*mockSys, sysconf(_SC_GETPW_R_SIZE_MAX)).WillOnce(Return(1024));
    EXPECT_CALL(*mockSys, sysconf(_SC_GETGR_R_SIZE_MAX)).WillOnce(Return(1024));

    EXPECT_CALL(*mockPasswd, setpwent());
    EXPECT_CALL(*mockPasswd, getpwent_r(_, _, _, _))
    .WillRepeatedly(Invoke(enumerate({{"alice", 1001, 100}, {"bob", 1002, 200}, {"carol", 1003, 300}})));
    EXPECT_CALL(*mockPasswd, endpwent());

    GroupDb groupDb(
    {
        {"dev", 20, {"alice", "alice"}},
        {"alicegrp", 100, {"alice"}},
        {"wheel", 10, {"bob", "alice"}},
        {"devalias", 20, {"alice", "bob"}},
        {"bobgrp", 200, {}},
        {"carolgrp", 300, {}}
    });
    groupDb.expectOneEnumeration(*mockGroup);
    EXPECT_CALL(*mockGroup, getgrgid_r(_, _, _, _, _)).Times(0);
    // Only the user no group lists is asked about on its own.
    EXPECT_CALL(*mockGroup, getgrouplist(StrEq("alice"), _, _, _)).Times(0);
    EXPECT_CALL(*mockGroup, getgrouplist(StrEq("bob"), _, _, _)).Times(0);
    EXPECT_CALL(*mockGroup, getgrouplist(StrEq("carol"), 300, _, _)).WillOnce(Invoke(primaryOnly));

    UserGroupsProvider provider(mockGroup, mockPasswd, mockSys);

    auto result = provider.getGroupNamesByUid({1001, 1002, 1003});

    ASSERT_TRUE(result.is_object());
    EXPECT_EQ(result["1001"], nlohmann::json::array({"alicegrp", "wheel", "dev"}));
    EXPECT_EQ(result["1002"], nlohmann::json::array({"bobgrp", "wheel", "dev"}));
    EXPECT_EQ(result["1003"], nlohmann::json::array({"carolgrp"}));
}

// collect() reports the same membership as (uid, gid) pairs, primary group included.
TEST_F(UserGroupsProviderLinuxTest, CollectReadsMembershipFromOneGroupEnumeration)
{
    auto mockGroup = std::make_shared<MockGroupWrapper>();
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockSys = std::make_shared<MockSystemWrapper>();

    EXPECT_CALL(*mockSys, sysconf(_SC_GETPW_R_SIZE_MAX)).WillOnce(Return(1024));

    EXPECT_CALL(*mockPasswd, setpwent());
    EXPECT_CALL(*mockPasswd, getpwent_r(_, _, _, _))
    .WillRepeatedly(Invoke(enumerate({{"alice", 1001, 100}, {"bob", 1002, 200}})));
    EXPECT_CALL(*mockPasswd, endpwent());

    GroupDb groupDb({{"wheel", 10, {"alice"}}, {"alicegrp", 100, {}}, {"bobgrp", 200, {}}});
    groupDb.expectOneEnumeration(*mockGroup);

    UserGroupsProvider provider(mockGroup, mockPasswd, mockSys);

    auto result = provider.collect({1001, 1002});

    std::vector<std::pair<uid_t, gid_t>> pairs;

    for (const auto& entry : result)
    {
        pairs.emplace_back(entry["uid"].get<uid_t>(), entry["gid"].get<gid_t>());
    }

    std::sort(pairs.begin(), pairs.end());
    const std::vector<std::pair<uid_t, gid_t>> expected {{1001, 10}, {1001, 100}, {1002, 200}};
    EXPECT_EQ(pairs, expected);
}

// A user whose name no group lists still gets its primary group, and an account without a
// name is reported with only its primary group instead of being dropped.
TEST_F(UserGroupsProviderLinuxTest, getGroupNamesByUidKeepsPrimaryGroupForUnlistedUsers)
{
    auto mockGroup = std::make_shared<MockGroupWrapper>();
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockSys = std::make_shared<MockSystemWrapper>();

    EXPECT_CALL(*mockSys, sysconf(_SC_GETPW_R_SIZE_MAX)).WillOnce(Return(1024));
    EXPECT_CALL(*mockSys, sysconf(_SC_GETGR_R_SIZE_MAX)).WillOnce(Return(1024));

    EXPECT_CALL(*mockPasswd, setpwent());
    EXPECT_CALL(*mockPasswd, getpwent_r(_, _, _, _))
    .WillRepeatedly(Invoke(enumerate({{"lonely", 1001, 100}, {nullptr, 1002, 200}})));
    EXPECT_CALL(*mockPasswd, endpwent());

    GroupDb groupDb({{"lonelygrp", 100, {}}, {"noname", 200, {}}, {"other", 300, {"someoneelse"}}});
    groupDb.expectOneEnumeration(*mockGroup);
    // An account without a name cannot be asked about with getgrouplist().
    EXPECT_CALL(*mockGroup, getgrouplist(StrEq("lonely"), 100, _, _)).WillOnce(Invoke(primaryOnly));

    UserGroupsProvider provider(mockGroup, mockPasswd, mockSys);

    auto result = provider.getGroupNamesByUid({1001, 1002});

    ASSERT_TRUE(result.is_object());
    EXPECT_EQ(result["1001"], nlohmann::json::array({"lonelygrp"}));
    EXPECT_EQ(result["1002"], nlohmann::json::array({"noname"}));
}

// A directory client can return its groups without members (SSSD's ignore_group_members) while
// initgroups still knows them. A user that no enumerated group lists beyond its primary group is
// asked about with getgrouplist(), and its answer is reported primary first, then by gid.
TEST_F(UserGroupsProviderLinuxTest, getGroupNamesByUidFallsBackToGetgrouplistForUnlistedUsers)
{
    auto mockGroup = std::make_shared<MockGroupWrapper>();
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockSys = std::make_shared<MockSystemWrapper>();

    EXPECT_CALL(*mockSys, sysconf(_SC_GETPW_R_SIZE_MAX)).WillOnce(Return(1024));
    EXPECT_CALL(*mockSys, sysconf(_SC_GETGR_R_SIZE_MAX)).WillOnce(Return(1024));

    EXPECT_CALL(*mockPasswd, setpwent());
    EXPECT_CALL(*mockPasswd, getpwent_r(_, _, _, _))
    .WillRepeatedly(Invoke(enumerate({{"diruser", 5000, 500}, {"listed", 1001, 100}})));
    EXPECT_CALL(*mockPasswd, endpwent());

    // The directory groups come without members; the local group lists its member.
    GroupDb groupDb({{"dirprimary", 500, {}}, {"dirb", 520, {}}, {"dira", 510, {}},
        {"localgrp", 100, {}}, {"wheel", 10, {"listed"}}});
    groupDb.expectOneEnumeration(*mockGroup);
    EXPECT_CALL(*mockGroup, getgrouplist(StrEq("listed"), _, _, _)).Times(0);
    EXPECT_CALL(*mockGroup, getgrouplist(StrEq("diruser"), 500, _, _))
    .WillOnce(Invoke([](const char*, gid_t, gid_t * groups, int* ngroups)
    {
        groups[0] = 500;
        groups[1] = 520;
        groups[2] = 510;
        groups[3] = 500;
        *ngroups = 4;
        return 4;
    }));
    EXPECT_CALL(*mockGroup, getgrgid_r(_, _, _, _, _)).Times(0);

    UserGroupsProvider provider(mockGroup, mockPasswd, mockSys);

    auto result = provider.getGroupNamesByUid({1001, 5000});

    ASSERT_TRUE(result.is_object());
    EXPECT_EQ(result["5000"], nlohmann::json::array({"dirprimary", "dira", "dirb"}));
    EXPECT_EQ(result["1001"], nlohmann::json::array({"localgrp", "wheel"}));
}

// getgrouplist() telling the caller its array is too small is retried with the size it asks for.
TEST_F(UserGroupsProviderLinuxTest, getGroupNamesByUidRetriesGetgrouplistWithTheSizeItAsksFor)
{
    auto mockGroup = std::make_shared<MockGroupWrapper>();
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockSys = std::make_shared<MockSystemWrapper>();

    EXPECT_CALL(*mockSys, sysconf(_SC_GETPW_R_SIZE_MAX)).WillOnce(Return(1024));
    EXPECT_CALL(*mockSys, sysconf(_SC_GETGR_R_SIZE_MAX)).WillOnce(Return(1024));

    EXPECT_CALL(*mockPasswd, getpwuid_r(5000, _, _, _, _))
    .WillOnce(Invoke([](uid_t, struct passwd * pwd, char*, size_t, struct passwd** result)
    {
        pwd->pw_name = const_cast<char*>("busyuser");
        pwd->pw_uid = 5000;
        pwd->pw_gid = 1000;
        *result = pwd;
        return 0;
    }));

    std::vector<GroupEntry> entries {{"g1000", 1000, {}}};

    for (gid_t gid = 1001; gid <= 1100; ++gid)
    {
        entries.push_back({"g" + std::to_string(gid), gid, {}});
    }

    GroupDb groupDb(entries);
    groupDb.expectOneEnumeration(*mockGroup);
    {
        InSequence seq;
        EXPECT_CALL(*mockGroup, getgrouplist(StrEq("busyuser"), 1000, _, _))
        .WillOnce(Invoke([](const char*, gid_t, gid_t*, int* ngroups)
        {
            *ngroups = 101;
            return -1;
        }));
        EXPECT_CALL(*mockGroup, getgrouplist(StrEq("busyuser"), 1000, _, _))
        .WillOnce(Invoke([](const char*, gid_t, gid_t * groups, int* ngroups)
        {
            if (*ngroups < 101)
            {
                return -1;
            }

            for (int i = 0; i < 101; ++i)
            {
                groups[i] = static_cast<gid_t>(1100 - i);
            }

            *ngroups = 101;
            return 101;
        }));
    }

    UserGroupsProvider provider(mockGroup, mockPasswd, mockSys);

    auto result = provider.getGroupNamesByUid({5000});

    ASSERT_TRUE(result.is_array());
    ASSERT_EQ(result.size(), 101u);
    EXPECT_EQ(result.front(), "g1000");
    EXPECT_EQ(result[1], "g1001");
    EXPECT_EQ(result.back(), "g1100");
}

// The group names come from the same enumeration as the memberships and are cached with them:
// a second call within the cache lifetime neither enumerates the groups again nor looks any gid up.
TEST_F(UserGroupsProviderLinuxTest, getGroupNamesByUidKeepsNamesWhileTheCacheIsWarm)
{
    auto mockGroup = std::make_shared<MockGroupWrapper>();
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockSys = std::make_shared<MockSystemWrapper>();

    EXPECT_CALL(*mockSys, sysconf(_SC_GETPW_R_SIZE_MAX)).WillRepeatedly(Return(1024));
    EXPECT_CALL(*mockSys, sysconf(_SC_GETGR_R_SIZE_MAX)).WillRepeatedly(Return(1024));

    const std::vector<PasswdEntry> accounts {{"usera", 1001, 100}, {"userb", 1002, 200}};
    auto stub = std::make_shared<std::function<int(struct passwd*, char*, size_t, struct passwd**)>>();
    EXPECT_CALL(*mockPasswd, setpwent()).Times(2).WillRepeatedly(Invoke([&]()
    {
        *stub = enumerate(accounts);
    }));
    EXPECT_CALL(*mockPasswd, getpwent_r(_, _, _, _))
    .WillRepeatedly(Invoke([stub](struct passwd * pwd, char* buf, size_t len, struct passwd** result)
    {
        return (*stub)(pwd, buf, len, result);
    }));
    EXPECT_CALL(*mockPasswd, endpwent()).Times(2);

    GroupDb groupDb({{"groupa", 100, {}}, {"groupb", 200, {}}, {"shared", 300, {"usera", "userb"}}});
    groupDb.expectOneEnumeration(*mockGroup);
    EXPECT_CALL(*mockGroup, getgrgid_r(_, _, _, _, _)).Times(0);

    UserGroupsProvider provider(mockGroup, mockPasswd, mockSys);

    const auto first = provider.getGroupNamesByUid({1001, 1002});
    const auto second = provider.getGroupNamesByUid({1001, 1002});

    EXPECT_EQ(first["1001"], nlohmann::json::array({"groupa", "shared"}));
    EXPECT_EQ(first["1002"], nlohmann::json::array({"groupb", "shared"}));
    EXPECT_EQ(second, first);
}

// A passwd entry that does not fit the buffer (a long GECOS field) grows it and is read again,
// instead of ending the enumeration and sending every remaining uid to getpwuid_r().
TEST_F(UserGroupsProviderLinuxTest, getGroupNamesByUidGrowsThePasswdBufferOnERANGE)
{
    auto mockGroup = std::make_shared<MockGroupWrapper>();
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockSys = std::make_shared<MockSystemWrapper>();

    EXPECT_CALL(*mockSys, sysconf(_SC_GETPW_R_SIZE_MAX)).WillOnce(Return(1024));
    EXPECT_CALL(*mockSys, sysconf(_SC_GETGR_R_SIZE_MAX)).WillOnce(Return(1024));

    auto next = std::make_shared<size_t>(0);
    auto sizes = std::make_shared<std::vector<size_t>>();
    EXPECT_CALL(*mockPasswd, setpwent());
    EXPECT_CALL(*mockPasswd, getpwent_r(_, _, _, _))
    .WillRepeatedly(Invoke([next, sizes](struct passwd * pwd, char*, size_t len, struct passwd** result)
    {
        sizes->push_back(len);
        static const std::vector<PasswdEntry> accounts {{"longgecos", 1001, 100}, {"userb", 1002, 200}};

        if (*next >= accounts.size())
        {
            *result = nullptr;
            return ENOENT;
        }

        // The first entry needs more than 1 KB.
        if (*next == 0 && len < 4096)
        {
            *result = nullptr;
            return ERANGE;
        }

        const auto& entry = accounts[(*next)++];
        pwd->pw_name = const_cast<char*>(entry.name);
        pwd->pw_uid = entry.uid;
        pwd->pw_gid = entry.gid;
        *result = pwd;
        return 0;
    }));
    EXPECT_CALL(*mockPasswd, endpwent());
    EXPECT_CALL(*mockPasswd, getpwuid_r(_, _, _, _, _)).Times(0);

    GroupDb groupDb({{"groupa", 100, {}}, {"groupb", 200, {}}});
    groupDb.expectOneEnumeration(*mockGroup);

    UserGroupsProvider provider(mockGroup, mockPasswd, mockSys);

    auto result = provider.getGroupNamesByUid({1001, 1002});

    ASSERT_TRUE(result.is_object());
    EXPECT_EQ(result["1001"], nlohmann::json::array({"groupa"}));
    EXPECT_EQ(result["1002"], nlohmann::json::array({"groupb"}));
    ASSERT_GE(sizes->size(), 3u);
    EXPECT_EQ((*sizes)[0], 1024u);
    EXPECT_EQ((*sizes)[1], 2048u);
    EXPECT_EQ((*sizes)[2], 4096u);
}

// A group whose entry does not fit the buffer (a long member list) grows it, so its members
// still count for the users it lists.
TEST_F(UserGroupsProviderLinuxTest, getGroupNamesByUidGrowsTheGroupBufferOnERANGE)
{
    auto mockGroup = std::make_shared<MockGroupWrapper>();
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockSys = std::make_shared<MockSystemWrapper>();

    EXPECT_CALL(*mockSys, sysconf(_SC_GETPW_R_SIZE_MAX)).WillOnce(Return(1024));
    EXPECT_CALL(*mockSys, sysconf(_SC_GETGR_R_SIZE_MAX)).WillOnce(Return(1024));

    EXPECT_CALL(*mockPasswd, setpwent());
    EXPECT_CALL(*mockPasswd, getpwent_r(_, _, _, _))
    .WillRepeatedly(Invoke(enumerate({{"usera", 1001, 100}, {"userb", 1002, 100}})));
    EXPECT_CALL(*mockPasswd, endpwent());

    GroupEntry big {"biggroup", 700, {"usera", "userb"}, 64 * 1024};
    GroupDb groupDb({{"groupa", 100, {}}, big});
    groupDb.expectOneEnumeration(*mockGroup);
    EXPECT_CALL(*mockGroup, getgrouplist(_, _, _, _)).Times(0);

    UserGroupsProvider provider(mockGroup, mockPasswd, mockSys);

    auto result = provider.getGroupNamesByUid({1001, 1002});

    ASSERT_TRUE(result.is_object());
    EXPECT_EQ(result["1001"], nlohmann::json::array({"groupa", "biggroup"}));
    EXPECT_EQ(result["1002"], nlohmann::json::array({"groupa", "biggroup"}));
}

// A gid looked up on its own (not in the enumeration) whose entry does not fit the buffer grows
// it and is looked up again, instead of being reported without a name.
TEST_F(UserGroupsProviderLinuxTest, getGroupNamesByUidGrowsTheGidLookupBufferOnERANGE)
{
    auto mockGroup = std::make_shared<MockGroupWrapper>();
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockSys = std::make_shared<MockSystemWrapper>();

    EXPECT_CALL(*mockSys, sysconf(_SC_GETPW_R_SIZE_MAX)).WillOnce(Return(1024));
    EXPECT_CALL(*mockSys, sysconf(_SC_GETGR_R_SIZE_MAX)).WillOnce(Return(1024));

    EXPECT_CALL(*mockPasswd, getpwuid_r(5000, _, _, _, _))
    .WillOnce(Invoke([](uid_t, struct passwd * pwd, char*, size_t, struct passwd** result)
    {
        pwd->pw_name = const_cast<char*>("diruser");
        pwd->pw_uid = 5000;
        pwd->pw_gid = 500;
        *result = pwd;
        return 0;
    }));

    GroupDb groupDb({});
    groupDb.expectOneEnumeration(*mockGroup);
    {
        InSequence seq;
        EXPECT_CALL(*mockGroup, getgrgid_r(500, _, _, 1024, _))
        .WillOnce(Invoke([](gid_t, struct group*, char*, size_t, struct group** result)
        {
            *result = nullptr;
            return ERANGE;
        }));
        EXPECT_CALL(*mockGroup, getgrgid_r(500, _, _, 2048, _))
        .WillOnce(Invoke([](gid_t, struct group * grp, char*, size_t, struct group** result)
        {
            grp->gr_name = const_cast<char*>("bigprimary");
            *result = grp;
            return 0;
        }));
    }

    UserGroupsProvider provider(mockGroup, mockPasswd, mockSys);

    auto result = provider.getGroupNamesByUid({5000});

    ASSERT_TRUE(result.is_array());
    EXPECT_EQ(result, nlohmann::json::array({"bigprimary"}));
}
