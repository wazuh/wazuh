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
#include <memory>
#include <vector>
#include "users_linux.hpp"
#include "ipasswd_wrapper.hpp"
#include "isystem_wrapper.hpp"

class MockSystemWrapper : public ISystemWrapper
{
    public:
        MOCK_METHOD(long, sysconf, (int name), (const, override));
        MOCK_METHOD(FILE*, fopen, (const char*, const char*), (override));
        MOCK_METHOD(int, fclose, (FILE*), (override));
        MOCK_METHOD(char*, strerror, (int), (override));
};

class MockPasswdWrapper : public IPasswdWrapperLinux
{
    public:
        MOCK_METHOD(int, fgetpwent_r,
                    (FILE*, struct passwd*, char*, size_t, struct passwd**), (override));
        MOCK_METHOD(void, setpwent, (), (override));
        MOCK_METHOD(int, getpwent_r,
                    (struct passwd*, char*, size_t, struct passwd**), (override));
        MOCK_METHOD(void, endpwent, (), (override));
        MOCK_METHOD(struct passwd*, getpwent, (), (override));
        MOCK_METHOD(int, getpwuid_r,
                    (uid_t, struct passwd*, char*, size_t, struct passwd**), (override));
        MOCK_METHOD(int, getpwnam_r,
                    (const char*, struct passwd*, char*, size_t, struct passwd**), (override));
};

/// @brief Builds a passwd row. The name is kept as a pointer, so pass a literal.
static struct passwd makePwd(const char* name, uid_t uid)
{
    struct passwd pwd {};
    pwd.pw_name = const_cast<char*>(name);
    pwd.pw_passwd = const_cast<char*>("x");
    pwd.pw_uid = uid;
    pwd.pw_gid = uid;
    pwd.pw_gecos = const_cast<char*>("");
    pwd.pw_dir = const_cast<char*>("/");
    pwd.pw_shell = const_cast<char*>("/bin/bash");
    return pwd;
}

/// @brief Rows one mocked enumeration hands out, plus its cursor. Each enumeration needs its own
///        instance: most tests here have /etc/passwd and NSS return different sets.
struct PasswdRows
{
    std::vector<struct passwd> rows;
    size_t index {0};
};

/// @brief Action for a mocked fgetpwent_r: next row, then ENOENT like glibc does at end of file.
static auto serveFgetpwent(const std::shared_ptr<PasswdRows>& state)
{
    return [state](FILE*, struct passwd * pwd, char*, size_t, struct passwd** result) -> int
    {
        if (state->index >= state->rows.size())
        {
            return ENOENT;
        }

        // Fill the caller's buffer and point result at it, the way glibc does. result[0] spells
        // *result without a leading dereference, which astyle mangles here.
        const auto& row = state->rows[state->index];
        pwd->pw_name = row.pw_name;
        pwd->pw_passwd = row.pw_passwd;
        pwd->pw_uid = row.pw_uid;
        pwd->pw_gid = row.pw_gid;
        pwd->pw_gecos = row.pw_gecos;
        pwd->pw_dir = row.pw_dir;
        pwd->pw_shell = row.pw_shell;
        result[0] = pwd;
        ++state->index;
        return 0;
    };
}

/// @brief Action for a mocked getpwent_r, same contract as serveFgetpwent.
static auto serveGetpwent(const std::shared_ptr<PasswdRows>& state)
{
    return [state](struct passwd * pwd, char*, size_t, struct passwd** result) -> int
    {
        if (state->index >= state->rows.size())
        {
            return ENOENT;
        }

        // Fill the caller's buffer and point result at it, the way glibc does. result[0] spells
        // *result without a leading dereference, which astyle mangles here.
        const auto& row = state->rows[state->index];
        pwd->pw_name = row.pw_name;
        pwd->pw_passwd = row.pw_passwd;
        pwd->pw_uid = row.pw_uid;
        pwd->pw_gid = row.pw_gid;
        pwd->pw_gecos = row.pw_gecos;
        pwd->pw_dir = row.pw_dir;
        pwd->pw_shell = row.pw_shell;
        result[0] = pwd;
        ++state->index;
        return 0;
    };
}

TEST(UsersProviderTest, CollectLocalUsers)
{

    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockSys = std::make_shared<MockSystemWrapper>();

    EXPECT_CALL(*mockSys, sysconf(_SC_GETPW_R_SIZE_MAX))
    .WillOnce(::testing::Return(1024));

    FILE* mockFile = reinterpret_cast<FILE*>(0x1234);
    EXPECT_CALL(*mockSys, fopen(::testing::StrEq("/etc/passwd"), ::testing::StrEq("r")))
    .WillOnce(::testing::Return(mockFile));

    struct passwd test_pwd =
    {
        .pw_name = const_cast<char*>("testuser"),
        .pw_passwd = const_cast<char*>("x"),
        .pw_uid = 1000,
        .pw_gid = 1000,
        .pw_gecos = const_cast<char*>("Test User"),
        .pw_dir = const_cast<char*>("/home/testuser"),
        .pw_shell = const_cast<char*>("/bin/bash")
    };

    EXPECT_CALL(*mockPasswd, fgetpwent_r(mockFile, ::testing::_, ::testing::NotNull(), 1024, ::testing::_))
    .WillOnce(::testing::DoAll(
                  ::testing::SetArgPointee<1>(test_pwd),
                  ::testing::SetArgPointee<4>(&test_pwd),
                  ::testing::Return(0)))
    .WillOnce(::testing::Return(ENOENT));

    EXPECT_CALL(*mockSys, fclose(mockFile))
    .WillOnce(::testing::Return(0));

    UsersProvider provider(mockPasswd, mockSys);
    auto result = provider.collect(false);

    ASSERT_EQ(result.size(), static_cast<size_t>(1));
    EXPECT_EQ(result[0]["username"], "testuser");
    EXPECT_EQ(result[0]["uid"], std::uint32_t{1000});
    EXPECT_EQ(result[0]["gid"], std::uint32_t{1000});
    EXPECT_EQ(result[0]["description"], "Test User");
    EXPECT_EQ(result[0]["directory"], "/home/testuser");
    EXPECT_EQ(result[0]["shell"], "/bin/bash");
    EXPECT_EQ(result[0]["is_remote"], 0);
}

// Regression test: every account was reported remote because is_remote carried the collection mode.
TEST(UsersProviderTest, CollectMarksOnlyDirectoryAccountsRemote)
{
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockSys = std::make_shared<MockSystemWrapper>();

    EXPECT_CALL(*mockSys, sysconf(_SC_GETPW_R_SIZE_MAX))
    .WillRepeatedly(::testing::Return(1024));

    FILE* mockFile = reinterpret_cast<FILE*>(0x1234);
    EXPECT_CALL(*mockSys, fopen(::testing::StrEq("/etc/passwd"), ::testing::StrEq("r")))
    .WillOnce(::testing::Return(mockFile));
    EXPECT_CALL(*mockSys, fclose(mockFile)).WillOnce(::testing::Return(0));

    auto localRows = std::make_shared<PasswdRows>();
    localRows->rows = {makePwd("root", 0), makePwd("daemon", 1), makePwd("alice", 1000)};

    // NSS returns the local accounts too, plus one that only exists in the directory.
    auto nssRows = std::make_shared<PasswdRows>();
    nssRows->rows = {makePwd("root", 0), makePwd("daemon", 1), makePwd("alice", 1000), makePwd("bob", 200001)};

    EXPECT_CALL(*mockPasswd, fgetpwent_r(mockFile, ::testing::_, ::testing::NotNull(), 16 * 1024, ::testing::_))
    .WillRepeatedly(::testing::Invoke(serveFgetpwent(localRows)));

    EXPECT_CALL(*mockPasswd, setpwent()).Times(1);
    EXPECT_CALL(*mockPasswd, endpwent()).Times(1);
    EXPECT_CALL(*mockPasswd, getpwent_r(::testing::_, ::testing::NotNull(), 1024, ::testing::_))
    .WillRepeatedly(::testing::Invoke(serveGetpwent(nssRows)));

    UsersProvider provider(mockPasswd, mockSys);
    auto result = provider.collect();

    ASSERT_EQ(result.size(), static_cast<size_t>(4));
    EXPECT_EQ(result[0]["username"], "root");
    EXPECT_EQ(result[0]["is_remote"], 0);
    EXPECT_EQ(result[1]["username"], "daemon");
    EXPECT_EQ(result[1]["is_remote"], 0);
    EXPECT_EQ(result[2]["username"], "alice");
    EXPECT_EQ(result[2]["is_remote"], 0);
    EXPECT_EQ(result[3]["username"], "bob");
    EXPECT_EQ(result[3]["is_remote"], 1);
}

TEST(UsersProviderTest, CollectMarksAllLocalWhenNoDirectoryModule)
{
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockSys = std::make_shared<MockSystemWrapper>();

    EXPECT_CALL(*mockSys, sysconf(_SC_GETPW_R_SIZE_MAX))
    .WillRepeatedly(::testing::Return(1024));

    FILE* mockFile = reinterpret_cast<FILE*>(0x1234);
    EXPECT_CALL(*mockSys, fopen(::testing::StrEq("/etc/passwd"), ::testing::StrEq("r")))
    .WillOnce(::testing::Return(mockFile));
    EXPECT_CALL(*mockSys, fclose(mockFile)).WillOnce(::testing::Return(0));

    auto localRows = std::make_shared<PasswdRows>();
    localRows->rows = {makePwd("root", 0), makePwd("daemon", 1), makePwd("alice", 1000)};

    auto nssRows = std::make_shared<PasswdRows>();
    nssRows->rows = {makePwd("root", 0), makePwd("daemon", 1), makePwd("alice", 1000)};

    EXPECT_CALL(*mockPasswd, fgetpwent_r(mockFile, ::testing::_, ::testing::NotNull(), 16 * 1024, ::testing::_))
    .WillRepeatedly(::testing::Invoke(serveFgetpwent(localRows)));

    EXPECT_CALL(*mockPasswd, setpwent()).Times(1);
    EXPECT_CALL(*mockPasswd, endpwent()).Times(1);
    EXPECT_CALL(*mockPasswd, getpwent_r(::testing::_, ::testing::NotNull(), 1024, ::testing::_))
    .WillRepeatedly(::testing::Invoke(serveGetpwent(nssRows)));

    UsersProvider provider(mockPasswd, mockSys);
    auto result = provider.collect();

    ASSERT_EQ(result.size(), static_cast<size_t>(3));

    for (const auto& user : result)
    {
        EXPECT_EQ(user["is_remote"], 0) << "user " << user["username"];
    }
}

// With no local set, locality is unknown. Local is the safe default: remote would reproduce the bug.
TEST(UsersProviderTest, CollectDefaultsToLocalWhenPasswdUnreadable)
{
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockSys = std::make_shared<MockSystemWrapper>();

    EXPECT_CALL(*mockSys, sysconf(_SC_GETPW_R_SIZE_MAX))
    .WillRepeatedly(::testing::Return(1024));

    EXPECT_CALL(*mockSys, fopen(::testing::StrEq("/etc/passwd"), ::testing::StrEq("r")))
    .WillOnce(::testing::Return(nullptr));
    EXPECT_CALL(*mockSys, fclose(::testing::_)).Times(0);
    EXPECT_CALL(*mockPasswd, fgetpwent_r(::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_))
    .Times(0);

    auto nssRows = std::make_shared<PasswdRows>();
    nssRows->rows = {makePwd("root", 0), makePwd("bob", 200001)};

    EXPECT_CALL(*mockPasswd, setpwent()).Times(1);
    EXPECT_CALL(*mockPasswd, endpwent()).Times(1);
    EXPECT_CALL(*mockPasswd, getpwent_r(::testing::_, ::testing::NotNull(), 1024, ::testing::_))
    .WillRepeatedly(::testing::Invoke(serveGetpwent(nssRows)));

    UsersProvider provider(mockPasswd, mockSys);
    auto result = provider.collect();

    ASSERT_EQ(result.size(), static_cast<size_t>(2));
    EXPECT_EQ(result[0]["is_remote"], 0);
    EXPECT_EQ(result[1]["is_remote"], 0);
}

// Keyed on the username: a directory account colliding with a local uid must not inherit its
// answer. Fails if the local set is keyed by uid.
TEST(UsersProviderTest, CollectClassifiesByNameNotUid)
{
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockSys = std::make_shared<MockSystemWrapper>();

    EXPECT_CALL(*mockSys, sysconf(_SC_GETPW_R_SIZE_MAX))
    .WillRepeatedly(::testing::Return(1024));

    FILE* mockFile = reinterpret_cast<FILE*>(0x1234);
    EXPECT_CALL(*mockSys, fopen(::testing::StrEq("/etc/passwd"), ::testing::StrEq("r")))
    .WillOnce(::testing::Return(mockFile));
    EXPECT_CALL(*mockSys, fclose(mockFile)).WillOnce(::testing::Return(0));

    auto localRows = std::make_shared<PasswdRows>();
    localRows->rows = {makePwd("alice", 1000)};

    auto nssRows = std::make_shared<PasswdRows>();
    nssRows->rows = {makePwd("alice", 1000), makePwd("bob", 1000)};

    EXPECT_CALL(*mockPasswd, fgetpwent_r(mockFile, ::testing::_, ::testing::NotNull(), 16 * 1024, ::testing::_))
    .WillRepeatedly(::testing::Invoke(serveFgetpwent(localRows)));

    EXPECT_CALL(*mockPasswd, setpwent()).Times(1);
    EXPECT_CALL(*mockPasswd, endpwent()).Times(1);
    EXPECT_CALL(*mockPasswd, getpwent_r(::testing::_, ::testing::NotNull(), 1024, ::testing::_))
    .WillRepeatedly(::testing::Invoke(serveGetpwent(nssRows)));

    UsersProvider provider(mockPasswd, mockSys);
    auto result = provider.collect();

    ASSERT_EQ(result.size(), static_cast<size_t>(2));
    EXPECT_EQ(result[0]["username"], "alice");
    EXPECT_EQ(result[0]["is_remote"], 0);
    EXPECT_EQ(result[1]["username"], "bob");
    EXPECT_EQ(result[1]["is_remote"], 1);
}

// Two names sharing one uid in /etc/passwd (the root/toor alias pattern) are both local.
TEST(UsersProviderTest, CollectHandlesPasswdAliasesSharingUid)
{
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockSys = std::make_shared<MockSystemWrapper>();

    EXPECT_CALL(*mockSys, sysconf(_SC_GETPW_R_SIZE_MAX))
    .WillRepeatedly(::testing::Return(1024));

    FILE* mockFile = reinterpret_cast<FILE*>(0x1234);
    EXPECT_CALL(*mockSys, fopen(::testing::StrEq("/etc/passwd"), ::testing::StrEq("r")))
    .WillOnce(::testing::Return(mockFile));
    EXPECT_CALL(*mockSys, fclose(mockFile)).WillOnce(::testing::Return(0));

    auto localRows = std::make_shared<PasswdRows>();
    localRows->rows = {makePwd("root", 0), makePwd("toor", 0)};

    auto nssRows = std::make_shared<PasswdRows>();
    nssRows->rows = {makePwd("root", 0), makePwd("toor", 0)};

    EXPECT_CALL(*mockPasswd, fgetpwent_r(mockFile, ::testing::_, ::testing::NotNull(), 16 * 1024, ::testing::_))
    .WillRepeatedly(::testing::Invoke(serveFgetpwent(localRows)));

    EXPECT_CALL(*mockPasswd, setpwent()).Times(1);
    EXPECT_CALL(*mockPasswd, endpwent()).Times(1);
    EXPECT_CALL(*mockPasswd, getpwent_r(::testing::_, ::testing::NotNull(), 1024, ::testing::_))
    .WillRepeatedly(::testing::Invoke(serveGetpwent(nssRows)));

    UsersProvider provider(mockPasswd, mockSys);
    auto result = provider.collect();

    ASSERT_EQ(result.size(), static_cast<size_t>(2));
    EXPECT_EQ(result[0]["is_remote"], 0);
    EXPECT_EQ(result[1]["is_remote"], 0);
}

TEST(UsersProviderTest, CollectTreatsEmptyPasswdFileAsAllLocal)
{
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockSys = std::make_shared<MockSystemWrapper>();

    EXPECT_CALL(*mockSys, sysconf(_SC_GETPW_R_SIZE_MAX))
    .WillRepeatedly(::testing::Return(1024));

    FILE* mockFile = reinterpret_cast<FILE*>(0x1234);
    EXPECT_CALL(*mockSys, fopen(::testing::StrEq("/etc/passwd"), ::testing::StrEq("r")))
    .WillOnce(::testing::Return(mockFile));
    EXPECT_CALL(*mockSys, fclose(mockFile)).WillOnce(::testing::Return(0));

    EXPECT_CALL(*mockPasswd, fgetpwent_r(mockFile, ::testing::_, ::testing::NotNull(), 16 * 1024, ::testing::_))
    .WillOnce(::testing::Return(ENOENT));

    auto nssRows = std::make_shared<PasswdRows>();
    nssRows->rows = {makePwd("root", 0), makePwd("bob", 200001)};

    EXPECT_CALL(*mockPasswd, setpwent()).Times(1);
    EXPECT_CALL(*mockPasswd, endpwent()).Times(1);
    EXPECT_CALL(*mockPasswd, getpwent_r(::testing::_, ::testing::NotNull(), 1024, ::testing::_))
    .WillRepeatedly(::testing::Invoke(serveGetpwent(nssRows)));

    UsersProvider provider(mockPasswd, mockSys);
    auto result = provider.collect();

    ASSERT_EQ(result.size(), static_cast<size_t>(2));
    EXPECT_EQ(result[0]["is_remote"], 0);
    EXPECT_EQ(result[1]["is_remote"], 0);
}

// The constraints filter the reported rows, never the local set the classification is built from.
TEST(UsersProviderTest, CollectWithConstraintsUsesUnfilteredLocalSet)
{
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockSys = std::make_shared<MockSystemWrapper>();

    EXPECT_CALL(*mockSys, sysconf(_SC_GETPW_R_SIZE_MAX))
    .WillRepeatedly(::testing::Return(1024));

    FILE* mockFile = reinterpret_cast<FILE*>(0x1234);
    EXPECT_CALL(*mockSys, fopen(::testing::StrEq("/etc/passwd"), ::testing::StrEq("r")))
    .WillOnce(::testing::Return(mockFile));
    EXPECT_CALL(*mockSys, fclose(mockFile)).WillOnce(::testing::Return(0));

    auto localRows = std::make_shared<PasswdRows>();
    localRows->rows = {makePwd("root", 0), makePwd("alice", 1000)};

    auto nssRows = std::make_shared<PasswdRows>();
    nssRows->rows = {makePwd("root", 0), makePwd("alice", 1000), makePwd("bob", 200001)};

    // Both local rows plus the terminator: the local pass ignores the filter.
    EXPECT_CALL(*mockPasswd, fgetpwent_r(mockFile, ::testing::_, ::testing::NotNull(), 16 * 1024, ::testing::_))
    .Times(3)
    .WillRepeatedly(::testing::Invoke(serveFgetpwent(localRows)));

    EXPECT_CALL(*mockPasswd, setpwent()).Times(1);
    EXPECT_CALL(*mockPasswd, endpwent()).Times(1);
    EXPECT_CALL(*mockPasswd, getpwent_r(::testing::_, ::testing::NotNull(), 1024, ::testing::_))
    .WillRepeatedly(::testing::Invoke(serveGetpwent(nssRows)));

    UsersProvider provider(mockPasswd, mockSys);
    auto result = provider.collectWithConstraints({"alice"}, {}, true);

    ASSERT_EQ(result.size(), static_cast<size_t>(1));
    EXPECT_EQ(result[0]["username"], "alice");
    EXPECT_EQ(result[0]["is_remote"], 0);
}

// DynamicUser= accounts are local and transient but absent from /etc/passwd, so without the
// carve-out they look like directory accounts. On AlmaLinux 9 one landed on uid 64627.
TEST(UsersProviderTest, CollectDoesNotReportSystemdDynamicUsersAsRemote)
{
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockSys = std::make_shared<MockSystemWrapper>();

    EXPECT_CALL(*mockSys, sysconf(_SC_GETPW_R_SIZE_MAX))
    .WillRepeatedly(::testing::Return(1024));

    FILE* mockFile = reinterpret_cast<FILE*>(0x1234);
    EXPECT_CALL(*mockSys, fopen(::testing::StrEq("/etc/passwd"), ::testing::StrEq("r")))
    .WillOnce(::testing::Return(mockFile));
    EXPECT_CALL(*mockSys, fclose(mockFile)).WillOnce(::testing::Return(0));

    auto localRows = std::make_shared<PasswdRows>();
    localRows->rows = {makePwd("root", 0)};

    // Both boundaries, one uid on each side, and a real directory account.
    auto nssRows = std::make_shared<PasswdRows>();
    nssRows->rows =
    {
        makePwd("root", 0),
        makePwd("justbelow", 61183),
        makePwd("dynlow", 61184),
        makePwd("dynusertest", 64627),
        makePwd("dynhigh", 65519),
        makePwd("justabove", 65520),
        makePwd("bob", 200001)
    };

    EXPECT_CALL(*mockPasswd, fgetpwent_r(mockFile, ::testing::_, ::testing::NotNull(), 16 * 1024, ::testing::_))
    .WillRepeatedly(::testing::Invoke(serveFgetpwent(localRows)));

    EXPECT_CALL(*mockPasswd, setpwent()).Times(1);
    EXPECT_CALL(*mockPasswd, endpwent()).Times(1);
    EXPECT_CALL(*mockPasswd, getpwent_r(::testing::_, ::testing::NotNull(), 1024, ::testing::_))
    .WillRepeatedly(::testing::Invoke(serveGetpwent(nssRows)));

    UsersProvider provider(mockPasswd, mockSys);
    auto result = provider.collect();

    ASSERT_EQ(result.size(), static_cast<size_t>(7));
    EXPECT_EQ(result[0]["is_remote"], 0) << "root is in the file";
    EXPECT_EQ(result[1]["is_remote"], 1) << "uid 61183 is below the reserved range";
    EXPECT_EQ(result[2]["is_remote"], 0) << "uid 61184 is the first reserved uid";
    EXPECT_EQ(result[3]["is_remote"], 0) << "a DynamicUser account is local";
    EXPECT_EQ(result[4]["is_remote"], 0) << "uid 65519 is the last reserved uid";
    EXPECT_EQ(result[5]["is_remote"], 1) << "uid 65520 is above the reserved range";
    EXPECT_EQ(result[6]["is_remote"], 1) << "a directory account is still remote";
}

// ERANGE is not end of file. Treating it as one would leave a partial set and flag every name past
// that line as remote, so the set is discarded and every row falls back to local.
TEST(UsersProviderTest, CollectTreatsShortReadAsUndeterminedLocality)
{
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockSys = std::make_shared<MockSystemWrapper>();

    EXPECT_CALL(*mockSys, sysconf(_SC_GETPW_R_SIZE_MAX))
    .WillRepeatedly(::testing::Return(1024));

    FILE* mockFile = reinterpret_cast<FILE*>(0x1234);
    EXPECT_CALL(*mockSys, fopen(::testing::StrEq("/etc/passwd"), ::testing::StrEq("r")))
    .WillOnce(::testing::Return(mockFile));
    EXPECT_CALL(*mockSys, fclose(mockFile)).WillOnce(::testing::Return(0));

    auto localRows = std::make_shared<PasswdRows>();
    localRows->rows = {makePwd("root", 0)};

    // One row read, then a line too long for the buffer.
    EXPECT_CALL(*mockPasswd, fgetpwent_r(mockFile, ::testing::_, ::testing::NotNull(), 16 * 1024, ::testing::_))
    .WillOnce(::testing::Invoke(serveFgetpwent(localRows)))
    .WillOnce(::testing::Return(ERANGE));

    auto nssRows = std::make_shared<PasswdRows>();
    nssRows->rows = {makePwd("root", 0), makePwd("bob", 200001)};

    EXPECT_CALL(*mockPasswd, setpwent()).Times(1);
    EXPECT_CALL(*mockPasswd, endpwent()).Times(1);
    EXPECT_CALL(*mockPasswd, getpwent_r(::testing::_, ::testing::NotNull(), 1024, ::testing::_))
    .WillRepeatedly(::testing::Invoke(serveGetpwent(nssRows)));

    UsersProvider provider(mockPasswd, mockSys);
    auto result = provider.collect();

    ASSERT_EQ(result.size(), static_cast<size_t>(2));
    EXPECT_EQ(result[0]["is_remote"], 0);
    EXPECT_EQ(result[1]["is_remote"], 0) << "a truncated local set must not make bob look remote";
}

// /etc/passwd is read only once the enumeration is closed; the other way round reports an account
// created in between as remote for one scan.
TEST(UsersProviderTest, CollectReadsPasswdAfterClosingEnumeration)
{
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockSys = std::make_shared<MockSystemWrapper>();

    EXPECT_CALL(*mockSys, sysconf(_SC_GETPW_R_SIZE_MAX))
    .WillRepeatedly(::testing::Return(1024));

    FILE* mockFile = reinterpret_cast<FILE*>(0x1234);

    auto localRows = std::make_shared<PasswdRows>();
    localRows->rows = {makePwd("root", 0)};
    auto nssRows = std::make_shared<PasswdRows>();
    nssRows->rows = {makePwd("root", 0)};

    {
        ::testing::InSequence seq;
        EXPECT_CALL(*mockPasswd, setpwent()).Times(1);
        EXPECT_CALL(*mockPasswd, getpwent_r(::testing::_, ::testing::NotNull(), 1024, ::testing::_))
        .WillRepeatedly(::testing::Invoke(serveGetpwent(nssRows)));
        EXPECT_CALL(*mockPasswd, endpwent()).Times(1);
        EXPECT_CALL(*mockSys, fopen(::testing::StrEq("/etc/passwd"), ::testing::StrEq("r")))
        .WillOnce(::testing::Return(mockFile));
        EXPECT_CALL(*mockPasswd, fgetpwent_r(mockFile, ::testing::_, ::testing::NotNull(), 16 * 1024, ::testing::_))
        .WillRepeatedly(::testing::Invoke(serveFgetpwent(localRows)));
        EXPECT_CALL(*mockSys, fclose(mockFile)).WillOnce(::testing::Return(0));
    }

    UsersProvider provider(mockPasswd, mockSys);
    auto result = provider.collect();

    ASSERT_EQ(result.size(), static_cast<size_t>(1));
    EXPECT_EQ(result[0]["is_remote"], 0);
}

// The name filter runs before classification and must tolerate a nameless row too.
TEST(UsersProviderTest, CollectWithConstraintsHandlesNullUsernameRow)
{
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockSys = std::make_shared<MockSystemWrapper>();

    EXPECT_CALL(*mockSys, sysconf(_SC_GETPW_R_SIZE_MAX))
    .WillRepeatedly(::testing::Return(1024));

    FILE* mockFile = reinterpret_cast<FILE*>(0x1234);
    EXPECT_CALL(*mockSys, fopen(::testing::StrEq("/etc/passwd"), ::testing::StrEq("r")))
    .WillOnce(::testing::Return(mockFile));
    EXPECT_CALL(*mockSys, fclose(mockFile)).WillOnce(::testing::Return(0));

    auto localRows = std::make_shared<PasswdRows>();
    localRows->rows = {makePwd("alice", 1000)};

    auto nameless = makePwd("placeholder", 4242);
    nameless.pw_name = nullptr;

    auto nssRows = std::make_shared<PasswdRows>();
    nssRows->rows = {nameless, makePwd("alice", 1000)};

    EXPECT_CALL(*mockPasswd, fgetpwent_r(mockFile, ::testing::_, ::testing::NotNull(), 16 * 1024, ::testing::_))
    .WillRepeatedly(::testing::Invoke(serveFgetpwent(localRows)));

    EXPECT_CALL(*mockPasswd, setpwent()).Times(1);
    EXPECT_CALL(*mockPasswd, endpwent()).Times(1);
    EXPECT_CALL(*mockPasswd, getpwent_r(::testing::_, ::testing::NotNull(), 1024, ::testing::_))
    .WillRepeatedly(::testing::Invoke(serveGetpwent(nssRows)));

    UsersProvider provider(mockPasswd, mockSys);
    auto result = provider.collectWithConstraints({"alice"}, {}, true);

    ASSERT_EQ(result.size(), static_cast<size_t>(1));
    EXPECT_EQ(result[0]["username"], "alice");
    EXPECT_EQ(result[0]["is_remote"], 0);
}

TEST(UsersProviderTest, CollectHandlesNullUsernameRow)
{
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockSys = std::make_shared<MockSystemWrapper>();

    EXPECT_CALL(*mockSys, sysconf(_SC_GETPW_R_SIZE_MAX))
    .WillRepeatedly(::testing::Return(1024));

    FILE* mockFile = reinterpret_cast<FILE*>(0x1234);
    EXPECT_CALL(*mockSys, fopen(::testing::StrEq("/etc/passwd"), ::testing::StrEq("r")))
    .WillOnce(::testing::Return(mockFile));
    EXPECT_CALL(*mockSys, fclose(mockFile)).WillOnce(::testing::Return(0));

    auto localRows = std::make_shared<PasswdRows>();
    localRows->rows = {makePwd("root", 0)};

    auto nameless = makePwd("placeholder", 4242);
    nameless.pw_name = nullptr;

    auto nssRows = std::make_shared<PasswdRows>();
    nssRows->rows = {makePwd("root", 0), nameless};

    EXPECT_CALL(*mockPasswd, fgetpwent_r(mockFile, ::testing::_, ::testing::NotNull(), 16 * 1024, ::testing::_))
    .WillRepeatedly(::testing::Invoke(serveFgetpwent(localRows)));

    EXPECT_CALL(*mockPasswd, setpwent()).Times(1);
    EXPECT_CALL(*mockPasswd, endpwent()).Times(1);
    EXPECT_CALL(*mockPasswd, getpwent_r(::testing::_, ::testing::NotNull(), 1024, ::testing::_))
    .WillRepeatedly(::testing::Invoke(serveGetpwent(nssRows)));

    UsersProvider provider(mockPasswd, mockSys);
    auto result = provider.collect();

    ASSERT_EQ(result.size(), static_cast<size_t>(2));
    EXPECT_EQ(result[1]["username"], "");
    EXPECT_EQ(result[1]["is_remote"], 0);
}
