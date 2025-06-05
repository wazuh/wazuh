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
        MOCK_METHOD(int, getpwuid_r,
                    (uid_t, struct passwd*, char*, size_t, struct passwd**), (override));
        MOCK_METHOD(int, getpwnam_r,
                    (const char*, struct passwd*, char*, size_t, struct passwd**), (override));
};

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
}
