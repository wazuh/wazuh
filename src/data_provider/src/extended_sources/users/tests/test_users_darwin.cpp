/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "users_darwin.hpp"
#include "iopen_directory_utils_wrapper.hpp"
#include "ipasswd_wrapper.hpp"
#include "iuuid_wrapper.hpp"

class MockUUIDWrapper : public IUUIDWrapper
{
    public:
        MOCK_METHOD(void, uidToUUID, (uid_t uid, uuid_t& uuid), (override));
        MOCK_METHOD(void, uuidToString, (const uuid_t& uuid, uuid_string_t& str), (override));
};

class MockPasswdWrapper : public IPasswdWrapperDarwin
{
    public:
        MOCK_METHOD(struct passwd*, getpwnam, (const char* name), (override));
        MOCK_METHOD(struct passwd*, getpwuid, (uid_t uid), (override));
        MOCK_METHOD(void, setpwent, (), (override));
        MOCK_METHOD(struct passwd*, getpwent, (), (override));
        MOCK_METHOD(void, endpwent, (), (override));
};

class MockODUtilsWrapper : public IODUtilsWrapper
{
        using StringBoolMap = std::map<std::string, bool>;
    public:
        MOCK_METHOD(void, genEntries,
                    (const std::string& recordType,
                     const std::string* record,
                     StringBoolMap& names),
                    (override));
        MOCK_METHOD(void, genAccountPolicyData,
                    (const std::string& uid,
                     nlohmann::json& policyData),
                    (override));
};

TEST(UsersProviderTest, CollectWithConstraintsSingleUser)
{
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockUUID = std::make_shared<MockUUIDWrapper>();
    auto mockOD = std::make_shared<MockODUtilsWrapper>();

    static struct passwd fakePasswd
    {
        .pw_name = (char*)"testuser",
        .pw_uid = 101,
        .pw_gid = 20,
        .pw_gecos = (char*)"Test User",
        .pw_dir = (char*)"/Users/testuser",
        .pw_shell = (char*)"/bin/bash"
    };

    EXPECT_CALL(*mockPasswd, getpwuid(101)).WillOnce(testing::Return(&fakePasswd));
    EXPECT_CALL(*mockUUID, uidToUUID(101, testing::_)).WillOnce([](uid_t, uuid_t& uuid)
    {
        std::fill(std::begin(uuid), std::end(uuid), 0xAB);
    });
    EXPECT_CALL(*mockUUID, uuidToString(testing::_, testing::_)).WillOnce([](const uuid_t&, uuid_string_t& str)
    {
        strcpy(str, "abcdef00-1234-5678-90ab-cdefabcdef12");
    });
    EXPECT_CALL(*mockOD, genEntries(testing::_, testing::_, testing::_)).WillOnce([](const std::string&, const std::string*, std::map<std::string, bool>& names)
    {
        names["testuser"] = false;
    });
    EXPECT_CALL(*mockOD, genAccountPolicyData(testing::_, testing::_))
    .WillOnce([](const std::string&, nlohmann::json & policyData)
    {
        policyData =
        {
            {"creation_time", 1735576566.727},
            {"failed_login_count", 0},
            {"failed_login_timestamp", 0},
            {"password_last_set_time", 1735576569.186}
        };
    });

    UsersProvider provider(mockPasswd, mockUUID, mockOD);

    auto result = provider.collectWithConstraints({101});

    ASSERT_EQ(result.size(), static_cast<size_t>(1));
    EXPECT_EQ(result[0]["username"], "testuser");
    EXPECT_EQ(result[0]["uuid"], "abcdef00-1234-5678-90ab-cdefabcdef12");
    EXPECT_EQ(result[0]["is_hidden"], 0);
    EXPECT_EQ(result[0]["creation_time"], 1735576566.727);
    EXPECT_EQ(result[0]["failed_login_count"], 0);
    EXPECT_EQ(result[0]["failed_login_timestamp"], 0);
    EXPECT_EQ(result[0]["password_last_set_time"], 1735576569.186);
}

TEST(UsersProviderTest, CollectInvokesCollectAccountPolicyData)
{
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockUUID = std::make_shared<MockUUIDWrapper>();
    auto mockOD = std::make_shared<MockODUtilsWrapper>();

    static struct passwd fakePasswd
    {
        .pw_name = (char*)"testuser",
        .pw_uid = 101,
        .pw_gid = 20,
        .pw_gecos = (char*)"Test User",
        .pw_dir = (char*)"/Users/testuser",
        .pw_shell = (char*)"/bin/bash"
    };

    EXPECT_CALL(*mockOD, genEntries(testing::_, testing::_, testing::_)).WillOnce([](const std::string&, const std::string*, std::map<std::string, bool>& names)
    {
        names["testuser"] = false;
    });

    EXPECT_CALL(*mockPasswd, getpwnam(testing::_)).WillOnce(testing::Return(&fakePasswd));
    EXPECT_CALL(*mockUUID, uidToUUID(101, testing::_)).WillOnce([](uid_t, uuid_t& uuid)
    {
        std::fill(std::begin(uuid), std::end(uuid), 0xAB);
    });
    EXPECT_CALL(*mockUUID, uuidToString(testing::_, testing::_)).WillOnce([](const uuid_t&, uuid_string_t& str)
    {
        strcpy(str, "abcdef00-1234-5678-90ab-cdefabcdef12");
    });
    EXPECT_CALL(*mockOD, genAccountPolicyData(testing::_, testing::_))
    .WillOnce([](const std::string&, nlohmann::json & policyData)
    {
        policyData =
        {
            {"creation_time", 1735576566.727},
            {"failed_login_count", 0},
            {"failed_login_timestamp", 0},
            {"password_last_set_time", 1735576569.186}
        };
    });

    UsersProvider provider(mockPasswd, mockUUID, mockOD);

    auto result = provider.collect();

    ASSERT_EQ(result.size(), static_cast<size_t>(1));
    const auto& user = result[0];
    EXPECT_EQ(user["username"], "testuser");
    EXPECT_EQ(user["uuid"], "abcdef00-1234-5678-90ab-cdefabcdef12");
    EXPECT_EQ(user["is_hidden"], 0);
    EXPECT_EQ(user["creation_time"], 1735576566.727);
    EXPECT_EQ(user["failed_login_count"], 0);
    EXPECT_EQ(user["failed_login_timestamp"], 0);
    EXPECT_EQ(user["password_last_set_time"], 1735576569.186);
}
