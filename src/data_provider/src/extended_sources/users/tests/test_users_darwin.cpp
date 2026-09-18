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
        using StringJsonMap = std::map<std::string, nlohmann::json>;
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
        MOCK_METHOD(void, genPasswordData,
                    (StringJsonMap& passwordData),
                    (override));
        MOCK_METHOD(bool, genDisabledUsers,
                    (std::set<std::string>& disabledUsers),
                    (override));
};

/// Sets up the OpenDirectory password lookups with an account that has a password set and no
/// disabled flag, for the tests that are not about the password data itself.
static void expectPasswordData(const std::shared_ptr<MockODUtilsWrapper>& mockOD)
{
    EXPECT_CALL(*mockOD, genDisabledUsers(testing::_)).WillOnce([](std::set<std::string>&)
    {
        return true;
    });
    EXPECT_CALL(*mockOD, genPasswordData(testing::_))
    .WillOnce([](std::map<std::string, nlohmann::json>& passwordData)
    {
        passwordData["testuser"] =
        {
            {"password_status", "active"},
            {"password_hash_algorithm", "SALTED-SHA512-PBKDF2"}
        };
    });
}

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

    expectPasswordData(mockOD);

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
    EXPECT_EQ(result[0]["password_status"], "active");
    EXPECT_EQ(result[0]["password_hash_algorithm"], "SALTED-SHA512-PBKDF2");
    EXPECT_FALSE(result[0].contains("password_max_days_between_changes"));
    EXPECT_FALSE(result[0].contains("password_expiration_date"));
}

TEST(UsersProviderTest, CollectDerivesAgingFieldsFromExpiresEveryNDays)
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
    EXPECT_CALL(*mockUUID, uidToUUID(101, testing::_)).WillOnce([](uid_t, uuid_t&) {});
    EXPECT_CALL(*mockUUID, uuidToString(testing::_, testing::_)).WillOnce([](const uuid_t&, uuid_string_t& str)
    {
        strcpy(str, "abcdef00-1234-5678-90ab-cdefabcdef12");
    });
    EXPECT_CALL(*mockOD, genEntries(testing::_, testing::_, testing::_)).WillOnce([](const std::string&, const std::string*, std::map<std::string, bool>& names)
    {
        names["testuser"] = false;
    });
    // A pwpolicy/MDM-imposed change interval, as read from the nested
    // policyCategoryPasswordChange/policyParameters entry.
    EXPECT_CALL(*mockOD, genAccountPolicyData(testing::_, testing::_))
    .WillOnce([](const std::string&, nlohmann::json & policyData)
    {
        policyData =
        {
            {"creation_time", 1735576566.727},
            {"failed_login_count", 0},
            {"failed_login_timestamp", 0},
            {"password_last_set_time", 1735576569.0},
            {"expires_every_n_days", 90}
        };
    });

    expectPasswordData(mockOD);

    UsersProvider provider(mockPasswd, mockUUID, mockOD);

    auto result = provider.collectWithConstraints({101});

    ASSERT_EQ(result.size(), static_cast<size_t>(1));
    EXPECT_EQ(result[0]["password_max_days_between_changes"], 90);
    EXPECT_EQ(result[0]["password_expiration_date"], 1735576569 + 90 * 86400);
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

    expectPasswordData(mockOD);

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
    EXPECT_EQ(user["password_status"], "active");
    EXPECT_EQ(user["password_hash_algorithm"], "SALTED-SHA512-PBKDF2");
}

TEST(UsersProviderTest, CollectReportsAccountWithoutPasswordAsNotSet)
{
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockUUID = std::make_shared<MockUUIDWrapper>();
    auto mockOD = std::make_shared<MockODUtilsWrapper>();

    static struct passwd fakePasswd
    {
        .pw_name = (char*)"_amavisd",
        .pw_uid = 83,
        .pw_gid = 83,
        .pw_gecos = (char*)"AMaViS Daemon",
        .pw_dir = (char*)"/var/virusmails",
        .pw_shell = (char*)"/usr/bin/false"
    };

    EXPECT_CALL(*mockPasswd, getpwuid(83)).WillOnce(testing::Return(&fakePasswd));
    EXPECT_CALL(*mockUUID, uidToUUID(83, testing::_)).WillOnce([](uid_t, uuid_t&) {});
    EXPECT_CALL(*mockUUID, uuidToString(testing::_, testing::_)).WillOnce([](const uuid_t&, uuid_string_t& str)
    {
        strcpy(str, "ffffeeee-dddd-cccc-bbbb-aaaa00000053");
    });
    EXPECT_CALL(*mockOD, genEntries(testing::_, testing::_, testing::_)).WillOnce([](const std::string&, const std::string*, std::map<std::string, bool>& names)
    {
        names["_amavisd"] = true;
    });
    EXPECT_CALL(*mockOD, genAccountPolicyData(testing::_, testing::_))
    .WillOnce([](const std::string&, nlohmann::json & policyData)
    {
        policyData = nlohmann::json::object();
    });
    EXPECT_CALL(*mockOD, genDisabledUsers(testing::_)).WillOnce([](std::set<std::string>&)
    {
        return true;
    });
    // Service accounts carry no ShadowHash authority, so no hash algorithm is reported either.
    EXPECT_CALL(*mockOD, genPasswordData(testing::_))
    .WillOnce([](std::map<std::string, nlohmann::json>& passwordData)
    {
        passwordData["_amavisd"] =
        {
            {"password_status", "not_set"},
            {"password_hash_algorithm", ""}
        };
    });

    UsersProvider provider(mockPasswd, mockUUID, mockOD);

    auto result = provider.collectWithConstraints({83});

    ASSERT_EQ(result.size(), static_cast<size_t>(1));
    EXPECT_EQ(result[0]["password_status"], "not_set");
    EXPECT_EQ(result[0]["password_hash_algorithm"], "");
}

TEST(UsersProviderTest, CollectReportsDisabledAccountAsLocked)
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
    EXPECT_CALL(*mockUUID, uidToUUID(101, testing::_)).WillOnce([](uid_t, uuid_t&) {});
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
        policyData = nlohmann::json::object();
    });
    EXPECT_CALL(*mockOD, genDisabledUsers(testing::_)).WillOnce([](std::set<std::string>& disabledUsers)
    {
        disabledUsers.insert("testuser");
        return true;
    });
    // A disabled account keeps its hash, so the group membership has to win over "active".
    EXPECT_CALL(*mockOD, genPasswordData(testing::_))
    .WillOnce([](std::map<std::string, nlohmann::json>& passwordData)
    {
        passwordData["testuser"] =
        {
            {"password_status", "active"},
            {"password_hash_algorithm", "SALTED-SHA512-PBKDF2"}
        };
    });

    UsersProvider provider(mockPasswd, mockUUID, mockOD);

    auto result = provider.collectWithConstraints({101});

    ASSERT_EQ(result.size(), static_cast<size_t>(1));
    EXPECT_EQ(result[0]["password_status"], "locked");
    EXPECT_EQ(result[0]["password_hash_algorithm"], "SALTED-SHA512-PBKDF2");
}

TEST(UsersProviderTest, CollectReportsUserMissingFromDirectoryAsNotCollected)
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
    EXPECT_CALL(*mockUUID, uidToUUID(101, testing::_)).WillOnce([](uid_t, uuid_t&) {});
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
        policyData = nlohmann::json::object();
    });
    EXPECT_CALL(*mockOD, genDisabledUsers(testing::_)).WillOnce([](std::set<std::string>&)
    {
        return true;
    });
    // The record was unreadable, so it is absent from the map entirely.
    EXPECT_CALL(*mockOD, genPasswordData(testing::_))
    .WillOnce([](std::map<std::string, nlohmann::json>&) {});

    UsersProvider provider(mockPasswd, mockUUID, mockOD);

    auto result = provider.collectWithConstraints({101});

    ASSERT_EQ(result.size(), static_cast<size_t>(1));
    EXPECT_EQ(result[0]["password_status"], "");
    EXPECT_EQ(result[0]["password_hash_algorithm"], "");
}

TEST(UsersProviderTest, CollectResolvesPasswordDataForUserAbsentFromPasswd)
{
    auto mockPasswd = std::make_shared<MockPasswdWrapper>();
    auto mockUUID = std::make_shared<MockUUIDWrapper>();
    auto mockOD = std::make_shared<MockODUtilsWrapper>();

    // The account exists in OpenDirectory but not in the local passwd database.
    EXPECT_CALL(*mockOD, genEntries(testing::_, testing::_, testing::_)).WillOnce([](const std::string&, const std::string*, std::map<std::string, bool>& names)
    {
        names["odonly"] = false;
    });
    EXPECT_CALL(*mockPasswd, getpwnam(testing::_)).WillOnce(testing::Return(nullptr));
    EXPECT_CALL(*mockOD, genAccountPolicyData(testing::_, testing::_))
    .WillOnce([](const std::string&, nlohmann::json & policyData)
    {
        policyData = nlohmann::json::object();
    });
    EXPECT_CALL(*mockOD, genDisabledUsers(testing::_)).WillOnce([](std::set<std::string>&)
    {
        return true;
    });
    EXPECT_CALL(*mockOD, genPasswordData(testing::_))
    .WillOnce([](std::map<std::string, nlohmann::json>& passwordData)
    {
        passwordData["odonly"] =
        {
            {"password_status", "active"},
            {"password_hash_algorithm", "SALTED-SHA512-PBKDF2"}
        };
    });

    UsersProvider provider(mockPasswd, mockUUID, mockOD);

    auto result = provider.collect();

    ASSERT_EQ(result.size(), static_cast<size_t>(1));
    EXPECT_EQ(result[0]["username"], "odonly");
    EXPECT_EQ(result[0]["password_status"], "active");
    EXPECT_EQ(result[0]["password_hash_algorithm"], "SALTED-SHA512-PBKDF2");
}

TEST(UsersProviderTest, CollectReportsNoStatusWhenTheDisabledAccountsCannotBeRead)
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
    EXPECT_CALL(*mockUUID, uidToUUID(101, testing::_)).WillOnce([](uid_t, uuid_t&) {});
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
        policyData = nlohmann::json::object();
    });
    // The directory could not be read, so an empty set does not mean nobody is disabled.
    EXPECT_CALL(*mockOD, genDisabledUsers(testing::_)).WillOnce([](std::set<std::string>&)
    {
        return false;
    });
    EXPECT_CALL(*mockOD, genPasswordData(testing::_))
    .WillOnce([](std::map<std::string, nlohmann::json>& passwordData)
    {
        passwordData["testuser"] =
        {
            {"password_status", "active"},
            {"password_hash_algorithm", "SALTED-SHA512-PBKDF2"}
        };
    });

    UsersProvider provider(mockPasswd, mockUUID, mockOD);

    auto result = provider.collectWithConstraints({101});

    ASSERT_EQ(result.size(), static_cast<size_t>(1));
    // A disabled account keeps its hash, so "active" cannot be trusted here.
    EXPECT_EQ(result[0]["password_status"], "");
    EXPECT_EQ(result[0]["password_hash_algorithm"], "SALTED-SHA512-PBKDF2");
}
