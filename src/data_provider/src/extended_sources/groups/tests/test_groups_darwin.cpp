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
#include "iuuid_wrapper.hpp"
#include "groups_darwin.hpp"

using ::testing::Return;
using ::testing::_;
using ::testing::Invoke;

class MockGroupWrapper : public IGroupWrapperDarwin
{
    public:
        MOCK_METHOD(struct group*, getgrgid, (gid_t gid), (const, override));
        MOCK_METHOD(struct group*, getgrnam, (const char* name), (const, override));
        MOCK_METHOD(int, getgrouplist, (const char* user, gid_t group, gid_t* groups, int* ngroups), (const, override));
        MOCK_METHOD(int, getgroupcount, (const char* user, gid_t group), (const, override));
};

class MockUUIDWrapper : public IUUIDWrapper
{
    public:
        MOCK_METHOD(void, uidToUUID, (uid_t uid, uuid_t& uuid), (override));
        MOCK_METHOD(void, gidToUUID, (gid_t gid, uuid_t& uuid), (override));
        MOCK_METHOD(void, uuidToString, (const uuid_t& uuid, uuid_string_t& str), (override));
};

class MockODUtilsWrapper : public IODUtilsWrapper
{
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
};

class GroupsProviderTest : public ::testing::Test
{
    protected:
        std::shared_ptr<MockGroupWrapper> mockGroupWrapper;
        std::shared_ptr<MockUUIDWrapper> mockUUIDWrapper;
        std::shared_ptr<MockODUtilsWrapper> mockODWrapper;
        GroupsProvider* provider;

        void SetUp() override
        {
            mockGroupWrapper = std::make_shared<MockGroupWrapper>();
            mockUUIDWrapper = std::make_shared<MockUUIDWrapper>();
            mockODWrapper = std::make_shared<MockODUtilsWrapper>();
            provider = new GroupsProvider(mockGroupWrapper, mockUUIDWrapper, mockODWrapper);
        }

        void TearDown() override
        {
            delete provider;
        }
};

TEST_F(GroupsProviderTest, CollectWithSpecificGid)
{
    gid_t testGid = 100;
    group* mockGroup = new group();
    mockGroup->gr_name = const_cast<char*>("testgroup");
    mockGroup->gr_gid = testGid;

    EXPECT_CALL(*mockGroupWrapper, getgrgid(testGid))
    .WillOnce(Return(mockGroup));

    EXPECT_CALL(*mockUUIDWrapper, gidToUUID(testGid, _)).WillOnce([](gid_t, uuid_t & uuid)
    {
        std::fill(std::begin(uuid), std::end(uuid), 0xAB);
    });
    EXPECT_CALL(*mockUUIDWrapper, uuidToString(_, _)).WillOnce([](const uuid_t&, uuid_string_t & str)
    {
        strcpy(str, "abcdef00-1234-5678-90ab-cdefabcdef12");
    });

    EXPECT_CALL(*mockODWrapper, genEntries("dsRecTypeStandard:Groups", _, _))
    .WillOnce(Invoke([](const std::string&, const std::string * name, std::map<std::string, bool>& output)
    {
        output[*name] = true;
    }));

    nlohmann::json result = provider->collect({testGid});

    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0]["groupname"], "testgroup");
    EXPECT_EQ(result[0]["gid"], testGid);
    EXPECT_EQ(result[0]["is_hidden"], 1);
    EXPECT_EQ(result[0]["uuid"], "abcdef00-1234-5678-90ab-cdefabcdef12");

    delete mockGroup;
}

TEST_F(GroupsProviderTest, CollectAllGroups)
{
    std::map<std::string, bool> fakeGroups = {{"admin", false}, {"staff", true}};

    EXPECT_CALL(*mockODWrapper, genEntries("dsRecTypeStandard:Groups", nullptr, _))
    .WillOnce(Invoke([&](const std::string&, const std::string*, std::map<std::string, bool>& out)
    {
        out = fakeGroups;
    }));

    group* adminGroup = new group();
    adminGroup->gr_name = const_cast<char*>("admin");
    adminGroup->gr_gid = 501;

    EXPECT_CALL(*mockGroupWrapper, getgrnam(::testing::StrEq("admin")))
    .WillOnce(Return(adminGroup));
    EXPECT_CALL(*mockGroupWrapper, getgrnam(::testing::StrEq("staff")))
    .WillOnce(Return(nullptr));

    EXPECT_CALL(*mockUUIDWrapper, gidToUUID(501, _)).WillOnce([](gid_t, uuid_t & uuid)
    {
        std::fill(std::begin(uuid), std::end(uuid), 0xAB);
    });
    EXPECT_CALL(*mockUUIDWrapper, uuidToString(_, _)).WillOnce([](const uuid_t&, uuid_string_t & str)
    {
        strcpy(str, "ffffeeee-dddd-cccc-bbbb-aaaa000001f5");
    });

    nlohmann::json result = provider->collect({});

    ASSERT_EQ(result.size(), 2u);
    EXPECT_EQ(result[0]["groupname"], "admin");
    EXPECT_EQ(result[0]["gid"], 501);
    EXPECT_EQ(result[0]["is_hidden"], 0);
    EXPECT_EQ(result[0]["uuid"], "ffffeeee-dddd-cccc-bbbb-aaaa000001f5");

    EXPECT_EQ(result[1]["groupname"], "staff");
    EXPECT_EQ(result[1]["is_hidden"], 1);

    delete adminGroup;
}
