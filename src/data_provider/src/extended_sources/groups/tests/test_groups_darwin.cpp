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

class GroupsProviderTest : public ::testing::Test
{
    protected:
        std::shared_ptr<MockGroupWrapper> mockGroupWrapper;
        std::shared_ptr<MockODUtilsWrapper> mockODWrapper;
        GroupsProvider* provider;

        void SetUp() override
        {
            mockGroupWrapper = std::make_shared<MockGroupWrapper>();
            mockODWrapper = std::make_shared<MockODUtilsWrapper>();
            provider = new GroupsProvider(mockGroupWrapper, mockODWrapper);
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

    nlohmann::json result = provider->collect({});

    ASSERT_EQ(result.size(), 2u);
    EXPECT_EQ(result[0]["groupname"], "admin");
    EXPECT_EQ(result[0]["gid"], 501);
    EXPECT_EQ(result[0]["is_hidden"], 0);

    EXPECT_EQ(result[1]["groupname"], "staff");
    EXPECT_EQ(result[1]["is_hidden"], 1);

    delete adminGroup;
}
