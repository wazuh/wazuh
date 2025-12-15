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
#include "groups_windows.hpp"

using ::testing::Return;

class MockGroupsHelper : public IGroupsHelper
{
    public:
        MOCK_METHOD(std::vector<Group>, processLocalGroups, (), (override));
};

TEST(GroupsProviderTest, CollectAllGroups)
{
    auto mockHelper = std::make_shared<MockGroupsHelper>();
    GroupsProvider provider(mockHelper);

    std::vector<Group> testGroups =
    {
        {0, 1, "S-1-1", "Administrators", "Admin group"},
        {0, 2, "S-1-2", "Users", "Users group"}
    };

    EXPECT_CALL(*mockHelper, processLocalGroups())
    .WillOnce(Return(testGroups));

    auto result = provider.collect({});

    ASSERT_EQ(result.size(), 2u);
    EXPECT_EQ(result[0]["gid"], 1);
    EXPECT_EQ(result[0]["group_sid"], "S-1-1");
    EXPECT_EQ(result[0]["comment"], "Admin group");
    EXPECT_EQ(result[0]["groupname"], "Administrators");
}

TEST(GroupsProviderTest, CollectWithSpecificGids)
{
    auto mockHelper = std::make_shared<MockGroupsHelper>();
    GroupsProvider provider(mockHelper);

    std::vector<Group> testGroups =
    {
        {0, 10, "S-1-10", "Group10", "Group 10"},
        {0, 20, "S-1-20", "Group20", "Group 20"},
        {0, 30, "S-1-30", "Group30", "Group 30"}
    };

    EXPECT_CALL(*mockHelper, processLocalGroups())
    .WillOnce(Return(testGroups));

    std::set<uint32_t> gids = {10, 30};

    auto result = provider.collect(gids);

    ASSERT_EQ(result.size(), 2u);
    EXPECT_EQ(result[0]["gid"], 10);
    EXPECT_EQ(result[1]["gid"], 30);
}

TEST(GroupsProviderTest, ReturnsEmptyWhenNoMatchingGids)
{
    auto mockHelper = std::make_shared<MockGroupsHelper>();
    GroupsProvider provider(mockHelper);

    std::vector<Group> testGroups =
    {
        {0, 5, "S-1-5", "OtherGroup", "Other"}
    };

    EXPECT_CALL(*mockHelper, processLocalGroups())
    .WillOnce(Return(testGroups));

    std::set<uint32_t> gids = {100, 200};

    auto result = provider.collect(gids);

    ASSERT_TRUE(result.empty());
}
