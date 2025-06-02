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
#include "groups_linux.hpp"

class MockGroupWrapper : public IGroupWrapperLinux
{
    public:
        MOCK_METHOD(int, getgrgid_r, (gid_t gid, struct group* grp, char* buf, size_t buflen, struct group** result), (const, override));
        MOCK_METHOD(int, getgrent_r, (struct group* grp, char* buf, size_t buflen, struct group** result), (const, override));
        MOCK_METHOD(void, setgrent, (), (const, override));
        MOCK_METHOD(void, endgrent, (), (const, override));
        MOCK_METHOD(int, getgrouplist, (const char* user, gid_t group, gid_t* groups, int* ngroups), (const, override));
};

using ::testing::_;
using ::testing::Return;
using ::testing::DoAll;
using ::testing::SetArgPointee;
using ::testing::Invoke;

TEST(GroupsProviderTest, CollectWithSpecificGids)
{
    auto mockWrapper = std::make_shared<MockGroupWrapper>();
    GroupsProvider provider(mockWrapper);

    gid_t testGid = 1000;
    struct group mockGroup =
    {
        .gr_name = const_cast<char*>("testgroup"),
        .gr_passwd = const_cast<char*>("x"),
        .gr_gid = testGid,
        .gr_mem = nullptr
    };
    struct group* groupResult = &mockGroup;

    EXPECT_CALL(*mockWrapper, getgrgid_r(testGid, _, _, _, _))
    .WillOnce(DoAll(
                  SetArgPointee<4>(groupResult),
                  Return(0)
              ));

    std::set<gid_t> gids = { testGid };
    auto result = provider.collect(gids);

    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0]["groupname"], "testgroup");
    EXPECT_EQ(result[0]["gid"], testGid);
}

TEST(GroupsProviderTest, CollectAllGroups)
{
    auto mockWrapper = std::make_shared<MockGroupWrapper>();
    GroupsProvider provider(mockWrapper);

    struct group group1 =
    {
        .gr_name = const_cast<char*>("group1"),
        .gr_passwd = const_cast<char*>("x"),
        .gr_gid = 1001,
        .gr_mem = nullptr
    };

    struct group group2 =
    {
        .gr_name = const_cast<char*>("group2"),
        .gr_passwd = const_cast<char*>("x"),
        .gr_gid = 1002,
        .gr_mem = nullptr
    };

    struct group* result1 = &group1;
    struct group* result2 = &group2;

    EXPECT_CALL(*mockWrapper, setgrent()).Times(1);
    EXPECT_CALL(*mockWrapper, getgrent_r(_, _, _, _))
    .WillOnce(DoAll(SetArgPointee<3>(result1), Return(0)))
    .WillOnce(DoAll(SetArgPointee<3>(result2), Return(0)))
    .WillOnce(DoAll(SetArgPointee<3>(nullptr), Return(0)));

    EXPECT_CALL(*mockWrapper, endgrent()).Times(1);

    std::set<gid_t> empty;
    auto result = provider.collect(empty);

    ASSERT_EQ(result.size(), 2u);
    EXPECT_EQ(result[0]["groupname"], "group1");
    EXPECT_EQ(result[1]["groupname"], "group2");
}
