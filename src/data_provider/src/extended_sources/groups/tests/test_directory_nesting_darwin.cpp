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
#include "directory_nesting_darwin.hpp"

using ::testing::ElementsAre;
using ::testing::IsEmpty;
using ::testing::Pair;

static const std::string EVERYONE {"ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C"};
static const std::string DOMAIN_ADMINS {"5A1E2B3C-0000-0000-0000-00000000AD01"};

TEST(DirectoryNestingDarwinTest, GroupNestingOnlyLocalGroupsHasNoFeeds)
{
    // A File Sharing group nests `everyone`, which is in the local node.
    const std::vector<DirectoryNesting::LocalGroup> groups {{20, "S", {}}, {101, "SHARE", {EVERYONE}}};

    EXPECT_THAT(DirectoryNesting::directoryFeeds(groups, {"S", "SHARE", EVERYONE}), IsEmpty());
}

TEST(DirectoryNestingDarwinTest, GroupNestingADirectoryGroupIsFedByIt)
{
    const std::vector<DirectoryNesting::LocalGroup> groups {{80, "ADMIN", {DOMAIN_ADMINS}}, {20, "S", {}}};

    EXPECT_THAT(DirectoryNesting::directoryFeeds(groups, {"ADMIN", "S"}),
                ElementsAre(Pair(80, ElementsAre(DOMAIN_ADMINS))));
}

TEST(DirectoryNestingDarwinTest, FeedsReachGroupsNestingAFedGroupWhateverTheOrder)
{
    // 300 nests 200, which nests 100, which nests a directory group. The groups come in the order
    // that needs one pass per level. 50 nests `everyone` and 300, so it is fed too.
    using Group = DirectoryNesting::LocalGroup;
    const std::vector<Group> groups {{300, "C", {"B"}}, {200, "B", {"A"}}, {100, "A", {DOMAIN_ADMINS}}, {50, "D", {EVERYONE, "C"}}};

    EXPECT_THAT(DirectoryNesting::directoryFeeds(groups, {"A", "B", "C", "D", EVERYONE}),
                ElementsAre(Pair(50, ElementsAre(DOMAIN_ADMINS)), Pair(100, ElementsAre(DOMAIN_ADMINS)),
                            Pair(200, ElementsAre(DOMAIN_ADMINS)), Pair(300, ElementsAre(DOMAIN_ADMINS))));
}

TEST(DirectoryNestingDarwinTest, LocalGroupsNestingEachOtherInACycleHaveNoFeeds)
{
    const std::vector<DirectoryNesting::LocalGroup> groups {{100, "A", {"B"}}, {200, "B", {"A"}}};

    EXPECT_THAT(DirectoryNesting::directoryFeeds(groups, {"A", "B"}), IsEmpty());
}

TEST(DirectoryNestingDarwinTest, GroupsWithoutGuidDoNotShareFeeds)
{
    const std::vector<DirectoryNesting::LocalGroup> groups {{10, "", {DOMAIN_ADMINS}}, {11, "", {}}};

    EXPECT_THAT(DirectoryNesting::directoryFeeds(groups, {""}), ElementsAre(Pair(10, ElementsAre(DOMAIN_ADMINS))));
}
