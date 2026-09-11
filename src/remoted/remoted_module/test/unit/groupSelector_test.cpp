/*
 * Wazuh remoted module - Group selector helper unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * September 7, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "control/groupSelector.hpp"

#include <gtest/gtest.h>

#include <string>
#include <vector>

using namespace remoted::control;

// These helpers were file-local to controlHandler.cpp until they became shared with /download's
// authorization check. The cases below pin the exact behaviour /control depends on: whatever
// config_token an agent was handed must be reproducible from its cached groups, byte for byte.

TEST(GroupSelectorTest, JoinsGroupsPreservingWdbOrder)
{
    EXPECT_EQ(toGroupsCsv({"web", "db", "default"}), "web,db,default");

    // Order is identity, not presentation: the reversed list is a DIFFERENT multigroup, because
    // the multigroup directory is named after the sha256 of this very string.
    EXPECT_EQ(toGroupsCsv({"default", "db", "web"}), "default,db,web");
}

TEST(GroupSelectorTest, JoinsASingleGroupWithoutSeparators)
{
    EXPECT_EQ(toGroupsCsv({"default"}), "default");
}

TEST(GroupSelectorTest, JoinsAnEmptyListToAnEmptyString)
{
    EXPECT_EQ(toGroupsCsv({}), "");
}

TEST(GroupSelectorTest, KeepsDuplicatesAndEmptyEntriesVerbatim)
{
    // No de-duplication and no filtering: the CSV must mirror what wdb returned, or the selector
    // stops naming the merged.mg config_hash was computed over.
    EXPECT_EQ(toGroupsCsv({"web", "web"}), "web,web");
    EXPECT_EQ(toGroupsCsv({"web", "", "db"}), "web,,db");
}

TEST(GroupSelectorTest, EmptyGroupListYieldsTheDefaultToken)
{
    EXPECT_EQ(makeConfigToken(""), "default");
    EXPECT_EQ(makeConfigToken(toGroupsCsv({})), "default");
}

TEST(GroupSelectorTest, NonEmptyCsvPassesThroughUnchanged)
{
    EXPECT_EQ(makeConfigToken("a,b"), "a,b");
    EXPECT_EQ(makeConfigToken("default"), "default");
}
