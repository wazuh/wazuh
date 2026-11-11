/*
 * Wazuh shared modules utils
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#include "wazuhDBQueryBuilder_test.hpp"
#include "wazuhDBQueryBuilder.hpp"
#include <string>

TEST_F(WazuhDBQueryBuilderTest, GlobalTest)
{
    std::string message = WazuhDBQueryBuilder::builder().global().selectAll().fromTable("agent").build();
    EXPECT_EQ(message, "global sql SELECT * FROM agent ");
}

TEST_F(WazuhDBQueryBuilderTest, WhereTest)
{
    std::string message = WazuhDBQueryBuilder::builder()
                              .global()
                              .selectAll()
                              .fromTable("agent")
                              .whereColumn("name")
                              .equalsTo("bash")
                              .build();
    EXPECT_EQ(message, "global sql SELECT * FROM agent WHERE name = 'bash' ");
}

TEST_F(WazuhDBQueryBuilderTest, WhereAndTest)
{
    std::string message = WazuhDBQueryBuilder::builder()
                              .global()
                              .selectAll()
                              .fromTable("agent")
                              .whereColumn("name")
                              .equalsTo("bash")
                              .andColumn("version")
                              .equalsTo("1")
                              .build();
    EXPECT_EQ(message, "global sql SELECT * FROM agent WHERE name = 'bash' AND version = '1' ");
}

TEST_F(WazuhDBQueryBuilderTest, WhereOrTest)
{
    std::string message = WazuhDBQueryBuilder::builder()
                              .global()
                              .selectAll()
                              .fromTable("agent")
                              .whereColumn("name")
                              .equalsTo("bash")
                              .orColumn("version")
                              .equalsTo("1")
                              .build();
    EXPECT_EQ(message, "global sql SELECT * FROM agent WHERE name = 'bash' OR version = '1' ");
}

TEST_F(WazuhDBQueryBuilderTest, WhereIsNullTest)
{
    std::string message =
        WazuhDBQueryBuilder::builder().global().selectAll().fromTable("agent").whereColumn("name").isNull().build();
    EXPECT_EQ(message, "global sql SELECT * FROM agent WHERE name IS NULL ");
}

TEST_F(WazuhDBQueryBuilderTest, WhereIsNotNullTest)
{
    std::string message =
        WazuhDBQueryBuilder::builder().global().selectAll().fromTable("agent").whereColumn("name").isNotNull().build();
    EXPECT_EQ(message, "global sql SELECT * FROM agent WHERE name IS NOT NULL ");
}

TEST_F(WazuhDBQueryBuilderTest, InvalidValue)
{
    EXPECT_THROW(WazuhDBQueryBuilder::builder()
                     .global()
                     .selectAll()
                     .fromTable("agent")
                     .whereColumn("name")
                     .equalsTo("bash'")
                     .build(),
                 std::runtime_error);
}

TEST_F(WazuhDBQueryBuilderTest, InvalidColumn)
{
    EXPECT_THROW(WazuhDBQueryBuilder::builder()
                     .global()
                     .selectAll()
                     .fromTable("agent")
                     .whereColumn("name'")
                     .equalsTo("bash")
                     .build(),
                 std::runtime_error);
}

TEST_F(WazuhDBQueryBuilderTest, InvalidTable)
{
    EXPECT_THROW(WazuhDBQueryBuilder::builder()
                     .global()
                     .selectAll()
                     .fromTable("agent'")
                     .whereColumn("name")
                     .equalsTo("bash")
                     .build(),
                 std::runtime_error);
}

TEST_F(WazuhDBQueryBuilderTest, GlobalGetCommand)
{
    std::string message = WazuhDBQueryBuilder::builder().globalGetCommand("agent-info 1").build();
    EXPECT_EQ(message, "global get-agent-info 1 ");
}

TEST_F(WazuhDBQueryBuilderTest, GlobalFindCommand)
{
    std::string message = WazuhDBQueryBuilder::builder().globalFindCommand("group default").build();
    EXPECT_EQ(message, "global find-group default ");
}

TEST_F(WazuhDBQueryBuilderTest, GlobalSelectCommand)
{
    std::string message = WazuhDBQueryBuilder::builder().globalSelectCommand("agent-group 1").build();
    EXPECT_EQ(message, "global select-agent-group 1 ");
}
