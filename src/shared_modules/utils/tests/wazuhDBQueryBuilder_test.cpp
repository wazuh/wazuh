/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * Nov 1, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wazuhDBQueryBuilder_test.hpp"
#include "wazuhDBQueryBuilder.hpp"
#include <string>

TEST_F(WazuhDBQueryBuilderTest, GlobalTest)
{
    std::string message = WazuhDBQueryBuilder::builder().global().selectAll().fromTable("agent").build();
    EXPECT_EQ(message, "global sql SELECT * FROM agent ");
}

TEST_F(WazuhDBQueryBuilderTest, AgentTest)
{
    std::string message = WazuhDBQueryBuilder::builder().agent("0").selectAll().fromTable("sys_programs").build();
    EXPECT_EQ(message, "agent 0 sql SELECT * FROM sys_programs ");
}

TEST_F(WazuhDBQueryBuilderTest, WhereTest)
{
    std::string message = WazuhDBQueryBuilder::builder()
                              .agent("0")
                              .selectAll()
                              .fromTable("sys_programs")
                              .whereColumn("name")
                              .equalsTo("bash")
                              .build();
    EXPECT_EQ(message, "agent 0 sql SELECT * FROM sys_programs WHERE name = 'bash' ");
}

TEST_F(WazuhDBQueryBuilderTest, WhereAndTest)
{
    std::string message = WazuhDBQueryBuilder::builder()
                              .agent("0")
                              .selectAll()
                              .fromTable("sys_programs")
                              .whereColumn("name")
                              .equalsTo("bash")
                              .andColumn("version")
                              .equalsTo("1")
                              .build();
    EXPECT_EQ(message, "agent 0 sql SELECT * FROM sys_programs WHERE name = 'bash' AND version = '1' ");
}

TEST_F(WazuhDBQueryBuilderTest, WhereOrTest)
{
    std::string message = WazuhDBQueryBuilder::builder()
                              .agent("0")
                              .selectAll()
                              .fromTable("sys_programs")
                              .whereColumn("name")
                              .equalsTo("bash")
                              .orColumn("version")
                              .equalsTo("1")
                              .build();
    EXPECT_EQ(message, "agent 0 sql SELECT * FROM sys_programs WHERE name = 'bash' OR version = '1' ");
}

TEST_F(WazuhDBQueryBuilderTest, WhereIsNullTest)
{
    std::string message = WazuhDBQueryBuilder::builder()
                              .agent("0")
                              .selectAll()
                              .fromTable("sys_programs")
                              .whereColumn("name")
                              .isNull()
                              .build();
    EXPECT_EQ(message, "agent 0 sql SELECT * FROM sys_programs WHERE name IS NULL ");
}

TEST_F(WazuhDBQueryBuilderTest, WhereIsNotNullTest)
{
    std::string message = WazuhDBQueryBuilder::builder()
                              .agent("0")
                              .selectAll()
                              .fromTable("sys_programs")
                              .whereColumn("name")
                              .isNotNull()
                              .build();
    EXPECT_EQ(message, "agent 0 sql SELECT * FROM sys_programs WHERE name IS NOT NULL ");
}

TEST_F(WazuhDBQueryBuilderTest, InvalidValue)
{
    EXPECT_THROW(WazuhDBQueryBuilder::builder()
                     .agent("0")
                     .selectAll()
                     .fromTable("sys_programs")
                     .whereColumn("name")
                     .equalsTo("bash'")
                     .build(),
                 std::runtime_error);
}

TEST_F(WazuhDBQueryBuilderTest, InvalidColumn)
{
    EXPECT_THROW(WazuhDBQueryBuilder::builder()
                     .agent("0")
                     .selectAll()
                     .fromTable("sys_programs")
                     .whereColumn("name'")
                     .equalsTo("bash")
                     .build(),
                 std::runtime_error);
}

TEST_F(WazuhDBQueryBuilderTest, InvalidTable)
{
    EXPECT_THROW(WazuhDBQueryBuilder::builder()
                     .agent("0")
                     .selectAll()
                     .fromTable("sys_programs'")
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
    std::string message = WazuhDBQueryBuilder::builder().globalFindCommand("agent 1").build();
    EXPECT_EQ(message, "global find-agent 1 ");
}

TEST_F(WazuhDBQueryBuilderTest, GlobalSelectCommand)
{
    std::string message = WazuhDBQueryBuilder::builder().globalSelectCommand("agent-name 1").build();
    EXPECT_EQ(message, "global select-agent-name 1 ");
}

TEST_F(WazuhDBQueryBuilderTest, AgentGetOsInfoCommand)
{
    std::string message = WazuhDBQueryBuilder::builder().agentGetOsInfoCommand("1").build();
    EXPECT_EQ(message, "agent 1 osinfo get ");
}

TEST_F(WazuhDBQueryBuilderTest, AgentGetHotfixesCommand)
{
    std::string message = WazuhDBQueryBuilder::builder().agentGetHotfixesCommand("1").build();
    EXPECT_EQ(message, "agent 1 hotfix get ");
}

TEST_F(WazuhDBQueryBuilderTest, AgentGetPackagesCommand)
{
    std::string message = WazuhDBQueryBuilder::builder().agentGetPackagesCommand("1").build();
    EXPECT_EQ(message, "agent 1 package get ");
}
