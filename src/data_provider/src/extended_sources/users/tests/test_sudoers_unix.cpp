/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "sudoers_unix.hpp"
#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include <filesystem>
#include <fstream>

static const auto SUDOERS_FILE_PATH
{
    std::filesystem::temp_directory_path() / "example_sudoers"
};

static const std::string SUDOERS_FILE_CONTENT = R"(
#
# This file MUST be edited with the 'visudo' command as root.
#
#
Defaults	secure_path="/dir/local/sbin:/dir/local/bin:/dir/sbin:/dir/bin:/sbin:/bin:/snap/bin"

# Ditto for agent
#Defaults:%sudo env_keep += "AGENT_INFO"
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL
someuser ALL=(ALL) /dir/bin/apt update, \
                     /dir/bin/apt upgrade, \
                     /dir/bin/apt install somepackage, \
                     /dir/bin/systemctl restart someservice
# See sudoers(5) for more information on "@include" directives:
@includedir /etc/anotherDir.d
)"; // sudoers example.

class SudoersProviderTest : public ::testing::Test
{

    protected:

        SudoersProviderTest() = default;
        virtual ~SudoersProviderTest() = default;

        void SetUp() override
        {
            std::ofstream outputFile(SUDOERS_FILE_PATH);
            outputFile << SUDOERS_FILE_CONTENT;
            outputFile.close();
        };

        void TearDown() override
        {
            std::filesystem::remove(SUDOERS_FILE_PATH);
        };
};

TEST_F(SudoersProviderTest, WrongFileNameReturnsEmptyArray)
{
    SudoersProvider provider("non_existent_file");
    EXPECT_EQ(provider.collect(), R"([])"_json);
}

TEST_F(SudoersProviderTest, CollectReturnsExpectedJson)
{
    SudoersProvider provider(SUDOERS_FILE_PATH);
    auto result = provider.collect();

    // Check that the result is an array
    ASSERT_TRUE(result.is_array());

    // Check that the array contains expected entries
    ASSERT_EQ(result.size(), 4);

    auto filePath = SUDOERS_FILE_PATH.c_str();
    EXPECT_EQ(result[0]["header"], "Defaults");
    EXPECT_EQ(result[0]["source"], filePath);
    EXPECT_EQ(result[0]["rule_details"], R"(secure_path="/dir/local/sbin:/dir/local/bin:/dir/sbin:/dir/bin:/sbin:/bin:/snap/bin")");

    EXPECT_EQ(result[1]["header"], "%sudo");
    EXPECT_EQ(result[1]["source"], filePath);
    EXPECT_EQ(result[1]["rule_details"], "ALL=(ALL:ALL) ALL");

    EXPECT_EQ(result[2]["header"], "someuser");
    EXPECT_EQ(result[2]["source"], filePath);
    EXPECT_EQ(result[2]["rule_details"], "ALL=(ALL) /dir/bin/apt update, \\/dir/bin/apt upgrade, \\/dir/bin/apt install somepackage, \\/dir/bin/systemctl restart someservice");

    EXPECT_EQ(result[3]["header"], "@includedir");
    EXPECT_EQ(result[3]["source"], filePath);
    EXPECT_EQ(result[3]["rule_details"], "/etc/anotherDir.d");
}
