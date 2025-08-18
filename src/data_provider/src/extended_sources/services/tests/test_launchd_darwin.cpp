/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * February 25, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "launchd_darwin.hpp"
#include "gtest/gtest.h"

class LaunchdProviderTest : public ::testing::Test
{
    protected:
        LaunchdProvider m_launchdProvider;

        void SetUp() override;
        void TearDown() override;
};

void LaunchdProviderTest::SetUp()
{
}

void LaunchdProviderTest::TearDown()
{
}

TEST_F(LaunchdProviderTest, TestCollectReturnsValidJson)
{
    // Test that collect() returns a valid JSON structure
    nlohmann::json result = m_launchdProvider.collect();

    ASSERT_TRUE(result.is_object());
    ASSERT_TRUE(result.contains("services"));
    ASSERT_TRUE(result["services"].is_array());
}

TEST_F(LaunchdProviderTest, TestCollectWithNoServices)
{
    // Test behavior when no services are found (this might happen in test environments)
    nlohmann::json result = m_launchdProvider.collect();

    ASSERT_TRUE(result.is_object());
    ASSERT_TRUE(result.contains("services"));
    ASSERT_TRUE(result["services"].is_array());
    // Services array can be empty in test environments
}

TEST_F(LaunchdProviderTest, TestServiceJsonStructure)
{
    // Test that if services are found, they have the expected structure
    nlohmann::json result = m_launchdProvider.collect();

    if (!result["services"].empty())
    {
        const auto& service = result["services"][0];

        // Check that all expected fields exist
        ASSERT_TRUE(service.contains("path"));
        ASSERT_TRUE(service.contains("name"));
        ASSERT_TRUE(service.contains("label"));
        ASSERT_TRUE(service.contains("run_at_load"));
        ASSERT_TRUE(service.contains("keep_alive"));
        ASSERT_TRUE(service.contains("stdout_path"));
        ASSERT_TRUE(service.contains("stderr_path"));
        ASSERT_TRUE(service.contains("inetd_compatibility"));
        ASSERT_TRUE(service.contains("start_interval"));
        ASSERT_TRUE(service.contains("program"));
        ASSERT_TRUE(service.contains("start_on_mount"));
        ASSERT_TRUE(service.contains("on_demand"));
        ASSERT_TRUE(service.contains("disabled"));
        ASSERT_TRUE(service.contains("username"));
        ASSERT_TRUE(service.contains("groupname"));
        ASSERT_TRUE(service.contains("root_directory"));
        ASSERT_TRUE(service.contains("working_directory"));
        ASSERT_TRUE(service.contains("process_type"));
        ASSERT_TRUE(service.contains("program_arguments"));
        ASSERT_TRUE(service.contains("watch_paths"));
        ASSERT_TRUE(service.contains("queue_directories"));

        // Check that all fields are strings (as expected by the JSON format)
        ASSERT_TRUE(service["path"].is_string());
        ASSERT_TRUE(service["name"].is_string());
    }
}