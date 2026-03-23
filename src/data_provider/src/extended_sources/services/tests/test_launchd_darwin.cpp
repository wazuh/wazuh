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

TEST_F(LaunchdProviderTest, TestCollectReturnsValidJsonArray)
{
    // Test that collect() returns a valid JSON array
    nlohmann::json result = m_launchdProvider.collect();

    ASSERT_TRUE(result.is_array());
    // size() always returns >= 0 by definition, so we just verify it's accessible
    ASSERT_NO_THROW(result.size());
}

TEST_F(LaunchdProviderTest, TestCollectConsistency)
{
    // Test that multiple calls return consistent results
    nlohmann::json result1 = m_launchdProvider.collect();
    nlohmann::json result2 = m_launchdProvider.collect();

    ASSERT_TRUE(result1.is_array());
    ASSERT_TRUE(result2.is_array());

    // Both results should have the same size (services don't change between calls)
    ASSERT_EQ(result1.size(), result2.size());
}

TEST_F(LaunchdProviderTest, TestServiceJsonStructure)
{
    // Test that if services are found, they have the expected structure
    nlohmann::json result = m_launchdProvider.collect();

    ASSERT_TRUE(result.is_array());

    if (!result.empty())
    {
        const auto& service = result[0];

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
        ASSERT_TRUE(service["label"].is_string());
        ASSERT_TRUE(service["run_at_load"].is_string());
        ASSERT_TRUE(service["keep_alive"].is_string());
        ASSERT_TRUE(service["stdout_path"].is_string());
        ASSERT_TRUE(service["stderr_path"].is_string());
        ASSERT_TRUE(service["inetd_compatibility"].is_string());
        ASSERT_TRUE(service["start_interval"].is_string());
        ASSERT_TRUE(service["program"].is_string());
        ASSERT_TRUE(service["start_on_mount"].is_string());
        ASSERT_TRUE(service["on_demand"].is_string());
        ASSERT_TRUE(service["disabled"].is_string());
        ASSERT_TRUE(service["username"].is_string());
        ASSERT_TRUE(service["groupname"].is_string());
        ASSERT_TRUE(service["root_directory"].is_string());
        ASSERT_TRUE(service["working_directory"].is_string());
        ASSERT_TRUE(service["process_type"].is_string());
        ASSERT_TRUE(service["program_arguments"].is_string());
        ASSERT_TRUE(service["watch_paths"].is_string());
        ASSERT_TRUE(service["queue_directories"].is_string());
    }
}

TEST_F(LaunchdProviderTest, TestJsonOutputFormat)
{
    // Test that the JSON output can be serialized/deserialized correctly
    nlohmann::json result = m_launchdProvider.collect();

    ASSERT_TRUE(result.is_array());

    // Test that the JSON can be converted to string and back
    std::string jsonString = result.dump();
    ASSERT_FALSE(jsonString.empty());

    nlohmann::json parsedJson = nlohmann::json::parse(jsonString);
    ASSERT_TRUE(parsedJson.is_array());
    ASSERT_EQ(result.size(), parsedJson.size());
}

TEST_F(LaunchdProviderTest, TestServiceFieldsAreNotNull)
{
    // Test that if services exist, their fields are not null
    nlohmann::json result = m_launchdProvider.collect();

    ASSERT_TRUE(result.is_array());

    for (const auto& service : result)
    {
        // All required fields should exist and be strings
        ASSERT_TRUE(service.contains("path"));
        ASSERT_TRUE(service["path"].is_string());

        ASSERT_TRUE(service.contains("name"));
        ASSERT_TRUE(service["name"].is_string());

        // Even if empty, fields should be strings, not null
        ASSERT_TRUE(service["label"].is_string());
        ASSERT_TRUE(service["program"].is_string());
    }
}

TEST_F(LaunchdProviderTest, TestServicePathValidation)
{
    // Test that if services are found, they have valid paths
    nlohmann::json result = m_launchdProvider.collect();

    ASSERT_TRUE(result.is_array());

    for (const auto& service : result)
    {
        if (service.contains("path") && !service["path"].get<std::string>().empty())
        {
            std::string path = service["path"].get<std::string>();
            // Path should end with .plist
            ASSERT_TRUE(path.length() >= 6);
            ASSERT_EQ(path.substr(path.length() - 6), ".plist");
        }
    }
}

TEST_F(LaunchdProviderTest, TestServiceNameExtractionFromPath)
{
    // Test that service name is correctly extracted from the path
    nlohmann::json result = m_launchdProvider.collect();

    ASSERT_TRUE(result.is_array());

    for (const auto& service : result)
    {
        if (service.contains("path") && service.contains("name") &&
                !service["path"].get<std::string>().empty())
        {
            std::string path = service["path"].get<std::string>();
            std::string name = service["name"].get<std::string>();

            // Name should be the filename from the path
            ASSERT_FALSE(name.empty());
            ASSERT_TRUE(path.find(name) != std::string::npos);
        }
    }
}
