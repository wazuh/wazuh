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
#include <filesystem>
#include <fstream>
#include <unistd.h>
#include <cstdint>

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

/// Fixture-backed tests. parsePlistFile reads the file through CoreFoundation rather than through
/// the filesystem wrapper, so the plists below are written to a real temporary directory and the
/// provider is pointed at it.
class LaunchdFixtureTest : public ::testing::Test
{
    protected:
        std::filesystem::path m_jobsDir;
        std::filesystem::path m_overridesDir;

        void SetUp() override
        {
            const auto base = std::filesystem::temp_directory_path() /
                              ("launchd_test_" + std::to_string(::getpid()) + "_" +
                               std::to_string(reinterpret_cast<uintptr_t>(this)));
            m_jobsDir = base / "jobs";
            m_overridesDir = base / "overrides";
            std::filesystem::create_directories(m_jobsDir);
            std::filesystem::create_directories(m_overridesDir);
        }

        void TearDown() override
        {
            std::error_code ec;
            std::filesystem::remove_all(m_jobsDir.parent_path(), ec);
        }

        /// Writes an XML plist whose root dictionary holds the given body.
        void writePlist(const std::filesystem::path& dir, const std::string& name, const std::string& body)
        {
            std::ofstream out(dir / name);
            out << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                << "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
                << "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
                << "<plist version=\"1.0\"><dict>\n" << body << "\n</dict></plist>\n";
        }

        /// Always points the provider at the fixture override directory, empty unless a test
        /// writes to it, so no test inherits the host's real override database.
        nlohmann::json collectFrom()
        {
            LaunchdProvider provider(nullptr, {m_jobsDir.string()}, m_overridesDir.string());
            return provider.collect();
        }

        static nlohmann::json findByLabel(const nlohmann::json& all, const std::string& label)
        {
            for (const auto& service : all)
            {
                if (service["label"] == label)
                {
                    return service;
                }
            }

            return nlohmann::json{};
        }
};

TEST_F(LaunchdFixtureTest, DisabledBooleanIsRenderedAsWords)
{
    writePlist(m_jobsDir, "on.plist",
               "<key>Label</key><string>com.test.on</string><key>Disabled</key><false/>");
    writePlist(m_jobsDir, "off.plist",
               "<key>Label</key><string>com.test.off</string><key>Disabled</key><true/>");

    const auto all = collectFrom();
    ASSERT_EQ(all.size(), 2u);
    EXPECT_EQ(findByLabel(all, "com.test.on")["disabled"], "false");
    EXPECT_EQ(findByLabel(all, "com.test.off")["disabled"], "true");
}

TEST_F(LaunchdFixtureTest, DisabledSpelledAsNumberIsCaptured)
{
    writePlist(m_jobsDir, "num.plist",
               "<key>Label</key><string>com.test.num</string><key>Disabled</key><integer>1</integer>");

    const auto all = collectFrom();
    ASSERT_EQ(all.size(), 1u);
    EXPECT_EQ(all[0]["disabled"], "1");
}

TEST_F(LaunchdFixtureTest, DisabledConditionalIsFlaggedAsUnevaluated)
{
    writePlist(m_jobsDir, "cond.plist",
               "<key>Label</key><string>com.test.cond</string>"
               "<key>Disabled</key><dict><key>#Then</key><true/></dict>");

    const auto all = collectFrom();
    ASSERT_EQ(all.size(), 1u);
    // Distinguishable from an absent key, which is empty and means enabled.
    EXPECT_EQ(all[0]["disabled"], LAUNCHD_UNEVALUATED_VALUE);
}

TEST_F(LaunchdFixtureTest, AbsentDisabledKeyStaysEmpty)
{
    writePlist(m_jobsDir, "plain.plist", "<key>Label</key><string>com.test.plain</string>");

    const auto all = collectFrom();
    ASSERT_EQ(all.size(), 1u);
    EXPECT_EQ(all[0]["disabled"], "");
}

TEST_F(LaunchdFixtureTest, InetdCompatibilityDictionaryMarksTheJob)
{
    writePlist(m_jobsDir, "inetd.plist",
               "<key>Label</key><string>com.test.inetd</string>"
               "<key>inetdCompatibility</key><dict><key>Wait</key><false/></dict>");

    const auto all = collectFrom();
    ASSERT_EQ(all.size(), 1u);
    EXPECT_EQ(all[0]["inetd_compatibility"], "true");
}

TEST_F(LaunchdFixtureTest, ProgramFallsBackToFirstProgramArgument)
{
    writePlist(m_jobsDir, "args.plist",
               "<key>Label</key><string>com.test.args</string>"
               "<key>ProgramArguments</key><array>"
               "<string>/usr/bin/tool</string><string>--flag</string></array>");

    const auto all = collectFrom();
    ASSERT_EQ(all.size(), 1u);
    EXPECT_EQ(all[0]["program"], "/usr/bin/tool");
    EXPECT_EQ(all[0]["program_arguments"], "/usr/bin/tool --flag");
}

TEST_F(LaunchdFixtureTest, ProgramKeyWinsOverProgramArguments)
{
    writePlist(m_jobsDir, "both.plist",
               "<key>Label</key><string>com.test.both</string>"
               "<key>Program</key><string>/usr/bin/real</string>"
               "<key>ProgramArguments</key><array><string>/usr/bin/other</string></array>");

    const auto all = collectFrom();
    ASSERT_EQ(all.size(), 1u);
    EXPECT_EQ(all[0]["program"], "/usr/bin/real");
}

TEST_F(LaunchdFixtureTest, OverrideDatabaseOutranksThePlistBothWays)
{
    writePlist(m_jobsDir, "a.plist",
               "<key>Label</key><string>com.test.a</string>");
    writePlist(m_jobsDir, "b.plist",
               "<key>Label</key><string>com.test.b</string><key>Disabled</key><true/>");
    writePlist(m_overridesDir, "disabled.plist",
               "<key>com.test.a</key><true/><key>com.test.b</key><false/>");

    const auto all = collectFrom();
    ASSERT_EQ(all.size(), 2u);
    // launchctl disable on a job whose plist says nothing.
    EXPECT_EQ(findByLabel(all, "com.test.a")["disabled"], "true");
    // launchctl enable on a job whose plist ships disabled.
    EXPECT_EQ(findByLabel(all, "com.test.b")["disabled"], "false");
}

TEST_F(LaunchdFixtureTest, AnyDomainDisablingWins)
{
    writePlist(m_jobsDir, "c.plist", "<key>Label</key><string>com.test.c</string>");
    writePlist(m_overridesDir, "disabled.plist", "<key>com.test.c</key><false/>");
    writePlist(m_overridesDir, "disabled.501.plist", "<key>com.test.c</key><true/>");

    const auto all = collectFrom();
    ASSERT_EQ(all.size(), 1u);
    EXPECT_EQ(all[0]["disabled"], "true");
}

TEST_F(LaunchdFixtureTest, MissingOverrideDirectoryLeavesThePlistUntouched)
{
    writePlist(m_jobsDir, "d.plist",
               "<key>Label</key><string>com.test.d</string><key>Disabled</key><true/>");
    std::filesystem::remove_all(m_overridesDir);

    const auto all = collectFrom();
    ASSERT_EQ(all.size(), 1u);
    EXPECT_EQ(all[0]["disabled"], "true");
}
