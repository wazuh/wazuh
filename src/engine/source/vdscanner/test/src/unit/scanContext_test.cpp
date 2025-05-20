/*
 * Wazuh Vulnerability Scanner - Unit Tests
 * Copyright (C) 2015, Wazuh Inc.
 * September 21, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "../../../src/scanContext.hpp"
#include <gtest/gtest.h>

// Test fixture for ScanContext
class ScanContextTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        // Set up test data
        packageData = R"(
            {
                "name": "test-package",
                "version": "1.0.0",
                "vendor": "test-vendor",
                "install_time": "2022-01-01",
                "location": "/usr/local",
                "architecture": "x86_64",
                "groups": "test-group",
                "description": "Test package",
                "size": 1024,
                "priority": "optional",
                "multiarch": "no",
                "source": "test-source",
                "format": "deb",
                "item_id": "test-item"
            }
        )"_json;

        agentData = R"(
            {
                "id": "test-agent",
                "ip": "192.168.0.1",
                "name": "Test Agent",
                "version": "1.0.0"
            }
        )"_json;

        osData = R"(
            {
                "hostname": "test-host",
                "architecture": "x86_64",
                "name": "Test OS",
                "version": "1.0.0",
                "codename": "test-codename",
                "major_version": "1",
                "minor_version": "0",
                "patch": "0",
                "build": "12345",
                "platform": "test-platform",
                "kernel_name": "test-kernel",
                "kernel_release": "1.0.0",
                "kernel_version": "1.0.0",
                "release": "1.0.0",
                "display_version": "Test OS 1.0.0"
            }
        )"_json;

        hotfixesData = R"(
            {
                "hotfix1": "value1",
                "hotfix2": "value2"
            }
        )"_json;

        // Create a ScanContext object for testing
        scanContext =
            std::make_unique<ScanContext>(ScannerType::Os, agentData, osData, packageData, hotfixesData, responseData);
    }

    void TearDown() override
    {
        // Clean up test data
        scanContext.reset();
    }

    // Test data
    nlohmann::json packageData;
    nlohmann::json agentData;
    nlohmann::json osData;
    nlohmann::json hotfixesData;
    nlohmann::json responseData;
    std::unique_ptr<ScanContext> scanContext;
};

// Test case for package name
TEST_F(ScanContextTest, PackageNameTest)
{
    std::string_view expected = "test-package";
    std::string_view actual = scanContext->packageName();
    EXPECT_EQ(expected, actual);
}

// Test case for package version
TEST_F(ScanContextTest, PackageVersionTest)
{
    std::string_view expected = "1.0.0";
    std::string_view actual = scanContext->packageVersion();
    EXPECT_EQ(expected, actual);
}

// Test case for package vendor
TEST_F(ScanContextTest, PackageVendorTest)
{
    std::string_view expected = "test-vendor";
    std::string_view actual = scanContext->packageVendor();
    EXPECT_EQ(expected, actual);
}

// Test case for package install time
TEST_F(ScanContextTest, PackageInstallTimeTest)
{
    std::string_view expected = "2022-01-01";
    std::string_view actual = scanContext->packageInstallTime();
    EXPECT_EQ(expected, actual);
}

// Test case for package location
TEST_F(ScanContextTest, PackageLocationTest)
{
    std::string_view expected = "/usr/local";
    std::string_view actual = scanContext->packageLocation();
    EXPECT_EQ(expected, actual);
}

// Test case for package architecture
TEST_F(ScanContextTest, PackageArchitectureTest)
{
    std::string_view expected = "x86_64";
    std::string_view actual = scanContext->packageArchitecture();
    EXPECT_EQ(expected, actual);
}

// Test case for package groups
TEST_F(ScanContextTest, PackageGroupsTest)
{
    std::string_view expected = "test-group";
    std::string_view actual = scanContext->packageGroups();
    EXPECT_EQ(expected, actual);
}

// Test case for package description
TEST_F(ScanContextTest, PackageDescriptionTest)
{
    std::string_view expected = "Test package";
    std::string_view actual = scanContext->packageDescription();
    EXPECT_EQ(expected, actual);
}

// Test case for package size
TEST_F(ScanContextTest, PackageSizeTest)
{
    int expected = 1024;
    uint64_t actual = scanContext->packageSize();
    EXPECT_EQ(expected, actual);
}

// Test case for package priority
TEST_F(ScanContextTest, PackagePriorityTest)
{
    std::string_view expected = "optional";
    std::string_view actual = scanContext->packagePriority();
    EXPECT_EQ(expected, actual);
}

// Test case for package multiarch
TEST_F(ScanContextTest, PackageMultiarchTest)
{
    std::string_view expected = "no";
    std::string_view actual = scanContext->packageMultiarch();
    EXPECT_EQ(expected, actual);
}

// Test case for package source
TEST_F(ScanContextTest, PackageSourceTest)
{
    std::string_view expected = "test-source";
    std::string_view actual = scanContext->packageSource();
    EXPECT_EQ(expected, actual);
}

// Test case for package format
TEST_F(ScanContextTest, PackageFormatTest)
{
    std::string_view expected = "deb";
    std::string_view actual = scanContext->packageFormat();
    EXPECT_EQ(expected, actual);
}

// Test case for package item ID
TEST_F(ScanContextTest, PackageItemIdTest)
{
    std::string_view expected = "test-item";
    std::string_view actual = scanContext->packageItemId();
    EXPECT_EQ(expected, actual);
}

// Test case for agent ID
TEST_F(ScanContextTest, AgentIdTest)
{
    std::string_view expected = "test-agent";
    std::string_view actual = scanContext->agentId();
    EXPECT_EQ(expected, actual);
}

// Test case for agent IP
TEST_F(ScanContextTest, AgentIpTest)
{
    std::string_view expected = "192.168.0.1";
    std::string_view actual = scanContext->agentIp();
    EXPECT_EQ(expected, actual);
}

// Test case for agent name
TEST_F(ScanContextTest, AgentNameTest)
{
    std::string_view expected = "Test Agent";
    std::string_view actual = scanContext->agentName();
    EXPECT_EQ(expected, actual);
}

// Test case for agent version
TEST_F(ScanContextTest, AgentVersionTest)
{
    std::string_view expected = "1.0.0";
    std::string_view actual = scanContext->agentVersion();
    EXPECT_EQ(expected, actual);
}

// Test case for OS hostname
TEST_F(ScanContextTest, OsHostnameTest)
{
    std::string_view expected = "test-host";
    std::string_view actual = scanContext->osHostName();
    EXPECT_EQ(expected, actual);
}

// Test case for OS architecture
TEST_F(ScanContextTest, OsArchitectureTest)
{
    std::string_view expected = "x86_64";
    std::string_view actual = scanContext->osArchitecture();
    EXPECT_EQ(expected, actual);
}

// Test case for OS name
TEST_F(ScanContextTest, OsNameTest)
{
    std::string_view expected = "Test OS";
    std::string_view actual = scanContext->osName();
    EXPECT_EQ(expected, actual);
}

// Test case for OS version
TEST_F(ScanContextTest, OsVersionTest)
{
    std::string_view expected = "1.0.0";
    std::string_view actual = scanContext->osVersion();
    EXPECT_EQ(expected, actual);
}

// Test case for OS codename
TEST_F(ScanContextTest, OsCodenameTest)
{
    std::string_view expected = "test-codename";
    std::string_view actual = scanContext->osCodeName();
    EXPECT_EQ(expected, actual);
}

// Test case for OS major version
TEST_F(ScanContextTest, OsMajorVersionTest)
{
    std::string_view expected = "1";
    std::string_view actual = scanContext->osMajorVersion();
    EXPECT_EQ(expected, actual);
}

// Test case for OS minor version
TEST_F(ScanContextTest, OsMinorVersionTest)
{
    std::string_view expected = "0";
    std::string_view actual = scanContext->osMinorVersion();
    EXPECT_EQ(expected, actual);
}

// Test case for OS patch
TEST_F(ScanContextTest, OsPatchTest)
{
    std::string_view expected = "0";
    std::string_view actual = scanContext->osPatch();
    EXPECT_EQ(expected, actual);
}

// Test case for OS build
TEST_F(ScanContextTest, OsBuildTest)
{
    std::string_view expected = "12345";
    std::string_view actual = scanContext->osBuild();
    EXPECT_EQ(expected, actual);
}

// Test case for OS platform
TEST_F(ScanContextTest, OsPlatformTest)
{
    std::string_view expected = "test-platform";
    std::string_view actual = scanContext->osPlatform();
    EXPECT_EQ(expected, actual);
}

// Test case for OS kernel name
TEST_F(ScanContextTest, OsKernelNameTest)
{
    std::string_view expected = "test-kernel";
    std::string_view actual = scanContext->osKernelSysName();
    EXPECT_EQ(expected, actual);
}

// Test case for OS kernel release
TEST_F(ScanContextTest, OsKernelReleaseTest)
{
    std::string_view expected = "1.0.0";
    std::string_view actual = scanContext->osKernelRelease();
    EXPECT_EQ(expected, actual);
}

// Test case for OS kernel version
TEST_F(ScanContextTest, OsKernelVersionTest)
{
    std::string_view expected = "1.0.0";
    std::string_view actual = scanContext->osKernelVersion();
    EXPECT_EQ(expected, actual);
}

// Test case for OS release
TEST_F(ScanContextTest, OsReleaseTest)
{
    std::string_view expected = "1.0.0";
    std::string_view actual = scanContext->osRelease();
    EXPECT_EQ(expected, actual);
}

// Test case for OS display version
TEST_F(ScanContextTest, OsDisplayVersionTest)
{
    std::string_view expected = "Test OS 1.0.0";
    std::string_view actual = scanContext->osDisplayVersion();
    EXPECT_EQ(expected, actual);
}

// Test case for hotfixes
TEST_F(ScanContextTest, HotfixesTest)
{
    auto expected = R"(
        {
            "hotfix1": "value1",
            "hotfix2": "value2"
        }
    )"_json;
    nlohmann::json actual = scanContext->hotfixes();
    EXPECT_EQ(expected, actual);
}
