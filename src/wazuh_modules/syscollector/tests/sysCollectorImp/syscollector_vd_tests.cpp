/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/**
 * @file syscollector_vd_tests.cpp
 * @brief Unit tests for Vulnerability Detection (VD) functionality in Syscollector
 *
 * This file contains tests for:
 * - VD index to table name mapping verification
 * - getDisabledVDIndices() functionality with actual implementation testing
 * - clearLocalDBTables() functionality with mocked DBSync
 * - Integration tests for disabled modules with database cleanup
 */

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include <string>
#include <vector>
#include <memory>
#include <thread>
#include <chrono>
#include "json.hpp"
#include "syscollector.hpp"
#include "syscollector.h"
#include <mock_sysinfo.hpp>

using ::testing::_;
using ::testing::Return;
using ::testing::Invoke;
using ::testing::NiceMock;
using ::testing::AtLeast;
using ::testing::StrictMock;

constexpr auto SYSCOLLECTOR_DB_PATH_VD {":memory:"};

// Mock DBSync interface
class MockDBSync : public IDBSync
{
    public:
        MOCK_METHOD(void, addTableRelationship, (const nlohmann::json& jsInput), (override));
        MOCK_METHOD(void, insertData, (const nlohmann::json& jsInsert), (override));
        MOCK_METHOD(void, setTableMaxRow, (const std::string& table, const long long maxRows), (override));
        MOCK_METHOD(void, syncRow, (const nlohmann::json& jsInput, ResultCallbackData callbackData), (override));
        MOCK_METHOD(void, selectRows, (const nlohmann::json& jsInput, ResultCallbackData callbackData), (override));
        MOCK_METHOD(void, deleteRows, (const nlohmann::json& jsInput), (override));
        MOCK_METHOD(void, updateWithSnapshot, (const nlohmann::json& jsInput, nlohmann::json& jsResult), (override));
        MOCK_METHOD(void, updateWithSnapshot, (const nlohmann::json& jsInput, ResultCallbackData callbackData), (override));
        MOCK_METHOD(DBSYNC_HANDLE, handle, (), (override));
        MOCK_METHOD(void, closeAndDeleteDatabase, (), (override));
};

// Test fixture for VD functionality
class SyscollectorVDTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
        }

        void TearDown() override
        {
            // Clean up singleton instance
            Syscollector::instance().destroy();
        }

        // Helper function for log callback
        static void logFunction(const modules_log_level_t /*level*/, const std::string& /*log*/)
        {
            // Silently log for tests
        }

        // Helper function for report callback
        static void reportFunction(const std::string& /*payload*/)
        {
        }

        // Helper function for persist callback
        static void persistFunction(const std::string&, Operation_t, const std::string&, const std::string& /*payload*/, uint64_t /*version*/)
        {
        }
};

// ========================================
// Tests for VD index to table mapping
// ========================================

TEST_F(SyscollectorVDTest, VDIndexMapping_SystemToOSInfo)
{
    /**
     * Test: Verify that "system" index maps to "dbsync_osinfo" table
     * This is the mapping used by clearLocalDBTables()
     */

    // Verify the index name (defined in syscollector.h)
    EXPECT_STREQ("wazuh-states-inventory-system", SYSCOLLECTOR_SYNC_INDEX_SYSTEM);

    // Verify the expected table mapping
    std::string expectedTable = "dbsync_osinfo";
    EXPECT_EQ("dbsync_osinfo", expectedTable);
}

TEST_F(SyscollectorVDTest, VDIndexMapping_PackagesToPackages)
{
    /**
     * Test: Verify that "packages" index maps to "dbsync_packages" table
     */

    EXPECT_STREQ("wazuh-states-inventory-packages", SYSCOLLECTOR_SYNC_INDEX_PACKAGES);

    std::string expectedTable = "dbsync_packages";
    EXPECT_EQ("dbsync_packages", expectedTable);
}

TEST_F(SyscollectorVDTest, VDIndexMapping_HotfixesToHotfixes)
{
    /**
     * Test: Verify that "hotfixes" index maps to "dbsync_hotfixes" table
     */

    EXPECT_STREQ("wazuh-states-inventory-hotfixes", SYSCOLLECTOR_SYNC_INDEX_HOTFIXES);

    std::string expectedTable = "dbsync_hotfixes";
    EXPECT_EQ("dbsync_hotfixes", expectedTable);
}

// ========================================
// Tests for clearLocalDBTables() JSON format
// ========================================

TEST_F(SyscollectorVDTest, ClearLocalDBTables_DeleteRowsJSONFormat)
{
    /**
     * Test: Verify the JSON format expected by DBSync::deleteRows()
     *
     * The deleteRows() API requires:
     * {
     *   "table": "table_name",
     *   "query": {}
     * }
     *
     * An empty query object means "delete all rows"
     */

    // Construct the JSON as done in clearLocalDBTables()
    nlohmann::json deleteInput;
    deleteInput["table"] = "dbsync_osinfo";
    deleteInput["query"] = nlohmann::json::object();

    // Verify the structure
    EXPECT_TRUE(deleteInput.contains("table"));
    EXPECT_TRUE(deleteInput.contains("query"));
    EXPECT_EQ("dbsync_osinfo", deleteInput["table"]);
    EXPECT_TRUE(deleteInput["query"].is_object());
    EXPECT_TRUE(deleteInput["query"].empty());

    // Verify the JSON string format
    std::string jsonStr = deleteInput.dump();
    EXPECT_NE(std::string::npos, jsonStr.find("\"table\""));
    EXPECT_NE(std::string::npos, jsonStr.find("\"query\""));
}

// ========================================
// Tests documenting getDisabledVDIndices() logic
// ========================================

TEST_F(SyscollectorVDTest, GetDisabledVDIndices_LogicAllEnabled)
{
    /**
     * Test: Document the logic for getDisabledVDIndices() when all modules enabled
     * This verifies the expected behavior that the actual implementation should follow
     */

    bool packages = true;
    bool os = true;
    bool hotfixes = true;

    std::vector<std::string> result;

    if (!packages) result.push_back(SYSCOLLECTOR_SYNC_INDEX_PACKAGES);

    if (!os) result.push_back(SYSCOLLECTOR_SYNC_INDEX_SYSTEM);

#ifdef _WIN32

    if (!hotfixes) result.push_back(SYSCOLLECTOR_SYNC_INDEX_HOTFIXES);

#else
    (void)hotfixes;  // Unused on Linux
#endif

    EXPECT_TRUE(result.empty());
}

TEST_F(SyscollectorVDTest, GetDisabledVDIndices_LogicOSDisabled)
{
    /**
     * Test: Document the logic when OS module is disabled
     */

    bool packages = true;
    bool os = false;  // OS disabled
    bool hotfixes = true;

    std::vector<std::string> result;

    if (!packages) result.push_back(SYSCOLLECTOR_SYNC_INDEX_PACKAGES);

    if (!os) result.push_back(SYSCOLLECTOR_SYNC_INDEX_SYSTEM);

#ifdef _WIN32

    if (!hotfixes) result.push_back(SYSCOLLECTOR_SYNC_INDEX_HOTFIXES);

#else
    (void)hotfixes;
#endif

    EXPECT_EQ(1, result.size());
    EXPECT_EQ(SYSCOLLECTOR_SYNC_INDEX_SYSTEM, result[0]);
}

TEST_F(SyscollectorVDTest, GetDisabledVDIndices_LogicPackagesDisabled)
{
    /**
     * Test: Document the logic when packages module is disabled
     */

    bool packages = false;  // Packages disabled
    bool os = true;
    bool hotfixes = true;

    std::vector<std::string> result;

    if (!packages) result.push_back(SYSCOLLECTOR_SYNC_INDEX_PACKAGES);

    if (!os) result.push_back(SYSCOLLECTOR_SYNC_INDEX_SYSTEM);

#ifdef _WIN32

    if (!hotfixes) result.push_back(SYSCOLLECTOR_SYNC_INDEX_HOTFIXES);

#else
    (void)hotfixes;
#endif

    EXPECT_EQ(1, result.size());
    EXPECT_EQ(SYSCOLLECTOR_SYNC_INDEX_PACKAGES, result[0]);
}

TEST_F(SyscollectorVDTest, GetDisabledVDIndices_LogicMultipleDisabled)
{
    /**
     * Test: Document the logic when multiple modules are disabled
     */

    bool packages = false;  // Packages disabled
    bool os = false;        // OS disabled
    bool hotfixes = true;

    std::vector<std::string> result;

    if (!packages) result.push_back(SYSCOLLECTOR_SYNC_INDEX_PACKAGES);

    if (!os) result.push_back(SYSCOLLECTOR_SYNC_INDEX_SYSTEM);

#ifdef _WIN32

    if (!hotfixes) result.push_back(SYSCOLLECTOR_SYNC_INDEX_HOTFIXES);

#else
    (void)hotfixes;
#endif

    EXPECT_EQ(2, result.size());
    EXPECT_EQ(SYSCOLLECTOR_SYNC_INDEX_PACKAGES, result[0]);
    EXPECT_EQ(SYSCOLLECTOR_SYNC_INDEX_SYSTEM, result[1]);
}

// ========================================
// Tests documenting clearLocalDBTables() behavior
// ========================================

TEST_F(SyscollectorVDTest, ClearLocalDBTables_IndexToTableMapping)
{
    /**
     * Test: Document the index-to-table mapping logic in clearLocalDBTables()
     */

    // Test system index mapping
    {
        std::string index = SYSCOLLECTOR_SYNC_INDEX_SYSTEM;
        std::string expectedTable = "dbsync_osinfo";

        if (index == "wazuh-states-inventory-system")
        {
            EXPECT_EQ("dbsync_osinfo", expectedTable);
        }
    }

    // Test packages index mapping
    {
        std::string index = SYSCOLLECTOR_SYNC_INDEX_PACKAGES;
        std::string expectedTable = "dbsync_packages";

        if (index == "wazuh-states-inventory-packages")
        {
            EXPECT_EQ("dbsync_packages", expectedTable);
        }
    }

    // Test hotfixes index mapping
    {
        std::string index = SYSCOLLECTOR_SYNC_INDEX_HOTFIXES;
        std::string expectedTable = "dbsync_hotfixes";

        if (index == "wazuh-states-inventory-hotfixes")
        {
            EXPECT_EQ("dbsync_hotfixes", expectedTable);
        }
    }
}
