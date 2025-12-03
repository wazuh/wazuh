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
 * - Local.db cleanup when VD data is cleaned
 * - DBSync deleteRows functionality for VD tables
 */

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "syscollector.hpp"
#include "dbsync.hpp"

#include <fstream>
#include <filesystem>
#include <memory>

using ::testing::_;
using ::testing::Return;
using ::testing::Invoke;
using ::testing::NiceMock;

// Test fixture for VD local.db cleanup functionality
class SyscollectorVDLocalDBTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            // Clean up any test databases
            cleanupTestFiles();
        }

        void TearDown() override
        {
            // Clean up after tests
            cleanupTestFiles();
        }

        void cleanupTestFiles()
        {
            const std::string testDb = "test_vd_cleanup.db";

            if (std::filesystem::exists(testDb))
            {
                std::filesystem::remove(testDb);
            }
        }
};

// ========================================
// Tests for DBSync deleteRows functionality
// These tests verify that deleteRows() can successfully clear VD tables
// ========================================

TEST_F(SyscollectorVDLocalDBTest, DBSync_DeleteRows_OSInfoTable)
{
    /**
     * Test: Verify DBSync::deleteRows() can clear the dbsync_osinfo table
     * This simulates what clearLocalDBTables() does for the "system" index
     */

    const std::string testDb = "test_vd_cleanup.db";

    // Create a DBSync instance with osinfo table
    auto dbSync = std::make_shared<DBSync>(
                      HostType::AGENT,
                      DbEngineType::SQLITE3,
                      testDb,
                      R"({
                "table": "dbsync_osinfo",
                "first_query":
                {
                    "column_list": ["architecture", "hostname", "os_build"],
                    "row_filter": "",
                    "distinct_opt": false,
                    "order_by_opt": "",
                    "count_opt": 0
                },
                "last_query":
                {
                    "column_list": ["architecture", "hostname", "os_build"],
                    "row_filter": "",
                    "distinct_opt": false,
                    "order_by_opt": "",
                    "count_opt": 0
                },
                "component": "syscollector_osinfo",
                "index": "system",
                "last_event": "last_event_osinfo",
                "checksum_field": "checksum",
                "range_checksum": true
            })");

    // Add table relationship
    dbSync->addTableRelationship(nlohmann::json::parse(R"({
        "table": "dbsync_osinfo",
        "last_query":
        {
            "column_list": ["architecture", "hostname", "os_build"],
            "row_filter": "",
            "distinct_opt": false,
            "order_by_opt": "",
            "count_opt": 0
        }
    })"));

    // Insert test data
    nlohmann::json insertData;
    insertData["table"] = "dbsync_osinfo";
    insertData["data"]["architecture"] = "x86_64";
    insertData["data"]["hostname"] = "test-host";
    insertData["data"]["os_build"] = "1234";

    bool dataInserted = false;
    auto insertCallback = [&dataInserted](ReturnTypeCallback result, const nlohmann::json & data)
    {
        dataInserted = true;
    };

    dbSync->syncRow(insertData, insertCallback);
    ASSERT_TRUE(dataInserted);

    // Now test deleteRows - this is what clearLocalDBTables() calls
    nlohmann::json deleteInput;
    deleteInput["table"] = "dbsync_osinfo";

    // deleteRows should not throw
    EXPECT_NO_THROW(dbSync->deleteRows(deleteInput));

    // Verify table is empty by trying to select rows
    bool hasRows = false;
    auto selectCallback = [&hasRows](ReturnTypeCallback result, const nlohmann::json & data)
    {
        hasRows = true;
    };

    nlohmann::json selectInput;
    selectInput["table"] = "dbsync_osinfo";
    dbSync->selectRows(selectInput, selectCallback);

    // After deleteRows, selectCallback should not have been called (no rows)
    EXPECT_FALSE(hasRows);
}

TEST_F(SyscollectorVDLocalDBTest, DBSync_DeleteRows_PackagesTable)
{
    /**
     * Test: Verify DBSync::deleteRows() can clear the dbsync_packages table
     * This simulates what clearLocalDBTables() does for the "packages" index
     */

    const std::string testDb = "test_vd_cleanup.db";

    auto dbSync = std::make_shared<DBSync>(
                      HostType::AGENT,
                      DbEngineType::SQLITE3,
                      testDb,
                      R"({
                "table": "dbsync_packages",
                "first_query":
                {
                    "column_list": ["name", "version", "architecture"],
                    "row_filter": "",
                    "distinct_opt": false,
                    "order_by_opt": "",
                    "count_opt": 0
                },
                "last_query":
                {
                    "column_list": ["name", "version", "architecture"],
                    "row_filter": "",
                    "distinct_opt": false,
                    "order_by_opt": "",
                    "count_opt": 0
                },
                "component": "syscollector_packages",
                "index": "packages",
                "last_event": "last_event_packages",
                "checksum_field": "checksum",
                "range_checksum": true
            })");

    dbSync->addTableRelationship(nlohmann::json::parse(R"({
        "table": "dbsync_packages",
        "last_query":
        {
            "column_list": ["name", "version", "architecture"],
            "row_filter": "",
            "distinct_opt": false,
            "order_by_opt": "",
            "count_opt": 0
        }
    })"));

    // Insert test data
    nlohmann::json insertData;
    insertData["table"] = "dbsync_packages";
    insertData["data"]["name"] = "test-package";
    insertData["data"]["version"] = "1.0.0";
    insertData["data"]["architecture"] = "amd64";

    bool dataInserted = false;
    auto insertCallback = [&dataInserted](ReturnTypeCallback result, const nlohmann::json & data)
    {
        dataInserted = true;
    };

    dbSync->syncRow(insertData, insertCallback);
    ASSERT_TRUE(dataInserted);

    // Test deleteRows
    nlohmann::json deleteInput;
    deleteInput["table"] = "dbsync_packages";

    EXPECT_NO_THROW(dbSync->deleteRows(deleteInput));

    // Verify table is empty
    bool hasRows = false;
    auto selectCallback = [&hasRows](ReturnTypeCallback result, const nlohmann::json & data)
    {
        hasRows = true;
    };

    nlohmann::json selectInput;
    selectInput["table"] = "dbsync_packages";
    dbSync->selectRows(selectInput, selectCallback);

    EXPECT_FALSE(hasRows);
}

#ifdef _WIN32
TEST_F(SyscollectorVDLocalDBTest, DBSync_DeleteRows_HotfixesTable)
{
    /**
     * Test: Verify DBSync::deleteRows() can clear the dbsync_hotfixes table (Windows only)
     * This simulates what clearLocalDBTables() does for the "hotfixes" index
     */

    const std::string testDb = "test_vd_cleanup.db";

    auto dbSync = std::make_shared<DBSync>(
                      HostType::AGENT,
                      DbEngineType::SQLITE3,
                      testDb,
                      R"({
                "table": "dbsync_hotfixes",
                "first_query":
                {
                    "column_list": ["hotfix_name"],
                    "row_filter": "",
                    "distinct_opt": false,
                    "order_by_opt": "",
                    "count_opt": 0
                },
                "last_query":
                {
                    "column_list": ["hotfix_name"],
                    "row_filter": "",
                    "distinct_opt": false,
                    "order_by_opt": "",
                    "count_opt": 0
                },
                "component": "syscollector_hotfixes",
                "index": "hotfixes",
                "last_event": "last_event_hotfixes",
                "checksum_field": "checksum",
                "range_checksum": true
            })");

    dbSync->addTableRelationship(nlohmann::json::parse(R"({
        "table": "dbsync_hotfixes",
        "last_query":
        {
            "column_list": ["hotfix_name"],
            "row_filter": "",
            "distinct_opt": false,
            "order_by_opt": "",
            "count_opt": 0
        }
    })"));

    // Insert test data
    nlohmann::json insertData;
    insertData["table"] = "dbsync_hotfixes";
    insertData["data"]["hotfix_name"] = "KB123456";

    bool dataInserted = false;
    auto insertCallback = [&dataInserted](ReturnTypeCallback result, const nlohmann::json & data)
    {
        dataInserted = true;
    };

    dbSync->syncRow(insertData, insertCallback);
    ASSERT_TRUE(dataInserted);

    // Test deleteRows
    nlohmann::json deleteInput;
    deleteInput["table"] = "dbsync_hotfixes";

    EXPECT_NO_THROW(dbSync->deleteRows(deleteInput));

    // Verify table is empty
    bool hasRows = false;
    auto selectCallback = [&hasRows](ReturnTypeCallback result, const nlohmann::json & data)
    {
        hasRows = true;
    };

    nlohmann::json selectInput;
    selectInput["table"] = "dbsync_hotfixes";
    dbSync->selectRows(selectInput, selectCallback);

    EXPECT_FALSE(hasRows);
}
#endif

TEST_F(SyscollectorVDLocalDBTest, DBSync_DeleteRows_EmptyTable)
{
    /**
     * Test: Verify DBSync::deleteRows() handles empty tables correctly
     * (no crash or error when deleting from empty table)
     */

    const std::string testDb = "test_vd_cleanup.db";

    auto dbSync = std::make_shared<DBSync>(
                      HostType::AGENT,
                      DbEngineType::SQLITE3,
                      testDb,
                      R"({
                "table": "dbsync_osinfo",
                "first_query":
                {
                    "column_list": ["architecture", "hostname"],
                    "row_filter": "",
                    "distinct_opt": false,
                    "order_by_opt": "",
                    "count_opt": 0
                },
                "last_query":
                {
                    "column_list": ["architecture", "hostname"],
                    "row_filter": "",
                    "distinct_opt": false,
                    "order_by_opt": "",
                    "count_opt": 0
                },
                "component": "syscollector_osinfo",
                "index": "system",
                "last_event": "last_event_osinfo",
                "checksum_field": "checksum",
                "range_checksum": true
            })");

    dbSync->addTableRelationship(nlohmann::json::parse(R"({
        "table": "dbsync_osinfo",
        "last_query":
        {
            "column_list": ["architecture", "hostname"],
            "row_filter": "",
            "distinct_opt": false,
            "order_by_opt": "",
            "count_opt": 0
        }
    })"));

    // Don't insert any data - table is empty

    // Test deleteRows on empty table
    nlohmann::json deleteInput;
    deleteInput["table"] = "dbsync_osinfo";

    // Should not throw even when table is empty
    EXPECT_NO_THROW(dbSync->deleteRows(deleteInput));
}
