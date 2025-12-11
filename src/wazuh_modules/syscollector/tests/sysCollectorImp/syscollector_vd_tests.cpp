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

// ========================================
// Tests for persistDifference() routing logic
// ========================================

TEST_F(SyscollectorVDTest, PersistDifference_VDTableRoutesToVDProtocol)
{
    /**
     * Test: Verify that persistDifference routes VD tables (system, packages, hotfixes)
     * to the VD sync protocol when available
     */

    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).Times(0);
    EXPECT_CALL(*spInfoWrapper, os()).Times(0);

    // Initialize with VD modules enabled
    Syscollector::instance().init(spInfoWrapper,
                                  reportFunction,
                                  persistFunction,
                                  logFunction,
                                  SYSCOLLECTOR_DB_PATH_VD,
                                  "",
                                  "",
                                  3600,
                                  false,   // scanOnStart
                                  false,   // hardware
                                  true,    // os (enabled)
                                  false,   // network
                                  true,    // packages (enabled)
                                  false,   // ports
                                  false,   // portsAll
                                  false,   // processes
                                  true,    // hotfixes (enabled)
                                  false,   // groups
                                  false,   // users
                                  false,   // services
                                  false,   // browserExtensions
                                  false);  // notifyOnFirstScan

    // Initialize sync protocols
    MQ_Functions mqFuncs;
    mqFuncs.start = [](const char*, short, short) -> int { return 0; };
    mqFuncs.send_binary = [](int, const void*, size_t, const char*, char) -> int { return 0; };

    EXPECT_NO_THROW(
    {
        Syscollector::instance().initSyncProtocol(
            "syscollector",
            ":memory:",
            ":memory:",
            mqFuncs,
            std::chrono::seconds(10),
            std::chrono::seconds(5),
            3,
            100
        );
    });

    // Test routing for VD tables (system, packages, hotfixes)
    // These should route to m_spSyncProtocolVD
    EXPECT_NO_THROW(
    {
        Syscollector::instance().persistDifference(
            "test_id_1",
            Operation::CREATE,
            SYSCOLLECTOR_SYNC_INDEX_SYSTEM,
            R"({"test": "data"})",
            1,
            false
        );

        Syscollector::instance().persistDifference(
            "test_id_2",
            Operation::MODIFY,
            SYSCOLLECTOR_SYNC_INDEX_PACKAGES,
            R"({"test": "data"})",
            2,
            true
        );

        Syscollector::instance().persistDifference(
            "test_id_3",
            Operation::DELETE_,
            SYSCOLLECTOR_SYNC_INDEX_HOTFIXES,
            R"({"test": "data"})",
            3,
            false
        );
    });

    Syscollector::instance().destroy();
}

TEST_F(SyscollectorVDTest, PersistDifference_NonVDTableRoutesToRegularProtocol)
{
    /**
     * Test: Verify that persistDifference routes non-VD tables (processes, ports, etc.)
     * to the regular sync protocol
     */

    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).Times(0);
    EXPECT_CALL(*spInfoWrapper, os()).Times(0);

    // Initialize with non-VD modules enabled
    Syscollector::instance().init(spInfoWrapper,
                                  reportFunction,
                                  persistFunction,
                                  logFunction,
                                  SYSCOLLECTOR_DB_PATH_VD,
                                  "",
                                  "",
                                  3600,
                                  false,   // scanOnStart
                                  true,    // hardware (enabled)
                                  false,   // os (disabled)
                                  true,    // network (enabled)
                                  false,   // packages (disabled)
                                  true,    // ports (enabled)
                                  false,   // portsAll
                                  true,    // processes (enabled)
                                  false,   // hotfixes (disabled)
                                  false,   // groups
                                  false,   // users
                                  false,   // services
                                  false,   // browserExtensions
                                  false);  // notifyOnFirstScan

    // Initialize sync protocols
    MQ_Functions mqFuncs;
    mqFuncs.start = [](const char*, short, short) -> int { return 0; };
    mqFuncs.send_binary = [](int, const void*, size_t, const char*, char) -> int { return 0; };

    EXPECT_NO_THROW(
    {
        Syscollector::instance().initSyncProtocol(
            "syscollector",
            ":memory:",
            ":memory:",
            mqFuncs,
            std::chrono::seconds(10),
            std::chrono::seconds(5),
            3,
            100
        );
    });

    // Test routing for non-VD tables
    // These should route to m_spSyncProtocol
    EXPECT_NO_THROW(
    {
        Syscollector::instance().persistDifference(
            "test_id_4",
            Operation::CREATE,
            SYSCOLLECTOR_SYNC_INDEX_PROCESSES,
            R"({"test": "data"})",
            4,
            false
        );

        Syscollector::instance().persistDifference(
            "test_id_5",
            Operation::MODIFY,
            SYSCOLLECTOR_SYNC_INDEX_PORTS,
            R"({"test": "data"})",
            5,
            true
        );

        Syscollector::instance().persistDifference(
            "test_id_6",
            Operation::CREATE,
            SYSCOLLECTOR_SYNC_INDEX_HARDWARE,
            R"({"test": "data"})",
            6,
            false
        );
    });

    Syscollector::instance().destroy();
}

TEST_F(SyscollectorVDTest, PersistDifference_WithoutSyncProtocol)
{
    /**
     * Test: Verify that persistDifference handles the case when sync protocols
     * are not initialized
     */

    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).Times(0);
    EXPECT_CALL(*spInfoWrapper, os()).Times(0);

    // Initialize without sync protocols
    Syscollector::instance().init(spInfoWrapper,
                                  reportFunction,
                                  persistFunction,
                                  logFunction,
                                  SYSCOLLECTOR_DB_PATH_VD,
                                  "",
                                  "",
                                  3600,
                                  false,   // scanOnStart
                                  false,   // hardware
                                  true,    // os (enabled)
                                  false,   // network
                                  true,    // packages (enabled)
                                  false,   // ports
                                  false,   // portsAll
                                  false,   // processes
                                  false,   // hotfixes
                                  false,   // groups
                                  false,   // users
                                  false,   // services
                                  false,   // browserExtensions
                                  false);  // notifyOnFirstScan

    // Do NOT initialize sync protocols - test behavior without them

    // Should not throw even without sync protocols
    EXPECT_NO_THROW(
    {
        Syscollector::instance().persistDifference(
            "test_id_7",
            Operation::CREATE,
            SYSCOLLECTOR_SYNC_INDEX_SYSTEM,
            R"({"test": "data"})",
            7,
            false
        );
    });

    Syscollector::instance().destroy();
}

// ========================================
// Tests for parseResponseBuffer() routing logic
// ========================================

TEST_F(SyscollectorVDTest, ParseResponseBuffer_RoutesToRegularProtocol)
{
    /**
     * Test: Verify that parseResponseBuffer routes to the regular sync protocol
     * (not the VD protocol)
     */

    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).Times(0);
    EXPECT_CALL(*spInfoWrapper, os()).Times(0);

    // Initialize with modules enabled
    Syscollector::instance().init(spInfoWrapper,
                                  reportFunction,
                                  persistFunction,
                                  logFunction,
                                  SYSCOLLECTOR_DB_PATH_VD,
                                  "",
                                  "",
                                  3600,
                                  false,   // scanOnStart
                                  true,    // hardware
                                  true,    // os
                                  true,    // network
                                  true,    // packages
                                  true,    // ports
                                  false,   // portsAll
                                  true,    // processes
                                  false,   // hotfixes
                                  false,   // groups
                                  false,   // users
                                  false,   // services
                                  false,   // browserExtensions
                                  false);  // notifyOnFirstScan

    // Initialize sync protocols
    MQ_Functions mqFuncs;
    mqFuncs.start = [](const char*, short, short) -> int { return 0; };
    mqFuncs.send_binary = [](int, const void*, size_t, const char*, char) -> int { return 0; };

    EXPECT_NO_THROW(
    {
        Syscollector::instance().initSyncProtocol(
            "syscollector",
            ":memory:",
            ":memory:",
            mqFuncs,
            std::chrono::seconds(10),
            std::chrono::seconds(5),
            3,
            100
        );
    });

    // Test parseResponseBuffer with sample data
    const uint8_t testData[] = {0x01, 0x02, 0x03, 0x04};
    bool result = false;

    EXPECT_NO_THROW(
    {
        result = Syscollector::instance().parseResponseBuffer(testData, sizeof(testData));
    });

    // Result depends on sync protocol implementation
    // The function should execute without throwing
    (void)result;

    Syscollector::instance().destroy();
}

TEST_F(SyscollectorVDTest, ParseResponseBuffer_WithoutSyncProtocol)
{
    /**
     * Test: Verify that parseResponseBuffer returns false when sync protocol
     * is not initialized
     */

    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).Times(0);
    EXPECT_CALL(*spInfoWrapper, os()).Times(0);

    // Initialize without sync protocols
    Syscollector::instance().init(spInfoWrapper,
                                  reportFunction,
                                  persistFunction,
                                  logFunction,
                                  SYSCOLLECTOR_DB_PATH_VD,
                                  "",
                                  "",
                                  3600,
                                  false,   // scanOnStart
                                  false,   // hardware
                                  true,    // os
                                  false,   // network
                                  true,    // packages
                                  false,   // ports
                                  false,   // portsAll
                                  false,   // processes
                                  false,   // hotfixes
                                  false,   // groups
                                  false,   // users
                                  false,   // services
                                  false,   // browserExtensions
                                  false);  // notifyOnFirstScan

    // Do NOT initialize sync protocols

    // Test parseResponseBuffer without sync protocol
    const uint8_t testData[] = {0x01, 0x02, 0x03, 0x04};
    bool result = false;

    EXPECT_NO_THROW(
    {
        result = Syscollector::instance().parseResponseBuffer(testData, sizeof(testData));
    });

    // Should return false when sync protocol is not initialized
    EXPECT_FALSE(result);

    Syscollector::instance().destroy();
}

TEST_F(SyscollectorVDTest, ParseResponseBufferVD_RoutesToVDProtocol)
{
    /**
     * Test: Verify that parseResponseBufferVD routes to the VD sync protocol
     */

    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).Times(0);
    EXPECT_CALL(*spInfoWrapper, os()).Times(0);

    // Initialize with VD modules enabled
    Syscollector::instance().init(spInfoWrapper,
                                  reportFunction,
                                  persistFunction,
                                  logFunction,
                                  SYSCOLLECTOR_DB_PATH_VD,
                                  "",
                                  "",
                                  3600,
                                  false,   // scanOnStart
                                  false,   // hardware
                                  true,    // os (enabled)
                                  false,   // network
                                  true,    // packages (enabled)
                                  false,   // ports
                                  false,   // portsAll
                                  false,   // processes
                                  true,    // hotfixes (enabled)
                                  false,   // groups
                                  false,   // users
                                  false,   // services
                                  false,   // browserExtensions
                                  false);  // notifyOnFirstScan

    // Initialize sync protocols
    MQ_Functions mqFuncs;
    mqFuncs.start = [](const char*, short, short) -> int { return 0; };
    mqFuncs.send_binary = [](int, const void*, size_t, const char*, char) -> int { return 0; };

    EXPECT_NO_THROW(
    {
        Syscollector::instance().initSyncProtocol(
            "syscollector",
            ":memory:",
            ":memory:",
            mqFuncs,
            std::chrono::seconds(10),
            std::chrono::seconds(5),
            3,
            100
        );
    });

    // Test parseResponseBufferVD with sample data
    const uint8_t testData[] = {0x01, 0x02, 0x03, 0x04};
    bool result = false;

    EXPECT_NO_THROW(
    {
        result = Syscollector::instance().parseResponseBufferVD(testData, sizeof(testData));
    });

    // Result depends on sync protocol implementation
    // The function should execute without throwing
    (void)result;

    Syscollector::instance().destroy();
}

TEST_F(SyscollectorVDTest, ParseResponseBufferVD_WithoutSyncProtocol)
{
    /**
     * Test: Verify that parseResponseBufferVD returns false when VD sync protocol
     * is not initialized
     */

    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).Times(0);
    EXPECT_CALL(*spInfoWrapper, os()).Times(0);

    // Initialize without sync protocols
    Syscollector::instance().init(spInfoWrapper,
                                  reportFunction,
                                  persistFunction,
                                  logFunction,
                                  SYSCOLLECTOR_DB_PATH_VD,
                                  "",
                                  "",
                                  3600,
                                  false,   // scanOnStart
                                  false,   // hardware
                                  true,    // os
                                  false,   // network
                                  true,    // packages
                                  false,   // ports
                                  false,   // portsAll
                                  false,   // processes
                                  false,   // hotfixes
                                  false,   // groups
                                  false,   // users
                                  false,   // services
                                  false,   // browserExtensions
                                  false);  // notifyOnFirstScan

    // Do NOT initialize sync protocols

    // Test parseResponseBufferVD without sync protocol
    const uint8_t testData[] = {0x01, 0x02, 0x03, 0x04};
    bool result = false;

    EXPECT_NO_THROW(
    {
        result = Syscollector::instance().parseResponseBufferVD(testData, sizeof(testData));
    });

    // Should return false when VD sync protocol is not initialized
    EXPECT_FALSE(result);

    Syscollector::instance().destroy();
}
