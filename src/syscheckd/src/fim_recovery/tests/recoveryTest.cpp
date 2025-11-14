/*
 * Wazuh Syscheck
 * Copyright (C) 2015, Wazuh Inc.
 * October 30, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "recovery.h"
#include "db.hpp"
#include "agent_sync_protocol_c_interface.h"
#include "agent_sync_protocol_c_wrapper.hpp"
#include <chrono>
#include <thread>
#include "timeHelper.h"

// Mock logging for tests
class MockLoggingCall
{
public:
    MOCK_METHOD(void, loggingFunction, (const modules_log_level_t, const char*), ());
};

MockLoggingCall* mockLog;

void mockLoggingFunction(const modules_log_level_t logLevel, const char* tag)
{
    mockLog->loggingFunction(logLevel, tag);
}

// Test fixture for recovery tests
class RecoveryTest : public ::testing::Test
{
protected:
    AgentSyncProtocolHandle* syncHandle = nullptr;

    RecoveryTest() = default;
    virtual ~RecoveryTest() = default;

    void SetUp() override
    {
        mockLog = new MockLoggingCall();
        // Initialize the real DB in memory mode for testing
        fim_db_init(FIM_DB_MEMORY, mockLoggingFunction, 100000, 100000, nullptr);

        // Create AgentSyncProtocol handle for tests using C interface
        MQ_Functions mq_funcs = {
            .start = [](const char*, short int, short int) { return 0; },
            .send_binary = [](int, const void*, size_t, const char*, char) { return 0; }
        };
        syncHandle = asp_create("syscheck", ":memory:", &mq_funcs,
                                [](modules_log_level_t, const char*){}, 1, 30, 3, 100);
    }

    void TearDown() override
    {
        fim_db_teardown();
        if (syncHandle) {
            asp_destroy(syncHandle);
        }
        delete mockLog;
    }

};

// Test: first time integrity check (last sync time is 0)
TEST_F(RecoveryTest, IntegrityIntervalFirstTime)
{
    const int64_t integrity_interval = 86400; // 24 hours in seconds

    // Verify last sync time is 0 initially
    int64_t initial_last_sync = DB::instance().getLastSyncTime("file_entry");
    EXPECT_EQ(initial_last_sync, 0);

    // First call should initialize timestamp and return false
    bool result = fim_recovery_integrity_interval_has_elapsed(
        const_cast<char*>("file_entry"),
        integrity_interval
    );

    EXPECT_FALSE(result);

    // Verify last sync time was updated to current time
    int64_t updated_last_sync = DB::instance().getLastSyncTime("file_entry");
    EXPECT_GT(updated_last_sync, 0);
}

// Test: integrity_interval has NOT elapsed (last sync recent)
TEST_F(RecoveryTest, IntegrityIntervalNotElapsed)
{
    const int64_t integrity_interval = 86400; // 24 hours in seconds

    // Set last sync time to current time (just synced)
    DB::instance().updateLastSyncTime("file_entry", Utils::getSecondsFromEpoch());

    // Check immediately - should not have elapsed
    bool result = fim_recovery_integrity_interval_has_elapsed(
        const_cast<char*>("file_entry"),
        integrity_interval
    );

    EXPECT_FALSE(result);
}

// Test: integrity_interval HAS elapsed (last sync was long ago)
TEST_F(RecoveryTest, IntegrityIntervalElapsed)
{
    const int64_t integrity_interval = 86400; // 24 hours in seconds
    // Set last sync time to 48h before current time
    DB::instance().updateLastSyncTime("file_entry",  Utils::getSecondsFromEpoch()- 2*integrity_interval);

    // Check after interval has elapsed
    bool result = fim_recovery_integrity_interval_has_elapsed(
        const_cast<char*>("file_entry"),
        integrity_interval
    );

    EXPECT_TRUE(result);
}

// Test: Checksum calculation with multiple entries
TEST_F(RecoveryTest, ChecksumCalculationMultipleEntries)
{
    const auto fileEntry1 = R"({"table": "file_entry", "data":[{"path": "/tmp/test1.txt", "checksum": "aaaa", "attributes": "10", "device": 1234, "gid": "0", "group_": "root", "hash_md5": "1234567890abcdef", "hash_sha1": "1234567890abcdef12345678", "hash_sha256": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", "inode": 5678, "mtime": 1234567890, "permissions": "-rw-r--r--", "size": 1024, "uid": "0", "owner": "root", "version": 1}]})"_json;

    const auto fileEntry2 = R"({"table": "file_entry", "data":[{"path": "/tmp/test2.txt", "checksum": "bbbb", "attributes": "10", "device": 1235, "gid": "0", "group_": "root", "hash_md5": "1234567890abcdef", "hash_sha1": "1234567890abcdef12345678", "hash_sha256": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", "inode": 5679, "mtime": 1234567891, "permissions": "-rw-r--r--", "size": 2048, "uid": "0", "owner": "root", "version": 1}]})"_json;

    DB::instance().updateFile(fileEntry1, [](int, const nlohmann::json&) {});
    DB::instance().updateFile(fileEntry2, [](int, const nlohmann::json&) {});

    std::string checksum = DB::instance().calculateTableChecksum("file_entry");

    // The actual checksum returned by the DB (depends on internal ordering/formatting)
    EXPECT_EQ(checksum, "c55e94247fbfc4f11842fc3bd979e5beb5ed1080");
}

// Mock callbacks for fim_recovery_persist_table_and_resync tests
bool mockSynchronizeModuleSuccess()
{
    // Simulate successful synchronization
    return true;
}

bool mockSynchronizeModuleFailure()
{
    // Simulate failed synchronization
    return false;
}

// Test: Persist and resync with successful synchronization
TEST_F(RecoveryTest, PersistAndResyncSuccess)
{
    // Insert test data into DB
    const auto fileEntry1 = R"({"table": "file_entry", "data":[{"path": "/tmp/persist1.txt", "checksum": "aaa111", "attributes": "10", "device": 1234, "gid": "0", "group_": "root", "hash_md5": "abcdef1234567890", "hash_sha1": "1234567890abcdef12345678", "hash_sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890", "inode": 1001, "mtime": 1234567890, "permissions": "-rw-r--r--", "size": 100, "uid": "0", "owner": "root", "version": 1}]})"_json;
    const auto fileEntry2 = R"({"table": "file_entry", "data":[{"path": "/tmp/persist2.txt", "checksum": "bbb222", "attributes": "10", "device": 1235, "gid": "0", "group_": "root", "hash_md5": "fedcba0987654321", "hash_sha1": "8765432109fedcba87654321", "hash_sha256": "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321", "inode": 1002, "mtime": 1234567891, "permissions": "-rw-r--r--", "size": 200, "uid": "0", "owner": "root", "version": 1}]})"_json;

    DB::instance().updateFile(fileEntry1, [](int, const nlohmann::json&) {});
    DB::instance().updateFile(fileEntry2, [](int, const nlohmann::json&) {});

    // Set last sync time to 0 initially
    DB::instance().updateLastSyncTime("file_entry", 0);

    // Call the function with successful sync mock
    fim_recovery_persist_table_and_resync(
        const_cast<char*>("file_entry"),
        syncHandle,
        mockSynchronizeModuleSuccess,
        mockLoggingFunction
    );

    // Success - function completed without errors
}

// Test: Persist and resync with failed synchronization
TEST_F(RecoveryTest, PersistAndResyncFailure)
{
    // Insert test data into DB
    const auto fileEntry = R"({"table": "file_entry", "data":[{"path": "/tmp/persist_fail.txt", "checksum": "ccc333", "attributes": "10", "device": 1236, "gid": "0", "group_": "root", "hash_md5": "1122334455667788", "hash_sha1": "1122334455667788aabbccdd", "hash_sha256": "11223344556677881122334455667788112233445566778811223344556677", "inode": 1003, "mtime": 1234567892, "permissions": "-rw-r--r--", "size": 300, "uid": "0", "owner": "root", "version": 1}]})"_json;

    DB::instance().updateFile(fileEntry, [](int, const nlohmann::json&) {});

    // Set last sync time to 0 initially
    DB::instance().updateLastSyncTime("file_entry", 0);

    // Call the function with failed sync mock
    fim_recovery_persist_table_and_resync(
        const_cast<char*>("file_entry"),
        syncHandle,
        mockSynchronizeModuleFailure,
        mockLoggingFunction
    );

    // Function completed - sync failed but that's expected for this test
}

// Test: Update last sync time using C wrapper function
TEST_F(RecoveryTest, UpdateLastSyncTime)
{
    // Initial state - last sync time should be 0
    int64_t initialTime = DB::instance().getLastSyncTime("file_entry");
    EXPECT_EQ(initialTime, 0);

    // Update last sync time using the C wrapper
    fim_db_update_last_sync_time("file_entry");

    // Verify the timestamp was updated
    int64_t updatedTime = DB::instance().getLastSyncTime("file_entry");
    EXPECT_GT(updatedTime, 0);
}

// Test: Update last sync time multiple times
TEST_F(RecoveryTest, UpdateLastSyncTimeMultipleTimes)
{
    // First update
    fim_db_update_last_sync_time("file_entry");
    int64_t firstTime = DB::instance().getLastSyncTime("file_entry");
    EXPECT_GT(firstTime, 0);

    // Small delay to ensure time difference
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    // Second update
    fim_db_update_last_sync_time("file_entry");
    int64_t secondTime = DB::instance().getLastSyncTime("file_entry");

    // Second update should be >= first update
    EXPECT_GE(secondTime, firstTime);
}
