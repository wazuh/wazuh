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

// Mock implementation for _minfo used in recovery.cpp - must be declared before including headers
extern "C" {
    void _minfo(__attribute__((unused)) const char* file,
                __attribute__((unused)) int line,
                __attribute__((unused)) const char* func,
                __attribute__((unused)) const char* msg,
                ...)
    {
        // No-op implementation for unit tests
    }
}

#include "../recovery.h"
#include "../../db/include/db.hpp"
#include <chrono>
#include <thread>

extern "C" {
    #include "debug_op.h"
}

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
    RecoveryTest() = default;
    virtual ~RecoveryTest() = default;

    void SetUp() override
    {
        mockLog = new MockLoggingCall();
        // Initialize the real DB in memory mode for testing
        fim_db_init(FIM_DB_MEMORY, mockLoggingFunction, 100000, 100000, nullptr);
    }

    void TearDown() override
    {
        fim_db_teardown();
        delete mockLog;
    }

    // Helper to get current Unix time
    int64_t getCurrentTime()
    {
        return std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();
    }
};

// Test: integrity_interval has NOT elapsed (last sync recent)
TEST_F(RecoveryTest, IntegrityIntervalNotElapsed)
{
    const int64_t integrity_interval = 86400; // 24 hours in seconds

    // Set last sync time to current time (just synced)
    DB::instance().updateLastSyncTime("file_entry", getCurrentTime());

    // Check immediately - should not have elapsed
    bool result = fim_recovery_integrity_interval_has_elapsed(
        const_cast<char*>("file_entry"),
        integrity_interval,
        nullptr  // Use singleton
    );

    EXPECT_FALSE(result);
}

// Test: integrity_interval HAS elapsed (last sync was long ago)
TEST_F(RecoveryTest, IntegrityIntervalElapsed)
{
    const int64_t integrity_interval = 86400; // 24 hours in seconds
    // Set last sync time to 48h before current time
    DB::instance().updateLastSyncTime("file_entry", getCurrentTime() - 2*integrity_interval);

    // Check after interval has elapsed
    bool result = fim_recovery_integrity_interval_has_elapsed(
        const_cast<char*>("file_entry"),
        integrity_interval,
        nullptr
    );

    EXPECT_TRUE(result);
}

