/*
 * Wazuh SCA
 * Copyright (C) 2015, Wazuh Inc.
 * November 24, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <sca_impl.hpp>
#include <mock_dbsync.hpp>
#include <mock_filesystem_wrapper.hpp>
#include "logging_helper.hpp"
#include "timeHelper.h"

#include <chrono>
#include <memory>
#include <string>

/**
 * @brief Test fixture for SCA recovery functionality
 *
 * Tests the recovery flow operations through public APIs:
 * - initSyncProtocol with integrity interval configuration
 * - check_integrity query command
 * - Response validation
 *
 * Note: Recovery methods are private, so we test them through
 * the public query() interface which is the actual usage pattern.
 */
class SCARecoveryTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            m_logOutput.clear();

            // Set up logging callback
            LoggingHelper::setLogCallback([this](const modules_log_level_t /* level */, const std::string & log)
            {
                m_logOutput += log + "\n";
            });

            m_mockDBSync = std::make_shared<MockDBSync>();
            m_mockFileSystem = std::make_shared<MockFileSystemWrapper>();

            // Basic mock setup for DBSync handle
            EXPECT_CALL(*m_mockDBSync, handle())
            .WillRepeatedly(::testing::Return(nullptr));

            m_sca = std::make_shared<SecurityConfigurationAssessment>("test_sca.db", m_mockDBSync, m_mockFileSystem);
        }

        void TearDown() override
        {
            m_sca.reset();
            m_mockDBSync.reset();
            m_mockFileSystem.reset();
        }

        // Helper method to initialize sync protocol with specific integrity interval
        void initSyncProtocolWithInterval(std::chrono::seconds integrityInterval)
        {
            // Mock MQ_Functions for sync protocol initialization
            MQ_Functions mqFuncs;
            mqFuncs.start = [](const char*, short, short) -> int { return 0; };
            mqFuncs.send_binary = [](int, const void*, size_t, const char*, char) -> int { return 0; };

            try
            {
                m_sca->initSyncProtocol("test_module", "test_sync.db", mqFuncs,
                                        std::chrono::seconds(1), std::chrono::seconds(30),
                                        3, 10, integrityInterval);
            }
            catch (const std::exception&)
            {
                // Ignore initialization errors in tests - we just need the interval set
            }
        }

        std::shared_ptr<MockDBSync> m_mockDBSync;
        std::shared_ptr<MockFileSystemWrapper> m_mockFileSystem;
        std::shared_ptr<SecurityConfigurationAssessment> m_sca;
        std::string m_logOutput;
};

// Test: initSyncProtocol with integrity interval stores the value correctly
TEST_F(SCARecoveryTest, SetIntegrityIntervalStoresValue)
{
    initSyncProtocolWithInterval(std::chrono::seconds(3600));

    // Verify it was set by checking log output
    EXPECT_TRUE(m_logOutput.find("3600") != std::string::npos);
}

// Test: initSyncProtocol with zero integrity interval disables checks
TEST_F(SCARecoveryTest, SetIntegrityIntervalZeroDisables)
{
    initSyncProtocolWithInterval(std::chrono::seconds(0));

    // Verify it was set
    EXPECT_TRUE(m_logOutput.find("0 seconds") != std::string::npos);
}

// Test: query check_integrity when interval not elapsed
TEST_F(SCARecoveryTest, QueryCheckIntegrityIntervalNotElapsed)
{
    initSyncProtocolWithInterval(std::chrono::seconds(3600));

    // Mock getLastIntegrityCheckTime to return recent timestamp (1 minute ago)
    // This will be called by integrityIntervalElapsed
    EXPECT_CALL(*m_mockDBSync, selectRows(::testing::_, ::testing::_))
    .WillOnce(::testing::Invoke([](const nlohmann::json& /* query */,
                                   std::function<void(ReturnTypeCallback, const nlohmann::json&)> callback)
    {
        nlohmann::json data;
        int64_t recentTime = Utils::getSecondsFromEpoch() - 60;  // 1 minute ago
        data["value"] = recentTime;
        callback(SELECTED, data);
    }));

    std::string response = m_sca->query(R"({"command":"check_integrity"})");

    // Parse JSON response
    nlohmann::json jsonResponse = nlohmann::json::parse(response);

    EXPECT_EQ(jsonResponse["error"], 0);
    EXPECT_EQ(jsonResponse["data"]["recovery_performed"], false);
    EXPECT_TRUE(jsonResponse["message"].get<std::string>().find("not elapsed") != std::string::npos);
}

// Test: query check_integrity when interval elapsed (first check)
TEST_F(SCARecoveryTest, QueryCheckIntegrityFirstCheck)
{
    initSyncProtocolWithInterval(std::chrono::seconds(3600));

    // Mock getLastIntegrityCheckTime to return 0 (first check)
    EXPECT_CALL(*m_mockDBSync, selectRows(::testing::_, ::testing::_))
    .WillOnce(::testing::Return());  // No metadata, returns 0

    // Mock updateLastIntegrityCheckTime
    EXPECT_CALL(*m_mockDBSync, handle())
    .WillRepeatedly(::testing::Return(reinterpret_cast<DBSYNC_HANDLE>(0x1)));

    std::string response = m_sca->query(R"({"command":"check_integrity"})");

    // Parse JSON response
    nlohmann::json jsonResponse = nlohmann::json::parse(response);

    // First check should defer (return false), so interval not elapsed
    EXPECT_EQ(jsonResponse["error"], 0);
    EXPECT_EQ(jsonResponse["data"]["recovery_performed"], false);

    // Should log first integrity check message
    EXPECT_TRUE(m_logOutput.find("First integrity check") != std::string::npos);
}

// Test: query check_integrity with disabled interval (0)
TEST_F(SCARecoveryTest, QueryCheckIntegrityDisabled)
{
    initSyncProtocolWithInterval(std::chrono::seconds(0));  // Disabled

    std::string response = m_sca->query(R"({"command":"check_integrity"})");

    // Parse JSON response
    nlohmann::json jsonResponse = nlohmann::json::parse(response);

    // Should return "not elapsed" since checks are disabled
    EXPECT_EQ(jsonResponse["error"], 0);
    EXPECT_EQ(jsonResponse["data"]["recovery_performed"], false);
}

// Test: query command with unknown command returns error
TEST_F(SCARecoveryTest, QueryUnknownCommandReturnsError)
{
    std::string response = m_sca->query(R"({"command":"unknown_command"})");

    nlohmann::json jsonResponse = nlohmann::json::parse(response);

    EXPECT_EQ(jsonResponse["error"], 1);  // MQ_ERR_UNKNOWN_COMMAND
    EXPECT_TRUE(jsonResponse["message"].get<std::string>().find("Unknown") != std::string::npos);
}

// Test: query command with malformed JSON
TEST_F(SCARecoveryTest, QueryMalformedJSONReturnsError)
{
    std::string response = m_sca->query("not valid json");

    nlohmann::json jsonResponse = nlohmann::json::parse(response);

    EXPECT_EQ(jsonResponse["error"], 98);  // MQ_ERR_INTERNAL
    EXPECT_TRUE(jsonResponse["message"].get<std::string>().find("Exception") != std::string::npos);
}

// Test: query command without command field
TEST_F(SCARecoveryTest, QueryMissingCommandField)
{
    std::string response = m_sca->query(R"({"data":"value"})");

    nlohmann::json jsonResponse = nlohmann::json::parse(response);

    EXPECT_EQ(jsonResponse["error"], 3);  // MQ_ERR_INVALID_PARAMS
    EXPECT_TRUE(jsonResponse["message"].get<std::string>().find("Missing") != std::string::npos);
}

// Test: existing pause command still works
TEST_F(SCARecoveryTest, QueryPauseCommand)
{
    std::string response = m_sca->query(R"({"command":"pause"})");

    nlohmann::json jsonResponse = nlohmann::json::parse(response);

    EXPECT_EQ(jsonResponse["error"], 0);
    EXPECT_EQ(jsonResponse["data"]["action"], "pause");
}

// Test: existing resume command still works
TEST_F(SCARecoveryTest, QueryResumeCommand)
{
    std::string response = m_sca->query(R"({"command":"resume"})");

    nlohmann::json jsonResponse = nlohmann::json::parse(response);

    EXPECT_EQ(jsonResponse["error"], 0);
    EXPECT_EQ(jsonResponse["data"]["action"], "resume");
}

// Test: existing get_version command still works
TEST_F(SCARecoveryTest, QueryGetVersionCommand)
{
    // Mock getMaxVersion
    EXPECT_CALL(*m_mockDBSync, selectRows(::testing::_, ::testing::_))
    .WillOnce(::testing::Invoke([](const nlohmann::json& /* query */,
                                   std::function<void(ReturnTypeCallback, const nlohmann::json&)> callback)
    {
        nlohmann::json data;
        data["max_version"] = 5;
        callback(SELECTED, data);
    }));

    std::string response = m_sca->query(R"({"command":"get_version"})");

    nlohmann::json jsonResponse = nlohmann::json::parse(response);

    EXPECT_EQ(jsonResponse["error"], 0);
    EXPECT_EQ(jsonResponse["data"]["version"], 5);
}

// Test: check_integrity with empty checksum (error case)
TEST_F(SCARecoveryTest, QueryCheckIntegrityEmptyChecksum)
{
    initSyncProtocolWithInterval(std::chrono::seconds(3600));

    int64_t oldTime = Utils::getSecondsFromEpoch() - 7200;  // 2 hours ago

    // Mock getLastIntegrityCheckTime to trigger check
    EXPECT_CALL(*m_mockDBSync, selectRows(::testing::_, ::testing::_))
    .WillOnce(::testing::Invoke([oldTime](const nlohmann::json& /* query */,
                                          std::function<void(ReturnTypeCallback, const nlohmann::json&)> callback)
    {
        nlohmann::json data;
        data["value"] = oldTime;
        callback(SELECTED, data);
    }))
    // Mock updateLastIntegrityCheckTime
    .WillRepeatedly(::testing::Return());

    // Mock concatenated checksums to throw error
    EXPECT_CALL(*m_mockDBSync, getConcatenatedChecksums(::testing::_, ::testing::_))
    .WillOnce(::testing::Throw(std::runtime_error("DB error")));

    std::string response = m_sca->query(R"({"command":"check_integrity"})");

    nlohmann::json jsonResponse = nlohmann::json::parse(response);

    // Should return error when checksum calculation fails
    EXPECT_EQ(jsonResponse["error"], 1);
    EXPECT_EQ(jsonResponse["data"]["recovery_performed"], false);
    EXPECT_TRUE(jsonResponse["message"].get<std::string>().find("Failed to calculate") != std::string::npos);
}

// Test: Configuration flow - setting integrity interval works
TEST_F(SCARecoveryTest, IntegrityIntervalConfiguration)
{
    // Test various intervals
    std::vector<int> intervals = {0, 60, 3600, 86400};

    for (int interval : intervals)
    {
        m_logOutput.clear();
        initSyncProtocolWithInterval(std::chrono::seconds(interval));

        // Verify logged correctly
        EXPECT_TRUE(m_logOutput.find(std::to_string(interval)) != std::string::npos);
    }
}

// Test: Recovery methods work together (integration test via query)
TEST_F(SCARecoveryTest, QueryCheckIntegrityIntegrationFlow)
{
    initSyncProtocolWithInterval(std::chrono::seconds(60));  // 1 minute for testing

    // Simulate old last check time (2 minutes ago) to trigger check
    int64_t oldTime = Utils::getSecondsFromEpoch() - 120;

    // Setup mock expectations for the full flow
    EXPECT_CALL(*m_mockDBSync, selectRows(::testing::_, ::testing::_))
    // 1. getLastIntegrityCheckTime - return old time
    .WillOnce(::testing::Invoke([oldTime](const nlohmann::json& /* query */,
                                          std::function<void(ReturnTypeCallback, const nlohmann::json&)> callback)
    {
        nlohmann::json data;
        data["value"] = oldTime;
        callback(SELECTED, data);
    }))
    // 2. Any subsequent calls (updateLastIntegrityCheckTime, etc.)
    .WillRepeatedly(::testing::Return());

    // Mock concatenated checksums (used to calculate table checksum)
    EXPECT_CALL(*m_mockDBSync, getConcatenatedChecksums(::testing::_, ::testing::_))
    .WillOnce(::testing::Return("abc123def456"));

    std::string response = m_sca->query(R"({"command":"check_integrity"})");

    // Should get valid JSON response
    EXPECT_NO_THROW(
    {
        nlohmann::json jsonResponse = nlohmann::json::parse(response);
        EXPECT_EQ(jsonResponse["data"]["module"], "sca");
        EXPECT_EQ(jsonResponse["data"]["action"], "check_integrity");
    });

    // Log should show integrity check was attempted
    EXPECT_TRUE(m_logOutput.find("Integrity interval elapsed") != std::string::npos ||
                m_logOutput.find("Checking with manager") != std::string::npos);
}

// Test: Verify JSON response structure for check_integrity
TEST_F(SCARecoveryTest, CheckIntegrityResponseStructure)
{
    initSyncProtocolWithInterval(std::chrono::seconds(0));  // Disabled for simple test

    std::string response = m_sca->query(R"({"command":"check_integrity"})");

    nlohmann::json jsonResponse = nlohmann::json::parse(response);

    // Verify response has required fields
    EXPECT_TRUE(jsonResponse.contains("error"));
    EXPECT_TRUE(jsonResponse.contains("message"));
    EXPECT_TRUE(jsonResponse.contains("data"));
    EXPECT_TRUE(jsonResponse["data"].contains("module"));
    EXPECT_TRUE(jsonResponse["data"].contains("action"));
    EXPECT_TRUE(jsonResponse["data"].contains("recovery_performed"));

    // Verify values
    EXPECT_EQ(jsonResponse["data"]["module"], "sca");
    EXPECT_EQ(jsonResponse["data"]["action"], "check_integrity");
}
