/*
 * Wazuh SCA
 * Copyright (C) 2015, Wazuh Inc.
 * December 1, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "logging_helper.hpp"
#include <mock_agent_sync_protocol.hpp>
#include <mock_dbsync.hpp>
#include <mock_filesystem_wrapper.hpp>
#include <sca_impl.hpp>
#include <sca_sca_mock.hpp>

#include <chrono>
#include <memory>
#include <string>
#include <thread>

/**
 * @brief Test fixture for SCA DataClean on Policy Removal functionality
 *
 * Tests the DataClean flow operations:
 * - All policies removed: DataClean + DB wipe + exit
 * - Partial policy removal: delete events + continue
 *
 * Issue Reference: #32183 - SCA Case: DataClean on Policy Removal
 */
class SCADataCleanTest : public ::testing::Test
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
            m_mockSyncProtocol = std::make_shared<MockAgentSyncProtocol>();

            // Basic mock setup for DBSync handle - return nullptr to skip actual DB operations in tests
            EXPECT_CALL(*m_mockDBSync, handle())
            .WillRepeatedly(::testing::Return(nullptr));

            m_sca = std::make_shared<SCAMock>(m_mockDBSync, m_mockFileSystem);
        }

        void TearDown() override
        {
            m_sca.reset();
            m_mockDBSync.reset();
            m_mockFileSystem.reset();
            m_mockSyncProtocol.reset();
        }

        // Helper to set up SCA with no policies but data in DB
        void setupWithEmptyPoliciesAndDataInDB()
        {
            // Setup with no policies
            m_sca->Setup(true, false, std::chrono::seconds(3600), 30, false, {});

            // Set sync protocol mock
            m_sca->setSyncProtocol(m_mockSyncProtocol);

            // Mock selectRows to return count > 0 for hasDataInDatabase()
            EXPECT_CALL(*m_mockDBSync, selectRows(::testing::_, ::testing::_))
            .WillOnce(::testing::Return()) // Sync manager initialization query
            .WillOnce(::testing::Invoke([](const nlohmann::json& /* query */,
                                           std::function<void(ReturnTypeCallback, const nlohmann::json&)> callback)
            {
                // Return policy count > 0
                nlohmann::json data;
                data["count"] = 5;
                callback(SELECTED, data);
            }))
            .WillOnce(::testing::Invoke([](const nlohmann::json& /* query */,
                                           std::function<void(ReturnTypeCallback, const nlohmann::json&)> callback)
            {
                // Return check count > 0
                nlohmann::json data;
                data["count"] = 10;
                callback(SELECTED, data);
            }))
            .WillRepeatedly(::testing::Return());
        }

        // Helper to set up SCA with policies and empty DB
        void setupWithPoliciesAndEmptyDB()
        {
            std::vector<sca::PolicyData> policies =
            {
                {"policy1.yaml", true, false}
            };

            m_sca->Setup(true, false, std::chrono::seconds(3600), 30, false, policies);
            m_sca->setSyncProtocol(m_mockSyncProtocol);

            // Mock selectRows to return count = 0 for hasDataInDatabase()
            EXPECT_CALL(*m_mockDBSync, selectRows(::testing::_, ::testing::_))
            .WillOnce(::testing::Return()) // Sync manager initialization query
            .WillRepeatedly(::testing::Invoke([](const nlohmann::json& /* query */,
                                                 std::function<void(ReturnTypeCallback, const nlohmann::json&)> callback)
            {
                nlohmann::json data;
                data["count"] = 0;
                callback(SELECTED, data);
            }));
        }

        std::shared_ptr<MockDBSync> m_mockDBSync;
        std::shared_ptr<MockFileSystemWrapper> m_mockFileSystem;
        std::shared_ptr<MockAgentSyncProtocol> m_mockSyncProtocol;
        std::shared_ptr<SCAMock> m_sca;
        std::string m_logOutput;
};

// Test: All policies removed at startup triggers DataClean
TEST_F(SCADataCleanTest, AllPoliciesRemovedAtStartup_TriggersDataClean)
{
    setupWithEmptyPoliciesAndDataInDB();

    // Expect notifyDataClean to be called with SCA index
    EXPECT_CALL(*m_mockSyncProtocol, notifyDataClean(::testing::_, ::testing::_))
    .WillOnce(::testing::Return(true));

    // Run should detect no policies + data in DB and trigger DataClean
    m_sca->Run();

    // Verify DataClean was logged
    EXPECT_TRUE(m_logOutput.find("All SCA policies removed from configuration") != std::string::npos);
    EXPECT_TRUE(m_logOutput.find("DataClean notification sent successfully") != std::string::npos);
    EXPECT_TRUE(m_logOutput.find("SCA module exiting") != std::string::npos);
}

// Test: All policies removed at startup with DataClean failure triggers retry
TEST_F(SCADataCleanTest, AllPoliciesRemovedAtStartup_DataCleanFailure_Retries)
{
    // Setup with short scan interval (1 second) for fast retry
    m_sca->Setup(true, false, std::chrono::seconds(1), 30, false, {});
    m_sca->setSyncProtocol(m_mockSyncProtocol);

    // Mock selectRows to return count > 0 for hasDataInDatabase()
    EXPECT_CALL(*m_mockDBSync, selectRows(::testing::_, ::testing::_))
    .WillOnce(::testing::Return()) // Sync manager initialization query
    .WillOnce(::testing::Invoke([](const nlohmann::json& /* query */,
                                   std::function<void(ReturnTypeCallback, const nlohmann::json&)> callback)
    {
        nlohmann::json data;
        data["count"] = 5;
        callback(SELECTED, data);
    }))
    .WillOnce(::testing::Invoke([](const nlohmann::json& /* query */,
                                   std::function<void(ReturnTypeCallback, const nlohmann::json&)> callback)
    {
        nlohmann::json data;
        data["count"] = 5;
        callback(SELECTED, data);
    }));

    // Expect notifyDataClean to fail on first call, retry will trigger,
    // then second call stops the module to exit the retry loop
    EXPECT_CALL(*m_mockSyncProtocol, notifyDataClean(::testing::_, ::testing::_))
    .WillOnce(::testing::Return(false))  // First call fails
    .WillOnce(::testing::Invoke([this](const std::vector<std::string>&, Option) -> bool
    {
        // Stop the module on retry to exit the loop
        m_sca->Stop();
        return false;
    }));

    // Run should detect failure and enter retry loop, then exit when Stop() is called on retry
    m_sca->Run();

    // Verify retry was attempted (debug log message)
    EXPECT_TRUE(m_logOutput.find("DataClean notification failed, retrying") != std::string::npos);
}

// Test: No policies and no data in DB exits cleanly
TEST_F(SCADataCleanTest, NoPoliciesNoData_ExitsCleanly)
{
    // Setup with no policies
    m_sca->Setup(true, false, std::chrono::seconds(3600), 30, false, {});
    m_sca->setSyncProtocol(m_mockSyncProtocol);

    // Mock selectRows to return count = 0 for hasDataInDatabase()
    EXPECT_CALL(*m_mockDBSync, selectRows(::testing::_, ::testing::_))
    .WillOnce(::testing::Return()) // Sync manager initialization query
    .WillOnce(::testing::Invoke([](const nlohmann::json& /* query */,
                                   std::function<void(ReturnTypeCallback, const nlohmann::json&)> callback)
    {
        nlohmann::json data;
        data["count"] = 0;
        callback(SELECTED, data);
    }))
    .WillOnce(::testing::Invoke([](const nlohmann::json& /* query */,
                                   std::function<void(ReturnTypeCallback, const nlohmann::json&)> callback)
    {
        nlohmann::json data;
        data["count"] = 0;
        callback(SELECTED, data);
    }));

    // DataClean should NOT be called since there's no data
    EXPECT_CALL(*m_mockSyncProtocol, notifyDataClean(::testing::_, ::testing::_))
    .Times(0);

    m_sca->Run();

    // Should exit cleanly with "nothing to scan" message
    EXPECT_TRUE(m_logOutput.find("No enabled policies configured") != std::string::npos);
}

// Test: handleAllPoliciesRemoved sends DataClean and exits
TEST_F(SCADataCleanTest, HandleAllPoliciesRemoved_SendsDataCleanAndExits)
{
    m_sca->Setup(true, false, std::chrono::seconds(3600), 30, false, {});
    m_sca->setSyncProtocol(m_mockSyncProtocol);

    // Expect notifyDataClean to succeed
    EXPECT_CALL(*m_mockSyncProtocol, notifyDataClean(::testing::_, ::testing::_))
    .WillOnce(::testing::Return(true));

    // Mock selectRows to indicate data exists
    EXPECT_CALL(*m_mockDBSync, selectRows(::testing::_, ::testing::_))
    .WillOnce(::testing::Return()) // Sync manager initialization query
    .WillOnce(::testing::Invoke([](const nlohmann::json& /* query */,
                                   std::function<void(ReturnTypeCallback, const nlohmann::json&)> callback)
    {
        nlohmann::json data;
        data["count"] = 1;
        callback(SELECTED, data);
    }))
    .WillOnce(::testing::Invoke([](const nlohmann::json& /* query */,
                                   std::function<void(ReturnTypeCallback, const nlohmann::json&)> callback)
    {
        nlohmann::json data;
        data["count"] = 1;
        callback(SELECTED, data);
    }))
    .WillRepeatedly(::testing::Return());

    m_sca->Run();

    // Verify DataClean was sent (DB clearing skipped with null handle in tests)
    EXPECT_TRUE(m_logOutput.find("DataClean notification sent successfully") != std::string::npos);
}

// Test: Module disabled does not trigger DataClean
TEST_F(SCADataCleanTest, ModuleDisabled_DoesNotTriggerDataClean)
{
    // Setup with disabled module
    m_sca->Setup(false, false, std::chrono::seconds(3600), 30, false, {});
    m_sca->setSyncProtocol(m_mockSyncProtocol);

    // DataClean should NOT be called for disabled module
    EXPECT_CALL(*m_mockSyncProtocol, notifyDataClean(::testing::_, ::testing::_))
    .Times(0);

    m_sca->Run();

    // Should log disabled message
    EXPECT_TRUE(m_logOutput.find("SCA module is disabled") != std::string::npos);
}

// Test: Partial policy removal (some policies deleted)
// This test verifies that when some policies are removed, the existing
// SyncPoliciesAndReportDelta flow generates delete events
TEST_F(SCADataCleanTest, PartialPolicyRemoval_GeneratesDeleteEvents)
{
    // This test is more of an integration test since partial removal
    // is handled by the existing DBSync comparison in SCAPolicyLoader.
    // The key behavior is:
    // 1. SCAPolicyLoader loads policies from config
    // 2. SyncWithDBSync compares with DB
    // 3. getDeletedRows returns policies/checks not in config
    // 4. ReportPoliciesDelta generates delete events

    // For unit testing, we verify that when policies are present,
    // the normal flow continues (no DataClean triggered)

    std::vector<sca::PolicyData> policies =
    {
        {"policy1.yaml", true, false}
    };

    m_sca->Setup(true, true, std::chrono::seconds(3600), 30, false, policies);
    m_sca->setSyncProtocol(m_mockSyncProtocol);

    // Mock file exists - scanOnStart=true so we reach this immediately
    EXPECT_CALL(*m_mockFileSystem, exists(::testing::_))
    .WillRepeatedly(::testing::Invoke([this](const std::filesystem::path&) -> bool
    {
        // Stop module to prevent infinite loop
        m_sca->Stop();
        return false;  // File doesn't exist, so no policy loads
    }));

    // DataClean should NOT be called since we have policies configured
    EXPECT_CALL(*m_mockSyncProtocol, notifyDataClean(::testing::_, ::testing::_))
    .Times(0);

    m_sca->Run();

    // Should NOT trigger DataClean flow
    EXPECT_TRUE(m_logOutput.find("All SCA policies removed") == std::string::npos);
}

// Test: Verify exit flag is set after DataClean
TEST_F(SCADataCleanTest, DataCleanSetsExitFlag)
{
    setupWithEmptyPoliciesAndDataInDB();

    EXPECT_CALL(*m_mockSyncProtocol, notifyDataClean(::testing::_, ::testing::_))
    .WillOnce(::testing::Return(true));

    m_sca->Run();

    // Verify the module exited (Run() returned after DataClean)
    EXPECT_TRUE(m_logOutput.find("SCA module exiting") != std::string::npos);
}

// Test: DataClean with sync protocol not initialized
TEST_F(SCADataCleanTest, DataClean_WithoutSyncProtocol_Fails)
{
    // Setup without setting sync protocol
    m_sca->Setup(true, false, std::chrono::seconds(3600), 30, false, {});
    // Don't set sync protocol: m_sca->setSyncProtocol(m_mockSyncProtocol);

    // Mock selectRows to indicate data exists
    EXPECT_CALL(*m_mockDBSync, selectRows(::testing::_, ::testing::_))
    .WillOnce(::testing::Return()) // Sync manager initialization query
    .WillOnce(::testing::Invoke([](const nlohmann::json& /* query */,
                                   std::function<void(ReturnTypeCallback, const nlohmann::json&)> callback)
    {
        nlohmann::json data;
        data["count"] = 1;
        callback(SELECTED, data);
    }))
    .WillOnce(::testing::Invoke([](const nlohmann::json& /* query */,
                                   std::function<void(ReturnTypeCallback, const nlohmann::json&)> callback)
    {
        nlohmann::json data;
        data["count"] = 1;
        callback(SELECTED, data);
    }));

    m_sca->Run();

    // Should fail with appropriate error
    EXPECT_TRUE(m_logOutput.find("Sync protocol not initialized") != std::string::npos);
}

// Test: DataClean waits for sync in progress to complete
TEST_F(SCADataCleanTest, DataClean_WaitsForSyncInProgress)
{
    // Setup with no policies but data in DB
    m_sca->Setup(true, false, std::chrono::seconds(3600), 30, false, {});
    m_sca->setSyncProtocol(m_mockSyncProtocol);

    // Set sync as in progress
    m_sca->setSyncInProgress(true);

    // Mock selectRows to indicate data exists
    EXPECT_CALL(*m_mockDBSync, selectRows(::testing::_, ::testing::_))
    .WillOnce(::testing::Return()) // Sync manager initialization query
    .WillOnce(::testing::Invoke(
                  [](const nlohmann::json& /* query */,
                     std::function<void(ReturnTypeCallback, const nlohmann::json&)> callback)
    {
        nlohmann::json data;
        data["count"] = 1;
        callback(SELECTED, data);
    }))
    .WillOnce(::testing::Invoke(
                  [](const nlohmann::json& /* query */,
                     std::function<void(ReturnTypeCallback, const nlohmann::json&)> callback)
    {
        nlohmann::json data;
        data["count"] = 1;
        callback(SELECTED, data);
    }))
    .WillRepeatedly(::testing::Return());

    // Expect DataClean to be called after sync completes
    EXPECT_CALL(*m_mockSyncProtocol, notifyDataClean(::testing::_, ::testing::_)).WillOnce(::testing::Return(true));

    // Start Run() in a separate thread since it will block waiting for sync
    std::thread runThread([this]()
    {
        m_sca->Run();
    });

    // Give Run() time to start and reach the wait
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Simulate sync completion
    m_sca->notifySyncComplete();

    // Wait for Run() to complete
    runThread.join();

    // Verify it waited for sync and then proceeded
    EXPECT_TRUE(m_logOutput.find("Waiting for sync to complete before DataClean") != std::string::npos);
    EXPECT_TRUE(m_logOutput.find("Proceeding with DataClean") != std::string::npos);
    EXPECT_TRUE(m_logOutput.find("DataClean notification sent successfully") != std::string::npos);
}
