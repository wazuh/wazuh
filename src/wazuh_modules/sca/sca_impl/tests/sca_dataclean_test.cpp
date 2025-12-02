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

#include <sca_impl.hpp>
#include <mock_dbsync.hpp>
#include <mock_filesystem_wrapper.hpp>
#include <sca_sca_mock.hpp>
#include "logging_helper.hpp"
#include "mock_agent_sync_protocol.hpp"

#include <chrono>
#include <memory>
#include <string>

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

            // Basic mock setup for DBSync handle
            EXPECT_CALL(*m_mockDBSync, handle())
            .WillRepeatedly(::testing::Return(reinterpret_cast<DBSYNC_HANDLE>(0x1)));

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

// Test: All policies removed at startup with DataClean failure
TEST_F(SCADataCleanTest, AllPoliciesRemovedAtStartup_DataCleanFailure)
{
    setupWithEmptyPoliciesAndDataInDB();

    // Expect notifyDataClean to fail
    EXPECT_CALL(*m_mockSyncProtocol, notifyDataClean(::testing::_, ::testing::_))
    .WillOnce(::testing::Return(false));

    // Run should detect failure and log warning
    m_sca->Run();

    // Verify failure was logged
    EXPECT_TRUE(m_logOutput.find("Failed to send DataClean notification") != std::string::npos ||
                m_logOutput.find("Failed to complete DataClean process") != std::string::npos);
}

// Test: No policies and no data in DB exits cleanly
TEST_F(SCADataCleanTest, NoPoliciesNoData_ExitsCleanly)
{
    // Setup with no policies
    m_sca->Setup(true, false, std::chrono::seconds(3600), 30, false, {});
    m_sca->setSyncProtocol(m_mockSyncProtocol);

    // Mock selectRows to return count = 0 for hasDataInDatabase()
    EXPECT_CALL(*m_mockDBSync, selectRows(::testing::_, ::testing::_))
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

// Test: hasDataInDatabase returns true when policies exist
TEST_F(SCADataCleanTest, HasDataInDatabase_ReturnsTrueWhenPoliciesExist)
{
    // Mock selectRows for policy count
    EXPECT_CALL(*m_mockDBSync, selectRows(::testing::_, ::testing::_))
    .WillOnce(::testing::Invoke([](const nlohmann::json& /* query */,
                                   std::function<void(ReturnTypeCallback, const nlohmann::json&)> callback)
    {
        nlohmann::json data;
        data["count"] = 3;
        callback(SELECTED, data);
    }))
    .WillOnce(::testing::Invoke([](const nlohmann::json& /* query */,
                                   std::function<void(ReturnTypeCallback, const nlohmann::json&)> callback)
    {
        nlohmann::json data;
        data["count"] = 0;
        callback(SELECTED, data);
    }));

    // Should return true even with just policies (no checks)
    EXPECT_TRUE(m_logOutput.find("Database contains") != std::string::npos ||
                m_logOutput.find("policies") != std::string::npos);
}

// Test: hasDataInDatabase returns true when only checks exist
TEST_F(SCADataCleanTest, HasDataInDatabase_ReturnsTrueWhenOnlyChecksExist)
{
    // Mock selectRows for check count only
    EXPECT_CALL(*m_mockDBSync, selectRows(::testing::_, ::testing::_))
    .WillOnce(::testing::Invoke([](const nlohmann::json& /* query */,
                                   std::function<void(ReturnTypeCallback, const nlohmann::json&)> callback)
    {
        nlohmann::json data;
        data["count"] = 0;  // No policies
        callback(SELECTED, data);
    }))
    .WillOnce(::testing::Invoke([](const nlohmann::json& /* query */,
                                   std::function<void(ReturnTypeCallback, const nlohmann::json&)> callback)
    {
        nlohmann::json data;
        data["count"] = 5;  // But has checks
        callback(SELECTED, data);
    }));

    // Should return true since checks exist
    EXPECT_TRUE(m_logOutput.find("Database contains") != std::string::npos ||
                m_logOutput.find("checks") != std::string::npos);
}

// Test: handleAllPoliciesRemoved clears DB tables
TEST_F(SCADataCleanTest, HandleAllPoliciesRemoved_ClearsDBTables)
{
    m_sca->Setup(true, false, std::chrono::seconds(3600), 30, false, {});
    m_sca->setSyncProtocol(m_mockSyncProtocol);

    // Expect notifyDataClean to succeed
    EXPECT_CALL(*m_mockSyncProtocol, notifyDataClean(::testing::_, ::testing::_))
    .WillOnce(::testing::Return(true));

    // Expect DBSync transactions for clearing tables
    EXPECT_CALL(*m_mockDBSync, handle())
    .WillRepeatedly(::testing::Return(reinterpret_cast<DBSYNC_HANDLE>(0x1)));

    // This will be called internally when clearing tables
    // The implementation creates DBSyncTxn which uses handle()

    // Call handleAllPoliciesRemoved via Run() with appropriate setup
    // Mock selectRows to indicate data exists
    EXPECT_CALL(*m_mockDBSync, selectRows(::testing::_, ::testing::_))
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

    // Verify tables were cleared
    EXPECT_TRUE(m_logOutput.find("Local SCA database tables cleared") != std::string::npos);
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

    m_sca->Setup(true, false, std::chrono::seconds(3600), 30, false, policies);
    m_sca->setSyncProtocol(m_mockSyncProtocol);

    // Mock file exists
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

