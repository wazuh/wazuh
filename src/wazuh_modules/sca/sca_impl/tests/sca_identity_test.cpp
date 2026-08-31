/*
 * Wazuh SCA
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// #38601: an agent deleted on the manager re-enrolls under a new id while its local database --
// first_sync_completed included -- survives untouched, so every later cycle sends a delta against
// a baseline the manager no longer has for this identity. These cases pin the decision procedure
// that repairs it, and in particular the two ways it must NOT fire: an unknown id, and a database
// that has never recorded one (which is every agent on the first cycle after an upgrade).

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "logging_helper.hpp"
#include <metadata_provider.h>
#include <mock_agent_sync_protocol.hpp>
#include <mock_dbsync.hpp>
#include <mock_filesystem_wrapper.hpp>
#include <sca_impl.hpp>
#include <sca_sca_mock.hpp>

#include <chrono>
#include <filesystem>
#include <memory>
#include <string>

namespace
{
    constexpr auto SYNCED_AGENT_ID_KEY {"synced_agent_id"};
    constexpr auto FIRST_SYNC_COMPLETED_KEY {"first_sync_completed"};
}

class SCAIdentityTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            m_logOutput.clear();

            // The provider is a file, and other test binaries in this tree write it too.
            // Own directory per binary: the provider is a file at a path relative to the working
            // directory, and other SCA test binaries in this tree write the same one, so sharing
            // it makes both flaky under a parallel ctest.
            std::filesystem::create_directories("sca_identity_test/var/run");
            std::filesystem::current_path("sca_identity_test");
            metadata_provider_reset();

            LoggingHelper::setLogCallback([this](const modules_log_level_t /* level */, const std::string & log)
            {
                m_logOutput += log + "\n";
            });

            m_mockDBSync = std::make_shared<MockDBSync>();
            m_mockFileSystem = std::make_shared<MockFileSystemWrapper>();
            m_mockSyncProtocol = std::make_shared<MockAgentSyncProtocol>();

            EXPECT_CALL(*m_mockDBSync, handle()).WillRepeatedly(::testing::Return(nullptr));

            m_sca = std::make_shared<SCAMock>(m_mockDBSync, m_mockFileSystem);
            m_sca->setSyncProtocol(m_mockSyncProtocol);
            // syncModule() answers immediately unless the module is paused -- that is how
            // agent-info drives a coordinated sync, and it is the state these cases exercise.
            m_sca->pause();
        }

        void TearDown() override
        {
            metadata_provider_reset();
            std::filesystem::current_path("..");
            m_sca.reset();
            m_mockDBSync.reset();
            m_mockFileSystem.reset();
            m_mockSyncProtocol.reset();
        }

        /// Publishes an agent id, the way agentd does after enrolling.
        static void publishAgentId(const char* agentId)
        {
            agent_metadata_t metadata = {};
            strncpy(metadata.agent_id, agentId, sizeof(metadata.agent_id) - 1);
            strncpy(metadata.agent_name, "test-agent", sizeof(metadata.agent_name) - 1);
            metadata_provider_update(&metadata);
        }

        /// Answers sca_metadata lookups per key, since the real getMetadataValue() filters in
        /// SQL and a mock that ignores the query would hand every key the same row.
        void expectMetadata(int64_t syncedAgentId, int64_t firstSyncCompleted)
        {
            EXPECT_CALL(*m_mockDBSync, selectRows(::testing::_, ::testing::_))
            .WillRepeatedly(::testing::Invoke(
                                [syncedAgentId, firstSyncCompleted](const nlohmann::json & query,
                                                                    std::function<void(ReturnTypeCallback, const nlohmann::json&)> callback)
            {
                const auto queryText = query.dump();

                if (queryText.find(SYNCED_AGENT_ID_KEY) != std::string::npos)
                {
                    if (syncedAgentId != 0)
                    {
                        callback(SELECTED, nlohmann::json {{"value", syncedAgentId}});
                    }
                }
                else if (queryText.find(FIRST_SYNC_COMPLETED_KEY) != std::string::npos)
                {
                    if (firstSyncCompleted != 0)
                    {
                        callback(SELECTED, nlohmann::json {{"value", firstSyncCompleted}});
                    }
                }
            }));
        }

        std::shared_ptr<MockDBSync> m_mockDBSync;
        std::shared_ptr<MockFileSystemWrapper> m_mockFileSystem;
        std::shared_ptr<MockAgentSyncProtocol> m_mockSyncProtocol;
        std::shared_ptr<SCAMock> m_sca;
        std::string m_logOutput;
};

// The marker has never been recorded -- every agent on its first cycle after an upgrade. It must
// be adopted in silence: if this resynced instead, upgrading a fleet in place would have every
// agent send its whole database at once.
TEST_F(SCAIdentityTest, MarkerAbsentIsAdoptedWithoutResyncing)
{
    publishAgentId("001");
    expectMetadata(/* syncedAgentId */ 0, /* firstSyncCompleted */ 123456);

    // A resync would have to clear the manager's index first.
    EXPECT_CALL(*m_mockSyncProtocol, notifyDataClean(::testing::_, ::testing::_)).Times(0);
    EXPECT_CALL(*m_mockSyncProtocol, synchronizeModule(::testing::_, ::testing::_))
    .WillOnce(::testing::Return(SyncModuleResult {true, {}}));

    m_sca->syncModule(Mode::DELTA);

    EXPECT_EQ(m_logOutput.find("now running as agent"), std::string::npos);
}

// The id is unchanged: the steady state, and also what a re-enrollment that hands back the SAME id
// looks like. That is the common case -- a key rotation, an authd password change, any 401 that is
// not a deletion -- so treating it as a change would resync the whole fleet on every credential
// refresh.
TEST_F(SCAIdentityTest, UnchangedIdIsANoOp)
{
    publishAgentId("007");
    expectMetadata(/* syncedAgentId */ 7, /* firstSyncCompleted */ 123456);

    EXPECT_CALL(*m_mockSyncProtocol, notifyDataClean(::testing::_, ::testing::_)).Times(0);
    EXPECT_CALL(*m_mockSyncProtocol, synchronizeModule(::testing::_, ::testing::_))
    .WillOnce(::testing::Return(SyncModuleResult {true, {}}));

    m_sca->syncModule(Mode::DELTA);

    EXPECT_EQ(m_logOutput.find("now running as agent"), std::string::npos);
}

// The provider has published nothing yet. "Unknown" must never read as "changed": an agent whose
// metadata has not been published would otherwise resync on every cycle.
TEST_F(SCAIdentityTest, UnknownIdIsANoOp)
{
    // No publishAgentId() here -- the provider was reset in SetUp().
    expectMetadata(/* syncedAgentId */ 7, /* firstSyncCompleted */ 123456);

    EXPECT_CALL(*m_mockSyncProtocol, notifyDataClean(::testing::_, ::testing::_)).Times(0);
    EXPECT_CALL(*m_mockSyncProtocol, synchronizeModule(::testing::_, ::testing::_))
    .WillOnce(::testing::Return(SyncModuleResult {true, {}}));

    m_sca->syncModule(Mode::DELTA);

    EXPECT_EQ(m_logOutput.find("now running as agent"), std::string::npos);
}

// The id changed: the manager holds nothing under the new identity, so the whole database goes
// again -- which starts by clearing the index.
TEST_F(SCAIdentityTest, ChangedIdClearsTheIndexAndResends)
{
    publishAgentId("002");
    expectMetadata(/* syncedAgentId */ 1, /* firstSyncCompleted */ 123456);

    EXPECT_CALL(*m_mockSyncProtocol, notifyDataClean(::testing::_, ::testing::_))
    .WillOnce(::testing::Return(true));
    EXPECT_CALL(*m_mockSyncProtocol, synchronizeModule(::testing::_, ::testing::_))
    .WillRepeatedly(::testing::Return(SyncModuleResult {true, {}}));

    m_sca->syncModule(Mode::DELTA);

    EXPECT_NE(m_logOutput.find("last synchronized as agent 1, now running as agent 2"), std::string::npos);
}

// The manager refused the DataClean. Nothing is recorded, so the next cycle tries again -- the
// alternative would be marking the new identity as synchronized when the manager never took the
// data.
TEST_F(SCAIdentityTest, FailedDataCleanRecordsNothing)
{
    publishAgentId("002");
    expectMetadata(/* syncedAgentId */ 1, /* firstSyncCompleted */ 123456);

    EXPECT_CALL(*m_mockSyncProtocol, notifyDataClean(::testing::_, ::testing::_))
    .WillOnce(::testing::Return(false));

    EXPECT_CALL(*m_mockSyncProtocol, synchronizeModule(::testing::_, ::testing::_))
    .WillRepeatedly(::testing::Return(SyncModuleResult {true, {}}));

    m_sca->syncModule(Mode::DELTA);

    EXPECT_NE(m_logOutput.find("Failed to clear SCA index"), std::string::npos);
}
