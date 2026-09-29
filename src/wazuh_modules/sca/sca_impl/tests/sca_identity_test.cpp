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

#include <atomic>
#include <chrono>
#include <filesystem>
#include <future>
#include <memory>
#include <mutex>
#include <stdexcept>
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

            // Locked: the shutdown cases log from the test thread and a woken worker at once.
            LoggingHelper::setLogCallback([this](const modules_log_level_t /* level */, const std::string & log)
            {
                std::lock_guard<std::mutex> lock(m_logMutex);
                m_logOutput += log + "\n";
            });

            m_mockDBSync = std::make_shared<MockDBSync>();
            m_mockFileSystem = std::make_shared<MockFileSystemWrapper>();
            m_mockSyncProtocol = std::make_shared<MockAgentSyncProtocol>();

            EXPECT_CALL(*m_mockDBSync, handle()).WillRepeatedly(::testing::Return(nullptr));

            m_sca = std::make_shared<SCAMock>(m_mockDBSync, m_mockFileSystem);
            m_sca->setSyncProtocol(m_mockSyncProtocol);
            // As once Run() is past its initialization, which is when the sync thread may act.
            m_sca->setRunInitializedForTest(true);
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

        /// Waits for a flush started on another thread. On a timeout, stops the module so the
        /// waiting flush returns: a failed assertion must fail the test, not hang it in ~future.
        bool finished(std::future<int>& flush)
        {
            if (flush.wait_for(std::chrono::seconds(5)) == std::future_status::ready)
            {
                return true;
            }

            m_sca->quiesce();
            return false;
        }

        /// Same for a DataClean started on another thread. Its retry wait is woken without the
        /// mutex it waits on, so quiesce() is repeated until it returns.
        bool finished(std::future<bool>& dataClean)
        {
            if (dataClean.wait_for(std::chrono::seconds(5)) == std::future_status::ready)
            {
                return true;
            }

            for (int i = 0; i < 50 && dataClean.wait_for(std::chrono::milliseconds(100)) != std::future_status::ready; ++i)
            {
                m_sca->quiesce();
            }

            return false;
        }

        std::shared_ptr<MockDBSync> m_mockDBSync;
        std::shared_ptr<MockFileSystemWrapper> m_mockFileSystem;
        std::shared_ptr<MockAgentSyncProtocol> m_mockSyncProtocol;
        std::shared_ptr<SCAMock> m_sca;
        std::string m_logOutput;
        std::mutex m_logMutex;
};

// The marker has never been recorded -- every agent on its first cycle after an upgrade. It must
// be adopted in silence: if this resynced instead, upgrading a fleet in place would have every
// agent send its whole database at once.
TEST_F(SCAIdentityTest, MarkerAbsentIsAdoptedWithoutResyncing)
{
    publishAgentId("001");
    expectMetadata(/* syncedAgentId */ 0, /* firstSyncCompleted */ 123456);

    // A resync would have to clear the manager's index first.
    EXPECT_CALL(*m_mockSyncProtocol, notifyDataClean(::testing::_, ::testing::_, ::testing::_)).Times(0);
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

    EXPECT_CALL(*m_mockSyncProtocol, notifyDataClean(::testing::_, ::testing::_, ::testing::_)).Times(0);
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

    EXPECT_CALL(*m_mockSyncProtocol, notifyDataClean(::testing::_, ::testing::_, ::testing::_)).Times(0);
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

    EXPECT_CALL(*m_mockSyncProtocol, notifyDataClean(::testing::_, ::testing::_, ::testing::_))
    .WillOnce(::testing::Return(SyncModuleResult {true, {}}));
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

    EXPECT_CALL(*m_mockSyncProtocol, notifyDataClean(::testing::_, ::testing::_, ::testing::_))
    .WillOnce(::testing::Return(SyncModuleResult {false, {}}));

    EXPECT_CALL(*m_mockSyncProtocol, synchronizeModule(::testing::_, ::testing::_))
    .WillRepeatedly(::testing::Return(SyncModuleResult {true, {}}));

    m_sca->syncModule(Mode::DELTA);

    EXPECT_NE(m_logOutput.find("Failed to clear SCA index"), std::string::npos);
}

// get_identity_changed must answer exactly what checkAgentIdentity() would decide, without acting
// on it, so the sync thread can poll it safely.
static int queryIdentityChanged(SCAMock& sca)
{
    const auto response = nlohmann::json::parse(sca.query(R"({"command":"get_identity_changed"})"));
    EXPECT_EQ(response["error"], 0);
    return response["data"]["identity_changed"].get<int>();
}

TEST_F(SCAIdentityTest, IdentityChangedQueryReportsAChangedId)
{
    publishAgentId("002");
    expectMetadata(/* syncedAgentId */ 1, /* firstSyncCompleted */ 123456);

    // Reporting only: the resync itself stays on the syncModule() path.
    EXPECT_CALL(*m_mockSyncProtocol, notifyDataClean(::testing::_, ::testing::_, ::testing::_)).Times(0);

    EXPECT_EQ(queryIdentityChanged(*m_sca), 1);
}

TEST_F(SCAIdentityTest, IdentityChangedQueryIgnoresAnUnchangedId)
{
    publishAgentId("007");
    expectMetadata(/* syncedAgentId */ 7, /* firstSyncCompleted */ 123456);

    EXPECT_EQ(queryIdentityChanged(*m_sca), 0);
}

TEST_F(SCAIdentityTest, IdentityChangedQueryIgnoresAnUnknownId)
{
    // No publishAgentId() here -- the provider was reset in SetUp().
    expectMetadata(/* syncedAgentId */ 7, /* firstSyncCompleted */ 123456);

    // "Cannot tell", not "unchanged": the sync thread keeps its retry state on it.
    EXPECT_EQ(queryIdentityChanged(*m_sca), -1);
}

// An unrecorded marker is adopted by checkAgentIdentity(), never resynced, so it is not a change.
TEST_F(SCAIdentityTest, IdentityChangedQueryIgnoresAnAbsentMarker)
{
    publishAgentId("001");
    expectMetadata(/* syncedAgentId */ 0, /* firstSyncCompleted */ 123456);

    EXPECT_EQ(queryIdentityChanged(*m_sca), 0);
}

// Without a sync protocol syncModule() never reaches checkAgentIdentity(), so reporting the change
// would only make the sync thread wake for nothing every poll period.
TEST_F(SCAIdentityTest, IdentityChangedQueryIgnoresAChangeWithoutSyncProtocol)
{
    publishAgentId("002");
    expectMetadata(/* syncedAgentId */ 1, /* firstSyncCompleted */ 123456);
    m_sca->setSyncProtocol(nullptr);

    EXPECT_EQ(queryIdentityChanged(*m_sca), -1);
}

// The flush and the sync thread's resend never overlap: the resend's DataClean would otherwise
// clear the queue a flush session is still sending. While the flush sends, a sync skips.
TEST_F(SCAIdentityTest, SyncSkipsWhileAFlushSends)
{
    publishAgentId("007");
    expectMetadata(/* syncedAgentId */ 7, /* firstSyncCompleted */ 123456);

    bool syncedDuringFlush = true;

    EXPECT_CALL(*m_mockSyncProtocol, synchronizeModule(::testing::_, ::testing::_))
    .WillOnce(::testing::Invoke([this, &syncedDuringFlush](auto&& ...)
    {
        syncedDuringFlush = m_sca->syncModule(Mode::DELTA);
        return SyncModuleResult {true, {}};
    }));

    EXPECT_EQ(m_sca->callExecuteFlushSync(), 0);

    EXPECT_FALSE(syncedDuringFlush);
    EXPECT_NE(m_logOutput.find("SCA sync skipped - flush in progress"), std::string::npos);
}

// A flush that arrives while a resend is running waits for it instead of overlapping it.
TEST_F(SCAIdentityTest, FlushWaitsForASyncInProgressThenSends)
{
    publishAgentId("007");
    expectMetadata(/* syncedAgentId */ 7, /* firstSyncCompleted */ 123456);

    EXPECT_CALL(*m_mockSyncProtocol, synchronizeModule(::testing::_, ::testing::_))
    .WillOnce(::testing::Return(SyncModuleResult {true, {}}));

    m_sca->setSyncInProgress(true);

    auto flush = std::async(std::launch::async, [this] { return m_sca->callExecuteFlushSync(); });

    EXPECT_EQ(flush.wait_for(std::chrono::milliseconds(200)), std::future_status::timeout);

    m_sca->notifySyncComplete();

    ASSERT_TRUE(finished(flush));
    EXPECT_EQ(flush.get(), 0);
}

// If the module stops while the flush waits, it gives up without sending anything.
TEST_F(SCAIdentityTest, FlushWaitingForASyncGivesUpOnShutdown)
{
    EXPECT_CALL(*m_mockSyncProtocol, synchronizeModule(::testing::_, ::testing::_)).Times(0);

    m_sca->setSyncInProgress(true);

    auto flush = std::async(std::launch::async, [this] { return m_sca->callExecuteFlushSync(); });

    EXPECT_EQ(flush.wait_for(std::chrono::milliseconds(200)), std::future_status::timeout);

    m_sca->quiesce();

    ASSERT_TRUE(finished(flush));
    EXPECT_EQ(flush.get(), -1);
    EXPECT_NE(m_logOutput.find("SCA flush aborted: the module is stopping"), std::string::npos);
}

// The flush hands its flag back on every path out: left set, every later synchronization would
// skip until the module restarts.
TEST_F(SCAIdentityTest, FlushClearsItsFlagWhenTheSessionThrows)
{
    publishAgentId("007");
    expectMetadata(/* syncedAgentId */ 7, /* firstSyncCompleted */ 123456);

    EXPECT_CALL(*m_mockSyncProtocol, synchronizeModule(::testing::_, ::testing::_))
    .WillOnce(::testing::Throw(std::runtime_error("session failed")))
    .WillOnce(::testing::Return(SyncModuleResult {true, {}}));

    EXPECT_THROW(m_sca->callExecuteFlushSync(), std::runtime_error);
    EXPECT_TRUE(m_sca->syncModule(Mode::DELTA));
}

// agent-info resumes SCA while its flush is still sending, so scans must not stay blocked behind
// it: pause() waits for scans and syncs, never for a flush.
TEST_F(SCAIdentityTest, PauseDoesNotWaitForAFlush)
{
    m_sca->resume();
    m_sca->setFlushInProgressForTest(true);

    auto pause = std::async(std::launch::async, [this] { m_sca->pause(); });
    const bool returned = pause.wait_for(std::chrono::seconds(5)) == std::future_status::ready;

    if (!returned)
    {
        m_sca->quiesce();
    }

    EXPECT_TRUE(returned);
}

// The sync thread starts before Run() and asks about the id right away. The resend waits for Run()
// to apply the document limits, or its snapshot could send rows that are about to be demoted.
TEST_F(SCAIdentityTest, ResendWaitsForRunToInitialize)
{
    publishAgentId("002");
    expectMetadata(/* syncedAgentId */ 1, /* firstSyncCompleted */ 123456);
    m_sca->setRunInitializedForTest(false);

    EXPECT_CALL(*m_mockSyncProtocol, notifyDataClean(::testing::_, ::testing::_, ::testing::_))
    .WillOnce(::testing::Return(SyncModuleResult {true, {}}));
    EXPECT_CALL(*m_mockSyncProtocol, synchronizeModule(::testing::_, ::testing::_))
    .WillRepeatedly(::testing::Return(SyncModuleResult {true, {}}));

    auto sync = std::async(std::launch::async, [this] { return m_sca->syncModule(Mode::DELTA); });

    EXPECT_EQ(sync.wait_for(std::chrono::milliseconds(200)), std::future_status::timeout);

    m_sca->setRunInitializedForTest(true);

    const bool returned = sync.wait_for(std::chrono::seconds(5)) == std::future_status::ready;

    if (!returned)
    {
        m_sca->quiesce();
    }

    ASSERT_TRUE(returned);
    EXPECT_TRUE(sync.get());
    EXPECT_NE(m_logOutput.find("last synchronized as agent 1, now running as agent 2"), std::string::npos);
}

// If the module stops first, the cycle gives up without sending anything -- not the resend, and
// not a delta under an id the manager holds no baseline for -- so the next start retries.
TEST_F(SCAIdentityTest, ResendWaitingForRunGivesUpOnShutdown)
{
    publishAgentId("002");
    expectMetadata(/* syncedAgentId */ 1, /* firstSyncCompleted */ 123456);
    m_sca->setRunInitializedForTest(false);

    EXPECT_CALL(*m_mockSyncProtocol, notifyDataClean(::testing::_, ::testing::_, ::testing::_)).Times(0);
    EXPECT_CALL(*m_mockSyncProtocol, synchronizeModule(::testing::_, ::testing::_)).Times(0);

    auto sync = std::async(std::launch::async, [this] { return m_sca->syncModule(Mode::DELTA); });

    EXPECT_EQ(sync.wait_for(std::chrono::milliseconds(200)), std::future_status::timeout);

    m_sca->quiesce();

    ASSERT_EQ(sync.wait_for(std::chrono::seconds(5)), std::future_status::ready);
    EXPECT_FALSE(sync.get());
}

// A resend the manager did not take leaves the markers alone and sends nothing else: a delta would
// go out under an id the manager holds no baseline for, and the cycle must not read as a success.
TEST_F(SCAIdentityTest, FailedResendSendsNoDelta)
{
    publishAgentId("002");
    expectMetadata(/* syncedAgentId */ 1, /* firstSyncCompleted */ 123456);

    EXPECT_CALL(*m_mockSyncProtocol, notifyDataClean(::testing::_, ::testing::_, ::testing::_))
    .WillOnce(::testing::Return(SyncModuleResult {false, {}}));
    EXPECT_CALL(*m_mockSyncProtocol, synchronizeModule(::testing::_, ::testing::_)).Times(0);

    EXPECT_FALSE(m_sca->syncModule(Mode::DELTA));
    EXPECT_NE(m_logOutput.find("SCA synchronization postponed: the agent id change was not resent"), std::string::npos);
}

// The sync thread backs off only after a resend was really started: it reads this count before and
// after a cycle, so a cycle that never tried must leave it alone.
static int queryResyncAttempts(SCAMock& sca)
{
    const auto response = nlohmann::json::parse(sca.query(R"({"command":"get_identity_changed"})"));
    EXPECT_EQ(response["error"], 0);
    return response["data"]["resync_attempts"].get<int>();
}

TEST_F(SCAIdentityTest, FailedResendCountsAsAResyncAttempt)
{
    publishAgentId("002");
    expectMetadata(/* syncedAgentId */ 1, /* firstSyncCompleted */ 123456);

    EXPECT_CALL(*m_mockSyncProtocol, notifyDataClean(::testing::_, ::testing::_, ::testing::_))
    .WillOnce(::testing::Return(SyncModuleResult {false, {}}));

    EXPECT_EQ(queryResyncAttempts(*m_sca), 0);
    EXPECT_FALSE(m_sca->syncModule(Mode::DELTA));
    EXPECT_EQ(queryResyncAttempts(*m_sca), 1);
}

// A cycle skipped because agent-info's flush was sending -- the usual collision right after a
// re-enrollment -- is no sign the manager refused anything, and must not count.
TEST_F(SCAIdentityTest, SkippedSyncIsNotAResyncAttempt)
{
    publishAgentId("002");
    expectMetadata(/* syncedAgentId */ 1, /* firstSyncCompleted */ 123456);

    EXPECT_CALL(*m_mockSyncProtocol, notifyDataClean(::testing::_, ::testing::_, ::testing::_)).Times(0);

    m_sca->setFlushInProgressForTest(true);
    EXPECT_FALSE(m_sca->syncModule(Mode::DELTA));
    m_sca->setFlushInProgressForTest(false);

    EXPECT_EQ(queryResyncAttempts(*m_sca), 0);
}

// Nor does a cycle that gave up waiting for Run() to apply the document limits.
TEST_F(SCAIdentityTest, ResendThatNeverStartedIsNotAResyncAttempt)
{
    publishAgentId("002");
    expectMetadata(/* syncedAgentId */ 1, /* firstSyncCompleted */ 123456);
    m_sca->setRunInitializedForTest(false);

    EXPECT_CALL(*m_mockSyncProtocol, notifyDataClean(::testing::_, ::testing::_, ::testing::_)).Times(0);

    auto sync = std::async(std::launch::async, [this] { return m_sca->syncModule(Mode::DELTA); });
    EXPECT_EQ(sync.wait_for(std::chrono::milliseconds(200)), std::future_status::timeout);
    m_sca->quiesce();
    ASSERT_EQ(sync.wait_for(std::chrono::seconds(5)), std::future_status::ready);
    EXPECT_FALSE(sync.get());

    // Read directly: the module is stopped by now.
    EXPECT_EQ(m_sca->identityResyncAttemptsForTest(), 0u);
}

// The integrity recovery's DataClean has no session guard either: beside a running flush it would
// reset that session. It stands back, leaves the check time alone so the next cycle runs it, and
// does not even ask the manager.
TEST_F(SCAIdentityTest, IntegrityCheckStandsBackFromAFlush)
{
    try
    {
        m_sca->initSyncProtocol("sca", ":memory:", std::chrono::seconds(3600));
    }
    catch (const std::exception&)
    {
        // Only the interval is needed; the protocol is the mock below.
    }

    m_sca->setSyncProtocol(m_mockSyncProtocol);

    EXPECT_CALL(*m_mockDBSync, selectRows(::testing::_, ::testing::_))
    .WillRepeatedly(::testing::Invoke([](const nlohmann::json & query,
                                         std::function<void(ReturnTypeCallback, const nlohmann::json&)> callback)
    {
        if (query.dump().find("last_integrity_check") != std::string::npos)
        {
            callback(SELECTED, nlohmann::json {{"value", 1}});
        }
    }));

    EXPECT_CALL(*m_mockSyncProtocol, requiresFullSync(::testing::_, ::testing::_)).Times(0);
    EXPECT_CALL(*m_mockSyncProtocol, notifyDataClean(::testing::_, ::testing::_, ::testing::_)).Times(0);

    m_sca->setFlushInProgressForTest(true);
    const auto response = nlohmann::json::parse(m_sca->query(R"({"command":"check_integrity"})"));
    m_sca->setFlushInProgressForTest(false);

    EXPECT_EQ(response["error"], 0);
    EXPECT_EQ(response["data"]["recovery_performed"], false);
    EXPECT_NE(m_logOutput.find("SCA integrity check deferred - flush or DataClean in progress"), std::string::npos);
    EXPECT_FALSE(m_sca->recoveryInProgressForTest());
}

// The other direction: a flush that arrives while a recovery DataClean runs waits for it.
TEST_F(SCAIdentityTest, FlushWaitsForARecoveryThenSends)
{
    EXPECT_CALL(*m_mockSyncProtocol, synchronizeModule(::testing::_, ::testing::_))
    .WillOnce(::testing::Return(SyncModuleResult {true, {}}));

    m_sca->setRecoveryInProgressForTest(true);

    auto flush = std::async(std::launch::async, [this] { return m_sca->callExecuteFlushSync(); });

    EXPECT_EQ(flush.wait_for(std::chrono::milliseconds(200)), std::future_status::timeout);

    m_sca->setRecoveryInProgressForTest(false);

    ASSERT_TRUE(finished(flush));
    EXPECT_EQ(flush.get(), 0);
}

// And a sync stands back from it too, as from a flush.
TEST_F(SCAIdentityTest, SyncSkipsWhileARecoveryDataCleanRuns)
{
    publishAgentId("007");
    expectMetadata(/* syncedAgentId */ 7, /* firstSyncCompleted */ 123456);

    EXPECT_CALL(*m_mockSyncProtocol, synchronizeModule(::testing::_, ::testing::_)).Times(0);

    m_sca->setRecoveryInProgressForTest(true);
    EXPECT_FALSE(m_sca->syncModule(Mode::DELTA));
    m_sca->setRecoveryInProgressForTest(false);

    EXPECT_NE(m_logOutput.find("SCA sync skipped - DataClean in progress"), std::string::npos);
}

// The all-policies-removed DataClean retries a scan interval apart. It holds the slot for each
// attempt only: a flush arriving while a failed attempt waits to retry sends right away, rather
// than leaving agent-info's coordination waiting out the whole interval.
TEST_F(SCAIdentityTest, AllPoliciesRemovedDataCleanFreesTheFlushBetweenAttempts)
{
    m_sca->Setup(true, false, std::chrono::seconds(3600), 30, false, {});
    m_sca->setSyncProtocol(m_mockSyncProtocol);

    std::promise<void> firstAttempt;
    EXPECT_CALL(*m_mockSyncProtocol, notifyDataClean(::testing::_, ::testing::_, ::testing::_))
    .WillOnce(::testing::Invoke([this, &firstAttempt](auto&& ...)
    {
        EXPECT_TRUE(m_sca->recoveryInProgressForTest());
        firstAttempt.set_value();
        return SyncModuleResult {false, {}};
    }));
    EXPECT_CALL(*m_mockSyncProtocol, synchronizeModule(::testing::_, ::testing::_))
    .WillOnce(::testing::Return(SyncModuleResult {true, {}}));

    auto dataClean = std::async(std::launch::async, [this] { return m_sca->callHandleAllPoliciesRemoved(); });
    firstAttempt.get_future().wait();

    auto flush = std::async(std::launch::async, [this] { return m_sca->callExecuteFlushSync(); });

    // Not ASSERT: the retry wait below must still be ended either way.
    EXPECT_TRUE(finished(flush));
    EXPECT_EQ(flush.get(), 0);
    EXPECT_FALSE(m_sca->recoveryInProgressForTest());

    // Ends the retry wait. Repeated: the wait is woken without the mutex it waits on.
    for (int i = 0; i < 50 && dataClean.wait_for(std::chrono::milliseconds(100)) != std::future_status::ready; ++i)
    {
        m_sca->quiesce();
    }

    ASSERT_EQ(dataClean.wait_for(std::chrono::seconds(0)), std::future_status::ready);
    EXPECT_FALSE(dataClean.get());
}

// And it waits for a flush that is sending before it claims the slot. On success it holds the slot
// until the databases are deleted, so a flush cannot resend the removed policies' queued rows
// after the DataClean.
TEST_F(SCAIdentityTest, AllPoliciesRemovedDataCleanWaitsForAFlush)
{
    m_sca->Setup(true, false, std::chrono::seconds(3600), 30, false, {});
    m_sca->setSyncProtocol(m_mockSyncProtocol);

    std::atomic<bool> flushSending {true};
    EXPECT_CALL(*m_mockSyncProtocol, notifyDataClean(::testing::_, ::testing::_, ::testing::_))
    .WillOnce(::testing::Invoke([&flushSending](auto&& ...)
    {
        EXPECT_FALSE(flushSending.load());
        return SyncModuleResult {true, {}};
    }));
    EXPECT_CALL(*m_mockSyncProtocol, deleteDatabase()).WillOnce(::testing::Invoke([this]()
    {
        EXPECT_TRUE(m_sca->recoveryInProgressForTest());
    }));
    EXPECT_CALL(*m_mockDBSync, closeAndDeleteDatabase()).WillOnce(::testing::Invoke([this]()
    {
        EXPECT_TRUE(m_sca->recoveryInProgressForTest());
    }));

    m_sca->setFlushInProgressForTest(true);
    auto dataClean = std::async(std::launch::async, [this] { return m_sca->callHandleAllPoliciesRemoved(); });

    EXPECT_EQ(dataClean.wait_for(std::chrono::milliseconds(200)), std::future_status::timeout);

    flushSending = false;
    m_sca->setFlushInProgressForTest(false);

    ASSERT_TRUE(finished(dataClean));
    EXPECT_TRUE(dataClean.get());
    EXPECT_FALSE(m_sca->recoveryInProgressForTest());
}

// Nor does it take the slot from an integrity recovery holding it: the first to finish would clear
// the other's claim and let a flush start beside a DataClean.
TEST_F(SCAIdentityTest, AllPoliciesRemovedDataCleanWaitsForARecovery)
{
    m_sca->Setup(true, false, std::chrono::seconds(3600), 30, false, {});
    m_sca->setSyncProtocol(m_mockSyncProtocol);

    std::atomic<bool> recoveryRunning {true};
    EXPECT_CALL(*m_mockSyncProtocol, notifyDataClean(::testing::_, ::testing::_, ::testing::_))
    .WillOnce(::testing::Invoke([&recoveryRunning](auto&& ...)
    {
        EXPECT_FALSE(recoveryRunning.load());
        return SyncModuleResult {true, {}};
    }));
    EXPECT_CALL(*m_mockSyncProtocol, deleteDatabase());
    EXPECT_CALL(*m_mockDBSync, closeAndDeleteDatabase());

    m_sca->setRecoveryInProgressForTest(true);
    auto dataClean = std::async(std::launch::async, [this] { return m_sca->callHandleAllPoliciesRemoved(); });

    EXPECT_EQ(dataClean.wait_for(std::chrono::milliseconds(200)), std::future_status::timeout);

    recoveryRunning = false;
    m_sca->setRecoveryInProgressForTest(false);

    ASSERT_TRUE(finished(dataClean));
    EXPECT_TRUE(dataClean.get());
    EXPECT_FALSE(m_sca->recoveryInProgressForTest());
}

// check_integrity stands back from that DataClean the same way it does from a flush.
TEST_F(SCAIdentityTest, IntegrityCheckStandsBackFromADataClean)
{
    try
    {
        m_sca->initSyncProtocol("sca", ":memory:", std::chrono::seconds(3600));
    }
    catch (const std::exception&)
    {
        // Only the interval is needed; the protocol is the mock below.
    }

    m_sca->setSyncProtocol(m_mockSyncProtocol);

    EXPECT_CALL(*m_mockDBSync, selectRows(::testing::_, ::testing::_))
    .WillRepeatedly(::testing::Invoke([](const nlohmann::json & query,
                                         std::function<void(ReturnTypeCallback, const nlohmann::json&)> callback)
    {
        if (query.dump().find("last_integrity_check") != std::string::npos)
        {
            callback(SELECTED, nlohmann::json {{"value", 1}});
        }
    }));

    EXPECT_CALL(*m_mockSyncProtocol, requiresFullSync(::testing::_, ::testing::_)).Times(0);
    EXPECT_CALL(*m_mockSyncProtocol, notifyDataClean(::testing::_, ::testing::_, ::testing::_)).Times(0);

    m_sca->setRecoveryInProgressForTest(true);
    const auto response = nlohmann::json::parse(m_sca->query(R"({"command":"check_integrity"})"));

    EXPECT_EQ(response["error"], 0);
    EXPECT_EQ(response["data"]["recovery_performed"], false);
    EXPECT_NE(m_logOutput.find("SCA integrity check deferred - flush or DataClean in progress"), std::string::npos);
    EXPECT_TRUE(m_sca->recoveryInProgressForTest());
    m_sca->setRecoveryInProgressForTest(false);
}
