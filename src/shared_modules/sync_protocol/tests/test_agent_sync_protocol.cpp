/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "gtest/gtest.h"
#include "mock_sync_transport.hpp"
#include "gmock/gmock.h"

#include "agent_sync_protocol.hpp"
#include "agent_sync_protocol_types.hpp"
#include "ipersistent_queue.hpp"
#include "agent_sync_protocol_c_interface.h"
#include "metadata_provider.h"

#include <future>
#include <atomic>
#include <mutex>
#include <optional>
#include <thread>
#include <iostream>
#include <utility>

using ::testing::_;
using ::testing::Return;
using ::testing::DoAll;

// IPersistentQueue Mock
class MockPersistentQueue : public IPersistentQueue
{
    public:
        MOCK_METHOD(void, submit, (const std::string& id,
                                   const std::string& index,
                                   const std::string& data,
                                   Operation operation,
                                   uint64_t version,
                                   bool isDataContext), (override));
        MOCK_METHOD(std::vector<PersistedData>, fetchAndMarkForSync, (size_t maxItems), (override));
        MOCK_METHOD(std::vector<PersistedData>, fetchPendingItems, (bool onlyDataValues), (override));
        MOCK_METHOD(void, clearSyncedItems, (), (override));
        MOCK_METHOD(void, resetSyncingItems, (), (override));
        MOCK_METHOD(void, clearItemsByIndex, (const std::string& index), (override));
        MOCK_METHOD(void, clearAllDataContext, (), (override));
        MOCK_METHOD(void, deleteDatabase, (), (override));

};

class AgentSyncProtocolTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            // Create and set dummy metadata
            agent_metadata_t metadata = {};
            strncpy(metadata.agent_id, "001", sizeof(metadata.agent_id) - 1);
            strncpy(metadata.agent_name, "test-agent", sizeof(metadata.agent_name) - 1);
            strncpy(metadata.agent_version, "4.5.0", sizeof(metadata.agent_version) - 1);
            strncpy(metadata.architecture, "x86_64", sizeof(metadata.architecture) - 1);
            strncpy(metadata.hostname, "test-host", sizeof(metadata.hostname) - 1);
            strncpy(metadata.os_name, "Linux", sizeof(metadata.os_name) - 1);
            strncpy(metadata.os_type, "linux", sizeof(metadata.os_type) - 1);
            strncpy(metadata.os_platform, "ubuntu", sizeof(metadata.os_platform) - 1);
            strncpy(metadata.os_version, "5.10", sizeof(metadata.os_version) - 1);
            char* groups[] = {const_cast<char*>("group1")};
            metadata.groups = groups;
            metadata.groups_count = 1;
            // A VD feed offset already received from the manager, so existing VDFIRST/VDSYNC
            // tests exercise the same "normal" path they did before the NO_VD_OFFSET_ERROR
            // gate (A11) existed; the gate itself is covered separately, with its own
            // explicit metadata (see the NoVdOffset* tests below).
            metadata.vd_feed_offset = 12345;
            metadata_provider_update(&metadata);

            // Set logger via asp_create

            auto handle = asp_create("test_module", ":memory:", +[](modules_log_level_t, const char* s)
            {
                std::cout << s << std::endl;
            });
            asp_destroy(handle);
        }

        void TearDown() override
        {
            // Reset metadata provider state for test isolation
            metadata_provider_reset();
        }

        /// Builds the wire format https_client_bridge.c sends for a /stateful outcome:
        /// "HCRESULT:<session>:<http_code>:<body>". forSession=0 skips the protocol's
        /// session-correlation check (matching how these tests never cared about it
        /// before the HTTP-result contract existed).
        static std::vector<uint8_t> buildHcResult(int httpCode, const std::string& body = "{}",
                                                  uint64_t forSession = 0)
        {
            const std::string text = "HCRESULT:" + std::to_string(forSession) + ":" +
                                     std::to_string(httpCode) + ":" + body;
            return std::vector<uint8_t>(text.begin(), text.end());
        }

        /// Feeds a /stateful HTTP result to the protocol, as https_client_bridge.c would.
        bool feedHttpResult(int httpCode, const std::string& body = "{}", uint64_t forSession = 0)
        {
            const auto buf = buildHcResult(httpCode, body, forSession);
            return protocol->parseResponseBuffer(buf.data(), buf.size());
        }

        std::shared_ptr<MockPersistentQueue> mockQueue;
        std::shared_ptr<MockSyncTransport> mockSyncTransport =
            std::make_shared<MockSyncTransport>();
        std::unique_ptr<AgentSyncProtocol> protocol;
        const uint64_t session = 1234;
        const uint64_t session2 = 5678;
        const unsigned int retries = 1;
        const unsigned int delay = 100;
        const uint8_t min_timeout = 1;
        const uint8_t max_timeout = 3;
};

TEST_F(AgentSyncProtocolTest, PersistDifferenceSuccess)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    const std::string testId = "test_id";
    const std::string testIndex = "test_index";
    const std::string testData = "test_data";
    const Operation testOperation = Operation::CREATE; // Any value
    const uint64_t testVersion = 123;

    EXPECT_CALL(*mockQueue, submit(testId, testIndex, testData, testOperation, testVersion, false))
    .Times(1);

    protocol->persistDifference(testId, testOperation, testIndex, testData, testVersion);
}

TEST_F(AgentSyncProtocolTest, PersistDifferenceCatchesException)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    const std::string testId = "test_id";
    const std::string testIndex = "test_index";
    const std::string testData = "test_data";
    const Operation testOperation = Operation::CREATE; // Any value
    const uint64_t testVersion = 123;

    EXPECT_CALL(*mockQueue, submit(testId, testIndex, testData, testOperation, testVersion, false))
    .WillOnce(::testing::Throw(std::runtime_error("Test exception")));

    EXPECT_NO_THROW(protocol->persistDifference(testId, testOperation, testIndex, testData, testVersion));
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleTransportUnavailable)
{
    mockQueue = std::make_shared<MockPersistentQueue>();

    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);
    mockSyncTransport->setAvailable(false);

    SyncModuleResult result = protocol->synchronizeModule(
                                  Mode::DELTA
                              );

    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.failureReason, "Failed to reach the sync intake socket.");
    // No stop was requested, so the failure must not be flagged as shutdown-induced.
    EXPECT_FALSE(result.stopped);
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleReportsStoppedWhenStopRequested)
{
    mockQueue = std::make_shared<MockPersistentQueue>();

    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);
    mockSyncTransport->setAvailable(false);

    // Simulate a shutdown/stop being requested before the sync runs.
    protocol->stop();

    SyncModuleResult result = protocol->synchronizeModule(
                                  Mode::DELTA
                              );

    EXPECT_FALSE(result.success);
    // The failure happened while a stop was in progress: the module can demote its log.
    EXPECT_TRUE(result.stopped);
}

// A local transport failure is not a "manager not ready yet" condition, so it must not be reported as
// manager-not-ready: the calling module keeps it at WARNING.
TEST_F(AgentSyncProtocolTest, SynchronizeModuleDoesNotReportTransientOnTransportFailure)
{
    mockQueue = std::make_shared<MockPersistentQueue>();

    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);
    mockSyncTransport->setAvailable(false);

    SyncModuleResult result = protocol->synchronizeModule(
                                  Mode::DELTA
                              );

    EXPECT_FALSE(result.success);
    EXPECT_FALSE(result.managerNotReady);
}

// Exercises the C interface (asp_sync_module -> SyncModuleResult_t.stopped): this is the path
// FIM depends on to distinguish a shutdown-aborted sync from a genuine failure.
TEST_F(AgentSyncProtocolTest, CInterfacePropagatesStoppedFlag)
{
    // asp_create wires the real socket transport and its intake socket does not
    // exist here, so synchronizeModule() returns at the checkStatus early out
    // (no persistent-queue data needed).

    auto* handle = asp_create("test_module", ":memory:", +[](modules_log_level_t, const char*) {});
    ASSERT_NE(handle, nullptr);

    // No stop requested: a real failure must not be flagged as shutdown-induced.
    SyncModuleResult_t noStop = asp_sync_module(handle, MODE_DELTA);
    EXPECT_FALSE(noStop.success);
    EXPECT_FALSE(noStop.stopped);

    // Stop requested: the C result must propagate stopped = true.
    asp_stop(handle);
    SyncModuleResult_t afterStop = asp_sync_module(handle, MODE_DELTA);
    EXPECT_FALSE(afterStop.success);
    EXPECT_TRUE(afterStop.stopped);

    asp_destroy(handle);
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleFetchAndMarkForSyncThrowsException)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync(_) )
    .WillOnce(::testing::Throw(std::runtime_error("Test exception")));

    SyncModuleResult result = protocol->synchronizeModule(
                                  Mode::DELTA
                              );

    EXPECT_FALSE(result.success);
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleDataToSyncEmpty)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync(_) )
    .WillOnce(Return(std::vector<PersistedData> {}));

    SyncModuleResult result = protocol->synchronizeModule(
                                  Mode::DELTA
                              );

    EXPECT_TRUE(result.success);
}

// The consecutive-failure streak is what tells a brief post-restart hiccup apart from a lasting
// condition (for example the manager having no indexer available, which also answers "not ready").
// Without it the modules would demote a permanent sync outage to INFO forever.
TEST_F(AgentSyncProtocolTest, SynchronizeModuleCountsConsecutiveFailures)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    // The queue opens fine and messages are sent, but no StartAck is ever parsed, so every attempt
    // ends in a Start timeout: the manager is never ready. A queue-open failure would not do, since
    // it returns before the streak is tracked.

    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    // There must be something to synchronize on every attempt, otherwise the sync short-circuits
    // as a success and never reaches the handshake.
    std::vector<PersistedData> testData =
    {
        {0, "memory_id_1", "memory_index_1", "memory_data_1", Operation::CREATE, 1}
    };
    EXPECT_CALL(*mockQueue, fetchAndMarkForSync(_) )
    .WillRepeatedly(Return(testData));

    unsigned int previous = 0;

    for (unsigned int attempt = 1; attempt <= SYNC_MANAGER_NOT_READY_TOLERANCE + 1; ++attempt)
    {
        SyncModuleResult result = protocol->synchronizeModule(Mode::DELTA);
        EXPECT_FALSE(result.success);
        EXPECT_TRUE(result.managerNotReady);
        // The count grows while the condition does not clear, so the module escalates to WARNING once
        // it goes past SYNC_MANAGER_NOT_READY_TOLERANCE.
        EXPECT_EQ(result.consecutiveFailures, attempt);
        previous = result.consecutiveFailures;
    }

    EXPECT_GT(previous, SYNC_MANAGER_NOT_READY_TOLERANCE);
}

// An Offline StartAck means the manager itself reports it cannot serve this agent yet. That is the
// manager-not-ready condition modules demote to INFO for the first few cycles, so it must be surfaced
// in the result (not just the Start timeout case).
TEST_F(AgentSyncProtocolTest, SynchronizeModuleOfflineStartAckReportsManagerNotReady)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    SyncModuleResult result;
    std::thread syncThread([this, &result]()
    {
        std::vector<PersistedData> testData =
        {
            {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1}
        };
        EXPECT_CALL(*mockQueue, fetchAndMarkForSync(_) )
        .WillOnce(Return(testData));

        result = protocol->synchronizeModule(Mode::DELTA);
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck with Offline status

    syncThread.join();

    EXPECT_FALSE(result.success);
    EXPECT_TRUE(result.managerNotReady);
    EXPECT_EQ(result.consecutiveFailures, 1u);
}

// An Offline EndAck reports the same manager-not-ready condition once the session is already open.
TEST_F(AgentSyncProtocolTest, SynchronizeModuleOfflineEndAckReportsManagerNotReady)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    SyncModuleResult result;
    std::thread syncThread([this, &result]()
    {
        std::vector<PersistedData> testData =
        {
            {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1}
        };
        EXPECT_CALL(*mockQueue, fetchAndMarkForSync(_) )
        .WillOnce(Return(testData));

        result = protocol->synchronizeModule(Mode::DELTA);
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck Ok to open the session

    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // EndAck with Offline status
    feedHttpResult(503);  // was Status::Offline

    syncThread.join();

    EXPECT_FALSE(result.success);
    EXPECT_TRUE(result.managerNotReady);
    EXPECT_EQ(result.consecutiveFailures, 1u);
}

// A timeout waiting for the EndAck (session opened, but the manager never acknowledges the End) is
// the same self-recovering manager-not-ready condition as a Start timeout.
TEST_F(AgentSyncProtocolTest, SynchronizeModuleEndTimeoutReportsManagerNotReady)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    SyncModuleResult result;
    std::thread syncThread([this, &result]()
    {
        std::vector<PersistedData> testData =
        {
            {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1}
        };
        EXPECT_CALL(*mockQueue, fetchAndMarkForSync(_) )
        .WillOnce(Return(testData));

        result = protocol->synchronizeModule(Mode::DELTA);
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck Ok to open the session, then never send the EndAck so the End wait times out.

    syncThread.join();

    EXPECT_FALSE(result.success);
    EXPECT_TRUE(result.managerNotReady);
    EXPECT_EQ(result.consecutiveFailures, 1u);
}

// A sync aborted because a stop was requested says nothing about the manager, so it must not add to
// the consecutive-failure streak.
TEST_F(AgentSyncProtocolTest, SynchronizeModuleStoppedDoesNotCountTowardsStreak)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    // There must be something to synchronize on every attempt, otherwise the sync short-circuits
    // as a success and never reaches the handshake.
    std::vector<PersistedData> testData =
    {
        {0, "memory_id_1", "memory_index_1", "memory_data_1", Operation::CREATE, 1}
    };
    EXPECT_CALL(*mockQueue, fetchAndMarkForSync(_) )
    .WillRepeatedly(Return(testData));

    // First failure (Start timeout) puts the streak at 1.
    SyncModuleResult firstFailure = protocol->synchronizeModule(Mode::DELTA);
    EXPECT_FALSE(firstFailure.success);
    EXPECT_EQ(firstFailure.consecutiveFailures, 1u);

    // A stop-aborted sync must leave the streak where it was.
    protocol->stop();
    SyncModuleResult stoppedResult = protocol->synchronizeModule(Mode::DELTA);
    EXPECT_FALSE(stoppedResult.success);
    EXPECT_TRUE(stoppedResult.stopped);
    EXPECT_EQ(stoppedResult.consecutiveFailures, 1u);
}

// The first successful sync clears the streak, so a later manager-not-ready failure starts again at 1
// and modules go back to reporting it at INFO instead of staying escalated.
TEST_F(AgentSyncProtocolTest, SynchronizeModuleSuccessResetsConsecutiveFailures)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    // There must be something to synchronize on every attempt, otherwise the sync short-circuits
    // as a success and never reaches the handshake. The first (failing) attempt aborts after its
    // one block, so it only ever fetches once; the second (successful) attempt's block loop keeps
    // going after that block succeeds, so it needs an empty fetch afterwards to stop cleanly
    // instead of trying (and hanging on) a second block.
    std::vector<PersistedData> testData =
    {
        {0, "memory_id_1", "memory_index_1", "memory_data_1", Operation::CREATE, 1}
    };
    EXPECT_CALL(*mockQueue, fetchAndMarkForSync(_) )
    .WillOnce(Return(testData))
    .WillOnce(Return(testData))
    .WillRepeatedly(Return(std::vector<PersistedData> {}));

    // First failure (Start timeout) puts the streak at 1.
    SyncModuleResult firstFailure = protocol->synchronizeModule(Mode::DELTA);
    EXPECT_FALSE(firstFailure.success);
    EXPECT_EQ(firstFailure.consecutiveFailures, 1u);

    // Second sync: drive a full successful handshake, which must reset the streak to 0.
    SyncModuleResult successResult;
    std::thread syncThread([this, &successResult]()
    {
        successResult = protocol->synchronizeModule(Mode::DELTA);
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck Ok

    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // EndAck Ok
    feedHttpResult(200);  // was Status::Ok

    syncThread.join();

    EXPECT_TRUE(successResult.success);
    EXPECT_EQ(successResult.consecutiveFailures, 0u);
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleInvalidModeValidation)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    // Expect NO calls to any queue methods since validation should fail early
    EXPECT_CALL(*mockQueue, fetchAndMarkForSync(_) )
    .Times(0);
    EXPECT_CALL(*mockQueue, clearSyncedItems())
    .Times(0);
    EXPECT_CALL(*mockQueue, resetSyncingItems())
    .Times(0);

    // Test invalid mode by casting an invalid integer to Mode enum
    Mode invalidMode = static_cast<Mode>(999);

    SyncModuleResult result = protocol->synchronizeModule(
                                  invalidMode
                              );

    EXPECT_FALSE(result.success);  // Should fail due to invalid mode validation
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleSendSessionFails)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    std::vector<PersistedData> testData =
    {
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1},
        {0, "test_id_2", "test_index_2", "test_data_2", Operation::MODIFY, 2}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync(_) )
    .WillOnce(Return(testData));

    EXPECT_CALL(*mockQueue, resetSyncingItems())
    .Times(1);

    SyncModuleResult result = protocol->synchronizeModule(
                                  Mode::DELTA
                              );

    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.failureReason, "Timed out waiting for manager response.");
}

TEST_F(AgentSyncProtocolTest, SendStartWaitsUntilMetadataAvailable)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    std::vector<PersistedData> testData =
    {
        {0, "id1", "index1", "data1", Operation::CREATE, 1}
    };
    EXPECT_CALL(*mockQueue, fetchAndMarkForSync(_) )
    .WillRepeatedly(Return(testData));

    // Remove metadata so provider returns -1 on the first polls
    metadata_provider_reset();

    std::atomic<bool> syncDone{false};
    auto syncFuture = std::async(std::launch::async, [&]()
    {
        SyncModuleResult result = protocol->synchronizeModule(Mode::DELTA);
        syncDone = true;
        return result;
    });

    // Let the thread enter the metadata polling loop
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));
    EXPECT_FALSE(syncDone.load()) << "Sync should be blocked waiting for metadata";

    // Provide metadata - the polling loop should unblock
    agent_metadata_t metadata = {};
    strncpy(metadata.agent_id, "001", sizeof(metadata.agent_id) - 1);
    strncpy(metadata.agent_name, "test-agent", sizeof(metadata.agent_name) - 1);
    strncpy(metadata.agent_version, "4.5.0", sizeof(metadata.agent_version) - 1);
    strncpy(metadata.architecture, "x86_64", sizeof(metadata.architecture) - 1);
    strncpy(metadata.hostname, "test-host", sizeof(metadata.hostname) - 1);
    strncpy(metadata.os_name, "Linux", sizeof(metadata.os_name) - 1);
    strncpy(metadata.os_type, "linux", sizeof(metadata.os_type) - 1);
    strncpy(metadata.os_platform, "ubuntu", sizeof(metadata.os_platform) - 1);
    strncpy(metadata.os_version, "5.10", sizeof(metadata.os_version) - 1);
    char* groups[] = {const_cast<char*>("group1")};
    metadata.groups = groups;
    metadata.groups_count = 1;
    metadata_provider_update(&metadata);

    // Sync proceeds past the metadata wait and eventually times out on StartAck.
    // Bound the wait: (retries + 1) * min_timeout for StartAck retries, plus margin.
    constexpr auto testTimeout = std::chrono::seconds(10);

    if (syncFuture.wait_for(testTimeout) == std::future_status::timeout)
    {
        protocol->stop();
        syncFuture.wait();
        FAIL() << "Sync thread did not finish in time; metadata unblocking may be broken";
    }

    EXPECT_FALSE(syncFuture.get().success); // Times out on StartAck, but it did get past the metadata wait
}

TEST_F(AgentSyncProtocolTest, SendStartAbortedOnStopWhileWaitingForMetadata)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    std::vector<PersistedData> testData =
    {
        {0, "id1", "index1", "data1", Operation::CREATE, 1}
    };
    EXPECT_CALL(*mockQueue, fetchAndMarkForSync(_) )
    .WillRepeatedly(Return(testData));

    // Remove metadata so provider returns -1 indefinitely
    metadata_provider_reset();

    auto syncFuture = std::async(std::launch::async, [&]()
    {
        return protocol->synchronizeModule(Mode::DELTA);
    });

    // Let the thread enter the metadata polling loop
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // Request stop - cv.notify_all() wakes the wait_for immediately
    protocol->stop();

    // The thread should exit promptly; give it a generous bound to avoid CI flakiness
    constexpr auto testTimeout = std::chrono::seconds(5);

    if (syncFuture.wait_for(testTimeout) == std::future_status::timeout)
    {
        FAIL() << "Sync thread did not respond to stop() in time; stop handling may be broken";
    }

    EXPECT_FALSE(syncFuture.get().success);
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleSessionTimeout)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    std::vector<PersistedData> testData =
    {
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1},
        {0, "test_id_2", "test_index_2", "test_data_2", Operation::MODIFY, 2}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync(_) )
    .WillOnce(Return(testData));

    EXPECT_CALL(*mockQueue, resetSyncingItems())
    .Times(1);

    SyncModuleResult result = protocol->synchronizeModule(
                                  Mode::DELTA
                              );

    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.failureReason, "Timed out waiting for manager response.");
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleSendDataMessagesFails)
{
    mockQueue = std::make_shared<MockPersistentQueue>();

    static int callCount = 0;
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    std::vector<PersistedData> testData =
    {
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1},
        {0, "test_id_2", "test_index_2", "test_data_2", Operation::MODIFY, 2}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync(_) )
    .WillOnce(Return(testData));

    EXPECT_CALL(*mockQueue, resetSyncingItems())
    .Times(1);

    // Start synchronization
    std::thread syncThread([this]()
    {
        SyncModuleResult result = protocol->synchronizeModule(
                                      Mode::DELTA
                                  );
        EXPECT_FALSE(result.success);
    });

    EXPECT_TRUE(mockSyncTransport->waitForSession());

    // StartAck

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleDeltaStopsAfterTenBlocks)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    std::vector<PersistedData> testData =
    {
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync(_) )
    .Times(10)
    .WillRepeatedly(Return(testData));
    EXPECT_CALL(*mockQueue, clearSyncedItems())
    .Times(10);
    EXPECT_CALL(*mockQueue, resetSyncingItems())
    .Times(0);

    std::atomic<bool> syncDone{false};
    auto syncFuture = std::async(std::launch::async, [this, &syncDone]()
    {
        auto result = protocol->synchronizeModule(Mode::DELTA);
        syncDone.store(true, std::memory_order_release);
        return result;
    });

    std::thread ackThread([this, &syncDone]()
    {
        int handled = 0;
        int lastSendCount = 0;

        while (handled < 10)
        {
            const int currentSendCount = mockSyncTransport->sendCount();

            if (currentSendCount > lastSendCount)
            {
                lastSendCount = currentSendCount;

                feedHttpResult(200);  // was Status::Ok
                ++handled;
                continue;
            }

            if (syncDone.load(std::memory_order_acquire) && currentSendCount == lastSendCount)
            {
                break;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    });

    if (syncFuture.wait_for(std::chrono::seconds(10)) == std::future_status::timeout)
    {
        syncDone.store(true, std::memory_order_release);
        ackThread.join();
        FAIL() << "Sync thread did not finish in time; block limit may be broken";
    }

    const SyncModuleResult result = syncFuture.get();
    syncDone.store(true, std::memory_order_release);
    ackThread.join();

    EXPECT_TRUE(result.success);
    EXPECT_EQ(mockSyncTransport->sendCount(), 10);
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleDeltaUsesBytePrefilterBudgetForSyncOption)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    constexpr size_t FULLSESSION_MAX_BYTES = 5U * 1024U * 1024U;
    constexpr size_t FULLSESSION_PREFILTER_GRACE_BYTES = 64U * 1024U;
    constexpr size_t EXPECTED_BUDGET = FULLSESSION_MAX_BYTES - FULLSESSION_PREFILTER_GRACE_BYTES;

    std::vector<PersistedData> testData =
    {
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync(EXPECTED_BUDGET))
    .WillOnce(Return(testData))
    .WillOnce(Return(std::vector<PersistedData> {}));
    EXPECT_CALL(*mockQueue, clearSyncedItems())
    .Times(1);
    EXPECT_CALL(*mockQueue, resetSyncingItems())
    .Times(0);

    SyncModuleResult result;
    std::thread syncThread([this, &result]()
    {
        result = protocol->synchronizeModule(Mode::DELTA, Option::SYNC);
    });

    EXPECT_TRUE(mockSyncTransport->waitForSession());

    feedHttpResult(200);  // was Status::Ok

    syncThread.join();
    EXPECT_TRUE(result.success);
}

/// Puts the built-in default back when it goes out of scope. The limit is
/// process-wide, so a test that changes it would otherwise leak into the next one.
class SessionMaxBytesGuard final
{
    public:
        explicit SessionMaxBytesGuard(size_t bytes)
        {
            AgentSyncProtocol::setSessionMaxBytes(bytes);
        }

        ~SessionMaxBytesGuard()
        {
            AgentSyncProtocol::setSessionMaxBytes(5U * 1024U * 1024U);
        }

        SessionMaxBytesGuard(const SessionMaxBytesGuard&) = delete;
        SessionMaxBytesGuard& operator=(const SessionMaxBytesGuard&) = delete;
};

TEST_F(AgentSyncProtocolTest, SessionByteBudgetFollowsTheConfiguredSessionMax)
{
    // <agent><batch><size> bounds a sync session the same way it bounds a
    // /stateless request; before it was configurable this budget was fixed at
    // 5 MiB whatever the agent had been told.
    constexpr size_t CONFIGURED_MAX_BYTES = 512U * 1024U;
    constexpr size_t FULLSESSION_PREFILTER_GRACE_BYTES = 64U * 1024U;
    constexpr size_t EXPECTED_BUDGET = CONFIGURED_MAX_BYTES - FULLSESSION_PREFILTER_GRACE_BYTES;

    const SessionMaxBytesGuard guard {CONFIGURED_MAX_BYTES};

    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    std::vector<PersistedData> testData =
    {
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync(EXPECTED_BUDGET))
    .WillOnce(Return(testData))
    .WillOnce(Return(std::vector<PersistedData> {}));
    EXPECT_CALL(*mockQueue, clearSyncedItems())
    .Times(1);

    SyncModuleResult result;
    std::thread syncThread([this, &result]()
    {
        result = protocol->synchronizeModule(Mode::DELTA, Option::SYNC);
    });

    EXPECT_TRUE(mockSyncTransport->waitForSession());

    feedHttpResult(200);

    syncThread.join();
    EXPECT_TRUE(result.success);
}

TEST_F(AgentSyncProtocolTest, AnUnsetSessionMaxKeepsTheBuiltInDefault)
{
    // Zero is what an absent <batch><size> reaches the module as, so it has to
    // read as "leave the default alone" rather than as a zero-byte session.
    constexpr size_t FULLSESSION_MAX_BYTES = 5U * 1024U * 1024U;
    constexpr size_t FULLSESSION_PREFILTER_GRACE_BYTES = 64U * 1024U;
    constexpr size_t EXPECTED_BUDGET = FULLSESSION_MAX_BYTES - FULLSESSION_PREFILTER_GRACE_BYTES;

    AgentSyncProtocol::setSessionMaxBytes(0);

    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    std::vector<PersistedData> testData =
    {
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync(EXPECTED_BUDGET))
    .WillOnce(Return(testData))
    .WillOnce(Return(std::vector<PersistedData> {}));
    EXPECT_CALL(*mockQueue, clearSyncedItems())
    .Times(1);

    SyncModuleResult result;
    std::thread syncThread([this, &result]()
    {
        result = protocol->synchronizeModule(Mode::DELTA, Option::SYNC);
    });

    EXPECT_TRUE(mockSyncTransport->waitForSession());

    feedHttpResult(200);

    syncThread.join();
    EXPECT_TRUE(result.success);
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleDeltaBypassesBytePrefilterBudgetForVDOptions)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    std::vector<PersistedData> testData =
    {
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync(0))
    .WillOnce(Return(testData))
    .WillOnce(Return(std::vector<PersistedData> {}))
    .WillOnce(Return(testData))
    .WillOnce(Return(std::vector<PersistedData> {}));
    EXPECT_CALL(*mockQueue, clearSyncedItems())
    .Times(2);
    EXPECT_CALL(*mockQueue, resetSyncingItems())
    .Times(0);

    auto runAndAck = [this](Option option)
    {
        SyncModuleResult result;
        const int sendCountBefore = mockSyncTransport->sendCount();
        std::thread syncThread([this, option, &result]()
        {
            result = protocol->synchronizeModule(Mode::DELTA, option);
        });

        auto waitDeadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);

        while (mockSyncTransport->sendCount() <= sendCountBefore &&
                std::chrono::steady_clock::now() < waitDeadline)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }

        EXPECT_GT(mockSyncTransport->sendCount(), sendCountBefore);

        feedHttpResult(200);  // was Status::Ok

        syncThread.join();
        EXPECT_TRUE(result.success);
    };

    runAndAck(Option::VDFIRST);
    runAndAck(Option::VDSYNC);
}

// A11: a VD sync must abort (no Start ever sent) when no feed offset has been received
// from the manager yet -- the state right after an agent restart, before the first
// /control notify reports one. Mirrors the NO_GROUPS_ERROR gate's shape exactly.
TEST_F(AgentSyncProtocolTest, NoVdOffsetAbortsVDFirstSyncWithoutSendingStart)
{
    agent_metadata_t metadata = {};
    strncpy(metadata.agent_id, "001", sizeof(metadata.agent_id) - 1);
    strncpy(metadata.agent_name, "test-agent", sizeof(metadata.agent_name) - 1);
    char* groups[] = {const_cast<char*>("group1")};
    metadata.groups = groups;
    metadata.groups_count = 1;
    metadata.vd_feed_offset = 0; // Not yet received.
    metadata_provider_update(&metadata);

    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    std::vector<PersistedData> testData =
    {
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1}
    };
    EXPECT_CALL(*mockQueue, fetchAndMarkForSync(_))
    .WillRepeatedly(Return(testData));

    const int sendCountBefore = mockSyncTransport->sendCount();
    const SyncModuleResult result = protocol->synchronizeModule(Mode::DELTA, Option::VDFIRST);

    EXPECT_FALSE(result.success);
    EXPECT_EQ(mockSyncTransport->sendCount(), sendCountBefore); // No Start was ever built/sent.
    EXPECT_THAT(result.failureReason, ::testing::HasSubstr("No VD feed offset available"));
    // Expected/benign, not a real failure: lets the caller (Syscollector::syncModule()) log
    // this at INFO instead of WARNING.
    EXPECT_TRUE(result.awaitingPrerequisite);
    EXPECT_FALSE(result.managerNotReady);
}

// The gate is VD-specific (isUncappedSyncOption): a plain SYNC must proceed even with no
// VD offset at all -- only VDFIRST/VDSYNC require one.
TEST_F(AgentSyncProtocolTest, NoVdOffsetDoesNotAbortNonVdSync)
{
    agent_metadata_t metadata = {};
    strncpy(metadata.agent_id, "001", sizeof(metadata.agent_id) - 1);
    char* groups[] = {const_cast<char*>("group1")};
    metadata.groups = groups;
    metadata.groups_count = 1;
    metadata.vd_feed_offset = 0;
    metadata_provider_update(&metadata);

    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    std::vector<PersistedData> testData =
    {
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1}
    };
    EXPECT_CALL(*mockQueue, fetchAndMarkForSync(_))
    .WillOnce(Return(testData))
    .WillOnce(Return(std::vector<PersistedData> {}));
    EXPECT_CALL(*mockQueue, clearSyncedItems())
    .Times(1);

    SyncModuleResult result;
    std::thread syncThread([this, &result]()
    {
        result = protocol->synchronizeModule(Mode::DELTA, Option::SYNC);
    });

    EXPECT_TRUE(mockSyncTransport->waitForSession());
    feedHttpResult(200);

    syncThread.join();
    EXPECT_TRUE(result.success);
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleDeltaAllowsOversizedRealPayloadWhenPrefilterSelectedIt)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    std::vector<PersistedData> oversizedBlock =
    {
        {0, "test_id_1", "test_index_1", std::string(6U * 1024U * 1024U, 'x'), Operation::CREATE, 1}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync(_))
    .WillOnce(Return(oversizedBlock))
    .WillOnce(Return(std::vector<PersistedData> {}));
    EXPECT_CALL(*mockQueue, resetSyncingItems())
    .Times(0);
    EXPECT_CALL(*mockQueue, clearSyncedItems())
    .Times(1);

    SyncModuleResult result;
    std::thread syncThread([this, &result]()
    {
        result = protocol->synchronizeModule(Mode::DELTA, Option::SYNC);
    });

    EXPECT_TRUE(mockSyncTransport->waitForSession());
    feedHttpResult(200);  // was Status::Ok

    syncThread.join();

    EXPECT_TRUE(result.success);
    EXPECT_EQ(mockSyncTransport->sendCount(), 1);
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleDeltaAbortsRemainingBlocksAfterSecondBlockFailure)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    std::vector<PersistedData> testData =
    {
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync(_))
    .Times(2)
    .WillOnce(Return(testData))
    .WillOnce(Return(testData));
    EXPECT_CALL(*mockQueue, clearSyncedItems())
    .Times(1);
    EXPECT_CALL(*mockQueue, resetSyncingItems())
    .Times(1);

    std::atomic<bool> syncDone{false};
    auto syncFuture = std::async(std::launch::async, [this, &syncDone]()
    {
        auto result = protocol->synchronizeModule(Mode::DELTA, Option::SYNC);
        syncDone.store(true, std::memory_order_release);
        return result;
    });

    std::thread ackThread([this, &syncDone]()
    {
        int handled = 0;
        int lastSendCount = 0;

        while (handled < 2)
        {
            const int currentSendCount = mockSyncTransport->sendCount();

            if (currentSendCount > lastSendCount)
            {
                lastSendCount = currentSendCount;
                ++handled;

                feedHttpResult(handled == 1 ? 200 : 500);  // was Status::Ok : Status::Error
                continue;
            }

            if (syncDone.load(std::memory_order_acquire) && currentSendCount == lastSendCount)
            {
                break;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    });

    if (syncFuture.wait_for(std::chrono::seconds(10)) == std::future_status::timeout)
    {
        syncDone.store(true, std::memory_order_release);
        ackThread.join();
        FAIL() << "Sync thread did not finish in time while validating block-failure abort behavior";
    }

    const SyncModuleResult result = syncFuture.get();
    syncDone.store(true, std::memory_order_release);
    ackThread.join();

    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.failureReason, "Manager reported synchronization failure.");
    EXPECT_EQ(mockSyncTransport->sendCount(), 2);
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleStopWakesEndAckWait)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    std::vector<PersistedData> testData =
    {
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync(_) )
    .WillOnce(Return(testData));

    EXPECT_CALL(*mockQueue, resetSyncingItems())
    .Times(1);

    auto syncFuture = std::async(std::launch::async, [&]()
    {
        return protocol->synchronizeModule(Mode::DELTA);
    });

    // Once the session is handed over, the worker is parked waiting for the
    // manager's answer.
    EXPECT_TRUE(mockSyncTransport->waitForSession());

    // stop() should wake the wait_for immediately via cv.notify_all().
    protocol->stop();

    // Without that wake-up the future would not be ready until the full answer
    // timeout had elapsed. Give a generous bound to avoid CI flakiness.
    constexpr auto testTimeout = std::chrono::seconds(5);

    if (syncFuture.wait_for(testTimeout) == std::future_status::timeout)
    {
        FAIL() << "Sync thread did not respond to stop() while waiting for the answer; "
               << "cv.wait_for may not be interruptible";
    }

    const SyncModuleResult endResult = syncFuture.get();
    EXPECT_FALSE(endResult.success);
    // stop() was requested during the answer wait, so the final return must flag the failure
    // as shutdown-induced (exercises the end-of-sync `stopped = shouldStop()` capture path).
    EXPECT_TRUE(endResult.stopped);
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleEndFailDueToManager)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    std::vector<PersistedData> testData =
    {
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1},
        {0, "test_id_2", "test_index_2", "test_data_2", Operation::MODIFY, 2}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync(_) )
    .WillOnce(Return(testData));

    EXPECT_CALL(*mockQueue, resetSyncingItems())
    .Times(1);

    // Start synchronization
    std::thread syncThread([this]()
    {
        SyncModuleResult result = protocol->synchronizeModule(
                                      Mode::DELTA
                                  );
        EXPECT_FALSE(result.success);
        EXPECT_EQ(result.failureReason, "Manager reported synchronization failure.");
    });

    EXPECT_TRUE(mockSyncTransport->waitForSession());

    // StartAck

    // Wait for data messages to be sent
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // EndAck with ERROR status
    feedHttpResult(500);  // was Status::Error

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleEndAckTimeout)
{
    mockQueue = std::make_shared<MockPersistentQueue>();

    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    std::vector<PersistedData> testData =
    {
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1},
        {0, "test_id_2", "test_index_2", "test_data_2", Operation::MODIFY, 2}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync(_) )
    .WillOnce(Return(testData));

    EXPECT_CALL(*mockQueue, resetSyncingItems())
    .Times(1);

    // Start synchronization
    std::thread syncThread([this]()
    {
        SyncModuleResult result = protocol->synchronizeModule(
                                      Mode::DELTA
                                  );
        EXPECT_FALSE(result.success);
        EXPECT_EQ(result.failureReason, "Timed out waiting for manager response.");
    });

    EXPECT_TRUE(mockSyncTransport->waitForSession());

    // StartAck

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleSuccessWithNoReqRet)
{
    mockQueue = std::make_shared<MockPersistentQueue>();

    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    std::vector<PersistedData> testData =
    {
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1},
        {0, "test_id_2", "test_index_2", "test_data_2", Operation::MODIFY, 2}
    };

    EXPECT_CALL(*mockQueue, fetchAndMarkForSync(_) )
    .WillOnce(Return(testData))
    .WillRepeatedly(Return(std::vector<PersistedData> {}));

    EXPECT_CALL(*mockQueue, clearSyncedItems())
    .Times(1);

    // Start synchronization
    std::thread syncThread([this]()
    {
        SyncModuleResult result = protocol->synchronizeModule(
                                      Mode::DELTA
                                  );
        EXPECT_TRUE(result.success);
    });

    EXPECT_TRUE(mockSyncTransport->waitForSession());

    // StartAck

    // Wait for data messages
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // EndAck
    feedHttpResult(200);  // was Status::Ok

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeModuleFinalizeSyncStateException)
{
    mockQueue = std::make_shared<MockPersistentQueue>();

    // Logger to capture error messages
    std::string loggedMessage;
    LoggerFunc testLogger = [&loggedMessage](modules_log_level_t level, const std::string & message)
    {
        if (level == LOG_ERROR && message.find("Failed to finalize DELTA sync block") != std::string::npos)
        {
            loggedMessage = message;
        }
    };

    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    // Create some sample data for synchronization to make it successful
    std::vector<PersistedData> testData =
    {
        {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 0}
    };

    // Set up mock expectations for successful sync until the finalization phase
    EXPECT_CALL(*mockQueue, fetchAndMarkForSync(_) )
    .WillOnce(testing::Return(testData));

    // The clearSyncedItems call will throw an exception
    EXPECT_CALL(*mockQueue, clearSyncedItems())
    .WillOnce(testing::Throw(std::runtime_error("Simulated clearSyncedItems exception")));

    // Start synchronization in background
    std::thread syncThread([this]()
    {
        SyncModuleResult result = protocol->synchronizeModule(Mode::DELTA);
        EXPECT_FALSE(result.success); // Finalization failed and must abort the DELTA cycle
    });

    EXPECT_TRUE(mockSyncTransport->waitForSession());

    // StartAck

    // Wait for data messages
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // EndAck
    feedHttpResult(200);  // was Status::Ok

    syncThread.join();

    // Verify that the error was logged
    EXPECT_TRUE(loggedMessage.find("Failed to finalize DELTA sync block") != std::string::npos);
    EXPECT_TRUE(loggedMessage.find("Simulated clearSyncedItems exception") != std::string::npos);
}

TEST_F(AgentSyncProtocolTest, ParseResponseBufferWithNullBuffer)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    bool response = protocol->parseResponseBuffer(nullptr, 0);

    EXPECT_FALSE(response);
}

// Thread-safe capture of (level, message) pairs emitted by the protocol logger,
// so tests can assert the level a given sync message is logged at.
struct LogCapture
{
    std::mutex mtx;
    std::vector<std::pair<modules_log_level_t, std::string>> entries;

    LoggerFunc logger()
    {
        return [this](modules_log_level_t level, const std::string & msg)
        {
            std::lock_guard<std::mutex> lock(mtx);
            entries.emplace_back(level, msg);
        };
    }

    // Asserts a message containing 'needle' was logged at LOG_DEBUG and never at LOG_ERROR.
    void expectDebugNotError(const std::string& needle)
    {
        std::lock_guard<std::mutex> lock(mtx);
        bool debugLogged = false;
        bool errorLogged = false;

        for (const auto& entry : entries)
        {
            if (entry.second.find(needle) != std::string::npos)
            {
                debugLogged = debugLogged || (entry.first == LOG_DEBUG);
                errorLogged = errorLogged || (entry.first == LOG_ERROR);
            }
        }

        EXPECT_TRUE(debugLogged) << "Expected '" << needle << "' to be logged at LOG_DEBUG";
        EXPECT_FALSE(errorLogged) << "Did not expect '" << needle << "' to be logged at LOG_ERROR";
    }
};

TEST_F(AgentSyncProtocolTest, ParseResponseBufferWhenNotWaitingForEndAck)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    bool response = feedHttpResult(200);  // was Status::Ok

    EXPECT_TRUE(response);
}

TEST_F(AgentSyncProtocolTest, ParseResponseBufferWithEndAckError)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LogCapture logCapture;
    LoggerFunc testLogger = logCapture.logger();
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    // Enter in WaitingEndAck phase
    std::thread syncThread([this]()
    {
        std::vector<PersistedData> testData =
        {
            {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1}
        };

        EXPECT_CALL(*mockQueue, fetchAndMarkForSync(_) )
        .WillOnce(Return(testData));

        protocol->synchronizeModule(
            Mode::DELTA
        );
    });

    // Wait for WaitingStartAck phase
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck

    // Wait for WaitingEndAck phase
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // EndAck with ERROR status
    bool response = feedHttpResult(500);  // was Status::Error

    EXPECT_TRUE(response);

    syncThread.join();

    // Transient manager-reported failures must be debug, not error (issue #36724).
    logCapture.expectDebugNotError("Manager reported a protocol error (500)");
    logCapture.expectDebugNotError("Synchronization failed: Manager reported an error status.");
}

TEST_F(AgentSyncProtocolTest, ParseResponseBufferWithEndAckOffline)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LogCapture logCapture;
    LoggerFunc testLogger = logCapture.logger();
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    // Enter in WaitingEndAck phase
    std::thread syncThread([this]()
    {
        std::vector<PersistedData> testData =
        {
            {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1}
        };

        EXPECT_CALL(*mockQueue, fetchAndMarkForSync(_) )
        .WillOnce(Return(testData));

        protocol->synchronizeModule(
            Mode::DELTA
        );
    });

    // Wait for WaitingStartAck phase
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck

    // Wait for WaitingEndAck phase
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // EndAck with OFFLINE status
    bool response = feedHttpResult(503);  // was Status::Offline

    EXPECT_TRUE(response);

    syncThread.join();

    // Offline EndAck is the same transient class: debug, not error (issue #36724).
    logCapture.expectDebugNotError("Manager reported not ready (503)");
}

TEST_F(AgentSyncProtocolTest, ParseResponseBufferWithEndAckCompressionRejected)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LogCapture logCapture;
    LoggerFunc testLogger = logCapture.logger();
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    // Enter in WaitingEndAck phase
    std::thread syncThread([this]()
    {
        std::vector<PersistedData> testData =
        {
            {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1}
        };

        EXPECT_CALL(*mockQueue, fetchAndMarkForSync(_) )
        .WillOnce(Return(testData));

        protocol->synchronizeModule(
            Mode::DELTA
        );
    });

    // Wait for WaitingStartAck phase
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck

    // Wait for WaitingEndAck phase
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // EndAck with 415: the manager rejected Content-Encoding: zstd. RetrySender's
    // own one-shot retry already absorbs this in the common case; this is the
    // rare compound-failure path where a raw 415 reaches the protocol layer.
    bool response = feedHttpResult(415);

    EXPECT_TRUE(response);

    syncThread.join();

    // Treated like 503 -- transient, retried next cycle, not a hard protocol
    // violation that would drop the session's data.
    logCapture.expectDebugNotError("Manager rejected the compressed encoding (415)");
}

TEST_F(AgentSyncProtocolTest, ParseResponseBufferWithEndAckSuccess)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    // Enter in WaitingEndAck phase
    std::thread syncThread([this]()
    {
        std::vector<PersistedData> testData =
        {
            {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1}
        };

        EXPECT_CALL(*mockQueue, fetchAndMarkForSync(_) )
        .WillOnce(Return(testData))
        .WillRepeatedly(Return(std::vector<PersistedData> {}));

        protocol->synchronizeModule(
            Mode::DELTA
        );
    });

    // Wait for WaitingStartAck phase
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck

    // Wait for WaitingEndAck phase
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // EndAck with OK status
    bool response = feedHttpResult(200);  // was Status::Ok

    EXPECT_TRUE(response);

    syncThread.join();
}


TEST_F(AgentSyncProtocolTest, ParseResponseBufferWithUnknownMessageType)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    flatbuffers::FlatBufferBuilder builder;

    auto message = Wazuh::SyncSchema::CreateMessage(builder);
    builder.Finish(message);

    const uint8_t* buffer = builder.GetBufferPointer();
    bool response = protocol->parseResponseBuffer(buffer, builder.GetSize());

    EXPECT_FALSE(response);
}

// Tests for requiresFullSync
TEST_F(AgentSyncProtocolTest, RequiresFullSyncWithMatchingChecksum)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    const std::string testIndex = "test_index";
    const std::string testChecksum = "matching_checksum";

    // Expect NO calls to database methods since no data needs to be sent
    EXPECT_CALL(*mockQueue, fetchAndMarkForSync(_) )
    .Times(0);

    // Start requiresFullSync in a separate thread
    std::thread syncThread([this, &testIndex, &testChecksum]()
    {
        bool result = protocol->requiresFullSync(
                          testIndex,
                          testChecksum
                      );
        EXPECT_FALSE(result);
    });

    // Wait for start message
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck with matching checksum status

    // Wait for checksum message
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // EndAck with matching checksum (Status::Ok)
    feedHttpResult(200);  // was Status::Ok

    syncThread.join();
}

// A single 409 no longer means "full sync required" -- the manager's old internal
// retry-against-indexer loop moved to the agent (2026-08-04, #38117/#38128), so this
// now takes CHECKSUM_MISMATCH_MAX_ATTEMPTS (5) consecutive 409s before the agent
// trusts the mismatch as genuine.
TEST_F(AgentSyncProtocolTest, RequiresFullSyncWithNonMatchingChecksum)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    const std::string testIndex = "test_index";
    const std::string testChecksum = "non_matching_checksum";

    // Expect NO calls to database methods since no data needs to be sent
    EXPECT_CALL(*mockQueue, fetchAndMarkForSync(_) )
    .Times(0);

    bool result = false;
    std::thread syncThread([this, &testIndex, &testChecksum, &result]()
    {
        result = protocol->requiresFullSync(testIndex, testChecksum);
    });

    int handled = 0;
    int lastSendCount = 0;

    while (handled < 5)
    {
        const int currentSendCount = mockSyncTransport->sendCount();

        if (currentSendCount > lastSendCount)
        {
            lastSendCount = currentSendCount;
            feedHttpResult(409);  // was Status::ChecksumMismatch
            ++handled;
            continue;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    syncThread.join();
    EXPECT_TRUE(result);
    EXPECT_EQ(mockSyncTransport->sendCount(), 5);
}

// The whole point of moving the retry budget to the agent: a checksum mismatch caused
// by the indexer not having caught up with a recent bulk write yet must resolve on
// retry, not force a full sync.
TEST_F(AgentSyncProtocolTest, RequiresFullSyncRecoversAfterTransientMismatch)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    const std::string testIndex = "test_index";
    const std::string testChecksum = "test_checksum";

    bool result = true;
    std::thread syncThread([this, &testIndex, &testChecksum, &result]()
    {
        result = protocol->requiresFullSync(testIndex, testChecksum);
    });

    // First attempt: 409 (indexer hasn't caught up yet).
    EXPECT_TRUE(mockSyncTransport->waitForSession());
    feedHttpResult(409);

    // Second attempt: 200 (indexer caught up) -- must NOT need all 5 attempts.
    const int sendCountBefore = mockSyncTransport->sendCount();

    while (mockSyncTransport->sendCount() <= sendCountBefore)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    feedHttpResult(200);

    syncThread.join();
    EXPECT_FALSE(result);
    EXPECT_EQ(mockSyncTransport->sendCount(), 2);
}

TEST_F(AgentSyncProtocolTest, RequiresFullSyncNoQueueAvailable)
{
    mockQueue = std::make_shared<MockPersistentQueue>();

    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    const std::string testIndex = "test_index";
    const std::string testChecksum = "test_checksum";

    bool result = protocol->requiresFullSync(
                      testIndex,
                      testChecksum
                  );

    EXPECT_FALSE(result);
}

TEST_F(AgentSyncProtocolTest, RequiresFullSyncSendStartFails)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    const std::string testIndex = "test_index";
    const std::string testChecksum = "test_checksum";

    bool result = protocol->requiresFullSync(
                      testIndex,
                      testChecksum
                  );

    EXPECT_FALSE(result);
}

TEST_F(AgentSyncProtocolTest, RequiresFullSyncStartAckTimeout)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    const std::string testIndex = "test_index";
    const std::string testChecksum = "test_checksum";

    bool result = protocol->requiresFullSync(
                      testIndex,
                      testChecksum
                  );

    EXPECT_FALSE(result);
}

// Tests for synchronizeMetadataOrGroups
TEST_F(AgentSyncProtocolTest, SynchronizeMetadataOrGroupsWithMetadataDeltaMode)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    // Expect NO calls to fetchAndMarkForSync since metadata/groups mode doesn't send data items
    EXPECT_CALL(*mockQueue, fetchAndMarkForSync(_) )
    .Times(0);

    // Start synchronizeMetadataOrGroups in a separate thread
    std::thread syncThread([this]()
    {
        std::vector<std::string> testIndices = {"test-index-1", "test-index-2"};
        SyncModuleResult result = protocol->synchronizeMetadataOrGroups(
                                      Mode::METADATA_DELTA,
                                      testIndices,
                                      12345 // globalVersion
                                  );
        EXPECT_TRUE(result.success);
    });

    // Wait for start message
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck

    // Wait for end message
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // EndAck
    feedHttpResult(200);  // was Status::Ok

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeMetadataOrGroupsWithMetadataCheckMode)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    // Expect NO calls to fetchAndMarkForSync since metadata/groups mode doesn't send data items
    EXPECT_CALL(*mockQueue, fetchAndMarkForSync(_) )
    .Times(0);

    // Start synchronizeMetadataOrGroups in a separate thread
    std::thread syncThread([this]()
    {
        std::vector<std::string> testIndices = {"test-index-1", "test-index-2"};
        SyncModuleResult result = protocol->synchronizeMetadataOrGroups(
                                      Mode::METADATA_CHECK,
                                      testIndices,
                                      12345 // globalVersion
                                  );
        EXPECT_TRUE(result.success);
    });

    // Wait for start message
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck

    // Wait for end message
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // EndAck
    feedHttpResult(200);  // was Status::Ok

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeMetadataOrGroupsWithGroupDeltaMode)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    // Expect NO calls to fetchAndMarkForSync since metadata/groups mode doesn't send data items
    EXPECT_CALL(*mockQueue, fetchAndMarkForSync(_) )
    .Times(0);

    // Start synchronizeMetadataOrGroups in a separate thread
    std::thread syncThread([this]()
    {
        std::vector<std::string> testIndices = {"test-index-1", "test-index-2"};
        SyncModuleResult result = protocol->synchronizeMetadataOrGroups(
                                      Mode::GROUP_DELTA,
                                      testIndices,
                                      12345 // globalVersion
                                  );
        EXPECT_TRUE(result.success);
    });

    // Wait for start message
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck

    // Wait for end message
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // EndAck
    feedHttpResult(200);  // was Status::Ok

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeMetadataOrGroupsWithGroupCheckMode)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    // Expect NO calls to fetchAndMarkForSync since metadata/groups mode doesn't send data items
    EXPECT_CALL(*mockQueue, fetchAndMarkForSync(_) )
    .Times(0);

    // Start synchronizeMetadataOrGroups in a separate thread
    std::thread syncThread([this]()
    {
        std::vector<std::string> testIndices = {"test-index-1", "test-index-2"};
        SyncModuleResult result = protocol->synchronizeMetadataOrGroups(
                                      Mode::GROUP_CHECK,
                                      testIndices,
                                      12345 // globalVersion
                                  );
        EXPECT_TRUE(result.success);
    });

    // Wait for start message
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck

    // Wait for end message
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // EndAck
    feedHttpResult(200);  // was Status::Ok

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeMetadataOrGroupsWithInvalidMode)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    // Try with Mode::DELTA (not allowed for synchronizeMetadataOrGroups)
    std::vector<std::string> testIndices = {"test-index-1", "test-index-2"};
    SyncModuleResult result = protocol->synchronizeMetadataOrGroups(
                                  Mode::DELTA,
                                  testIndices,
                                  12345 // globalVersion
                              );

    EXPECT_FALSE(result.success);
}

TEST_F(AgentSyncProtocolTest, SynchronizeMetadataOrGroupsTransportUnavailable)
{
    mockQueue = std::make_shared<MockPersistentQueue>();

    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);
    mockSyncTransport->setAvailable(false);

    std::vector<std::string> testIndices = {"test-index-1", "test-index-2"};
    SyncModuleResult result = protocol->synchronizeMetadataOrGroups(
                                  Mode::METADATA_DELTA,
                                  testIndices,
                                  12345 // globalVersion
                              );

    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.failureReason, "Failed to reach the sync intake socket.");
    // No stop was requested, so the failure must not be flagged as shutdown-induced.
    EXPECT_FALSE(result.stopped);
}

TEST_F(AgentSyncProtocolTest, SynchronizeMetadataOrGroupsSessionTimeout)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    // Don't send any response, causing timeout
    std::vector<std::string> testIndices = {"test-index-1", "test-index-2"};
    SyncModuleResult result = protocol->synchronizeMetadataOrGroups(
                                  Mode::METADATA_CHECK,
                                  testIndices,
                                  12345 // globalVersion
                              );

    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.failureReason, "Timed out waiting for manager response.");
}

TEST_F(AgentSyncProtocolTest, SynchronizeMetadataOrGroupsEndAckTimeout)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    // Start synchronizeMetadataOrGroups in a separate thread
    std::thread syncThread([this]()
    {
        std::vector<std::string> testIndices = {"test-index-1", "test-index-2"};
        SyncModuleResult result = protocol->synchronizeMetadataOrGroups(
                                      Mode::GROUP_DELTA,
                                      testIndices,
                                      12345 // globalVersion
                                  );
        EXPECT_FALSE(result.success);
        EXPECT_EQ(result.failureReason, "Timed out waiting for manager response.");
    });

    // Wait for start message
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // Send StartAck

    // Don't send EndAck, causing timeout

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, SynchronizeMetadataOrGroupsWithEndAckError)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    // Start synchronizeMetadataOrGroups in a separate thread
    std::thread syncThread([this]()
    {
        std::vector<std::string> testIndices = {"test-index-1", "test-index-2"};
        SyncModuleResult result = protocol->synchronizeMetadataOrGroups(
                                      Mode::GROUP_CHECK,
                                      testIndices,
                                      12345 // globalVersion
                                  );
        EXPECT_FALSE(result.success);
    });

    // Wait for start message
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck

    // Wait for end message
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // EndAck with Error status
    feedHttpResult(500);  // was Status::Error

    syncThread.join();
}

// Tests for deleteDatabase
TEST_F(AgentSyncProtocolTest, DeleteDatabaseCallsQueueDeleteDatabase)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    EXPECT_CALL(*mockQueue, deleteDatabase())
    .Times(1);

    EXPECT_NO_THROW(protocol->deleteDatabase());
}

TEST_F(AgentSyncProtocolTest, DeleteDatabaseThrowsOnQueueError)
{
    mockQueue = std::make_shared<MockPersistentQueue>();

    bool errorLogged = false;
    std::string loggedMessage;
    LoggerFunc testLogger = [&errorLogged, &loggedMessage](modules_log_level_t level, const std::string & message)
    {
        if (level == LOG_ERROR && message.find("Failed to delete database") != std::string::npos)
        {
            errorLogged = true;
            loggedMessage = message;
        }
    };

    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    EXPECT_CALL(*mockQueue, deleteDatabase())
    .WillOnce(::testing::Throw(std::runtime_error("Database deletion failed")));

    EXPECT_NO_THROW(protocol->deleteDatabase());
    EXPECT_TRUE(errorLogged);
    EXPECT_NE(loggedMessage.find("Database deletion failed"), std::string::npos);
}

// Tests for notifyDataClean
TEST_F(AgentSyncProtocolTest, NotifyDataCleanWithEmptyIndices)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    std::vector<std::string> emptyIndices;

    // Should not call any queue methods with empty indices
    EXPECT_CALL(*mockQueue, clearItemsByIndex(_))
    .Times(0);

    bool result = protocol->notifyDataClean(emptyIndices);

    EXPECT_FALSE(result); // Should fail with empty indices
}

TEST_F(AgentSyncProtocolTest, NotifyDataCleanNoQueueAvailable)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    std::vector<std::string> indices = {"test_index_1", "test_index_2"};

    // Should not call clearItemsByIndex when queue is not available
    EXPECT_CALL(*mockQueue, clearItemsByIndex(_))
    .Times(0);

    bool result = protocol->notifyDataClean(indices);

    EXPECT_FALSE(result);
}

TEST_F(AgentSyncProtocolTest, NotifyDataCleanSendStartFails)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    std::vector<std::string> indices = {"test_index_1", "test_index_2"};

    // Should not call clearItemsByIndex when send fails
    EXPECT_CALL(*mockQueue, clearItemsByIndex(_))
    .Times(0);

    bool result = protocol->notifyDataClean(indices);

    EXPECT_FALSE(result);
}

TEST_F(AgentSyncProtocolTest, NotifyDataCleanStartAckTimeout)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    std::vector<std::string> indices = {"test_index_1"};

    // Should not call clearItemsByIndex when StartAck times out
    EXPECT_CALL(*mockQueue, clearItemsByIndex(_))
    .Times(0);

    bool result = protocol->notifyDataClean(indices);

    EXPECT_FALSE(result); // Should fail due to timeout
}

TEST_F(AgentSyncProtocolTest, NotifyDataCleanStartAckError)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    std::vector<std::string> indices = {"test_index_1"};

    // Should not call clearItemsByIndex when StartAck has error
    EXPECT_CALL(*mockQueue, clearItemsByIndex(_))
    .Times(0);

    // Start synchronization in background
    std::thread syncThread([this, &indices]()
    {
        bool result = protocol->notifyDataClean(indices);
        EXPECT_FALSE(result); // Should fail due to manager error
    });

    EXPECT_TRUE(mockSyncTransport->waitForSession());

    // Send StartAck with ERROR status

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, NotifyDataCleanEndAckTimeout)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    std::vector<std::string> indices = {"test_index_1"};

    // Should not call clearItemsByIndex when EndAck times out
    EXPECT_CALL(*mockQueue, clearItemsByIndex(_))
    .Times(0);

    // Start synchronization in background
    std::thread syncThread([this, &indices]()
    {
        bool result = protocol->notifyDataClean(indices);
        EXPECT_FALSE(result); // Should fail due to timeout
    });

    EXPECT_TRUE(mockSyncTransport->waitForSession());

    // Send StartAck with OK status

    // Wait for data messages
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // Don't send EndAck to cause timeout
    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, NotifyDataCleanEndAckError)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    std::vector<std::string> indices = {"test_index_1"};

    // Should not call clearItemsByIndex when EndAck has error
    EXPECT_CALL(*mockQueue, clearItemsByIndex(_))
    .Times(0);

    // Start synchronization in background
    std::thread syncThread([this, &indices]()
    {
        bool result = protocol->notifyDataClean(indices);
        EXPECT_FALSE(result); // Should fail due to manager error
    });

    EXPECT_TRUE(mockSyncTransport->waitForSession());

    // Send StartAck with OK status

    // Wait for data messages
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // Send EndAck with ERROR status
    feedHttpResult(500);  // was Status::Error

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, NotifyDataCleanClearItemsByIndexThrows)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    std::vector<std::string> indices = {"test_index_1"};

    // clearItemsByIndex should be called but throw exception
    EXPECT_CALL(*mockQueue, clearItemsByIndex("test_index_1"))
    .WillOnce(::testing::Throw(std::runtime_error("Clear items failed")));

    // Start synchronization in background
    std::thread syncThread([this, &indices]()
    {
        bool result = protocol->notifyDataClean(indices);
        EXPECT_FALSE(result); // Should fail due to clearItemsByIndex exception
    });

    EXPECT_TRUE(mockSyncTransport->waitForSession());

    // Send StartAck with OK status

    // Wait for data messages
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // Send EndAck with OK status
    feedHttpResult(200);  // was Status::Ok

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, NotifyDataCleanSuccessWithSingleIndex)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    std::vector<std::string> indices = {"test_index_1"};

    // clearItemsByIndex should be called once for successful notification
    EXPECT_CALL(*mockQueue, clearItemsByIndex("test_index_1"))
    .Times(1);

    // Start synchronization in background
    std::thread syncThread([this, &indices]()
    {
        bool result = protocol->notifyDataClean(indices);
        EXPECT_TRUE(result); // Should succeed
    });

    EXPECT_TRUE(mockSyncTransport->waitForSession());

    // Send StartAck with OK status

    // Wait for data messages
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // Send EndAck with OK status
    feedHttpResult(200);  // was Status::Ok

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, NotifyDataCleanSuccessWithMultipleIndices)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    std::vector<std::string> indices = {"test_index_1", "test_index_2", "test_index_3"};

    // clearItemsByIndex should be called once for each index
    EXPECT_CALL(*mockQueue, clearItemsByIndex("test_index_1"))
    .Times(1);
    EXPECT_CALL(*mockQueue, clearItemsByIndex("test_index_2"))
    .Times(1);
    EXPECT_CALL(*mockQueue, clearItemsByIndex("test_index_3"))
    .Times(1);

    // Start synchronization in background
    std::thread syncThread([this, &indices]()
    {
        bool result = protocol->notifyDataClean(indices);
        EXPECT_TRUE(result); // Should succeed
    });

    EXPECT_TRUE(mockSyncTransport->waitForSession());

    // Send StartAck with OK status

    // Wait for data messages
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // Send EndAck with OK status
    feedHttpResult(200);  // was Status::Ok

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, NotifyDataCleanNoAnswerLeavesDatabaseUntouched)
{
    mockQueue = std::make_shared<MockPersistentQueue>();

    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    std::vector<std::string> indices = {"test_index_1"};

    // The manager never answers the session, so the local database must stay untouched.
    EXPECT_CALL(*mockQueue, clearItemsByIndex(_))
    .Times(0);

    // Start synchronization in background
    std::thread syncThread([this, &indices]()
    {
        bool result = protocol->notifyDataClean(indices);
        EXPECT_FALSE(result); // Fails: no answer ever arrives.
    });

    EXPECT_TRUE(mockSyncTransport->waitForSession());

    syncThread.join();
}

// ============================================================================
// Tests for Optional Database Path (No Persistence Mode)
// ============================================================================

TEST_F(AgentSyncProtocolTest, ConstructionWithoutDbPathSuccess)
{
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};

    // Construct without dbPath
    EXPECT_NO_THROW(
    {
        protocol = std::make_unique<AgentSyncProtocol>("test_module", std::nullopt, testLogger, nullptr, mockSyncTransport);
    });
}

TEST_F(AgentSyncProtocolTest, PersistDifferenceLogsErrorWithoutQueue)
{

    // Capture logger output
    std::string loggedMessage;
    modules_log_level_t loggedLevel;
    LoggerFunc testLogger = [&loggedMessage, &loggedLevel](modules_log_level_t level, const std::string & msg)
    {
        loggedLevel = level;
        loggedMessage = msg;
    };

    // Construct without dbPath and without queue
    protocol = std::make_unique<AgentSyncProtocol>("test_module", std::nullopt, testLogger, nullptr, mockSyncTransport);

    // persistDifference should log error when no queue is available
    protocol->persistDifference("id1", Operation::CREATE, "index1", "data1", 1);

    // Verify error was logged
    EXPECT_EQ(loggedLevel, LOG_ERROR);
    EXPECT_TRUE(loggedMessage.find("Failed to persist item") != std::string::npos);
    EXPECT_TRUE(loggedMessage.find("requires a persistent queue") != std::string::npos);
}

TEST_F(AgentSyncProtocolTest, DeltaModeSyncLogsErrorWithoutQueue)
{

    // Capture logger output
    std::string loggedMessage;
    modules_log_level_t loggedLevel;
    LoggerFunc testLogger = [&loggedMessage, &loggedLevel](modules_log_level_t level, const std::string & msg)
    {
        loggedLevel = level;
        loggedMessage = msg;
    };

    // Construct without dbPath
    protocol = std::make_unique<AgentSyncProtocol>("test_module", std::nullopt, testLogger, nullptr, mockSyncTransport);

    // DELTA mode should return false and log error when no queue is available
    SyncModuleResult result = protocol->synchronizeModule(Mode::DELTA);

    EXPECT_FALSE(result.success);
    EXPECT_EQ(loggedLevel, LOG_ERROR);
    EXPECT_TRUE(loggedMessage.find("Failed to initialize DELTA sync") != std::string::npos);
    EXPECT_TRUE(loggedMessage.find("requires a persistent queue") != std::string::npos);
}

TEST_F(AgentSyncProtocolTest, NotifyDataCleanLogsErrorWithoutQueue)
{

    // Capture logger output
    std::vector<std::string> loggedMessages;
    std::vector<modules_log_level_t> loggedLevels;
    LoggerFunc testLogger = [&loggedMessages, &loggedLevels](modules_log_level_t level, const std::string & msg)
    {
        loggedLevels.push_back(level);
        loggedMessages.push_back(msg);
    };

    // Construct without dbPath
    protocol = std::make_unique<AgentSyncProtocol>("test_module", std::nullopt, testLogger, nullptr, mockSyncTransport);

    std::vector<std::string> indices = {"test_index_1"};

    // Start synchronization in background
    std::thread syncThread([this, &indices]()
    {
        bool result = protocol->notifyDataClean(indices);
        EXPECT_FALSE(result); // Should fail due to clearItemsByIndex exception
    });


    // Send StartAck with OK status

    // Wait for DataClean to be sent
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // Send EndAck with OK status
    feedHttpResult(200);  // was Status::Ok

    syncThread.join();

    // Verify error was logged
    bool foundError = false;

    for (const auto& msg : loggedMessages)
    {
        if (msg.find("Failed to clear items by index") != std::string::npos ||
                msg.find("requires a persistent queue") != std::string::npos)
        {
            foundError = true;
            break;
        }
    }

    EXPECT_TRUE(foundError);
}

TEST_F(AgentSyncProtocolTest, DeleteDatabaseLogsErrorWithoutQueue)
{

    // Capture logger output
    std::string loggedMessage;
    modules_log_level_t loggedLevel;
    LoggerFunc testLogger = [&loggedMessage, &loggedLevel](modules_log_level_t level, const std::string & msg)
    {
        loggedLevel = level;
        loggedMessage = msg;
    };

    // Construct without dbPath
    protocol = std::make_unique<AgentSyncProtocol>("test_module", std::nullopt, testLogger, nullptr, mockSyncTransport);

    // deleteDatabase should log error when no queue is available
    protocol->deleteDatabase();

    // Verify error was logged
    EXPECT_EQ(loggedLevel, LOG_ERROR);
    EXPECT_TRUE(loggedMessage.find("Failed to delete database") != std::string::npos);
    EXPECT_TRUE(loggedMessage.find("requires a persistent queue") != std::string::npos);
}

TEST_F(AgentSyncProtocolTest, ParseResponseBufferWithEndAckChecksumMismatch)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&)
    {
    };
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    // Enter in WaitingEndAck phase
    std::thread syncThread(
        [this]()
    {
        std::vector<PersistedData> testData =
        {
            {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1}
        };

        EXPECT_CALL(*mockQueue, fetchAndMarkForSync(_) ).WillOnce(Return(testData));

        SyncModuleResult syncResult = protocol->synchronizeModule(Mode::DELTA);
        EXPECT_FALSE(syncResult.success);
    });

    // Wait for WaitingStartAck phase
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck

    // Wait for WaitingEndAck phase
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // EndAck with ChecksumMismatch status
    bool response = feedHttpResult(409);  // was Status::ChecksumMismatch

    EXPECT_TRUE(response);

    syncThread.join();
}

// 413: the manager rejected the session as larger than its total in-flight budget
// (see the D2 HTTP contract). New behavior - never existed as an EndAck status.
TEST_F(AgentSyncProtocolTest, ParseResponseBufferWithPayloadTooLarge)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&)
    {
    };
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    std::thread syncThread(
        [this]()
    {
        std::vector<PersistedData> testData =
        {
            {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1}
        };

        EXPECT_CALL(*mockQueue, fetchAndMarkForSync(_) ).WillOnce(Return(testData));

        SyncModuleResult syncResult = protocol->synchronizeModule(Mode::DELTA);
        EXPECT_FALSE(syncResult.success);
        EXPECT_FALSE(syncResult.managerNotReady) << "413 is not a manager-not-ready condition";
        EXPECT_NE(syncResult.failureReason.find("too large"), std::string::npos);
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    bool response = feedHttpResult(413, R"({"error":"session exceeds max_inflight_bytes","code":413})");

    EXPECT_TRUE(response);

    syncThread.join();
}

// httpCode 0: no HTTP response at all (timeout/connect/TLS failure/abort) - treated
// like a 503, since the transport layer already exhausted its own retries.
TEST_F(AgentSyncProtocolTest, ParseResponseBufferWithNoHttpResponse)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&)
    {
    };
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    std::thread syncThread(
        [this]()
    {
        std::vector<PersistedData> testData =
        {
            {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1}
        };

        EXPECT_CALL(*mockQueue, fetchAndMarkForSync(_) ).WillOnce(Return(testData));

        SyncModuleResult syncResult = protocol->synchronizeModule(Mode::DELTA);
        EXPECT_FALSE(syncResult.success);
        EXPECT_TRUE(syncResult.managerNotReady);
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    bool response = feedHttpResult(0, "");

    EXPECT_TRUE(response);

    syncThread.join();
}

TEST_F(AgentSyncProtocolTest, ParseResponseBufferWithEndAckGenericError)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&)
    {
    };
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    // Enter in WaitingEndAck phase
    std::thread syncThread(
        [this]()
    {
        std::vector<PersistedData> testData =
        {
            {0, "test_id_1", "test_index_1", "test_data_1", Operation::CREATE, 1}
        };

        EXPECT_CALL(*mockQueue, fetchAndMarkForSync(_) ).WillOnce(Return(testData));

        SyncModuleResult syncResult = protocol->synchronizeModule(Mode::DELTA);
        EXPECT_FALSE(syncResult.success);
    });

    // Wait for WaitingStartAck phase
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // StartAck

    // Wait for WaitingEndAck phase
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // EndAck with Error status (which should map to GENERIC_ERROR)
    bool response = feedHttpResult(500);  // was Status::Error

    EXPECT_TRUE(response);

    syncThread.join();
}

// Test to cover IAgentSyncProtocol D0 destructor (delete through base pointer)
TEST(InterfaceDestructorTest, IAgentSyncProtocolDeletingDestructor)
{
    // Create concrete implementation through base interface pointer
    IAgentSyncProtocol* protocol = nullptr;

    // Set up mock queue
    auto mockQueue = std::make_shared<MockPersistentQueue>();

    // Create mock MQ functions

    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};

    // Create AgentSyncProtocol through base interface pointer
    protocol = new AgentSyncProtocol("test_module", std::nullopt, testLogger, mockQueue, std::make_shared<MockSyncTransport>());

    // Delete through base pointer - this calls D0 destructor
    delete protocol;
}

// ========================================
// Tests for fetchPendingItems()
// ========================================

TEST_F(AgentSyncProtocolTest, fetchPendingItems_WithNullPersistentQueue)
{
    /**
     * Test: fetchPendingItems should throw when persistent queue is null
     * This happens when AgentSyncProtocol is initialized without a dbPath
     */


    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};

    // Create AgentSyncProtocol WITHOUT persistent queue (dbPath = std::nullopt)
    protocol = std::make_unique<AgentSyncProtocol>("test_module", std::nullopt, testLogger, nullptr, mockSyncTransport);

    // fetchPendingItems should catch exception and return empty vector
    auto result = protocol->fetchPendingItems(true);

    EXPECT_TRUE(result.empty());
}

TEST_F(AgentSyncProtocolTest, fetchPendingItems_OnlyDataValues_True)
{
    /**
     * Test: fetchPendingItems with onlyDataValues=true
     * Should fetch only DataValue items (not DataContext)
     */

    mockQueue = std::make_shared<MockPersistentQueue>();


    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};

    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    // Prepare test data - DataValue items only
    std::vector<PersistedData> expectedData;
    PersistedData item1;
    item1.seq = 1;
    item1.id = "hash_id_1";
    item1.index = "wazuh-states-inventory-packages";
    item1.data = R"({"name":"package1","version":"1.0"})";
    item1.operation = Operation::CREATE;
    expectedData.push_back(item1);

    PersistedData item2;
    item2.seq = 2;
    item2.id = "hash_id_2";
    item2.index = "wazuh-states-inventory-system";
    item2.data = R"({"hostname":"test-host"})";
    item2.operation = Operation::MODIFY;
    expectedData.push_back(item2);

    // Mock fetchPendingItems to return DataValue items
    EXPECT_CALL(*mockQueue, fetchPendingItems(true))
    .Times(1)
    .WillOnce(Return(expectedData));

    // Call fetchPendingItems with onlyDataValues=true
    auto result = protocol->fetchPendingItems(true);

    // Verify results
    ASSERT_EQ(result.size(), 2);
    EXPECT_EQ(result[0].seq, 1);
    EXPECT_EQ(result[0].id, "hash_id_1");
    EXPECT_EQ(result[0].index, "wazuh-states-inventory-packages");
    EXPECT_EQ(result[0].operation, Operation::CREATE);
    EXPECT_EQ(result[1].seq, 2);
    EXPECT_EQ(result[1].id, "hash_id_2");
    EXPECT_EQ(result[1].index, "wazuh-states-inventory-system");
    EXPECT_EQ(result[1].operation, Operation::MODIFY);
}

TEST_F(AgentSyncProtocolTest, fetchPendingItems_OnlyDataValues_False)
{
    /**
     * Test: fetchPendingItems with onlyDataValues=false
     * Should fetch both DataValue AND DataContext items
     */

    mockQueue = std::make_shared<MockPersistentQueue>();


    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};

    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    // Prepare test data - Mix of DataValue and DataContext
    std::vector<PersistedData> expectedData;

    // DataValue item
    PersistedData dataValue;
    dataValue.seq = 1;
    dataValue.id = "hash_id_1";
    dataValue.index = "wazuh-states-inventory-packages";
    dataValue.data = R"({"name":"package1","version":"1.0"})";
    dataValue.operation = Operation::CREATE;
    expectedData.push_back(dataValue);

    // DataContext item
    PersistedData dataContext;
    dataContext.seq = 2;
    dataContext.id = "hash_id_2";
    dataContext.index = "wazuh-states-inventory-system";
    dataContext.data = R"({"hostname":"test-host"})";
    dataContext.operation = Operation::MODIFY;
    expectedData.push_back(dataContext);

    // Mock fetchPendingItems to return both types
    EXPECT_CALL(*mockQueue, fetchPendingItems(false))
    .Times(1)
    .WillOnce(Return(expectedData));

    // Call fetchPendingItems with onlyDataValues=false
    auto result = protocol->fetchPendingItems(false);

    // Verify results include both types
    ASSERT_EQ(result.size(), 2);
    EXPECT_EQ(result[0].seq, 1);
    EXPECT_EQ(result[1].seq, 2);
}

TEST_F(AgentSyncProtocolTest, fetchPendingItems_EmptyQueue)
{
    /**
     * Test: fetchPendingItems returns empty vector when queue is empty
     */

    mockQueue = std::make_shared<MockPersistentQueue>();


    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};

    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    // Mock fetchPendingItems to return empty vector
    EXPECT_CALL(*mockQueue, fetchPendingItems(true))
    .Times(1)
    .WillOnce(Return(std::vector<PersistedData>()));

    // Call fetchPendingItems
    auto result = protocol->fetchPendingItems(true);

    // Verify result is empty
    EXPECT_TRUE(result.empty());
}

TEST_F(AgentSyncProtocolTest, fetchPendingItems_MultipleIndices)
{
    /**
     * Test: fetchPendingItems correctly returns items from multiple indices
     * Tests packages, system, and hotfixes indices
     */

    mockQueue = std::make_shared<MockPersistentQueue>();


    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};

    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    // Prepare test data from multiple indices
    std::vector<PersistedData> expectedData;

    PersistedData pkgItem;
    pkgItem.seq = 1;
    pkgItem.id = "pkg_hash_1";
    pkgItem.index = "wazuh-states-inventory-packages";
    pkgItem.data = R"({"name":"vim","version":"8.2"})";
    pkgItem.operation = Operation::CREATE;
    expectedData.push_back(pkgItem);

    PersistedData sysItem;
    sysItem.seq = 2;
    sysItem.id = "sys_hash_1";
    sysItem.index = "wazuh-states-inventory-system";
    sysItem.data = R"({"os_name":"Ubuntu","os_version":"22.04"})";
    sysItem.operation = Operation::MODIFY;
    expectedData.push_back(sysItem);

    PersistedData hfItem;
    hfItem.seq = 3;
    hfItem.id = "hf_hash_1";
    hfItem.index = "wazuh-states-inventory-hotfixes";
    hfItem.data = R"({"hotfix":"KB123456"})";
    hfItem.operation = Operation::CREATE;
    expectedData.push_back(hfItem);

    // Mock fetchPendingItems to return items from all indices
    EXPECT_CALL(*mockQueue, fetchPendingItems(true))
    .Times(1)
    .WillOnce(Return(expectedData));

    // Call fetchPendingItems
    auto result = protocol->fetchPendingItems(true);

    // Verify all items are returned
    ASSERT_EQ(result.size(), 3);
    EXPECT_EQ(result[0].index, "wazuh-states-inventory-packages");
    EXPECT_EQ(result[1].index, "wazuh-states-inventory-system");
    EXPECT_EQ(result[2].index, "wazuh-states-inventory-hotfixes");
}

TEST_F(AgentSyncProtocolTest, fetchPendingItems_DifferentOperations)
{
    /**
     * Test: fetchPendingItems correctly preserves operation types
     * Tests CREATE, MODIFY, and DELETE operations
     */

    mockQueue = std::make_shared<MockPersistentQueue>();


    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};

    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    // Prepare test data with different operations
    std::vector<PersistedData> expectedData;

    PersistedData createItem;
    createItem.seq = 1;
    createItem.id = "create_hash";
    createItem.index = "wazuh-states-inventory-packages";
    createItem.data = R"({"name":"new-package"})";
    createItem.operation = Operation::CREATE;
    expectedData.push_back(createItem);

    PersistedData modifyItem;
    modifyItem.seq = 2;
    modifyItem.id = "modify_hash";
    modifyItem.index = "wazuh-states-inventory-packages";
    modifyItem.data = R"({"name":"updated-package"})";
    modifyItem.operation = Operation::MODIFY;
    expectedData.push_back(modifyItem);

    PersistedData deleteItem;
    deleteItem.seq = 3;
    deleteItem.id = "delete_hash";
    deleteItem.index = "wazuh-states-inventory-packages";
    deleteItem.data = R"({"name":"removed-package"})";
    deleteItem.operation = Operation::DELETE_;
    expectedData.push_back(deleteItem);

    // Mock fetchPendingItems
    EXPECT_CALL(*mockQueue, fetchPendingItems(true))
    .Times(1)
    .WillOnce(Return(expectedData));

    // Call fetchPendingItems
    auto result = protocol->fetchPendingItems(true);

    // Verify operations are preserved
    ASSERT_EQ(result.size(), 3);
    EXPECT_EQ(result[0].operation, Operation::CREATE);
    EXPECT_EQ(result[1].operation, Operation::MODIFY);
    EXPECT_EQ(result[2].operation, Operation::DELETE_);
}

TEST_F(AgentSyncProtocolTest, fetchPendingItems_ExceptionHandling)
{
    /**
     * Test: fetchPendingItems handles exceptions and returns empty vector
     * Verifies graceful error handling when persistent queue throws
     */

    mockQueue = std::make_shared<MockPersistentQueue>();


    bool loggerCalled = false;
    LoggerFunc testLogger = [&loggerCalled](modules_log_level_t level, const std::string & msg)
    {
        if (level == LOG_ERROR && msg.find("Failed to fetch pending items") != std::string::npos)
        {
            loggerCalled = true;
        }
    };

    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    // Mock fetchPendingItems to throw exception
    EXPECT_CALL(*mockQueue, fetchPendingItems(true))
    .Times(1)
    .WillOnce(testing::Throw(std::runtime_error("Database error")));

    // Call fetchPendingItems - should catch exception and return empty
    auto result = protocol->fetchPendingItems(true);

    // Verify error handling
    EXPECT_TRUE(result.empty());
    EXPECT_TRUE(loggerCalled);
}

TEST_F(AgentSyncProtocolTest, fetchPendingItems_LargeDataSet)
{
    /**
     * Test: fetchPendingItems handles large number of items
     * Verifies performance and correctness with many items
     */

    mockQueue = std::make_shared<MockPersistentQueue>();


    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};

    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    // Prepare large dataset (1000 items)
    std::vector<PersistedData> expectedData;

    for (int i = 0; i < 1000; ++i)
    {
        PersistedData item;
        item.seq = i + 1;
        item.id = "hash_id_" + std::to_string(i);
        item.index = "wazuh-states-inventory-packages";
        item.data = R"({"name":"package)" + std::to_string(i) + R"("})";
        item.operation = Operation::CREATE;
        expectedData.push_back(item);
    }

    // Mock fetchPendingItems to return large dataset
    EXPECT_CALL(*mockQueue, fetchPendingItems(true))
    .Times(1)
    .WillOnce(Return(expectedData));

    // Call fetchPendingItems
    auto result = protocol->fetchPendingItems(true);

    // Verify all items are returned correctly
    ASSERT_EQ(result.size(), 1000);
    EXPECT_EQ(result[0].seq, 1);
    EXPECT_EQ(result[999].seq, 1000);
    EXPECT_EQ(result[0].id, "hash_id_0");
    EXPECT_EQ(result[999].id, "hash_id_999");
}

TEST_F(AgentSyncProtocolTest, fetchPendingItems_SequenceNumberOrdering)
{
    /**
     * Test: fetchPendingItems returns items in correct sequence order
     * Verifies sequence numbers are properly maintained
     */

    mockQueue = std::make_shared<MockPersistentQueue>();


    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};

    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    // Prepare test data with specific sequence numbers
    std::vector<PersistedData> expectedData;

    PersistedData item1;
    item1.seq = 100;
    item1.id = "hash_100";
    item1.index = "wazuh-states-inventory-packages";
    item1.data = R"({})";
    item1.operation = Operation::CREATE;
    expectedData.push_back(item1);

    PersistedData item2;
    item2.seq = 101;
    item2.id = "hash_101";
    item2.index = "wazuh-states-inventory-packages";
    item2.data = R"({})";
    item2.operation = Operation::CREATE;
    expectedData.push_back(item2);

    PersistedData item3;
    item3.seq = 102;
    item3.id = "hash_102";
    item3.index = "wazuh-states-inventory-packages";
    item3.data = R"({})";
    item3.operation = Operation::CREATE;
    expectedData.push_back(item3);

    // Mock fetchPendingItems
    EXPECT_CALL(*mockQueue, fetchPendingItems(true))
    .Times(1)
    .WillOnce(Return(expectedData));

    // Call fetchPendingItems
    auto result = protocol->fetchPendingItems(true);

    // Verify sequence ordering is maintained
    ASSERT_EQ(result.size(), 3);
    EXPECT_EQ(result[0].seq, 100);
    EXPECT_EQ(result[1].seq, 101);
    EXPECT_EQ(result[2].seq, 102);
}

// ========================================
// Tests for clearAllDataContext()
// ========================================

TEST_F(AgentSyncProtocolTest, clearAllDataContext_WithValidQueue)
{
    /**
     * Test: clearAllDataContext should call clearAllDataContext on the persistent queue
     */

    mockQueue = std::make_shared<MockPersistentQueue>();

    auto logger = [](modules_log_level_t, const std::string&) {};

    protocol = std::make_unique<AgentSyncProtocol>("test_module", std::nullopt, logger, mockQueue, mockSyncTransport);

    // Expect clearAllDataContext to be called once
    EXPECT_CALL(*mockQueue, clearAllDataContext())
    .Times(1);

    // Call clearAllDataContext
    EXPECT_NO_THROW(protocol->clearAllDataContext());
}

TEST_F(AgentSyncProtocolTest, clearAllDataContext_WithNullQueue)
{
    /**
     * Test: clearAllDataContext should handle null persistent queue gracefully
     */


    auto logger = [](modules_log_level_t, const std::string&) {};

    protocol = std::make_unique<AgentSyncProtocol>("test_module", std::nullopt, logger, nullptr, mockSyncTransport);

    // Should not throw when queue is null
    EXPECT_NO_THROW(protocol->clearAllDataContext());
}

TEST_F(AgentSyncProtocolTest, clearAllDataContext_ExceptionHandling)
{
    /**
     * Test: clearAllDataContext should handle exceptions from the persistent queue
     */

    mockQueue = std::make_shared<MockPersistentQueue>();

    auto logger = [](modules_log_level_t, const std::string&) {};

    protocol = std::make_unique<AgentSyncProtocol>("test_module", std::nullopt, logger, mockQueue, mockSyncTransport);

    // Make clearAllDataContext throw an exception
    EXPECT_CALL(*mockQueue, clearAllDataContext())
    .Times(1)
    .WillOnce(::testing::Throw(std::runtime_error("Database error")));

    // Should handle exception gracefully
    EXPECT_NO_THROW(protocol->clearAllDataContext());
}

// ========================================
// Tests for notifyDataClean() with Option parameter
// ========================================

TEST_F(AgentSyncProtocolTest, notifyDataClean_WithSyncOption_EmptyIndices)
{
    /**
     * Test: notifyDataClean should return false when indices vector is empty
     */

    mockQueue = std::make_shared<MockPersistentQueue>();

    auto logger = [](modules_log_level_t, const std::string&) {};

    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", logger, mockQueue, mockSyncTransport);

    std::vector<std::string> emptyIndices;

    // Should return false for empty indices
    bool result = protocol->notifyDataClean(emptyIndices, Option::SYNC);
    EXPECT_FALSE(result);
}

TEST_F(AgentSyncProtocolTest, notifyDataClean_WithSyncOption_MultipleIndices)
{
    /**
     * Test: notifyDataClean should handle multiple indices with SYNC option
     */

    mockQueue = std::make_shared<MockPersistentQueue>();

    auto logger = [](modules_log_level_t, const std::string&) {};

    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", logger, mockQueue, mockSyncTransport);

    std::vector<std::string> indices =
    {
        "wazuh-states-inventory-hardware",
        "wazuh-states-inventory-ports",
        "wazuh-states-inventory-networks"
    };

    // Should handle multiple indices
    EXPECT_NO_THROW(protocol->notifyDataClean(indices, Option::SYNC));
}

TEST_F(AgentSyncProtocolTest, notifyDataClean_DefaultOption)
{
    /**
     * Test: notifyDataClean should use SYNC as default option when not specified
     */

    mockQueue = std::make_shared<MockPersistentQueue>();

    auto logger = [](modules_log_level_t, const std::string&) {};

    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", logger, mockQueue, mockSyncTransport);

    std::vector<std::string> indices = {"wazuh-states-inventory-hardware"};

    // Should use default SYNC option
    EXPECT_NO_THROW(protocol->notifyDataClean(indices));
}

TEST_F(AgentSyncProtocolTest, notifyDataClean_WithNullQueue)
{
    /**
     * Test: notifyDataClean should handle null persistent queue
     */


    auto logger = [](modules_log_level_t, const std::string&) {};

    protocol = std::make_unique<AgentSyncProtocol>("test_module", std::nullopt, logger, nullptr, mockSyncTransport);

    std::vector<std::string> indices = {"wazuh-states-inventory-hardware"};

    // Should handle null queue gracefully
    EXPECT_NO_THROW(protocol->notifyDataClean(indices, Option::SYNC));
}

// ========================================
// Tests for Option enum conversions
// ========================================

TEST_F(AgentSyncProtocolTest, Option_SYNC_Value)
{
    /**
     * Test: Verify Option::SYNC has correct value
     */

    EXPECT_EQ(static_cast<int>(Option::SYNC), OPTION_SYNC);
}

TEST_F(AgentSyncProtocolTest, Option_VDFIRST_Value)
{
    /**
     * Test: Verify Option::VDFIRST has correct value
     */

    EXPECT_EQ(static_cast<int>(Option::VDFIRST), OPTION_VD_FIRST);
}

TEST_F(AgentSyncProtocolTest, Option_VDSYNC_Value)
{
    /**
     * Test: Verify Option::VDSYNC has correct value
     */

    EXPECT_EQ(static_cast<int>(Option::VDSYNC), OPTION_VD_SYNC);
}

// ========================================
// Integration tests for VD workflow
// ========================================

TEST_F(AgentSyncProtocolTest, VDWorkflow_ClearDataContextBeforeSync)
{
    /**
     * Test: VD workflow should clear DataContext before synchronization
     * This simulates the workflow in processVDDataContext()
     */

    mockQueue = std::make_shared<MockPersistentQueue>();

    auto logger = [](modules_log_level_t, const std::string&) {};

    protocol = std::make_unique<AgentSyncProtocol>("syscollector_vd", ":memory:", logger, mockQueue, mockSyncTransport);

    // Step 1: Clear all DataContext
    EXPECT_CALL(*mockQueue, clearAllDataContext())
    .Times(1);

    protocol->clearAllDataContext();

    // Step 2: Fetch pending DataValue items (onlyDataValues=true)
    std::vector<PersistedData> dataValues;
    PersistedData item1;
    item1.seq = 0;
    item1.id = "pkg1";
    item1.index = "wazuh-states-inventory-packages";
    item1.data = R"({"name":"test-pkg"})";
    item1.operation = Operation::CREATE;
    item1.is_data_context = false;
    dataValues.push_back(item1);

    EXPECT_CALL(*mockQueue, fetchPendingItems(true))
    .Times(1)
    .WillOnce(Return(dataValues));

    auto result = protocol->fetchPendingItems(true);
    ASSERT_EQ(result.size(), 1);
    EXPECT_FALSE(result[0].is_data_context);
}

TEST_F(AgentSyncProtocolTest, VDWorkflow_FetchOnlyDataValues)
{
    /**
     * Test: VD workflow should be able to fetch only DataValue items
     * excluding DataContext items
     */

    mockQueue = std::make_shared<MockPersistentQueue>();

    auto logger = [](modules_log_level_t, const std::string&) {};

    protocol = std::make_unique<AgentSyncProtocol>("syscollector_vd", ":memory:", logger, mockQueue, mockSyncTransport);

    // Create mixed data (DataValue and DataContext)
    std::vector<PersistedData> allData;

    PersistedData dataValue;
    dataValue.seq = 0;
    dataValue.id = "os1";
    dataValue.index = "wazuh-states-inventory-system";
    dataValue.data = R"({"os_name":"Linux"})";
    dataValue.operation = Operation::MODIFY;
    dataValue.is_data_context = false;
    allData.push_back(dataValue);

    PersistedData dataContext;
    dataContext.seq = 1;
    dataContext.id = "ctx1";
    dataContext.index = "wazuh-states-inventory-packages";
    dataContext.data = R"({"context":"data"})";
    dataContext.operation = Operation::MODIFY;
    dataContext.is_data_context = true;
    allData.push_back(dataContext);

    // When fetching only DataValues, should return only non-context items
    std::vector<PersistedData> onlyDataValues = {dataValue};

    EXPECT_CALL(*mockQueue, fetchPendingItems(true))
    .Times(1)
    .WillOnce(Return(onlyDataValues));

    auto result = protocol->fetchPendingItems(true);
    ASSERT_EQ(result.size(), 1);
    EXPECT_FALSE(result[0].is_data_context);
    EXPECT_EQ(result[0].index, "wazuh-states-inventory-system");
}

// ========================================
// Tests for EndAck{Processing} behavior
// ========================================

// Verifies that EndAck{Processing} is correctly parsed and the sync continues waiting.
// After Processing, the protocol must accept a subsequent EndAck{Ok} and complete.
namespace
{
    std::mutex END_RETRY_TEST_MTX;
    std::condition_variable END_RETRY_TEST_CV;
    int END_RETRY_TEST_MSG_COUNT = 0;

    int endRetryTestSendBinary(int, const void*, size_t, const char*, char)
    {
        {
            std::lock_guard<std::mutex> lock(END_RETRY_TEST_MTX);
            ++END_RETRY_TEST_MSG_COUNT;
        }
        END_RETRY_TEST_CV.notify_all();
        return 0;
    }
} // namespace

namespace
{
    std::mutex END_FAIL_TEST_MTX;
    std::condition_variable END_FAIL_TEST_CV;
    int END_FAIL_TEST_MSG_COUNT = 0;
    std::atomic<bool> END_FAIL_TEST_FAIL_MODE{false};

    int endFailTestSendBinary(int, const void*, size_t, const char*, char)
    {
        // Once fail mode is on, simulate the local socket being gone (as during restart).
        if (END_FAIL_TEST_FAIL_MODE.load())
        {
            return -1;
        }

        {
            std::lock_guard<std::mutex> lock(END_FAIL_TEST_MTX);
            ++END_FAIL_TEST_MSG_COUNT;
        }

        END_FAIL_TEST_CV.notify_all();
        return 0;
    }
} // namespace

// Verifies that m_syncInProgress guards against concurrent synchronizeModule() calls.
//
// Two threads call synchronizeModule() on the same instance simultaneously. The first
// thread is held inside the method (blocked waiting for StartAck). While it is blocked,
// the second thread's call must return true immediately without touching the in-flight
// session state. If the guard were absent the second caller would call clearSyncState(),
// resetting the session ID and flags mid-handshake and causing the first call to fail.
//
// The test confirms:
//   1. The concurrent call returns true quickly (skipped, not queued).
//   2. The in-flight sync completes successfully (session state was not corrupted).
//   3. m_syncInProgress is cleared after the first call, so a subsequent call can run.
TEST_F(AgentSyncProtocolTest, SynchronizeModuleConcurrentCallIsSkippedAndDoesNotCorruptSession)
{
    mockQueue = std::make_shared<MockPersistentQueue>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    protocol = std::make_unique<AgentSyncProtocol>("test_module", ":memory:", testLogger, mockQueue, mockSyncTransport);

    std::vector<PersistedData> testData =
    {
        {0, "id1", "idx1", "data1", Operation::CREATE, 1},
    };

    // First call fetches data and runs a full sync; second concurrent call finds an
    // empty queue (or is blocked by the guard before reaching the queue).
    EXPECT_CALL(*mockQueue, fetchAndMarkForSync(_) )
    .WillOnce(Return(testData))     // first (in-flight) call
    .WillRepeatedly(Return(std::vector<PersistedData> {})); // any subsequent call
    EXPECT_CALL(*mockQueue, clearSyncedItems()).Times(1);

    // Thread 1: starts the in-flight sync (will block waiting for StartAck).
    std::promise<SyncModuleResult> firstResult;
    auto firstFuture = firstResult.get_future();
    std::thread syncThread([this, &firstResult]()
    {
        firstResult.set_value(protocol->synchronizeModule(Mode::DELTA));
    });

    // Give Thread 1 time to enter synchronizeModule() and park waiting for the session answer.
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    // Thread 2: concurrent call while Thread 1 is in-flight.
    // Must return true immediately without touching the session state.
    auto concurrentFuture = std::async(std::launch::async, [this]()
    {
        return protocol->synchronizeModule(Mode::DELTA);
    });

    // The concurrent call must complete quickly (it is skipped, not blocked).
    auto status = concurrentFuture.wait_for(std::chrono::seconds(2));
    ASSERT_EQ(status, std::future_status::ready) << "Concurrent call did not return quickly — likely blocked inside synchronizeModule instead of being skipped";
    EXPECT_TRUE(concurrentFuture.get().success) << "Concurrent call should return true (skipped, not an error)";

    // Complete Thread 1's sync normally: StartAck then EndAck.
    {
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));
    {
        feedHttpResult(200);  // was Status::Ok
    }

    syncThread.join();

    // Thread 1 must have succeeded — session state was not corrupted by the concurrent call.
    EXPECT_TRUE(firstFuture.get().success) << "In-flight sync failed, likely due to session state corruption from concurrent call";

    // After Thread 1 completes, m_syncInProgress must be cleared.
    // A fresh call with an empty queue must run to completion (not be skipped).
    EXPECT_TRUE(protocol->synchronizeModule(Mode::DELTA).success) << "Post-sync call was skipped — m_syncInProgress was not reset after completion";
}
