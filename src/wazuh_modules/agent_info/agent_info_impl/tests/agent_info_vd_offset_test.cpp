#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <agent_info_impl.hpp>

#include <dbsync.hpp>
#include <mock_dbsync.hpp>
#include <metadata_provider.h>

#include <cstring>
#include <filesystem>
#include <memory>
#include <string>

/**
 * @brief Tests for the durable VD feed offset + pending-rescan state
 * (AgentInfoImpl::observeVdFeedOffset/clearVdRescanPending/getVdFeedState),
 * backed by the `vd_feed_state` table, and its VDFirst-done gate (issue
 * #38204: agent-driven VD re-scan coordination).
 *
 * DBSync is mocked, same as agent_info_dbsync_test.cpp: selectRows() is
 * intercepted to simulate what the `vd_feed_state` row would contain, and
 * handle() returns nullptr (writeVdFeedStateLocked's DBSyncTxn path is a
 * no-op under this mock, same limitation the existing db_metadata/setSyncFlag
 * tests already accept) -- these tests verify the RETURN-VALUE contract and
 * which queries fire, not that a write actually lands in a real DB.
 */
class AgentInfoVdOffsetTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            // Create directory for shared memory file (required on Unix/macOS), same as
            // agent_info_integrity_test.cpp: the metadata_provider tests below construct the
            // real SharedMemoryProvider singleton, which opens "var/run/.wazuh_agent_metadata"
            // relative to the test binary's cwd. Not currently reachable in CI (an earlier test
            // file in the same build dir creates the directory first), but this test should not
            // depend on that ordering to pass in isolation.
            std::filesystem::create_directories("var/run");

            m_mockDBSync = std::make_shared<MockDBSync>();

            EXPECT_CALL(*m_mockDBSync, handle())
            .WillRepeatedly(::testing::Return(nullptr));

            m_logFunc = [this](modules_log_level_t level, const std::string & msg)
            {
                m_logMessages.push_back({level, msg});
                m_logOutput += msg + "\n";
            };
        }

        void TearDown() override
        {
            m_agentInfo.reset();
            m_mockDBSync.reset();
        }

        /// A queryModuleFunc that answers get_vd_first_sync_completed with a fixed
        /// value and records whether it was called.
        std::function<int(const std::string&, const std::string&, char**)> vdFirstSyncQueryFunc(bool done)
        {
            return [this, done](const std::string & moduleName, const std::string & query, char** response) -> int
            {
                m_queryModuleCalls.push_back(moduleName + ":" + query);

                nlohmann::json commandJson = nlohmann::json::parse(query);
                const auto command = commandJson.at("command").get<std::string>();

                nlohmann::json responseJson;
                responseJson["error"] = 0;

                if (command == "get_vd_first_sync_completed")
                {
                    responseJson["data"]["vd_first_sync_completed"] = done ? 1 : 0;
                }
                else if (command == "get_vd_scan_owed")
                {
                    if (m_getOwedFails)
                    {
                        responseJson["error"] = 1; // syscollector is not answering yet
                    }
                    else
                    {
                        responseJson["data"]["vd_scan_owed"] = m_vdScanOwed;
                        responseJson["data"]["skips"] = m_vdScanOwedSkips;
                    }
                }
                else if (command == "clear_vd_scan_owed")
                {
                    const auto& parameters = commandJson.at("parameters");
                    const auto value = parameters.at("value").get<int64_t>();
                    m_clearedOwed.push_back(value);

                    if (m_raiseOwedBeforeClear)
                    {
                        // A skip syscollector recorded between agent-info's read and this clear.
                        m_vdScanOwed = *m_raiseOwedBeforeClear;
                        m_raiseOwedBeforeClear.reset();
                    }

                    if (m_clearFails)
                    {
                        responseJson["error"] = 1; // syscollector could not write its metadata
                    }
                    else if (m_vdScanOwed > value || (m_vdScanOwed < 0 && value != m_vdScanOwed) ||
                             (m_vdScanOwed != 0 && parameters.at("skips").get<uint64_t>() != m_vdScanOwedSkips))
                    {
                        // Compare-and-clear: raised, reset or skipped again since it was read, left
                        // in place.
                        responseJson["data"]["vd_scan_owed"] = m_vdScanOwed;
                        responseJson["data"]["skips"] = m_vdScanOwedSkips;
                    }
                    else
                    {
                        m_vdScanOwed = 0;
                        responseJson["data"]["vd_scan_owed"] = 0;
                        responseJson["data"]["skips"] = m_vdScanOwedSkips;
                    }
                }

                const std::string responseStr = responseJson.dump();
                * response = strdup(responseStr.c_str());
                return 0;
            };
        }

        /// Simulates the `vd_feed_state` row not existing yet (fresh DB).
        static void expectNotFound(std::shared_ptr<MockDBSync>& mockDBSync)
        {
            EXPECT_CALL(*mockDBSync, selectRows(::testing::_, ::testing::_))
            .WillOnce(::testing::Invoke([](const nlohmann::json & query, ResultCallbackData)
            {
                EXPECT_EQ("vd_feed_state", query.at("table").get<std::string>());
                // No callback invocation: simulates "row not found".
            }));
        }

        /// Simulates the `vd_feed_state` row already holding the given state.
        static void expectStoredState(std::shared_ptr<MockDBSync>& mockDBSync, uint64_t offset,
                                      bool pending, uint64_t pendingOffset)
        {
            EXPECT_CALL(*mockDBSync, selectRows(::testing::_, ::testing::_))
            .WillOnce(::testing::Invoke([offset, pending, pendingOffset](const nlohmann::json&,
                                                                         ResultCallbackData callback)
            {
                nlohmann::json row;
                row["has_offset"] = 1;
                row["last_offset"] = static_cast<int64_t>(offset);
                row["pending"] = pending ? 1 : 0;
                row["pending_offset"] = static_cast<int64_t>(pendingOffset);
                callback(SELECTED, row);
            }));
        }

        std::shared_ptr<MockDBSync> m_mockDBSync;
        std::shared_ptr<AgentInfoImpl> m_agentInfo;
        std::function<void(const modules_log_level_t, const std::string&)> m_logFunc;
        std::vector<std::string> m_queryModuleCalls;
        /// What the fake syscollector answers to get_vd_scan_owed: 0 none, 1 a
        /// scan, 2 a first scan, -1 a reset.
        int64_t m_vdScanOwed {0};
        /// The skip count the fake syscollector reports with its record and clears against.
        uint64_t m_vdScanOwedSkips {0};
        /// Makes the fake syscollector fail get_vd_scan_owed.
        bool m_getOwedFails {false};
        /// The `value` of every clear_vd_scan_owed the takeover sent.
        std::vector<int64_t> m_clearedOwed;
        /// Makes the fake syscollector fail clear_vd_scan_owed, leaving its record in place.
        bool m_clearFails {false};
        /// Raises the fake syscollector's record to this value just before its next clear.
        std::optional<int64_t> m_raiseOwedBeforeClear;

        /// The owed-scan probes alone.
        size_t owedProbes() const
        {
            size_t probes = 0;

            for (const auto& call : m_queryModuleCalls)
            {
                probes += call.find("get_vd_scan_owed") != std::string::npos ? 1 : 0;
            }

            return probes;
        }

        /// The VDFirst-completion queries alone: the owed-scan takeover polls syscollector on every
        /// observation too, which the gate tests below do not count.
        std::vector<std::string> firstSyncQueries() const
        {
            std::vector<std::string> queries;

            for (const auto& call : m_queryModuleCalls)
            {
                if (call.find("get_vd_first_sync_completed") != std::string::npos)
                {
                    queries.push_back(call);
                }
            }

            return queries;
        }
        std::string m_logOutput;
        std::vector<std::pair<modules_log_level_t, std::string>> m_logMessages;
};

// A shutdown can race observeVdFeedOffset() against releaseResources() closing the same
// DBSync handle; that race is expected and harmless, so it must log at DEBUG during
// shutdown (verified below) and WARNING otherwise.
TEST_F(AgentInfoVdOffsetTest, ObserveFailsClosedWithoutDBSync)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(":memory:", nullptr, m_logFunc,
                                                  vdFirstSyncQueryFunc(true), m_mockDBSync);
    m_agentInfo->releaseResources(); // Drops the DBSync connection, no shutdown signaled.

    m_logMessages.clear();
    const auto result = m_agentInfo->observeVdFeedOffset(100);
    EXPECT_FALSE(result.changed);
    EXPECT_FALSE(result.pending);

    ASSERT_EQ(1u, m_logMessages.size());
    EXPECT_EQ(LOG_WARNING, m_logMessages[0].first);
    EXPECT_THAT(m_logMessages[0].second, ::testing::HasSubstr("Cannot observe VD feed offset: DBSync not available"));
}

TEST_F(AgentInfoVdOffsetTest, ObserveWithoutDBSyncLogsDebugDuringShutdown)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(":memory:", nullptr, m_logFunc,
                                                  vdFirstSyncQueryFunc(true), m_mockDBSync);
    m_agentInfo->stop(); // Signals a real shutdown is in progress (isShutdownInProgress() == true).
    m_agentInfo->releaseResources(); // Drops the DBSync connection, same as the real shutdown path.

    m_logMessages.clear();
    const auto result = m_agentInfo->observeVdFeedOffset(100);
    EXPECT_FALSE(result.changed);
    EXPECT_FALSE(result.pending);

    ASSERT_EQ(1u, m_logMessages.size());
    EXPECT_EQ(LOG_DEBUG, m_logMessages[0].first);
    EXPECT_THAT(m_logMessages[0].second, ::testing::HasSubstr("Cannot observe VD feed offset: DBSync not available"));
}

TEST_F(AgentInfoVdOffsetTest, ClearPendingFailsClosedWithoutDBSync)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(":memory:", nullptr, m_logFunc,
                                                  vdFirstSyncQueryFunc(true), m_mockDBSync);
    m_agentInfo->releaseResources();

    m_logMessages.clear();
    EXPECT_FALSE(m_agentInfo->clearVdRescanPending(100));

    ASSERT_EQ(1u, m_logMessages.size());
    EXPECT_EQ(LOG_WARNING, m_logMessages[0].first);
    EXPECT_THAT(m_logMessages[0].second, ::testing::HasSubstr("Cannot clear VD rescan pending: DBSync not available"));
}

TEST_F(AgentInfoVdOffsetTest, ClearPendingWithoutDBSyncLogsDebugDuringShutdown)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(":memory:", nullptr, m_logFunc,
                                                  vdFirstSyncQueryFunc(true), m_mockDBSync);
    m_agentInfo->stop();
    m_agentInfo->releaseResources();

    m_logMessages.clear();
    EXPECT_FALSE(m_agentInfo->clearVdRescanPending(100));

    ASSERT_EQ(1u, m_logMessages.size());
    EXPECT_EQ(LOG_DEBUG, m_logMessages[0].first);
    EXPECT_THAT(m_logMessages[0].second, ::testing::HasSubstr("Cannot clear VD rescan pending: DBSync not available"));
}

TEST_F(AgentInfoVdOffsetTest, GetStateFailsClosedWithoutDBSync)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(":memory:", nullptr, m_logFunc,
                                                  vdFirstSyncQueryFunc(true), m_mockDBSync);
    m_agentInfo->releaseResources();

    const auto state = m_agentInfo->getVdFeedState();
    EXPECT_FALSE(state.hasOffset);
    EXPECT_FALSE(state.pending);
}

// First offset ever observed, VDFirst already done -> advances and marks pending (the
// common steady-state case: a feed update after the agent is fully bootstrapped).
TEST_F(AgentInfoVdOffsetTest, ObserveNewOffsetWithVDFirstDoneMarksPending)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(":memory:", nullptr, m_logFunc,
                                                  vdFirstSyncQueryFunc(true), m_mockDBSync);

    ::testing::InSequence seq;
    expectNotFound(m_mockDBSync);                    // initial read: nothing stored yet
    expectStoredState(m_mockDBSync, 100, false, 0);   // re-read after the (mocked) write

    const auto result = m_agentInfo->observeVdFeedOffset(100);

    EXPECT_TRUE(result.changed);
    EXPECT_TRUE(result.pending);
    EXPECT_EQ(100u, result.pendingOffset);
    ASSERT_EQ(1u, firstSyncQueries().size());
    EXPECT_THAT(firstSyncQueries()[0], ::testing::HasSubstr("get_vd_first_sync_completed"));
    EXPECT_THAT(firstSyncQueries()[0], ::testing::HasSubstr("syscollector"));
}

// Q5: VDFirst has not completed yet -> the offset is persisted (changed=true) but NO
// re-scan is requested, since VDFirst's own full scan will cover it via Start.feed_offset.
TEST_F(AgentInfoVdOffsetTest, ObserveNewOffsetWithVDFirstNotDoneDoesNotMarkPending)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(":memory:", nullptr, m_logFunc,
                                                  vdFirstSyncQueryFunc(false), m_mockDBSync);

    // Only ONE selectRows call: the re-check-and-mark-pending branch is never reached
    // when VDFirst is not done.
    expectNotFound(m_mockDBSync);

    const auto result = m_agentInfo->observeVdFeedOffset(50);

    EXPECT_TRUE(result.changed);
    EXPECT_FALSE(result.pending);
    ASSERT_EQ(1u, firstSyncQueries().size());
}

// N3: an offset not newer than the stored one is a no-op, and does not even query
// VDFirst status (no need to -- nothing changed).
TEST_F(AgentInfoVdOffsetTest, ObserveOlderOffsetIsNoOp)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(":memory:", nullptr, m_logFunc,
                                                  vdFirstSyncQueryFunc(true), m_mockDBSync);

    expectStoredState(m_mockDBSync, 100, true, 100);

    const auto result = m_agentInfo->observeVdFeedOffset(50);

    EXPECT_FALSE(result.changed);
    EXPECT_TRUE(result.pending);       // reports the current (unrelated) pending state
    EXPECT_EQ(100u, result.pendingOffset);
    EXPECT_TRUE(firstSyncQueries().empty());
}

// #39543: observeVdFeedOffset() must publish the fresh offset straight to metadata_provider
// (metadata_provider_update_vd_feed_offset()), not only to its own durable vd_feed_state table
// -- real, unmocked metadata_provider, since this call bypasses DBSync entirely.
TEST_F(AgentInfoVdOffsetTest, ObserveNewOffsetPublishesToMetadataProviderWhenSnapshotExists)
{
    metadata_provider_reset();
    agent_metadata_t seeded{};
    std::strncpy(seeded.agent_id, "001", sizeof(seeded.agent_id) - 1);
    std::strncpy(seeded.hostname, "test_host", sizeof(seeded.hostname) - 1);
    seeded.vd_feed_offset = 1;
    ASSERT_EQ(metadata_provider_update(&seeded), 0);

    m_agentInfo = std::make_shared<AgentInfoImpl>(":memory:", nullptr, m_logFunc,
                                                  vdFirstSyncQueryFunc(false), m_mockDBSync);
    expectNotFound(m_mockDBSync);

    const auto result = m_agentInfo->observeVdFeedOffset(777);
    EXPECT_TRUE(result.changed);

    agent_metadata_t retrieved{};
    ASSERT_EQ(metadata_provider_get(&retrieved), 0);
    EXPECT_EQ(retrieved.vd_feed_offset, 777u);
    EXPECT_STREQ(retrieved.agent_id, "001");   // untouched by the narrow update
    EXPECT_STREQ(retrieved.hostname, "test_host");

    metadata_provider_reset();
}

// Before any full metadata_provider_update() ever ran, the narrow publish is a no-op --
// observeVdFeedOffset()'s own durable-table write (and its return value) are unaffected.
TEST_F(AgentInfoVdOffsetTest, ObserveNewOffsetIsHarmlessWhenNoMetadataSnapshotYet)
{
    metadata_provider_reset();

    m_agentInfo = std::make_shared<AgentInfoImpl>(":memory:", nullptr, m_logFunc,
                                                  vdFirstSyncQueryFunc(false), m_mockDBSync);
    expectNotFound(m_mockDBSync);

    const auto result = m_agentInfo->observeVdFeedOffset(777);
    EXPECT_TRUE(result.changed);

    agent_metadata_t retrieved{};
    EXPECT_EQ(metadata_provider_get(&retrieved), -1);   // still no snapshot at all
}

TEST_F(AgentInfoVdOffsetTest, ObserveEqualOffsetIsNoOp)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(":memory:", nullptr, m_logFunc,
                                                  vdFirstSyncQueryFunc(true), m_mockDBSync);

    expectStoredState(m_mockDBSync, 100, false, 0);

    const auto result = m_agentInfo->observeVdFeedOffset(100);

    EXPECT_FALSE(result.changed);
    EXPECT_TRUE(firstSyncQueries().empty());
}

// R10: a legitimate offset of 0 (e.g. VD disabled on the node that answered) must not
// thrash -- observing 0 again is a no-op, not a spurious "advance".
TEST_F(AgentInfoVdOffsetTest, ObserveZeroTwiceIsIdempotent)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(":memory:", nullptr, m_logFunc,
                                                  vdFirstSyncQueryFunc(true), m_mockDBSync);

    expectStoredState(m_mockDBSync, 0, false, 0);

    const auto result = m_agentInfo->observeVdFeedOffset(0);

    EXPECT_FALSE(result.changed);
}

TEST_F(AgentInfoVdOffsetTest, ClearPendingSucceedsForMatchingOffset)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(":memory:", nullptr, m_logFunc,
                                                  vdFirstSyncQueryFunc(true), m_mockDBSync);

    expectStoredState(m_mockDBSync, 100, true, 100);

    EXPECT_TRUE(m_agentInfo->clearVdRescanPending(100));
}

// Note 2: a stale confirmation (a newer offset has since superseded the pending one, or
// nothing is pending) must be a no-op -- pending is cleared ONLY by a matching 200 OK.
TEST_F(AgentInfoVdOffsetTest, ClearPendingIsNoOpForMismatchedOffset)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(":memory:", nullptr, m_logFunc,
                                                  vdFirstSyncQueryFunc(true), m_mockDBSync);

    expectStoredState(m_mockDBSync, 200, true, 200);

    EXPECT_FALSE(m_agentInfo->clearVdRescanPending(100));
}

TEST_F(AgentInfoVdOffsetTest, ClearPendingIsNoOpWhenNothingPending)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(":memory:", nullptr, m_logFunc,
                                                  vdFirstSyncQueryFunc(true), m_mockDBSync);

    expectStoredState(m_mockDBSync, 100, false, 0);

    EXPECT_FALSE(m_agentInfo->clearVdRescanPending(100));
}

TEST_F(AgentInfoVdOffsetTest, GetVdFeedStateReturnsStoredValues)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(":memory:", nullptr, m_logFunc,
                                                  vdFirstSyncQueryFunc(true), m_mockDBSync);

    expectStoredState(m_mockDBSync, 100, true, 100);

    const auto state = m_agentInfo->getVdFeedState();

    EXPECT_TRUE(state.hasOffset);
    EXPECT_EQ(100u, state.offset);
    EXPECT_TRUE(state.pending);
    EXPECT_EQ(100u, state.pendingOffset);
}

// A node without a running scanner indexed a VD session and syscollector recorded
// the scan as owed. The agent comes back to a scanning node that advertises the offset it already
// holds -- the not-newer path -- and the owed scan becomes the pending request anyway, at that
// offset, as a first scan when that is what is owed. syscollector's record is cleared with the
// exact value taken over.
TEST_F(AgentInfoVdOffsetTest, AnOwedFirstScanIsTakenOverAtAnUnchangedOffset)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(":memory:", nullptr, m_logFunc,
                                                  vdFirstSyncQueryFunc(true), m_mockDBSync);
    m_vdScanOwed = 2;

    ::testing::InSequence seq;
    expectStoredState(m_mockDBSync, 100, false, 0); // observe's read: not newer
    expectStoredState(m_mockDBSync, 100, false, 0); // the takeover's read

    const auto result = m_agentInfo->observeVdFeedOffset(100);

    EXPECT_FALSE(result.changed);
    EXPECT_TRUE(result.pending);
    EXPECT_EQ(100u, result.pendingOffset);
    EXPECT_TRUE(result.pendingFirst) << "the manager must run it without alerting";
    EXPECT_THAT(m_clearedOwed, ::testing::ElementsAre(2));
}

TEST_F(AgentInfoVdOffsetTest, AnOwedScanIsTakenOverAsAPlainRescan)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(":memory:", nullptr, m_logFunc,
                                                  vdFirstSyncQueryFunc(true), m_mockDBSync);
    m_vdScanOwed = 1;

    ::testing::InSequence seq;
    expectStoredState(m_mockDBSync, 100, false, 0);
    expectStoredState(m_mockDBSync, 100, false, 0);

    const auto result = m_agentInfo->observeVdFeedOffset(100);

    EXPECT_TRUE(result.pending);
    EXPECT_EQ(100u, result.pendingOffset);
    EXPECT_FALSE(result.pendingFirst);
    EXPECT_THAT(m_clearedOwed, ::testing::ElementsAre(1));
}

// A first scan already pending is not downgraded by a plain owed scan taken over later.
TEST_F(AgentInfoVdOffsetTest, APendingFirstScanStaysOne)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(":memory:", nullptr, m_logFunc,
                                                  vdFirstSyncQueryFunc(true), m_mockDBSync);
    m_vdScanOwed = 1;

    const auto pendingFirstRow = [](const nlohmann::json&, ResultCallbackData callback)
    {
        nlohmann::json row;
        row["has_offset"] = 1;
        row["last_offset"] = 100;
        row["pending"] = 1;
        row["pending_offset"] = 100;
        row["pending_first"] = 1;
        callback(SELECTED, row);
    };
    EXPECT_CALL(*m_mockDBSync, selectRows(::testing::_, ::testing::_))
    .Times(2)
    .WillRepeatedly(::testing::Invoke(pendingFirstRow));

    const auto result = m_agentInfo->observeVdFeedOffset(100);

    EXPECT_TRUE(result.pending);
    EXPECT_TRUE(result.pendingFirst);
}

TEST_F(AgentInfoVdOffsetTest, NothingOwedLeavesThePendingStateAndSyscollectorAlone)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(":memory:", nullptr, m_logFunc,
                                                  vdFirstSyncQueryFunc(true), m_mockDBSync);

    expectStoredState(m_mockDBSync, 100, false, 0); // only observe's own read

    const auto result = m_agentInfo->observeVdFeedOffset(100);

    EXPECT_FALSE(result.pending);
    EXPECT_FALSE(result.pendingFirst);
    EXPECT_TRUE(m_clearedOwed.empty());
}

// A rescan already pending for a NEWER feed is not lowered to the offset a lagging node
// advertises: that node's 200 would clear the pending flag and drop the newer rescan with it.
TEST_F(AgentInfoVdOffsetTest, AnOwedScanDoesNotLowerANewerPendingRescan)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(":memory:", nullptr, m_logFunc,
                                                  vdFirstSyncQueryFunc(true), m_mockDBSync);
    m_vdScanOwed = 2;

    ::testing::InSequence seq;
    expectStoredState(m_mockDBSync, 100, true, 100); // observe's read: 90 is not newer
    expectStoredState(m_mockDBSync, 100, true, 100); // the takeover's read

    const auto result = m_agentInfo->observeVdFeedOffset(90);

    EXPECT_TRUE(result.pending);
    EXPECT_EQ(100u, result.pendingOffset);
    EXPECT_TRUE(result.pendingFirst);
    EXPECT_THAT(m_clearedOwed, ::testing::ElementsAre(2));
}

// The takeover runs on every keepalive notify, where a scan is almost never owed: an unchanged
// offset asks syscollector once per interval, not once per notify.
TEST_F(AgentInfoVdOffsetTest, AnUnchangedOffsetProbesSyscollectorOncePerInterval)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(":memory:", nullptr, m_logFunc,
                                                  vdFirstSyncQueryFunc(true), m_mockDBSync);

    EXPECT_CALL(*m_mockDBSync, selectRows(::testing::_, ::testing::_))
    .WillRepeatedly(::testing::Invoke([](const nlohmann::json&, ResultCallbackData callback)
    {
        nlohmann::json row;
        row["has_offset"] = 1;
        row["last_offset"] = 100;
        row["pending"] = 0;
        row["pending_offset"] = 0;
        callback(SELECTED, row);
    }));

    m_agentInfo->observeVdFeedOffset(100);
    m_agentInfo->observeVdFeedOffset(100);
    m_agentInfo->observeVdFeedOffset(100);
    EXPECT_EQ(1u, owedProbes());

    // Recorded by syscollector meanwhile: found once the interval has elapsed.
    m_vdScanOwed = 1;
    m_agentInfo->setOwedVdScanProbeInterval(std::chrono::seconds {0});
    const auto result = m_agentInfo->observeVdFeedOffset(100);

    EXPECT_EQ(2u, owedProbes());
    EXPECT_TRUE(result.pending);
    EXPECT_THAT(m_clearedOwed, ::testing::ElementsAre(1));
}

// A clear that keeps failing must not turn into one scan request per keepalive: the record is
// taken over once, and later notifies only retry the clear. Once it lands nothing is requested
// again: no skip was recorded while the record was stuck, and a second request is a second full
// scan.
TEST_F(AgentInfoVdOffsetTest, AFailingClearIsRetriedWithoutTakingTheScanOverAgain)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(":memory:", nullptr, m_logFunc,
                                                  vdFirstSyncQueryFunc(true), m_mockDBSync);
    m_agentInfo->setOwedVdScanProbeInterval(std::chrono::seconds {0});
    m_vdScanOwed = 1;
    m_clearFails = true;

    EXPECT_CALL(*m_mockDBSync, selectRows(::testing::_, ::testing::_))
    .WillRepeatedly(::testing::Invoke([](const nlohmann::json&, ResultCallbackData callback)
    {
        // The row as the /scan/vd 200 leaves it: handle() is null under this mock, so writes do
        // not land and every read sees nothing pending.
        nlohmann::json row;
        row["has_offset"] = 1;
        row["last_offset"] = 100;
        row["pending"] = 0;
        row["pending_offset"] = 0;
        callback(SELECTED, row);
    }));

    EXPECT_TRUE(m_agentInfo->observeVdFeedOffset(100).pending) << "taken over once";

    EXPECT_FALSE(m_agentInfo->observeVdFeedOffset(100).pending) << "only the clear is retried";
    EXPECT_FALSE(m_agentInfo->observeVdFeedOffset(100).pending);
    EXPECT_EQ(1u, owedProbes());
    EXPECT_THAT(m_clearedOwed, ::testing::ElementsAre(1, 1, 1));

    m_clearFails = false;
    EXPECT_FALSE(m_agentInfo->observeVdFeedOffset(100).pending) << "the clear landing requests nothing";
    EXPECT_FALSE(m_agentInfo->observeVdFeedOffset(100).pending);
    EXPECT_THAT(m_clearedOwed, ::testing::ElementsAre(1, 1, 1, 1));
    EXPECT_EQ(0, m_vdScanOwed);
}

// The clear was stuck and syscollector recorded another skip of the same kind meanwhile. The value
// did not change, the skip count did: the retried clear leaves the record in place and it is
// taken over again, so the delta skipped last still gets its scan.
TEST_F(AgentInfoVdOffsetTest, ASkipRecordedWhileItsClearWasStuckIsRequestedAgain)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(":memory:", nullptr, m_logFunc,
                                                  vdFirstSyncQueryFunc(true), m_mockDBSync);
    m_agentInfo->setOwedVdScanProbeInterval(std::chrono::seconds {0});
    m_vdScanOwed = 1;
    m_clearFails = true;

    EXPECT_CALL(*m_mockDBSync, selectRows(::testing::_, ::testing::_))
    .WillRepeatedly(::testing::Invoke([](const nlohmann::json&, ResultCallbackData callback)
    {
        nlohmann::json row;
        row["has_offset"] = 1;
        row["last_offset"] = 100;
        row["pending"] = 0;
        row["pending_offset"] = 0;
        callback(SELECTED, row);
    }));

    EXPECT_TRUE(m_agentInfo->observeVdFeedOffset(100).pending);

    m_clearFails = false;
    m_vdScanOwedSkips = 1; // one more skip, same value

    EXPECT_TRUE(m_agentInfo->observeVdFeedOffset(100).pending) << "the later skip is taken over";
    EXPECT_THAT(m_clearedOwed, ::testing::ElementsAre(1, 1, 1));
    EXPECT_EQ(0, m_vdScanOwed) << "cleared against the count read with it";

    EXPECT_FALSE(m_agentInfo->observeVdFeedOffset(100).pending);
}

// The offset changed, VDFirst is recorded as done, and syscollector does not say whether a first
// scan is owed. A plain request now would make the manager alert on every vulnerability of an
// agent whose first scan a node without a scanner skipped, so it is held back until syscollector
// answers.
TEST_F(AgentInfoVdOffsetTest, APlainRescanWaitsWhileTheOwedScanIsUnknown)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(":memory:", nullptr, m_logFunc,
                                                  vdFirstSyncQueryFunc(true), m_mockDBSync);
    m_agentInfo->setOwedVdScanProbeInterval(std::chrono::seconds {0});
    m_getOwedFails = true;
    m_vdScanOwed = 2;

    const auto pendingPlainRow = [](const nlohmann::json&, ResultCallbackData callback)
    {
        nlohmann::json row;
        row["has_offset"] = 1;
        row["last_offset"] = 100;
        row["pending"] = 1;
        row["pending_offset"] = 100;
        callback(SELECTED, row);
    };

    {
        ::testing::InSequence seq;
        expectNotFound(m_mockDBSync);                   // initial read: nothing stored yet
        expectStoredState(m_mockDBSync, 100, false, 0); // re-read before marking pending
        EXPECT_CALL(*m_mockDBSync, selectRows(::testing::_, ::testing::_))
        .WillRepeatedly(::testing::Invoke(pendingPlainRow));
    }

    const auto held = m_agentInfo->observeVdFeedOffset(100);
    EXPECT_TRUE(held.changed);
    EXPECT_FALSE(held.pending) << "not sent as a plain scan while a first scan may be owed";

    EXPECT_FALSE(m_agentInfo->observeVdFeedOffset(100).pending) << "still unknown";

    m_getOwedFails = false;
    const auto first = m_agentInfo->observeVdFeedOffset(100);
    EXPECT_TRUE(first.pending);
    EXPECT_TRUE(first.pendingFirst) << "requested as the first scan it is";
    EXPECT_THAT(m_clearedOwed, ::testing::ElementsAre(2));
}

// An agent whose syscollector never answers (disabled) still gets its rescans: the request is
// only held for the grace period.
TEST_F(AgentInfoVdOffsetTest, APlainRescanGoesOutOnceTheGraceForAnUnknownOwedScanIsOver)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(":memory:", nullptr, m_logFunc,
                                                  vdFirstSyncQueryFunc(true), m_mockDBSync);
    m_agentInfo->setOwedVdScanUnknownGrace(std::chrono::seconds {0});
    m_getOwedFails = true;

    ::testing::InSequence seq;
    expectNotFound(m_mockDBSync);
    expectStoredState(m_mockDBSync, 100, false, 0);

    const auto result = m_agentInfo->observeVdFeedOffset(100);

    EXPECT_TRUE(result.pending);
    EXPECT_FALSE(result.pendingFirst);
}

// A syscollector that does not answer is not asked again on every keepalive.
TEST_F(AgentInfoVdOffsetTest, AnUnansweredProbeIsNotRepeatedWithinTheInterval)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(":memory:", nullptr, m_logFunc,
                                                  vdFirstSyncQueryFunc(true), m_mockDBSync);
    m_getOwedFails = true;

    EXPECT_CALL(*m_mockDBSync, selectRows(::testing::_, ::testing::_))
    .WillRepeatedly(::testing::Invoke([](const nlohmann::json&, ResultCallbackData callback)
    {
        nlohmann::json row;
        row["has_offset"] = 1;
        row["last_offset"] = 100;
        row["pending"] = 0;
        row["pending_offset"] = 0;
        callback(SELECTED, row);
    }));

    m_agentInfo->observeVdFeedOffset(100);
    m_agentInfo->observeVdFeedOffset(100);
    m_agentInfo->observeVdFeedOffset(100);

    EXPECT_EQ(1u, owedProbes());
}

// Syscollector is resending the whole VD inventory as a VDFirst session (a re-enrollment), whose
// own scan is the first scan. The first scan request already taken over is dropped, and the reset
// is acknowledged with its own value.
TEST_F(AgentInfoVdOffsetTest, AResetDropsThePendingFirstScanRequest)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(":memory:", nullptr, m_logFunc,
                                                  vdFirstSyncQueryFunc(true), m_mockDBSync);
    m_vdScanOwed = -1;

    EXPECT_CALL(*m_mockDBSync, selectRows(::testing::_, ::testing::_))
    .Times(2)
    .WillRepeatedly(::testing::Invoke([](const nlohmann::json&, ResultCallbackData callback)
    {
        nlohmann::json row;
        row["has_offset"] = 1;
        row["last_offset"] = 100;
        row["pending"] = 1;
        row["pending_offset"] = 100;
        row["pending_first"] = 1;
        callback(SELECTED, row);
    }));

    const auto result = m_agentInfo->observeVdFeedOffset(100);

    EXPECT_FALSE(result.pending);
    EXPECT_FALSE(result.pendingFirst);
    EXPECT_THAT(m_clearedOwed, ::testing::ElementsAre(-1));
    EXPECT_EQ(0, m_vdScanOwed);
}

// A reset leaves a plain rescan alone: it was asked for by a feed update, not by a skipped scan.
TEST_F(AgentInfoVdOffsetTest, AResetLeavesAPlainPendingRescanAlone)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(":memory:", nullptr, m_logFunc,
                                                  vdFirstSyncQueryFunc(true), m_mockDBSync);
    m_vdScanOwed = -1;

    ::testing::InSequence seq;
    expectStoredState(m_mockDBSync, 100, true, 100); // observe's read
    expectStoredState(m_mockDBSync, 100, true, 100); // the reset's read

    const auto result = m_agentInfo->observeVdFeedOffset(100);

    EXPECT_TRUE(result.pending);
    EXPECT_FALSE(result.pendingFirst);
    EXPECT_THAT(m_clearedOwed, ::testing::ElementsAre(-1));
}

// The clear of a plain scan taken over failed, and a skipped VDFirst raised the record meanwhile.
// The retried clear leaves the raised record in place, so it is taken over as what it now is: a
// plain request here would alert on every vulnerability of an agent still owed its first scan.
TEST_F(AgentInfoVdOffsetTest, ARecordRaisedWhileItsClearWasStuckIsTakenOverAsAFirstScan)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(":memory:", nullptr, m_logFunc,
                                                  vdFirstSyncQueryFunc(true), m_mockDBSync);
    m_agentInfo->setOwedVdScanProbeInterval(std::chrono::seconds {0});
    m_vdScanOwed = 1;
    m_clearFails = true;

    EXPECT_CALL(*m_mockDBSync, selectRows(::testing::_, ::testing::_))
    .WillRepeatedly(::testing::Invoke([](const nlohmann::json&, ResultCallbackData callback)
    {
        nlohmann::json row;
        row["has_offset"] = 1;
        row["last_offset"] = 100;
        row["pending"] = 0;
        row["pending_offset"] = 0;
        callback(SELECTED, row);
    }));

    const auto plain = m_agentInfo->observeVdFeedOffset(100);
    EXPECT_TRUE(plain.pending);
    EXPECT_FALSE(plain.pendingFirst);

    m_clearFails = false;
    m_vdScanOwed = 2;

    const auto first = m_agentInfo->observeVdFeedOffset(100);
    EXPECT_TRUE(first.pending);
    EXPECT_TRUE(first.pendingFirst) << "the raised record is requested as a first scan";
    EXPECT_THAT(m_clearedOwed, ::testing::ElementsAre(1, 1, 2)) << "then cleared for the value taken over";
    EXPECT_EQ(0, m_vdScanOwed);

    EXPECT_FALSE(m_agentInfo->observeVdFeedOffset(100).pending) << "nothing is left to take over";
}

// The node that answered advertises an offset below the one this agent already holds (a lagging
// node, or one with no feed offset yet). The request is recorded for the agent's own offset:
// recorded for the lower one, every node holding the current feed would refuse it, and nothing
// raises a pending offset again until the feed advances.
TEST_F(AgentInfoVdOffsetTest, AnOwedScanIsNotRecordedBelowTheOffsetTheAgentHolds)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(":memory:", nullptr, m_logFunc,
                                                  vdFirstSyncQueryFunc(true), m_mockDBSync);
    m_vdScanOwed = 2;

    ::testing::InSequence seq;
    expectStoredState(m_mockDBSync, 500, false, 0); // observe's read: 0 is not newer
    expectStoredState(m_mockDBSync, 500, false, 0); // the takeover's read

    const auto result = m_agentInfo->observeVdFeedOffset(0);

    EXPECT_FALSE(result.changed);
    EXPECT_TRUE(result.pending);
    EXPECT_EQ(500u, result.pendingOffset);
    EXPECT_TRUE(result.pendingFirst);
}

// Syscollector recorded a skipped VDFirst between the read of a plain owed scan and its clear. The
// clear leaves the raised record in place and says so; the request recorded a moment before is
// raised to a first scan before it is reported, because sent as a plain scan it would alert on
// every vulnerability and its 200 would leave nothing pending to correct.
TEST_F(AgentInfoVdOffsetTest, ARecordRaisedBetweenTheReadAndTheClearIsRequestedAsAFirstScan)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(":memory:", nullptr, m_logFunc,
                                                  vdFirstSyncQueryFunc(true), m_mockDBSync);
    m_vdScanOwed = 1;
    m_raiseOwedBeforeClear = 2;

    EXPECT_CALL(*m_mockDBSync, selectRows(::testing::_, ::testing::_))
    .WillRepeatedly(::testing::Invoke([](const nlohmann::json&, ResultCallbackData callback)
    {
        nlohmann::json row;
        row["has_offset"] = 1;
        row["last_offset"] = 100;
        row["pending"] = 1;
        row["pending_offset"] = 100;
        callback(SELECTED, row);
    }));

    const auto result = m_agentInfo->observeVdFeedOffset(100);

    EXPECT_TRUE(result.pending);
    EXPECT_EQ(100u, result.pendingOffset);
    EXPECT_TRUE(result.pendingFirst);
    EXPECT_THAT(m_clearedOwed, ::testing::ElementsAre(1, 2)) << "cleared for the value it was raised to";
    EXPECT_EQ(0, m_vdScanOwed);
}
