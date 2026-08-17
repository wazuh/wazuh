#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <agent_info_impl.hpp>

#include <dbsync.hpp>
#include <mock_dbsync.hpp>

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
            m_mockDBSync = std::make_shared<MockDBSync>();

            EXPECT_CALL(*m_mockDBSync, handle())
            .WillRepeatedly(::testing::Return(nullptr));

            m_logFunc = [this](modules_log_level_t /* level */, const std::string & msg)
            {
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
        std::string m_logOutput;
};

TEST_F(AgentInfoVdOffsetTest, ObserveFailsClosedWithoutDBSync)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(":memory:", nullptr, m_logFunc,
                                                  vdFirstSyncQueryFunc(true), m_mockDBSync);
    m_agentInfo->stop(); // Resets the DBSync connection (see AgentInfoImpl::stop()).

    const auto result = m_agentInfo->observeVdFeedOffset(100);
    EXPECT_FALSE(result.changed);
    EXPECT_FALSE(result.pending);
}

TEST_F(AgentInfoVdOffsetTest, ClearPendingFailsClosedWithoutDBSync)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(":memory:", nullptr, m_logFunc,
                                                  vdFirstSyncQueryFunc(true), m_mockDBSync);
    m_agentInfo->stop();

    EXPECT_FALSE(m_agentInfo->clearVdRescanPending(100));
}

TEST_F(AgentInfoVdOffsetTest, GetStateFailsClosedWithoutDBSync)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(":memory:", nullptr, m_logFunc,
                                                  vdFirstSyncQueryFunc(true), m_mockDBSync);
    m_agentInfo->stop();

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
    ASSERT_EQ(1u, m_queryModuleCalls.size());
    EXPECT_THAT(m_queryModuleCalls[0], ::testing::HasSubstr("get_vd_first_sync_completed"));
    EXPECT_THAT(m_queryModuleCalls[0], ::testing::HasSubstr("syscollector"));
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
    ASSERT_EQ(1u, m_queryModuleCalls.size());
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
    EXPECT_TRUE(m_queryModuleCalls.empty());
}

TEST_F(AgentInfoVdOffsetTest, ObserveEqualOffsetIsNoOp)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(":memory:", nullptr, m_logFunc,
                                                  vdFirstSyncQueryFunc(true), m_mockDBSync);

    expectStoredState(m_mockDBSync, 100, false, 0);

    const auto result = m_agentInfo->observeVdFeedOffset(100);

    EXPECT_FALSE(result.changed);
    EXPECT_TRUE(m_queryModuleCalls.empty());
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
