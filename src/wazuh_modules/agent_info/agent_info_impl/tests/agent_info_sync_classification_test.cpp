#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "agent_info_impl_mock.hpp"

#include <mock_agent_sync_protocol.hpp>
#include <mock_dbsync.hpp>

#include <memory>
#include <string>

// --- Local-transport-unavailable log-level decision (issue #38621) ------------------------------
// Exercises performIntegritySync()'s SyncModuleResult classification (issue #37553's fix) through
// AgentInfoImplMock, which injects a MockAgentSyncProtocol and forwards the private method.

namespace
{
    constexpr auto kAgentMetadataTable = "agent_metadata";

    int noopQueryModuleFunction(const std::string&, const std::string&, char** response)
    {
        if (response)
        {
            *response = nullptr;
        }

        return 0;
    }

    std::unique_ptr<AgentInfoImplMock> makeAgentInfoWithMockedSync(std::string& logOutput,
                                                                   const std::shared_ptr<MockDBSync>& mockDBSync,
                                                                   const SyncModuleResult& result)
    {
        auto logFunc = [&logOutput](modules_log_level_t /* level */, const std::string & msg)
        {
            logOutput += msg + "\n";
        };

        // A null handle makes updateDbMetadata() (called unconditionally at the end of the
        // integrity check to record the last-run timestamp) a safe no-op -- it isn't what this
        // test is about.
        EXPECT_CALL(*mockDBSync, handle())
        .WillRepeatedly(testing::Return(nullptr));

        auto agentInfo = std::make_unique<AgentInfoImplMock>(":memory:", nullptr, logFunc, noopQueryModuleFunction,
                                                             mockDBSync);

        auto mockSyncProtocol = std::make_unique<MockAgentSyncProtocol>();
        EXPECT_CALL(*mockSyncProtocol, synchronizeMetadataOrGroups(testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(result));
        agentInfo->setSyncProtocol(std::move(mockSyncProtocol));

        return agentInfo;
    }
}

// While the local sync intake itself isn't reachable yet (streak within tolerance), the
// integrity check is reported at INFO as deferred, not as a WARNING.
TEST(AgentInfoSyncClassificationTest, IntegritySync_LocalTransportUnavailableWithinToleranceLogsDeferred)
{
    std::string logOutput;
    auto mockDBSync = std::make_shared<MockDBSync>();
    auto agentInfo = makeAgentInfoWithMockedSync(
                         logOutput, mockDBSync,
                         SyncModuleResult{false, "Local sync intake is unreachable.", false, false, 1u, false, true});

    EXPECT_FALSE(agentInfo->callPerformIntegritySync(kAgentMetadataTable));

    EXPECT_THAT(logOutput, ::testing::HasSubstr(
                    "Integrity check for agent_metadata deferred: Local sync intake is unreachable. Will retry next cycle."));
    EXPECT_THAT(logOutput, ::testing::Not(::testing::HasSubstr("Integrity check for agent_metadata failed")));
}

// Right at the tolerance boundary, still deferred at INFO.
TEST(AgentInfoSyncClassificationTest, IntegritySync_LocalTransportUnavailableAtToleranceLogsDeferred)
{
    std::string logOutput;
    auto mockDBSync = std::make_shared<MockDBSync>();
    auto agentInfo = makeAgentInfoWithMockedSync(
                         logOutput, mockDBSync,
                         SyncModuleResult{false, "Local sync intake is unreachable.", false, false,
                                          SYNC_MANAGER_NOT_READY_TOLERANCE, false, true});

    EXPECT_FALSE(agentInfo->callPerformIntegritySync(kAgentMetadataTable));

    EXPECT_THAT(logOutput, ::testing::HasSubstr(
                    "Integrity check for agent_metadata deferred: Local sync intake is unreachable. Will retry next cycle."));
    EXPECT_THAT(logOutput, ::testing::Not(::testing::HasSubstr("Integrity check for agent_metadata failed")));
}

// Past the tolerance, escalates to a WARNING that names the streak.
TEST(AgentInfoSyncClassificationTest, IntegritySync_LocalTransportUnavailablePastToleranceLogsWarning)
{
    const unsigned int streak = SYNC_MANAGER_NOT_READY_TOLERANCE + 1;
    std::string logOutput;
    auto mockDBSync = std::make_shared<MockDBSync>();
    auto agentInfo = makeAgentInfoWithMockedSync(
                         logOutput, mockDBSync,
                         SyncModuleResult{false, "Local sync intake is unreachable.", false, false, streak, false, true});

    EXPECT_FALSE(agentInfo->callPerformIntegritySync(kAgentMetadataTable));

    EXPECT_THAT(logOutput, ::testing::HasSubstr(
                    "Integrity check for agent_metadata failed " + std::to_string(streak) +
                    " times in a row: Local sync intake is unreachable."));
}
