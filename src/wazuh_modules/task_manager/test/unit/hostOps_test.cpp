/*
 * Wazuh task manager module
 * Copyright (C) 2015, Wazuh Inc.
 * September 1, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "host/cHostOps.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

using namespace task_manager;
using namespace task_manager::host;

/*
 * The adapter between modulesd's C function-pointer table and the interface the handlers depend on.
 *
 * Everything it does is a translation, and every one of those translations is a decision that fails
 * quietly if it is wrong: a missing entry must degrade rather than crash, a query that did not
 * complete must be nullopt rather than an empty list, and every string the host allocated must go
 * back through the host's own free_json. None of that is visible from a handler test, which uses a
 * fake IHostOps and never sees this class at all.
 */

namespace
{
    /// What the fake host was asked for, and what it should answer. A file-scope struct rather
    /// than captures, because the table is plain C function pointers with no context parameter.
    struct FakeHost
    {
        int workerState {0};
        int disconnectResult {0};
        int byStatusResult {0};
        int agentInfoResult {0};
        int removeResult {0};
        int authdError {0};
        int rotateDailyResult {0};
        int rotateSizeResult {0};

        std::string disconnectJson {"[1,2,3]"};
        std::string byStatusJson {"[7]"};
        std::string agentInfoJson {R"({"name":"agent-7"})"};

        // Set to true to hand back a NULL document while still reporting success, which is a real
        // possibility across a C boundary and must not be dereferenced.
        bool returnNullJson {false};

        long lastKeepAlive {0};
        std::string lastSyncStatus;
        int lastAfterId {-1};
        std::string lastStatus;
        int lastAgentId {0};
        int lastTimeout {0};

        int allocations {0};
        int frees {0};
    };

    FakeHost g_host;

    char* duplicate(const std::string& text)
    {
        ++g_host.allocations;
        auto* raw {static_cast<char*>(std::malloc(text.size() + 1))};
        std::memcpy(raw, text.c_str(), text.size() + 1);
        return raw;
    }

    int fakeIsWorker()
    {
        return g_host.workerState;
    }

    int fakeDisconnect(long keepAlive, const char* syncStatus, char** out)
    {
        g_host.lastKeepAlive = keepAlive;
        g_host.lastSyncStatus = syncStatus != nullptr ? syncStatus : "";
        *out = g_host.returnNullJson ? nullptr : duplicate(g_host.disconnectJson);
        return g_host.disconnectResult;
    }

    int fakeByStatus(int afterId, const char* status, char** out)
    {
        g_host.lastAfterId = afterId;
        g_host.lastStatus = status != nullptr ? status : "";
        *out = g_host.returnNullJson ? nullptr : duplicate(g_host.byStatusJson);
        return g_host.byStatusResult;
    }

    int fakeAgentInfo(int agentId, char** out)
    {
        g_host.lastAgentId = agentId;
        *out = g_host.returnNullJson ? nullptr : duplicate(g_host.agentInfoJson);
        return g_host.agentInfoResult;
    }

    void fakeFreeJson(char* json)
    {
        ++g_host.frees;
        std::free(json);
    }

    int fakeRemoveAgent(int agentId, int timeout, int* authdError)
    {
        g_host.lastAgentId = agentId;
        g_host.lastTimeout = timeout;
        if (authdError != nullptr)
        {
            *authdError = g_host.authdError;
        }
        return g_host.removeResult;
    }

    int fakeRotateDaily(int, int, int)
    {
        return g_host.rotateDailyResult;
    }

    int fakeRotateSize(int, int, int, long)
    {
        return g_host.rotateSizeResult;
    }

    /// @brief A fully populated table. Tests null out the one entry they are about.
    task_manager_host_ops_t completeTable()
    {
        task_manager_host_ops_t ops {};
        ops.is_worker = fakeIsWorker;
        ops.disconnect_agents = fakeDisconnect;
        ops.get_agents_by_status_from = fakeByStatus;
        ops.get_agent_info = fakeAgentInfo;
        ops.free_json = fakeFreeJson;
        ops.remove_agent = fakeRemoveAgent;
        ops.rotate_log_daily = fakeRotateDaily;
        ops.rotate_log_size = fakeRotateSize;
        return ops;
    }

    class HostOpsTest : public ::testing::Test
    {
    protected:
        void SetUp() override
        {
            g_host = FakeHost {};
        }

        void TearDown() override
        {
            // Nothing the host allocated may outlive the call that asked for it.
            EXPECT_EQ(g_host.allocations, g_host.frees) << "a host-allocated document was leaked";
        }
    };
} // namespace

// ---- the table itself --------------------------------------------------------------------------

TEST_F(HostOpsTest, ACompleteTableReportsNothingMissing)
{
    CHostOps ops {completeTable()};
    EXPECT_TRUE(ops.missingOperations().empty());
}

TEST_F(HostOpsTest, EveryAbsentEntryIsNamedOnce)
{
    // The point of naming them: a stale .so paired with a newer modulesd should say so at start,
    // rather than dying inside a handler hours later.
    CHostOps ops {task_manager_host_ops_t {}};

    const auto missing {ops.missingOperations()};
    EXPECT_EQ(missing.size(), 8U);
    EXPECT_NE(std::find(missing.cbegin(), missing.cend(), "is_worker"), missing.cend());
    EXPECT_NE(std::find(missing.cbegin(), missing.cend(), "free_json"), missing.cend());
    EXPECT_NE(std::find(missing.cbegin(), missing.cend(), "rotate_log_size"), missing.cend());
}

// ---- cluster role ------------------------------------------------------------------------------

TEST_F(HostOpsTest, TheClusterRoleIsPassedThrough)
{
    CHostOps ops {completeTable()};

    g_host.workerState = 1;
    EXPECT_EQ(ops.workerState(), 1);

    g_host.workerState = 0;
    EXPECT_EQ(ops.workerState(), 0);
}

TEST_F(HostOpsTest, AMissingRoleCallIsUnknownRatherThanMaster)
{
    auto table {completeTable()};
    table.is_worker = nullptr;

    // The monitord bug this module exists to stop repeating: "unknown" read as master means two
    // nodes run master-scoped work at once.
    CHostOps ops {table};
    EXPECT_EQ(ops.workerState(), -1);
}

// ---- the JSON-returning queries ------------------------------------------------------------------

TEST_F(HostOpsTest, TheDisconnectionSweepReturnsTheAffectedIds)
{
    CHostOps ops {completeTable()};

    const auto ids {ops.disconnectAgents(1700000000, "synced")};

    ASSERT_TRUE(ids.has_value());
    EXPECT_EQ(*ids, (std::vector<int> {1, 2, 3}));

    // The arguments reach the host unchanged: the sweep's window and the sync_status it writes.
    EXPECT_EQ(g_host.lastKeepAlive, 1700000000);
    EXPECT_EQ(g_host.lastSyncStatus, "synced");
}

TEST_F(HostOpsTest, ARetentionPageIsKeyedOnTheCursorAndStatus)
{
    CHostOps ops {completeTable()};

    const auto ids {ops.agentsByStatusFrom(42, "disconnected")};

    ASSERT_TRUE(ids.has_value());
    EXPECT_EQ(*ids, (std::vector<int> {7}));
    EXPECT_EQ(g_host.lastAfterId, 42);
    EXPECT_EQ(g_host.lastStatus, "disconnected");
}

TEST_F(HostOpsTest, AnAgentRowIsHandedBackAsAParsedObject)
{
    CHostOps ops {completeTable()};

    const auto info {ops.agentInfo(7)};

    ASSERT_TRUE(info.has_value());
    ASSERT_TRUE(info->is_object());
    EXPECT_EQ((*info)["name"], "agent-7");
    EXPECT_EQ(g_host.lastAgentId, 7);
}

TEST_F(HostOpsTest, AQueryThatFailedIsNulloptRatherThanAnEmptyList)
{
    CHostOps ops {completeTable()};

    // THE distinction this adapter exists to preserve. An empty list would tell the disconnection
    // sweep that no agent was silent and let it report success; nullopt tells it to retry. A
    // wedged wazuh-db must not look like a quiet fleet.
    g_host.disconnectResult = -1;
    EXPECT_FALSE(ops.disconnectAgents(1, "synced").has_value());

    g_host.byStatusResult = -1;
    EXPECT_FALSE(ops.agentsByStatusFrom(0, "disconnected").has_value());

    g_host.agentInfoResult = -1;
    EXPECT_FALSE(ops.agentInfo(7).has_value());
}

TEST_F(HostOpsTest, SuccessWithNoDocumentIsAlsoAFailure)
{
    CHostOps ops {completeTable()};
    g_host.returnNullJson = true;

    // Reported success, handed back nothing. Dereferencing it is what a C boundary makes easy to
    // get wrong, and treating it as an empty result is the same silent-no-op bug as above.
    EXPECT_FALSE(ops.disconnectAgents(1, "synced").has_value());
    EXPECT_FALSE(ops.agentInfo(7).has_value());
}

TEST_F(HostOpsTest, AMalformedDocumentIsAFailureNotAnEmptyList)
{
    CHostOps ops {completeTable()};
    g_host.disconnectJson = "{not json";

    EXPECT_FALSE(ops.disconnectAgents(1, "synced").has_value());
}

TEST_F(HostOpsTest, ADocumentOfTheWrongShapeIsAFailure)
{
    CHostOps ops {completeTable()};

    // Parses, but is not the array of ids the contract promises.
    g_host.disconnectJson = R"({"agents":[1,2]})";
    EXPECT_FALSE(ops.disconnectAgents(1, "synced").has_value());
}

TEST_F(HostOpsTest, NonIntegerEntriesAreSkippedRatherThanFailingThePage)
{
    CHostOps ops {completeTable()};
    g_host.byStatusJson = R"([1,"two",3,null])";

    const auto ids {ops.agentsByStatusFrom(0, "disconnected")};

    ASSERT_TRUE(ids.has_value());
    EXPECT_EQ(*ids, (std::vector<int> {1, 3}));
}

TEST_F(HostOpsTest, AQueryWithoutItsFreeCallIsRefusedRatherThanLeaked)
{
    auto table {completeTable()};
    table.free_json = nullptr;

    CHostOps ops {table};

    // No way to release what the host would allocate, so the call is not made at all. The
    // TearDown allocation/free balance is what proves nothing was allocated here.
    EXPECT_FALSE(ops.agentInfo(7).has_value());
    EXPECT_EQ(g_host.allocations, 0);
}

TEST_F(HostOpsTest, AMissingQueryIsRefusedRatherThanCalled)
{
    auto table {completeTable()};
    table.get_agent_info = nullptr;

    CHostOps ops {table};
    EXPECT_FALSE(ops.agentInfo(7).has_value());
}

// ---- authd -------------------------------------------------------------------------------------

TEST_F(HostOpsTest, ARemovalThatSucceededAnswersTrueWithNoError)
{
    CHostOps ops {completeTable()};

    int authdError {-1};
    EXPECT_TRUE(ops.removeAgent(7, 30, authdError));
    EXPECT_EQ(authdError, 0);
    EXPECT_EQ(g_host.lastAgentId, 7);
    EXPECT_EQ(g_host.lastTimeout, 30);
}

TEST_F(HostOpsTest, ARefusalStillCountsAsAnAnswerAndCarriesItsCode)
{
    CHostOps ops {completeTable()};
    g_host.removeResult = -1;
    g_host.authdError = AUTHD_DELETE_BACKLOG;

    int authdError {0};

    // TRUE, despite the refusal: the return says whether authd ANSWERED, not whether it complied.
    // The retention sweep leans on exactly that -- deleteOldOutcome() reads a false return as "no
    // answer" and retries blindly, while an answer is dispatched on its code, and three of those
    // codes ("already gone", "already journaled") are successes rather than failures. Collapsing
    // the two would turn a fleet whose agents are already deleted into an endless retry.
    const auto answered {ops.removeAgent(7, 30, authdError)};

    EXPECT_TRUE(answered);
    EXPECT_EQ(authdError, AUTHD_DELETE_BACKLOG);
}

TEST_F(HostOpsTest, AnUnreachableAuthdIsNotAnAnswer)
{
    CHostOps ops {completeTable()};

    // Failed, and named no code. This is the other side of the boundary above, and the only shape
    // that means "we do not know what happened to this agent".
    g_host.removeResult = -1;
    g_host.authdError = 0;

    int authdError {-1};
    EXPECT_FALSE(ops.removeAgent(7, 30, authdError));
    EXPECT_EQ(authdError, 0);
}

TEST_F(HostOpsTest, AMissingRemovalCallIsNotAnAnswer)
{
    auto table {completeTable()};
    table.remove_agent = nullptr;

    CHostOps ops {table};

    int authdError {0};
    EXPECT_FALSE(ops.removeAgent(7, 30, authdError));
}

// ---- log rotation --------------------------------------------------------------------------------

TEST_F(HostOpsTest, DailyRotationReportsWhetherItCompleted)
{
    CHostOps ops {completeTable()};

    EXPECT_TRUE(ops.rotateLogDaily(true, 30, 12));

    g_host.rotateDailyResult = -1;
    EXPECT_FALSE(ops.rotateLogDaily(true, 30, 12));
}

TEST_F(HostOpsTest, SizeRotationSeparatesDidNotRotateFromFailed)
{
    CHostOps ops {completeTable()};

    // 1 rotated, 0 under the threshold, -1 failed. Only the first is "it happened", and the
    // periodic action must not treat an under-threshold log as an error.
    g_host.rotateSizeResult = 1;
    EXPECT_TRUE(ops.rotateLogBySize(true, 30, 12, 1024));

    g_host.rotateSizeResult = 0;
    EXPECT_FALSE(ops.rotateLogBySize(true, 30, 12, 1024));

    g_host.rotateSizeResult = -1;
    EXPECT_FALSE(ops.rotateLogBySize(true, 30, 12, 1024));
}

TEST_F(HostOpsTest, MissingRotationCallsDoNothing)
{
    auto table {completeTable()};
    table.rotate_log_daily = nullptr;
    table.rotate_log_size = nullptr;

    CHostOps ops {table};

    EXPECT_FALSE(ops.rotateLogDaily(true, 30, 12));
    EXPECT_FALSE(ops.rotateLogBySize(true, 30, 12, 1024));
}
