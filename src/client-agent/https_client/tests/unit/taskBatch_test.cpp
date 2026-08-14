/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 21, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "taskBatch.hpp"

#include <gtest/gtest.h>

namespace
{
    NotifyTask task(const std::string& id, const std::string& type)
    {
        return {id, type, "{}"};
    }

    std::vector<std::string> typesOf(const std::vector<NotifyTask>& tasks)
    {
        std::vector<std::string> types;

        for (const auto& entry : tasks)
        {
            types.push_back(entry.type);
        }

        return types;
    }

    std::vector<std::string> idsOf(const std::vector<NotifyTask>& tasks)
    {
        std::vector<std::string> ids;

        for (const auto& entry : tasks)
        {
            ids.push_back(entry.id);
        }

        return ids;
    }
} // namespace

TEST(TaskBatchTest, AllFourTypesShuffledComeOutInCanonicalOrder)
{
    // Terminal-last over the four contract types: quick work first, then the
    // tasks that end the process. No upgrade/restart interplay here beyond
    // the reload subsumption, so use distinct batches.
    auto plan = planTaskBatch({task("t1", "agent_restart"), task("t2", "active_response"),
                               task("t3", "remote_upgrade"), task("t4", "agent_reload")});
    // upgrade present: restart and reload are covered.
    EXPECT_EQ((std::vector<std::string> {"active_response", "remote_upgrade"}),
              typesOf(plan.ordered));
    ASSERT_EQ(2u, plan.dropped.size());
}

TEST(TaskBatchTest, FullOrderWithoutSubsumers)
{
    // Without upgrade/restart present, reload survives and slots into rank.
    auto plan = planTaskBatch({task("t1", "agent_reload"), task("t2", "active_response")});
    EXPECT_EQ((std::vector<std::string> {"active_response", "agent_reload"}),
              typesOf(plan.ordered));
    EXPECT_TRUE(plan.dropped.empty());
}

TEST(TaskBatchTest, SameTypeKeepsArrivalOrder)
{
    auto plan = planTaskBatch({task("ar-1", "active_response"), task("ar-2", "active_response"),
                               task("ar-3", "active_response")});
    EXPECT_EQ((std::vector<std::string> {"ar-1", "ar-2", "ar-3"}), idsOf(plan.ordered));
}

TEST(TaskBatchTest, SameTypeIsNeverCollapsed)
{
    // Redundancy collapse is across types only, by design. Two active
    // responses are two different actions (their payloads differ), so folding
    // them would discard real work; and for two upgrades, picking a winner is
    // a contract question rather than a planner one. The manager is expected
    // not to send a batch like this, but if it does, both are dispatched.
    auto responses = planTaskBatch({task("ar-1", "active_response"), task("ar-2", "active_response")});
    EXPECT_TRUE(responses.dropped.empty());
    EXPECT_EQ((std::vector<std::string> {"ar-1", "ar-2"}), idsOf(responses.ordered));

    auto upgrades = planTaskBatch({task("up-1", "remote_upgrade"), task("up-2", "remote_upgrade")});
    EXPECT_TRUE(upgrades.dropped.empty());
    EXPECT_EQ((std::vector<std::string> {"up-1", "up-2"}), idsOf(upgrades.ordered));
}

TEST(TaskBatchTest, UpgradeSubsumesRestart)
{
    auto plan = planTaskBatch({task("t1", "agent_restart"), task("t2", "remote_upgrade")});
    EXPECT_EQ((std::vector<std::string> {"remote_upgrade"}), typesOf(plan.ordered));
    ASSERT_EQ(1u, plan.dropped.size());
    EXPECT_EQ("agent_restart", plan.dropped[0].first.type);
    EXPECT_EQ("remote_upgrade", plan.dropped[0].second);
}

TEST(TaskBatchTest, RestartSubsumesReload)
{
    auto plan = planTaskBatch({task("t1", "agent_reload"), task("t2", "agent_restart")});
    EXPECT_EQ((std::vector<std::string> {"agent_restart"}), typesOf(plan.ordered));
    ASSERT_EQ(1u, plan.dropped.size());
    EXPECT_EQ("agent_reload", plan.dropped[0].first.type);
    EXPECT_EQ("agent_restart", plan.dropped[0].second);
}

TEST(TaskBatchTest, PresenceIsEvaluatedPreDrop)
{
    // The restart is itself dropped by the upgrade, but it was present in the
    // delivered batch, so the reload is still covered (attributed to the
    // upgrade, the stronger subsumer).
    auto plan = planTaskBatch({task("t1", "agent_reload"), task("t2", "agent_restart"),
                               task("t3", "remote_upgrade")});
    EXPECT_EQ((std::vector<std::string> {"remote_upgrade"}), typesOf(plan.ordered));
    ASSERT_EQ(2u, plan.dropped.size());
    EXPECT_EQ("agent_reload", plan.dropped[0].first.type);
    EXPECT_EQ("remote_upgrade", plan.dropped[0].second);
    EXPECT_EQ("agent_restart", plan.dropped[1].first.type);
    EXPECT_EQ("remote_upgrade", plan.dropped[1].second);
}

TEST(TaskBatchTest, TheUserScenarioRestartPlusUpgrade)
{
    // "If there's a restart and an upgrade, just the upgrade would do."
    auto plan = planTaskBatch({task("t1", "active_response"), task("t2", "agent_restart"),
                               task("t3", "remote_upgrade")});
    EXPECT_EQ((std::vector<std::string> {"active_response", "remote_upgrade"}),
              typesOf(plan.ordered));
    ASSERT_EQ(1u, plan.dropped.size());
    EXPECT_EQ("agent_restart", plan.dropped[0].first.type);
}

TEST(TaskBatchTest, LegacyReconnectAndInfoRequestRankLastAndStillDispatch)
{
    // Removed from the contract (#37733 2026-07-21): they are unknown types
    // now -- tolerated, dispatched last in arrival order, never subsumed.
    auto plan = planTaskBatch({task("t1", "agent_reconnect"), task("t2", "info_request"),
                               task("t3", "active_response"), task("t4", "remote_upgrade")});
    EXPECT_EQ((std::vector<std::string> {"active_response", "remote_upgrade",
                                         "agent_reconnect", "info_request"
                                        }),
              typesOf(plan.ordered));
    EXPECT_TRUE(plan.dropped.empty());
}

TEST(TaskBatchTest, UnknownTypesRankLastInArrivalOrderAndNeverInteract)
{
    // Forward compatibility: an unknown type is dispatched (the consumer
    // decides what to do), after everything known, and no subsumption rule
    // touches it.
    auto plan = planTaskBatch({task("t1", "future_thing"), task("t2", "another_future"),
                               task("t3", "active_response"), task("t4", "remote_upgrade")});
    EXPECT_EQ((std::vector<std::string> {"active_response", "remote_upgrade", "future_thing",
                                         "another_future"
                                        }),
              typesOf(plan.ordered));
    EXPECT_TRUE(plan.dropped.empty());
}

TEST(TaskBatchTest, EmptyBatchYieldsEmptyPlan)
{
    const auto plan = planTaskBatch({});
    EXPECT_TRUE(plan.ordered.empty());
    EXPECT_TRUE(plan.dropped.empty());
}
