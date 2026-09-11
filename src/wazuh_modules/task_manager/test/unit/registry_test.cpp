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

#include "registry/builtinTypes.hpp"
#include "registry/taskRegistry.hpp"
#include "testDoubles.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdio>
#include <stdexcept>

using namespace task_manager;
using namespace task_manager::registry;
using namespace task_manager::test;

namespace
{
    TaskTypeDescriptor validDescriptor(const std::string& name = "a_type")
    {
        TaskTypeDescriptor descriptor;
        descriptor.name = name;
        descriptor.watchdogBudget = std::chrono::seconds {60};
        descriptor.handler = std::make_shared<TestHandler>();
        return descriptor;
    }

    TaskRegistry build(std::vector<TaskTypeDescriptor> descriptors)
    {
        return TaskRegistry {RetryPolicy {}, std::move(descriptors)};
    }
} // namespace

// ---- validation --------------------------------------------------------------------------------
//
// Each of these is a programming error that would otherwise fail late and quietly: a type that is
// registered but unrunnable accumulates rows forever, because a pending manager task is never
// expired by age.

TEST(TaskRegistry, RejectsAnEmptyName)
{
    auto descriptor {validDescriptor()};
    descriptor.name.clear();
    EXPECT_THROW(build({descriptor}), std::invalid_argument);
}

TEST(TaskRegistry, RejectsADuplicateName)
{
    // A duplicate would shadow one of the two handlers, silently.
    EXPECT_THROW(build({validDescriptor("same"), validDescriptor("same")}), std::invalid_argument);
}

TEST(TaskRegistry, RejectsAMissingHandler)
{
    auto descriptor {validDescriptor()};
    descriptor.handler.reset();
    EXPECT_THROW(build({descriptor}), std::invalid_argument);
}

TEST(TaskRegistry, RejectsAConcurrencyCapBelowOne)
{
    auto descriptor {validDescriptor()};
    descriptor.maxConcurrent = 0;
    EXPECT_THROW(build({descriptor}), std::invalid_argument);
}

TEST(TaskRegistry, RejectsAZeroWatchdogBudget)
{
    // The stall predicate would degenerate to the bare margin, which healthy work legitimately
    // exceeds -- a warning that fires on correct behaviour is worse than no warning.
    auto descriptor {validDescriptor()};
    descriptor.watchdogBudget = std::chrono::seconds {0};
    EXPECT_THROW(build({descriptor}), std::invalid_argument);
}

TEST(TaskRegistry, RejectsAGroupDeclaredWithTwoDifferentCaps)
{
    auto first {validDescriptor("first")};
    first.concurrencyGroup = "shared";
    first.maxConcurrent = 1;

    auto second {validDescriptor("second")};
    second.concurrencyGroup = "shared";
    second.maxConcurrent = 4;

    // There is no defensible way to resolve it, so it is refused rather than picked.
    EXPECT_THROW(build({first, second}), std::invalid_argument);
}

TEST(TaskRegistry, AcceptsAGroupSharedAtOneCap)
{
    auto first {validDescriptor("first")};
    first.concurrencyGroup = "rotation";
    first.maxConcurrent = 1;

    auto second {validDescriptor("second")};
    second.concurrencyGroup = "rotation";
    second.maxConcurrent = 1;

    const auto registry {build({first, second})};
    ASSERT_EQ(registry.groupLimits().size(), 1U);
    EXPECT_EQ(registry.groupLimits().at("rotation"), 1);
}

TEST(TaskRegistry, AnUnnamedGroupDefaultsToTheTypeName)
{
    const auto registry {build({validDescriptor("solo")})};
    ASSERT_NE(registry.find("solo"), nullptr);
    EXPECT_EQ(registry.groupLimits().count("solo"), 1U);
}

TEST(TaskRegistry, AnUnknownTypeIsNotAnError)
{
    // Normal, not exceptional: a row whose type was renamed across an upgrade is exactly what the
    // orphaned-type reaper looks for.
    const auto registry {build({validDescriptor("known")})};
    EXPECT_EQ(registry.find("renamed_away"), nullptr);
}

TEST(TaskRegistry, ReportsEveryTypeNameForTheOrphanReaper)
{
    const auto registry {build({validDescriptor("a"), validDescriptor("b")})};
    const auto names {registry.typeNames()};
    ASSERT_EQ(names.size(), 2U);
    EXPECT_EQ(names[0], "a");
    EXPECT_EQ(names[1], "b");
}

// ---- the built-in set --------------------------------------------------------------------------

namespace
{
    task_manager_config_t defaultConfig()
    {
        task_manager_config_t config {};
        std::snprintf(config.inventory_sync_socket,
                      sizeof(config.inventory_sync_socket),
                      "%s",
                      "queue/sockets/inventory-sync-http.sock");
        return config;
    }
} // namespace

TEST(BuiltinRegistry, RegistersTheFiveTypesUnderTheirPersistedNames)
{
    FakeHostOps hostOps;
    handlers::LocalConfig local;

    const auto registry {buildBuiltinRegistry(defaultConfig(), hostOps, local)};

    // These strings live in MANAGER_TASKS.TASK_TYPE. Renaming one strands every existing row of
    // that type.
    for (const auto* name : {TYPE_AGENT_DELETE_INDEXER,
                             TYPE_VD_SCAN,
                             TYPE_AGENT_DISCONNECT_SWEEP,
                             TYPE_AGENT_DELETE_OLD,
                             TYPE_LOG_ROTATE_DAILY})
    {
        EXPECT_NE(registry.find(name), nullptr) << name;
    }

    EXPECT_EQ(registry.all().size(), 5U);
}

TEST(BuiltinRegistry, AgentDeletionNeverGivesUp)
{
    FakeHostOps hostOps;
    handlers::LocalConfig local;
    const auto registry {buildBuiltinRegistry(defaultConfig(), hostOps, local)};

    const auto* deletion {registry.find(TYPE_AGENT_DELETE_INDEXER)};
    ASSERT_NE(deletion, nullptr);

    // All three, not just the budgets: a 4xx maps to Terminal, which is as final as dead_letter,
    // so setting only the budgets would still abandon the work.
    EXPECT_EQ(deletion->maxAttempts, UNBOUNDED);
    EXPECT_EQ(deletion->maxDefer, UNBOUNDED);
    EXPECT_FALSE(deletion->allowTerminalFailure);

    // And it must not coalesce: two deletions of one agent are two obligations.
    EXPECT_FALSE(deletion->coalesceByAgent);
}

TEST(BuiltinRegistry, OnlyTheScanCoalesces)
{
    FakeHostOps hostOps;
    handlers::LocalConfig local;
    const auto registry {buildBuiltinRegistry(defaultConfig(), hostOps, local)};

    EXPECT_TRUE(registry.find(TYPE_VD_SCAN)->coalesceByAgent);
    for (const auto* name :
         {TYPE_AGENT_DELETE_INDEXER, TYPE_AGENT_DISCONNECT_SWEEP, TYPE_AGENT_DELETE_OLD, TYPE_LOG_ROTATE_DAILY})
    {
        EXPECT_FALSE(registry.find(name)->coalesceByAgent) << name;
    }
}

TEST(BuiltinRegistry, OnlyTheTwoRotationsShareAGroup)
{
    FakeHostOps hostOps;
    handlers::LocalConfig local;
    const auto registry {buildBuiltinRegistry(defaultConfig(), hostOps, local)};

    // The single "local" lane really only enforced that the two rotations never overlap. Expressing
    // that as a group is what lets the disconnection sweep run alongside one.
    EXPECT_EQ(registry.find(TYPE_LOG_ROTATE_DAILY)->concurrencyGroup, GROUP_ROTATION);
    EXPECT_EQ(registry.find(TYPE_AGENT_DISCONNECT_SWEEP)->concurrencyGroup, TYPE_AGENT_DISCONNECT_SWEEP);
    EXPECT_EQ(registry.find(TYPE_AGENT_DELETE_OLD)->concurrencyGroup, TYPE_AGENT_DELETE_OLD);
}

TEST(BuiltinRegistry, TheDeleteDeadlineMustExceedTheScanDeadline)
{
    FakeHostOps hostOps;
    handlers::LocalConfig local;

    auto config {defaultConfig()};
    config.vd_scan_timeout = 600;
    config.delete_timeout = 600;

    // A scan holding an agent parks that agent's deletion behind it in the consumer's per-agent
    // queue, so an equal deadline would expire the deletion while it was parked and re-queue it
    // over work that was never its own fault.
    EXPECT_THROW(buildBuiltinRegistry(config, hostOps, local), std::invalid_argument);

    config.delete_timeout = 601;
    EXPECT_NO_THROW(buildBuiltinRegistry(config, hostOps, local));
}

TEST(BuiltinRegistry, TheDeletionLaneKeepsItsDepthOfFour)
{
    FakeHostOps hostOps;
    handlers::LocalConfig local;
    const auto registry {buildBuiltinRegistry(defaultConfig(), hostOps, local)};

    EXPECT_EQ(registry.find(TYPE_AGENT_DELETE_INDEXER)->maxConcurrent, 4);
    EXPECT_EQ(registry.find(TYPE_VD_SCAN)->maxConcurrent, 1);
}

TEST(BuiltinRegistry, ABackoffBaseAboveTheCapIsClampedRatherThanRefused)
{
    FakeHostOps hostOps;
    handlers::LocalConfig local;

    auto config {defaultConfig()};
    config.backoff_base = 5000;
    config.backoff_cap = 900;

    const auto registry {buildBuiltinRegistry(config, hostOps, local)};
    EXPECT_LE(registry.policy().backoffBase, registry.policy().backoffCap);
}

// ---- schedules ---------------------------------------------------------------------------------

TEST(BuiltinSchedules, TheSweepIntervalIsTheConfiguredDisconnectionTime)
{
    auto config {defaultConfig()};
    config.disconnection_time = 120;
    config.monitor_agents = 1;

    const auto schedules {buildBuiltinSchedules(config)};
    const auto sweep {std::find_if(schedules.cbegin(),
                                   schedules.cend(),
                                   [](const schedule::Schedule& s)
                                   { return s.definition.id == SCHEDULE_AGENT_DISCONNECT_SWEEP; })};

    ASSERT_NE(sweep, schedules.cend());

    // It IS agents_disconnection_time, which merely defaults to 900 -- not a hardcoded fifteen
    // minutes.
    EXPECT_EQ(sweep->interval.count(), 120);
    EXPECT_TRUE(sweep->enabled);
}

TEST(BuiltinSchedules, RetentionDeletionIsDisabledUntilItIsConfigured)
{
    auto config {defaultConfig()};
    config.delete_old_agents = 0;

    const auto schedules {buildBuiltinSchedules(config)};
    const auto retention {std::find_if(schedules.cbegin(),
                                       schedules.cend(),
                                       [](const schedule::Schedule& s)
                                       { return s.definition.id == SCHEDULE_AGENT_DELETE_OLD; })};

    ASSERT_NE(retention, schedules.cend());
    EXPECT_FALSE(retention->enabled) << "a destructive sweep must not be on by default";

    config.delete_old_agents = 30;
    const auto enabled {buildBuiltinSchedules(config)};
    EXPECT_TRUE(enabled[1].enabled);
    EXPECT_EQ(enabled[1].interval.count(), 30 * 60);
}

TEST(BuiltinSchedules, RotationRunsOnEveryNodeButTheAgentSweepsDoNot)
{
    const auto schedules {buildBuiltinSchedules(defaultConfig())};

    for (const auto& schedule : schedules)
    {
        if (schedule.definition.id == SCHEDULE_LOG_ROTATE_DAILY)
        {
            // Every node writes its own log files, so every node rotates them.
            EXPECT_EQ(schedule.definition.scope, schedule::NodeScope::Any);
            EXPECT_EQ(schedule.definition.cadence, schedule::Cadence::Daily);
        }
        else
        {
            EXPECT_EQ(schedule.definition.scope, schedule::NodeScope::Master) << schedule.definition.id;
        }
    }
}
