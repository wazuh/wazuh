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

#include "storage/sqliteTaskStore.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <set>
#include <stdexcept>
#include <thread>
#include <vector>

using namespace task_manager;
using namespace task_manager::storage;

/*
 * These run against REAL SQLite, in memory. That is a deliberate departure from the retired cmocka
 * suite, which mocked sqlite3_step() and friends and therefore asserted on a sequence of bind and
 * step calls rather than on results -- a test that passes when the SQL is wrong. Here the schema,
 * the statements, the indexes and the transaction boundaries are all exercised for real, and the
 * only thing not covered is what a file-backed database adds (WAL, fsync), which no unit test can
 * assert on anyway.
 */
namespace
{
    class StoreTest : public ::testing::Test
    {
    protected:
        void SetUp() override
        {
            SqliteTaskStore::Options options;
            options.dbPath = DB_MEMORY;
            // Commit every write immediately, so a test never observes a batch that has not landed.
            options.groupCommitWindow = std::chrono::milliseconds {0};
            m_store = std::make_unique<SqliteTaskStore>(std::move(options));
        }

        CreateManagerTaskRequest request(const std::string& id,
                                         const std::string& type = "vd_scan",
                                         const std::optional<std::string>& agentId = std::nullopt)
        {
            CreateManagerTaskRequest req;
            req.taskId = id;
            req.taskType = type;
            req.payload = R"({"agent_id":"1"})";
            req.agentId = agentId;
            req.createTime = 1000;
            return req;
        }

        std::unique_ptr<SqliteTaskStore> m_store;
    };
} // namespace

TEST_F(StoreTest, CreateReturnsTheIdAndTheRowIsReadable)
{
    const auto outcome {m_store->createManagerTask(request("a"))};
    EXPECT_EQ(outcome.result, CreateResult::Created);
    EXPECT_EQ(outcome.taskId, "a");

    const auto row {m_store->getManagerTask("a")};
    ASSERT_TRUE(row.has_value());
    EXPECT_EQ(row->status, TaskStatus::Pending);

    // Seeded from CREATE_TIME, never left at zero: with a zero default and a claim ordered by this
    // column, every never-attempted row would sort ahead of every retried row.
    EXPECT_EQ(row->nextAttemptAt, 1000);
}

TEST_F(StoreTest, ADuplicateIdCollidesRatherThanThrowing)
{
    ASSERT_EQ(m_store->createManagerTask(request("a")).result, CreateResult::Created);

    const auto second {m_store->createManagerTask(request("a"))};
    EXPECT_EQ(second.result, CreateResult::Collided);
    EXPECT_EQ(second.taskId, "a");
}

TEST_F(StoreTest, CoalescingReturnsTheSurvivingIdNotTheRequestedOne)
{
    auto first {request("a", "vd_scan", "007")};
    first.coalesce = true;
    ASSERT_EQ(m_store->createManagerTask(first).result, CreateResult::Created);

    auto second {request("b", "vd_scan", "007")};
    second.coalesce = true;
    const auto outcome {m_store->createManagerTask(second)};

    EXPECT_EQ(outcome.result, CreateResult::Coalesced);

    // The SURVIVING id. Returning the requested one would hand the caller an id with no row behind
    // it, and a later lookup on it would find nothing.
    EXPECT_EQ(outcome.taskId, "a");
    EXPECT_FALSE(m_store->getManagerTask("b").has_value());
}

TEST_F(StoreTest, CoalescingIsPerTypeSoTwoDeletionsNeverCollapse)
{
    auto first {request("a", "agent_delete_indexer", "007")};
    first.coalesce = false;
    auto second {request("b", "agent_delete_indexer", "007")};
    second.coalesce = false;

    EXPECT_EQ(m_store->createManagerTask(first).result, CreateResult::Created);

    // Two distinct deletions of one agent are two obligations, not one.
    EXPECT_EQ(m_store->createManagerTask(second).result, CreateResult::Created);
}

TEST_F(StoreTest, TheAdmissionBoundIsExact)
{
    auto first {request("a")};
    first.maxPending = 2;
    auto second {request("b")};
    second.maxPending = 2;
    auto third {request("c")};
    third.maxPending = 2;

    EXPECT_EQ(m_store->createManagerTask(first).result, CreateResult::Created);
    EXPECT_EQ(m_store->createManagerTask(second).result, CreateResult::Created);
    EXPECT_EQ(m_store->createManagerTask(third).result, CreateResult::QueueFull);
}

TEST_F(StoreTest, ClaimTakesTheEarliestEligibleRowAndSkipsFutureOnes)
{
    auto early {request("early")};
    early.nextAttemptAt = 100;
    auto late {request("late")};
    late.nextAttemptAt = 200;
    auto future {request("future")};
    future.nextAttemptAt = 9000;

    m_store->createManagerTask(late);
    m_store->createManagerTask(early);
    m_store->createManagerTask(future);

    const auto first {m_store->claim("vd_scan", "owner-1", 1000)};
    ASSERT_TRUE(first.has_value());
    EXPECT_EQ(first->taskId, "early");

    const auto second {m_store->claim("vd_scan", "owner-1", 1000)};
    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(second->taskId, "late");

    // Still backing off.
    EXPECT_FALSE(m_store->claim("vd_scan", "owner-1", 1000).has_value());
}

TEST_F(StoreTest, ClaimIsExactlyOnceUnderConcurrency)
{
    constexpr int taskCount {200};
    for (int i = 0; i < taskCount; ++i)
    {
        m_store->createManagerTask(request("task-" + std::to_string(i)));
    }

    std::mutex mutex;
    std::vector<std::string> claimed;
    std::vector<std::thread> threads;

    for (int worker = 0; worker < 8; ++worker)
    {
        threads.emplace_back(
            [&, worker]
            {
                while (true)
                {
                    const auto task {m_store->claim("vd_scan", "owner-" + std::to_string(worker), 5000)};
                    if (!task.has_value())
                    {
                        break;
                    }
                    std::lock_guard lock {mutex};
                    claimed.push_back(task->taskId);
                }
            });
    }

    for (auto& thread : threads)
    {
        thread.join();
    }

    // Every row claimed, and each of them exactly once. This is the property the whole claim design
    // exists for; anything less is double execution.
    EXPECT_EQ(claimed.size(), static_cast<std::size_t>(taskCount));
    const std::set<std::string> unique {claimed.cbegin(), claimed.cend()};
    EXPECT_EQ(unique.size(), static_cast<std::size_t>(taskCount));
}

TEST_F(StoreTest, RequeueReturnsARowToPending)
{
    m_store->createManagerTask(request("a"));
    ASSERT_TRUE(m_store->claim("vd_scan", "owner-1", 1000).has_value());

    RequeueRequest requeue;
    requeue.taskId = "a";
    requeue.nextAttemptAt = 2000;
    requeue.attempts = 1;
    requeue.lastError = "boom";

    EXPECT_EQ(m_store->requeue(requeue), RequeueResult::Requeued);

    const auto row {m_store->getManagerTask("a")};
    ASSERT_TRUE(row.has_value());
    EXPECT_EQ(row->status, TaskStatus::Pending);
    EXPECT_EQ(row->attempts, 1);
    EXPECT_EQ(row->nextAttemptAt, 2000);
    EXPECT_FALSE(row->owner.has_value());
    EXPECT_FALSE(row->endTime.has_value()) << "a live row must not carry an END_TIME";
}

TEST_F(StoreTest, ACompetingPendingRowSupersedesAndInheritsTheLargerCounters)
{
    auto first {request("running", "vd_scan", "007")};
    first.coalesce = true;
    m_store->createManagerTask(first);
    ASSERT_TRUE(m_store->claim("vd_scan", "owner-1", 1000).has_value());

    auto second {request("waiting", "vd_scan", "007")};
    second.coalesce = true;
    ASSERT_EQ(m_store->createManagerTask(second).result, CreateResult::Created);

    RequeueRequest requeue;
    requeue.taskId = "running";
    requeue.taskType = "vd_scan";
    requeue.agentId = "007";
    requeue.coalesce = true;
    requeue.attempts = 5;
    requeue.deferCount = 3;
    requeue.nextAttemptAt = 2000;

    EXPECT_EQ(m_store->requeue(requeue), RequeueResult::Superseded);

    const auto superseded {m_store->getManagerTask("running")};
    ASSERT_TRUE(superseded.has_value());
    EXPECT_EQ(superseded->status, TaskStatus::Superseded);

    // The survivor takes the MAXIMUM of both rows' counters, so the budget belongs to the work
    // rather than to the row. Without it a coalescing type could never dead-letter under load:
    // every timed-out row would be superseded by a fresh one starting at zero.
    const auto survivor {m_store->getManagerTask("waiting")};
    ASSERT_TRUE(survivor.has_value());
    EXPECT_EQ(survivor->status, TaskStatus::Pending);
    EXPECT_EQ(survivor->attempts, 5);
    EXPECT_EQ(survivor->deferCount, 3);
}

TEST_F(StoreTest, SetResultRefusesSupersededBecauseNoHandlerMayChooseIt)
{
    m_store->createManagerTask(request("a"));

    EXPECT_THROW(m_store->setResult("a", TaskStatus::Superseded, 0, 0, std::nullopt, 2000), std::invalid_argument);
    EXPECT_THROW(m_store->setResult("a", TaskStatus::Pending, 0, 0, std::nullopt, 2000), std::invalid_argument);

    m_store->setResult("a", TaskStatus::Completed, 1, 0, std::nullopt, 2000);
    const auto row {m_store->getManagerTask("a")};
    ASSERT_TRUE(row.has_value());
    EXPECT_EQ(row->status, TaskStatus::Completed);
    EXPECT_EQ(row->endTime.value_or(0), 2000);
}

TEST_F(StoreTest, TheEarliestPendingAttemptDrivesTheSchedulersSleep)
{
    EXPECT_FALSE(m_store->minPendingNextAttemptAt().has_value())
        << "MIN() over an empty set is one row containing NULL, not zero rows";

    auto late {request("late")};
    late.nextAttemptAt = 5000;
    auto early {request("early")};
    early.nextAttemptAt = 3000;
    m_store->createManagerTask(late);
    m_store->createManagerTask(early);

    ASSERT_TRUE(m_store->minPendingNextAttemptAt().has_value());
    EXPECT_EQ(*m_store->minPendingNextAttemptAt(), 3000);
}

TEST_F(StoreTest, RetentionRemovesOnlyTerminalRows)
{
    m_store->createManagerTask(request("pending"));
    m_store->createManagerTask(request("done"));
    m_store->setResult("done", TaskStatus::Completed, 1, 0, std::nullopt, 1000);

    RetentionRules rules;
    rules.terminalBefore = 5000;
    const auto stats {m_store->applyRetention(rules)};

    EXPECT_EQ(stats.byAge, 1);

    // A pending manager task is NEVER expired by age -- doing so would destroy exactly the
    // long-outage work the queue exists to survive.
    EXPECT_TRUE(m_store->getManagerTask("pending").has_value());
    EXPECT_FALSE(m_store->getManagerTask("done").has_value());
}

TEST_F(StoreTest, DeadLettersOutliveOrdinaryTerminalRows)
{
    m_store->createManagerTask(request("failed"));
    m_store->createManagerTask(request("dead"));
    m_store->setResult("failed", TaskStatus::Failed, 1, 0, std::nullopt, 1000);
    m_store->setResult("dead", TaskStatus::DeadLetter, 8, 0, "gave up", 1000);

    RetentionRules rules;
    rules.terminalBefore = 5000;
    rules.deadLetterBefore = 500; // not yet due
    m_store->applyRetention(rules);

    EXPECT_FALSE(m_store->getManagerTask("failed").has_value());
    EXPECT_TRUE(m_store->getManagerTask("dead").has_value())
        << "a dead letter is the only record of work that was abandoned";
}

TEST_F(StoreTest, TheCeilingEvictsCompletedRowsBeforeDeadLetters)
{
    m_store->createManagerTask(request("dead"));
    m_store->setResult("dead", TaskStatus::DeadLetter, 8, 0, "gave up", 1000);

    for (int i = 0; i < 5; ++i)
    {
        const auto id {"done-" + std::to_string(i)};
        m_store->createManagerTask(request(id));
        m_store->setResult(id, TaskStatus::Completed, 1, 0, std::nullopt, 1000 + i);
    }

    RetentionRules rules;
    rules.maxRows = 2;
    const auto stats {m_store->applyRetention(rules)};

    EXPECT_EQ(stats.byCeiling, 4);
    EXPECT_EQ(stats.remaining, 2);

    // The ceiling must be able to evict everything eventually or it is not a ceiling, so dead
    // letters are protected by eviction ORDER rather than by exemption.
    EXPECT_TRUE(m_store->getManagerTask("dead").has_value());
}

TEST_F(StoreTest, ListingPagesOnTaskId)
{
    for (int i = 0; i < 5; ++i)
    {
        m_store->createManagerTask(request("task-" + std::to_string(i)));
    }

    const auto firstPage {m_store->listManagerTasks("vd_scan", std::nullopt, "", 2)};
    ASSERT_EQ(firstPage.size(), 2U);
    EXPECT_EQ(firstPage[0].taskId, "task-0");

    const auto secondPage {m_store->listManagerTasks("vd_scan", std::nullopt, firstPage.back().taskId, 2)};
    ASSERT_EQ(secondPage.size(), 2U);
    EXPECT_EQ(secondPage[0].taskId, "task-2");
}

TEST_F(StoreTest, OrphanedTypesAreDiscoverableAndRetirable)
{
    m_store->createManagerTask(request("a", "a_type_that_was_renamed"));

    const auto types {m_store->distinctPendingTaskTypes()};
    ASSERT_EQ(types.size(), 1U);
    EXPECT_EQ(types[0], "a_type_that_was_renamed");

    EXPECT_EQ(m_store->failPendingByType("a_type_that_was_renamed", "unknown task type", 2000), 1);

    const auto row {m_store->getManagerTask("a")};
    ASSERT_TRUE(row.has_value());
    EXPECT_EQ(row->status, TaskStatus::Failed);
    EXPECT_EQ(row->lastError.value_or(""), "unknown task type");
}

// ---- agent tasks -----------------------------------------------------------------------------

TEST_F(StoreTest, TakingPendingAgentTasksMarksThemDeliveredInOnePass)
{
    AgentTask task;
    task.taskId = "t1";
    task.agentId = "001";
    task.taskType = "agent_restart";
    task.payload = "{}";
    task.createTime = 1000;

    ASSERT_TRUE(m_store->createAgentTask(task));

    const auto first {m_store->takePendingAgentTasks("001", 10)};
    ASSERT_EQ(first.size(), 1U);
    EXPECT_EQ(first[0].taskId, "t1");

    // Marking on read is deliberate and preserved: delivery is the caller's job, and both remoted
    // pollers keep their own retry list for what they could not hand over.
    EXPECT_TRUE(m_store->takePendingAgentTasks("001", 10).empty());
}

TEST_F(StoreTest, AgentTaskCreationIsIdempotent)
{
    AgentTask task;
    task.taskId = "t1";
    task.agentId = "001";
    task.taskType = "agent_restart";
    task.payload = "{}";
    task.createTime = 1000;

    EXPECT_TRUE(m_store->createAgentTask(task));

    // Ids are deterministic, so the same logical request arriving twice is one task, not an error.
    EXPECT_TRUE(m_store->createAgentTask(task));
    EXPECT_EQ(m_store->takePendingAgentTasks("001", 10).size(), 1U);
}

TEST_F(StoreTest, BulkCreationReportsPerRowOutcomes)
{
    std::vector<AgentTask> tasks;
    for (int i = 0; i < 3; ++i)
    {
        AgentTask task;
        task.taskId = "t" + std::to_string(i);
        task.agentId = "00" + std::to_string(i);
        task.taskType = "agent_restart";
        task.payload = "{}";
        task.createTime = 1000;
        tasks.push_back(std::move(task));
    }

    const auto flags {m_store->createAgentTasks(tasks)};
    ASSERT_EQ(flags.size(), 3U);
    EXPECT_TRUE(flags[0] && flags[1] && flags[2]);
}

TEST_F(StoreTest, AgentTasksDoAgeOutWhilePendingUnlikeManagerTasks)
{
    AgentTask task;
    task.taskId = "t1";
    task.agentId = "001";
    task.taskType = "agent_restart";
    task.payload = "{}";
    task.createTime = 1000;
    m_store->createAgentTask(task);

    EXPECT_EQ(m_store->expireAgentTasks(5000), 1);
    EXPECT_TRUE(m_store->takePendingAgentTasks("001", 10).empty());
}

// ---- schedules -------------------------------------------------------------------------------

TEST_F(StoreTest, TheUpsertReportsThePreviousRowSoAReEnableIsDetectable)
{
    EXPECT_FALSE(m_store->upsertSchedule("s1", 100, false).has_value());

    const auto previous {m_store->upsertSchedule("s1", 200, true)};
    ASSERT_TRUE(previous.has_value());
    EXPECT_EQ(previous->nextRunAt, 100);

    // The persisted ENABLED is the ONLY way to detect a disabled-to-enabled transition, and that
    // transition can straddle a restart.
    EXPECT_FALSE(previous->enabled);
}

TEST_F(StoreTest, OnlyEnabledSchedulesComeBackAsDue)
{
    m_store->upsertSchedule("enabled", 100, true);
    m_store->upsertSchedule("disabled", 100, false);

    const auto due {m_store->dueSchedules(1000)};
    ASSERT_EQ(due.size(), 1U);
    EXPECT_EQ(due[0].scheduleId, "enabled");
}

TEST_F(StoreTest, ANonTerminalInstanceSuppressesTheNextRun)
{
    auto req {request("run-1", "agent_delete_old")};
    req.scheduleId = "agent_delete_old";
    req.scheduledRunAt = 1000;
    m_store->createManagerTask(req);

    EXPECT_TRUE(m_store->scheduleHasActiveRun("agent_delete_old"));

    m_store->setResult("run-1", TaskStatus::Completed, 1, 0, std::nullopt, 2000);
    EXPECT_FALSE(m_store->scheduleHasActiveRun("agent_delete_old"));
}
