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

#include "execution/executor.hpp"
#include "execution/sweeper.hpp"
#include "testDoubles.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <set>
#include <stdexcept>
#include <thread>

using namespace task_manager;
using namespace task_manager::execution;
using namespace task_manager::test;

using namespace std::chrono_literals;

namespace
{
    constexpr auto WAIT {3000ms};

    class ExecutorTest : public ::testing::Test
    {
    protected:
        void SetUp() override { m_store = makeMemoryStore(); }

        void TearDown() override
        {
            if (m_executor)
            {
                m_executor->stop();
            }
        }

        void startExecutor(registry::TaskRegistry registry, const int workers = 4)
        {
            m_registry = std::make_unique<registry::TaskRegistry>(std::move(registry));

            Executor::Options options;
            options.workerCount = workers;
            m_executor = std::make_unique<Executor>(*m_store, *m_registry, options, nullptr);
            m_executor->start();
        }

        std::unique_ptr<storage::SqliteTaskStore> m_store;
        std::unique_ptr<registry::TaskRegistry> m_registry;
        std::unique_ptr<Executor> m_executor;
    };
} // namespace

TEST_F(ExecutorTest, RunsAPendingTaskAndRetiresItCompleted)
{
    auto handler {std::make_shared<TestHandler>()};
    m_store->createManagerTask(pendingRow("a"));

    startExecutor(registryWith(handler));
    m_executor->notify("test_type");

    ASSERT_TRUE(handler->waitForRuns(1, WAIT));
    m_executor->stop();

    const auto row {m_store->getManagerTask("a")};
    ASSERT_TRUE(row.has_value());
    EXPECT_EQ(row->status, TaskStatus::Completed);
    EXPECT_FALSE(row->owner.has_value()) << "a retired row must not keep an owner";
}

TEST_F(ExecutorTest, RunsEveryPendingTaskExactlyOnce)
{
    auto handler {std::make_shared<TestHandler>()};
    for (int i = 0; i < 50; ++i)
    {
        m_store->createManagerTask(pendingRow("task-" + std::to_string(i)));
    }

    startExecutor(registryWith(handler, "test_type", 4));
    m_executor->notify("test_type");

    ASSERT_TRUE(handler->waitForRuns(50, WAIT));
    m_executor->stop();

    const auto ran {handler->ran()};
    const std::set<std::string> unique {ran.cbegin(), ran.cend()};
    EXPECT_EQ(unique.size(), 50U) << "a task ran more than once";
}

TEST_F(ExecutorTest, TheGroupCapBoundsSimultaneousRuns)
{
    auto handler {std::make_shared<TestHandler>()};
    handler->holdRuns(true);

    for (int i = 0; i < 10; ++i)
    {
        m_store->createManagerTask(pendingRow("task-" + std::to_string(i)));
    }

    // A cap of two with four workers available: the cap, not the pool size, is what bounds it.
    startExecutor(registryWith(handler, "test_type", 2), 4);
    m_executor->notify("test_type");

    std::this_thread::sleep_for(300ms);
    EXPECT_LE(handler->peakConcurrent(), 2);

    handler->holdRuns(false);
    ASSERT_TRUE(handler->waitForRuns(10, WAIT));
    EXPECT_LE(handler->peakConcurrent(), 2) << "the cap was exceeded at some point";
}

TEST_F(ExecutorTest, TypesInOneGroupShareTheCap)
{
    auto handler {std::make_shared<TestHandler>()};
    handler->holdRuns(true);

    registry::TaskTypeDescriptor first;
    first.name = "rotate_daily";
    first.concurrencyGroup = "rotation";
    first.maxConcurrent = 1;
    first.watchdogBudget = std::chrono::seconds {60};
    first.handler = handler;

    registry::TaskTypeDescriptor second {first};
    second.name = "rotate_other";

    m_store->createManagerTask(pendingRow("a", "rotate_daily"));
    m_store->createManagerTask(pendingRow("b", "rotate_other"));

    startExecutor(registry::TaskRegistry {registry::RetryPolicy {}, {first, second}}, 4);
    m_executor->notifyTypes({"rotate_daily", "rotate_other"});

    std::this_thread::sleep_for(300ms);

    // This is what the retired single "local" lane was really enforcing, and the only reason the
    // two rotations still share anything.
    EXPECT_EQ(handler->peakConcurrent(), 1);

    handler->holdRuns(false);
    ASSERT_TRUE(handler->waitForRuns(2, WAIT));
}

TEST_F(ExecutorTest, TypesInDifferentGroupsRunAtTheSameTime)
{
    auto handler {std::make_shared<TestHandler>()};
    handler->holdRuns(true);

    registry::TaskTypeDescriptor sweep;
    sweep.name = "disconnect_sweep";
    sweep.concurrencyGroup = "disconnect_sweep";
    sweep.maxConcurrent = 1;
    sweep.watchdogBudget = std::chrono::seconds {60};
    sweep.handler = handler;

    registry::TaskTypeDescriptor rotation {sweep};
    rotation.name = "rotate_daily";
    rotation.concurrencyGroup = "rotation";

    m_store->createManagerTask(pendingRow("a", "disconnect_sweep"));
    m_store->createManagerTask(pendingRow("b", "rotate_daily"));

    startExecutor(registry::TaskRegistry {registry::RetryPolicy {}, {sweep, rotation}}, 4);
    m_executor->notifyTypes({"disconnect_sweep", "rotate_daily"});

    std::this_thread::sleep_for(300ms);

    // The lane model forbade this purely to save threads. Nothing about the work required it.
    EXPECT_EQ(handler->peakConcurrent(), 2);

    handler->holdRuns(false);
    ASSERT_TRUE(handler->waitForRuns(2, WAIT));
}

TEST_F(ExecutorTest, ARetryableOutcomeReturnsTheRowToPendingWithBackoff)
{
    auto handler {std::make_shared<TestHandler>(HandlerResult::of(Outcome::Retryable, "boom"))};
    m_store->createManagerTask(pendingRow("a"));

    startExecutor(registryWith(handler));
    m_executor->notify("test_type");

    ASSERT_TRUE(handler->waitForRuns(1, WAIT));
    m_executor->stop();

    const auto row {m_store->getManagerTask("a")};
    ASSERT_TRUE(row.has_value());
    EXPECT_EQ(row->status, TaskStatus::Pending);
    EXPECT_EQ(row->attempts, 1);
    EXPECT_EQ(row->lastError.value_or(""), "boom");

    // Backed off, so it is not immediately eligible again -- which is also why the run count above
    // stayed at one rather than spinning.
    EXPECT_GT(row->nextAttemptAt, 1000);
}

TEST_F(ExecutorTest, AnIncompleteOutcomeIsEligibleImmediatelyAndRunsAgain)
{
    auto handler {std::make_shared<TestHandler>()};
    handler->queueResult(HandlerResult::of(Outcome::Incomplete, "more to do"));
    // The second run takes the default, Ok, which ends the loop.

    m_store->createManagerTask(pendingRow("a"));

    startExecutor(registryWith(handler));
    m_executor->notify("test_type");

    // Incomplete re-queues eligible NOW and self-notifies, so the second batch starts without the
    // scheduler having to wake.
    ASSERT_TRUE(handler->waitForRuns(2, WAIT));
    m_executor->stop();

    const auto row {m_store->getManagerTask("a")};
    ASSERT_TRUE(row.has_value());
    EXPECT_EQ(row->status, TaskStatus::Completed);
    EXPECT_EQ(row->attempts, 0) << "incomplete is progress, not an attempt";
}

TEST_F(ExecutorTest, AHandlerThatThrowsDoesNotKillTheWorker)
{
    class ThrowingHandler final : public IHandler
    {
    public:
        HandlerResult run(const ClaimedTask&, const StopToken&) override
        {
            ++calls;
            throw std::runtime_error("handler bug");
        }
        std::atomic<int> calls {0};
    };

    auto handler {std::make_shared<ThrowingHandler>()};
    m_store->createManagerTask(pendingRow("a"));

    startExecutor(registryWith(handler), 1);
    m_executor->notify("test_type");

    // The row must be recorded as retryable rather than left claimed, and the worker must survive
    // to take the next task -- otherwise one bug stops the type for the life of the process.
    for (int i = 0; i < 100 && handler->calls.load() == 0; ++i)
    {
        std::this_thread::sleep_for(10ms);
    }
    m_executor->stop();

    EXPECT_GE(handler->calls.load(), 1);
    const auto row {m_store->getManagerTask("a")};
    ASSERT_TRUE(row.has_value());
    EXPECT_EQ(row->status, TaskStatus::Pending);
    EXPECT_EQ(row->attempts, 1);
}

TEST_F(ExecutorTest, ExhaustingTheAttemptBudgetDeadLetters)
{
    registry::RetryPolicy policy;
    policy.maxAttempts = 2;
    policy.backoffBase = std::chrono::seconds {0}; // eligible again at once, so the test does not wait

    registry::TaskTypeDescriptor descriptor;
    descriptor.name = "test_type";
    descriptor.concurrencyGroup = "test_type";
    descriptor.maxConcurrent = 1;
    descriptor.watchdogBudget = std::chrono::seconds {60};
    descriptor.handler = std::make_shared<TestHandler>(HandlerResult::of(Outcome::Retryable, "nope"));

    m_store->createManagerTask(pendingRow("a"));

    startExecutor(registry::TaskRegistry {policy, {descriptor}}, 1);

    // Nudge it until it retires; a backoff of zero degenerates to the cap, so drive it explicitly.
    for (int i = 0; i < 50; ++i)
    {
        m_executor->notify("test_type");
        std::this_thread::sleep_for(20ms);
        const auto row {m_store->getManagerTask("a")};
        if (row.has_value() && row->status == TaskStatus::DeadLetter)
        {
            break;
        }
        if (row.has_value() && row->status == TaskStatus::Pending)
        {
            // Make it eligible again without waiting out the ladder.
            storage::RequeueRequest requeue;
            requeue.taskId = "a";
            requeue.attempts = row->attempts;
            requeue.deferCount = row->deferCount;
            requeue.nextAttemptAt = 0;
            m_store->requeue(requeue);
        }
    }
    m_executor->stop();

    const auto row {m_store->getManagerTask("a")};
    ASSERT_TRUE(row.has_value());
    EXPECT_EQ(row->status, TaskStatus::DeadLetter);
    EXPECT_GE(row->attempts, 2);
}

TEST_F(ExecutorTest, AnEmptyClaimDoesNotSwallowAConcurrentNotification)
{
    // The ready set holds a token per type, and a worker that claims nothing drops the type only if
    // that token has not moved. Without the check, a producer inserting between the empty claim and
    // the drop would have its notification discarded, and the row would wait for the scheduler's
    // backstop instead of starting now.
    auto handler {std::make_shared<TestHandler>()};
    startExecutor(registryWith(handler), 1);

    m_executor->notify("test_type"); // nothing to claim yet

    for (int round = 0; round < 20; ++round)
    {
        const auto id {"task-" + std::to_string(round)};
        m_store->createManagerTask(pendingRow(id));
        m_executor->notify("test_type");
    }

    ASSERT_TRUE(handler->waitForRuns(20, WAIT));
}

TEST_F(ExecutorTest, PeriodicActionsRunOnSignalAndCoalesce)
{
    auto handler {std::make_shared<TestHandler>()};
    m_registry = std::make_unique<registry::TaskRegistry>(registryWith(handler));

    Executor::Options options;
    options.workerCount = 2;
    m_executor = std::make_unique<Executor>(*m_store, *m_registry, options, nullptr);

    std::atomic<int> runs {0};
    auto action {std::make_shared<Executor::PeriodicAction>()};
    action->name = "log_rotate_size";
    action->concurrencyGroup = "rotation";
    action->run = [&runs](const StopToken&) { ++runs; };

    // BEFORE start(), as the contract requires: the action list is read by workers under the
    // executor's mutex but written without it, so registering afterwards would be a data race.
    m_executor->registerPeriodicAction(action);
    m_executor->start();

    m_executor->signalPeriodicAction("log_rotate_size");
    for (int i = 0; i < 100 && runs.load() == 0; ++i)
    {
        std::this_thread::sleep_for(10ms);
    }

    EXPECT_EQ(runs.load(), 1);

    // Repeated signals before it runs collapse into one: a rotation already owed is not owed twice.
    m_executor->signalPeriodicAction("log_rotate_size");
    m_executor->signalPeriodicAction("log_rotate_size");
    m_executor->signalPeriodicAction("log_rotate_size");

    for (int i = 0; i < 100 && runs.load() < 2; ++i)
    {
        std::this_thread::sleep_for(10ms);
    }
    m_executor->stop();

    EXPECT_GE(runs.load(), 2);
    EXPECT_LE(runs.load(), 4) << "signals before a run should coalesce, not queue";
}

TEST_F(ExecutorTest, StoppingLeavesAnInFlightRowClaimedForTheNextBoot)
{
    auto handler {std::make_shared<TestHandler>()};
    handler->holdRuns(true);

    m_store->createManagerTask(pendingRow("a"));

    startExecutor(registryWith(handler), 1);
    m_executor->notify("test_type");

    ASSERT_TRUE(handler->waitForRuns(1, WAIT));

    const auto during {m_store->getManagerTask("a")};
    ASSERT_TRUE(during.has_value());
    EXPECT_EQ(during->status, TaskStatus::Claimed);
    EXPECT_TRUE(during->owner.has_value());

    handler->holdRuns(false);
    m_executor->stop();
}

// ---- the ownership sweep -----------------------------------------------------------------------

namespace
{
    class SweeperTest : public ::testing::Test
    {
    protected:
        void SetUp() override
        {
            m_store = makeMemoryStore();
            m_handler = std::make_shared<TestHandler>();
            m_registry = std::make_unique<registry::TaskRegistry>(registryWith(m_handler));

            Executor::Options options;
            options.workerCount = 1;
            m_executor = std::make_unique<Executor>(*m_store, *m_registry, options, nullptr);

            m_sweeper = std::make_unique<Sweeper>(*m_store, *m_registry, *m_executor, Sweeper::Options {}, nullptr);
        }

        std::unique_ptr<storage::SqliteTaskStore> m_store;
        std::shared_ptr<TestHandler> m_handler;
        std::unique_ptr<registry::TaskRegistry> m_registry;
        std::unique_ptr<Executor> m_executor;
        std::unique_ptr<Sweeper> m_sweeper;
    };
} // namespace

TEST_F(SweeperTest, ReclaimsARowLeftClaimedByADeadProcess)
{
    m_store->createManagerTask(pendingRow("a"));

    // A pid that cannot be running, claimed long ago.
    ASSERT_TRUE(m_store->claim("test_type", "999999:12345:w0", 1000).has_value());

    EXPECT_EQ(m_sweeper->sweepAll(), 1);

    const auto row {m_store->getManagerTask("a")};
    ASSERT_TRUE(row.has_value());
    EXPECT_EQ(row->status, TaskStatus::Pending);
    EXPECT_FALSE(row->owner.has_value());
}

TEST_F(SweeperTest, ReclaimingDoesNotChargeAnAttempt)
{
    m_store->createManagerTask(pendingRow("a"));
    ASSERT_TRUE(m_store->claim("test_type", "999999:12345:w0", 1000).has_value());

    m_sweeper->sweepAll();

    // A crashed worker is not the task failing. Charging it would spend the task's budget on the
    // process, so a manager crash-looping for an unrelated reason would dead-letter healthy work.
    const auto row {m_store->getManagerTask("a")};
    ASSERT_TRUE(row.has_value());
    EXPECT_EQ(row->attempts, 0);
}

TEST_F(SweeperTest, LeavesARowOwnedByALiveForeignProcessAlone)
{
    m_store->createManagerTask(pendingRow("a"));

    const LiveForeignProcess other;
    ASSERT_TRUE(other.valid()) << "/proc must be readable for this test to mean anything";

    // A real live pid with its real start time: alive, and not us.
    ASSERT_TRUE(m_store->claim("test_type", other.owner(), 1000).has_value());

    EXPECT_EQ(m_sweeper->sweepAll(), 0);
    EXPECT_EQ(m_store->getManagerTask("a")->status, TaskStatus::Claimed);
}

TEST_F(SweeperTest, ReclaimsARowOfAnUnknownTypeSoTheReaperCanRetireIt)
{
    m_store->createManagerTask(pendingRow("a", "a_renamed_type"));
    ASSERT_TRUE(m_store->claim("a_renamed_type", "999999:12345:w0", 1000).has_value());

    // The retired implementation skipped these, which left a claimed row of a renamed type stuck
    // forever: the sweep would not release it, so it never became pending, so the reaper -- which
    // only looks at pending rows -- never saw it, and the ceiling cannot evict a non-terminal row.
    EXPECT_EQ(m_sweeper->sweepAll(), 1);
    EXPECT_EQ(m_store->getManagerTask("a")->status, TaskStatus::Pending);

    EXPECT_EQ(m_sweeper->reapOrphanedTypes(), 1);

    const auto row {m_store->getManagerTask("a")};
    ASSERT_TRUE(row.has_value());
    EXPECT_EQ(row->status, TaskStatus::Failed);
    EXPECT_EQ(row->lastError.value_or(""), "unknown task type");
}

TEST_F(SweeperTest, TheReaperLeavesKnownTypesAlone)
{
    m_store->createManagerTask(pendingRow("a"));
    EXPECT_EQ(m_sweeper->reapOrphanedTypes(), 0);
    EXPECT_EQ(m_store->getManagerTask("a")->status, TaskStatus::Pending);
}

TEST_F(SweeperTest, TheSweepPagesPastOneFullPage)
{
    for (int i = 0; i < 250; ++i)
    {
        const auto id {"task-" + std::to_string(i)};
        m_store->createManagerTask(pendingRow(id));
        ASSERT_TRUE(m_store->claim("test_type", "999999:12345:w0", 1000).has_value());
    }

    // Paged on TASK_ID, not OFFSET: rows are written concurrently in production, and an offset walk
    // would skip or repeat as the set shifts.
    EXPECT_EQ(m_sweeper->sweepAll(), 250);
}
