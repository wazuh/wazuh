// SPDX-License-Identifier: AGPL-3.0-or-later
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <base/logging.hpp>
#include <scheduler/mockScheduler.hpp>
#include <scheduler/triggerableTask.hpp>

using ::testing::_;
using ::testing::Invoke;
using ::testing::StrictMock;
using ::testing::Throw;

namespace
{

class TriggerableTaskTest : public ::testing::Test
{
protected:
    void SetUp() override { logging::testInit(); }

    /// Accept every scheduleTask call, remembering what each one was handed.
    void recordSchedules()
    {
        EXPECT_CALL(*m_scheduler, scheduleTask(_, _))
            .WillRepeatedly(Invoke(
                [this](std::string_view name, scheduler::TaskConfig&& config)
                {
                    m_names.emplace_back(name);
                    m_configs.push_back(config);
                }));
    }

    /// Accept every scheduleTaskFirst call.
    void allowMovesToTheFront() { EXPECT_CALL(*m_scheduler, scheduleTaskFirst(_)).Times(::testing::AnyNumber()); }

    std::shared_ptr<StrictMock<scheduler::mocks::MockIScheduler>> m_scheduler {
        std::make_shared<StrictMock<scheduler::mocks::MockIScheduler>>()};
    std::vector<std::string> m_names;
    std::vector<scheduler::TaskConfig> m_configs;
};

} // namespace

TEST_F(TriggerableTaskTest, StartRegistersARecurringTaskWithoutAnImmediateRun)
{
    int runs = 0;
    scheduler::TriggerableTask task {m_scheduler, "task", 60, 0, [&runs]() { ++runs; }};

    recordSchedules();
    task.start();

    ASSERT_EQ(m_names.size(), 1U);
    EXPECT_EQ(m_names[0], "task");
    EXPECT_EQ(m_configs[0].interval, 60U);
    EXPECT_FALSE(m_configs[0].runImmediately) << "a run right away is what trigger() is for";
    m_configs[0].taskFunction();
    EXPECT_EQ(runs, 1);
}

TEST_F(TriggerableTaskTest, StartCanRunTheFirstRecurringRunNowAtTheFront)
{
    scheduler::TriggerableTask task {m_scheduler, "task", 60, 0, []() {}};

    recordSchedules();
    EXPECT_CALL(*m_scheduler, scheduleTaskFirst(std::string_view {"task"}));
    task.start(/*runNow=*/true);

    ASSERT_EQ(m_names.size(), 1U);
    EXPECT_EQ(m_names[0], "task") << "the recurring task itself, so nextInterval follows that first run";
    EXPECT_EQ(m_configs[0].interval, 60U);
    EXPECT_TRUE(m_configs[0].runImmediately);
}

TEST_F(TriggerableTaskTest, TheRecurringTaskCarriesNextIntervalAndRequestRunsDoNot)
{
    scheduler::TriggerableTask task {m_scheduler, "task", 60, 0, []() {}, []() -> std::size_t { return 5; }};

    recordSchedules();
    allowMovesToTheFront();
    task.start();
    task.trigger();

    ASSERT_EQ(m_configs.size(), 2U);
    ASSERT_TRUE(static_cast<bool>(m_configs[0].nextInterval));
    EXPECT_EQ(m_configs[0].nextInterval(), 5U);
    EXPECT_FALSE(static_cast<bool>(m_configs[1].nextInterval)) << "a request run is one-time";
}

TEST_F(TriggerableTaskTest, WithoutAnIntervalStartNowTriggersARun)
{
    scheduler::TriggerableTask task {m_scheduler, "task", 0, 0, []() {}};

    recordSchedules();
    EXPECT_CALL(*m_scheduler, scheduleTaskFirst(std::string_view {"task/request-1"}));
    task.start(/*runNow=*/true);

    ASSERT_EQ(m_names.size(), 1U);
    EXPECT_EQ(m_names[0], "task/request-1");
}

TEST_F(TriggerableTaskTest, WithoutAnIntervalStartSchedulesNothing)
{
    scheduler::TriggerableTask task {m_scheduler, "task", 0, 0, []() {}};
    task.start(); // StrictMock: any scheduler call fails the test.
}

TEST_F(TriggerableTaskTest, ATriggerQueuesAOneTimeRunAtTheFront)
{
    int runs = 0;
    scheduler::TriggerableTask task {m_scheduler, "task", 60, 0, [&runs]() { ++runs; }};

    recordSchedules();
    EXPECT_CALL(*m_scheduler, scheduleTaskFirst(std::string_view {"task/request-1"}));
    task.trigger();

    ASSERT_EQ(m_names.size(), 1U);
    EXPECT_EQ(m_names[0], "task/request-1");
    EXPECT_EQ(m_configs[0].interval, 0U) << "a one-time task";
    m_configs[0].taskFunction();
    EXPECT_EQ(runs, 1);
}

TEST_F(TriggerableTaskTest, ATriggerRightAfterARunIsNotLost)
{
    // The recurring task is out of the queue between its run returning and the scheduler re-queuing
    // it; a request in that window must still get a run of its own.
    int runs = 0;
    scheduler::TriggerableTask task {m_scheduler, "task", 60, 0, [&runs]() { ++runs; }};

    recordSchedules();
    allowMovesToTheFront();
    task.start();
    m_configs[0].taskFunction(); // The recurring run ends...
    task.trigger();              // ...and a request arrives before the scheduler re-queues it.

    ASSERT_EQ(m_names.size(), 2U);
    EXPECT_EQ(m_names[1], "task/request-1");
    m_configs[1].taskFunction();
    EXPECT_EQ(runs, 2);
}

TEST_F(TriggerableTaskTest, EachRequestRunHasItsOwnName)
{
    scheduler::TriggerableTask task {m_scheduler, "task", 0, 0, []() {}};

    recordSchedules();
    allowMovesToTheFront();
    task.trigger();
    m_configs[0].taskFunction();
    task.trigger();

    ASSERT_EQ(m_names.size(), 2U);
    EXPECT_NE(m_names[0], m_names[1]) << "a finished request run may still be registered under its name";
}

TEST_F(TriggerableTaskTest, RequestsBeforeTheRunStartsShareIt)
{
    int runs = 0;
    scheduler::TriggerableTask task {m_scheduler, "task", 0, 0, [&runs]() { ++runs; }};

    recordSchedules();
    allowMovesToTheFront();
    task.trigger();
    task.trigger();

    ASSERT_EQ(m_names.size(), 1U);
    m_configs[0].taskFunction();
    EXPECT_EQ(runs, 1);
}

TEST_F(TriggerableTaskTest, ATriggerDuringARunRunsOnceMoreRightAfter)
{
    int runs = 0;
    std::unique_ptr<scheduler::TriggerableTask> task;
    task = std::make_unique<scheduler::TriggerableTask>(m_scheduler,
                                                        "task",
                                                        60,
                                                        0,
                                                        [&runs, &task]()
                                                        {
                                                            // A request arriving mid-run: twice, to show
                                                            // requests coalesce into one more run.
                                                            if (++runs == 1)
                                                            {
                                                                task->trigger();
                                                                task->trigger();
                                                            }
                                                        });

    recordSchedules();
    task->start();
    m_configs[0].taskFunction(); // StrictMock: the mid-run triggers must not reach the scheduler.

    EXPECT_EQ(runs, 2);
    EXPECT_EQ(m_names.size(), 1U);
}

TEST_F(TriggerableTaskTest, RunsNeverOverlap)
{
    int runs = 0;
    int concurrent = 0;
    std::function<void()> otherRun;
    scheduler::TriggerableTask task {m_scheduler,
                                     "task",
                                     60,
                                     0,
                                     [&]()
                                     {
                                         ++runs;
                                         ++concurrent;
                                         if (runs == 1)
                                         {
                                             // The recurring task fires while this run is going.
                                             otherRun();
                                         }
                                         EXPECT_EQ(concurrent, 1);
                                         --concurrent;
                                     }};

    recordSchedules();
    allowMovesToTheFront();
    task.start();
    task.trigger();
    otherRun = m_configs[0].taskFunction;

    m_configs[1].taskFunction();
    EXPECT_EQ(runs, 2) << "the overlapping execution became one more run, after the first";
}

TEST_F(TriggerableTaskTest, AFailingRunIsContainedAndTheTaskStaysUsable)
{
    int runs = 0;
    scheduler::TriggerableTask task {m_scheduler,
                                     "task",
                                     60,
                                     0,
                                     [&runs]()
                                     {
                                         ++runs;
                                         throw std::runtime_error("boom");
                                     }};

    recordSchedules();
    allowMovesToTheFront();
    task.start();
    EXPECT_NO_THROW(m_configs[0].taskFunction());
    EXPECT_NO_THROW(m_configs[0].taskFunction());
    EXPECT_EQ(runs, 2);

    task.trigger();
    EXPECT_EQ(m_names.size(), 2U);
}

TEST_F(TriggerableTaskTest, AnUnknownExceptionDoesNotWedgeTheTask)
{
    int runs = 0;
    scheduler::TriggerableTask task {m_scheduler,
                                     "task",
                                     60,
                                     0,
                                     [&runs]()
                                     {
                                         if (++runs == 1)
                                         {
                                             throw 42; // Not a std::exception.
                                         }
                                     }};

    recordSchedules();
    task.start();
    EXPECT_NO_THROW(m_configs[0].taskFunction());
    m_configs[0].taskFunction();
    EXPECT_EQ(runs, 2) << "the task must not be left marked as running";
}

TEST_F(TriggerableTaskTest, ARefusedRequestDoesNotBlockTheNextOne)
{
    scheduler::TriggerableTask task {m_scheduler, "task", 0, 0, []() {}};

    EXPECT_CALL(*m_scheduler, scheduleTask(_, _))
        .WillOnce(Throw(std::runtime_error("refused")))
        .WillOnce(Invoke([](std::string_view, scheduler::TaskConfig&&) {}));
    EXPECT_CALL(*m_scheduler, scheduleTaskFirst(_));

    EXPECT_NO_THROW(task.trigger());
    task.trigger(); // Queued this time: the refusal did not leave the request marked as pending.
}

TEST_F(TriggerableTaskTest, ARequestRunAlreadyTakenIsNotMoved)
{
    scheduler::TriggerableTask task {m_scheduler, "task", 0, 0, []() {}};

    recordSchedules();
    EXPECT_CALL(*m_scheduler, scheduleTaskFirst(_)).WillOnce(Throw(std::invalid_argument("not registered")));

    EXPECT_NO_THROW(task.trigger());
    EXPECT_EQ(m_names.size(), 1U);
}

TEST_F(TriggerableTaskTest, AGoneSchedulerIsContained)
{
    std::weak_ptr<scheduler::IScheduler> gone;
    scheduler::TriggerableTask task {gone, "task", 60, 0, []() {}};

    EXPECT_NO_THROW(task.trigger());
    EXPECT_THROW(task.start(), std::runtime_error);
}
