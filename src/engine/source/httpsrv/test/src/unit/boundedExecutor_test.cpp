// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <future>
#include <thread>
#include <vector>

#include <httpsrv/boundedExecutor.hpp>

using httpsrv::BoundedExecutor;
using namespace std::chrono_literals;

namespace
{
BoundedExecutor::Job job(std::function<void()> run, std::function<void()> reject = {})
{
    return BoundedExecutor::Job {std::move(run), std::move(reject)};
}

/// A gate the test opens to let blocked jobs finish.
struct Gate
{
    std::promise<void> promise;
    std::shared_future<void> future {promise.get_future().share()};
    void open() { promise.set_value(); }
    void wait() const { future.wait(); }
};
} // namespace

TEST(BoundedExecutorTest, RunsEverySubmittedJobOnce)
{
    std::atomic<int> ran {0};
    {
        BoundedExecutor executor {"test", 4, 64};
        for (int i = 0; i < 50; ++i)
        {
            ASSERT_EQ(BoundedExecutor::Submit::Accepted, executor.trySubmit(job([&] { ++ran; })));
        }
        executor.drainUntil(std::chrono::steady_clock::now() + 5s);
    }
    EXPECT_EQ(50, ran.load());
}

TEST(BoundedExecutorTest, RefusesWhenTheQueueIsFull)
{
    Gate gate;
    std::atomic<bool> started {false};
    BoundedExecutor executor {"test", 1, 2};

    // The single worker blocks on the first job, so the next two fill the queue.
    ASSERT_EQ(BoundedExecutor::Submit::Accepted,
              executor.trySubmit(job(
                  [&]
                  {
                      started = true;
                      gate.wait();
                  })));
    while (!started)
    {
        std::this_thread::sleep_for(1ms);
    }
    ASSERT_EQ(BoundedExecutor::Submit::Accepted, executor.trySubmit(job([] {})));
    ASSERT_EQ(BoundedExecutor::Submit::Accepted, executor.trySubmit(job([] {})));

    EXPECT_EQ(BoundedExecutor::Submit::Full, executor.trySubmit(job([] {})));
    EXPECT_EQ(2U, executor.depth());

    gate.open();
}

TEST(BoundedExecutorTest, RefusesAfterAdmissionCloses)
{
    BoundedExecutor executor {"test", 1, 8};
    executor.closeAdmission();

    EXPECT_EQ(BoundedExecutor::Submit::Closed, executor.trySubmit(job([] {})));
}

// Closing admission is not cancelling: what was queued still runs if it can before the deadline.
TEST(BoundedExecutorTest, DrainRunsQueuedJobsBeforeTheDeadline)
{
    std::atomic<int> ran {0};
    BoundedExecutor executor {"test", 2, 64};
    for (int i = 0; i < 20; ++i)
    {
        ASSERT_EQ(BoundedExecutor::Submit::Accepted,
                  executor.trySubmit(job(
                      [&]
                      {
                          std::this_thread::sleep_for(1ms);
                          ++ran;
                      })));
    }

    const auto report = executor.drainUntil(std::chrono::steady_clock::now() + 5s);

    EXPECT_EQ(20, ran.load());
    EXPECT_EQ(0U, report.rejected);
    EXPECT_EQ(0U, report.abandoned);
}

TEST(BoundedExecutorTest, DrainRejectsUnstartedJobsAtTheDeadline)
{
    Gate gate;
    std::atomic<bool> started {false};
    std::atomic<int> rejected {0};
    std::atomic<int> ran {0};
    BoundedExecutor executor {"test", 1, 8};

    ASSERT_EQ(BoundedExecutor::Submit::Accepted,
              executor.trySubmit(job(
                  [&]
                  {
                      started = true;
                      gate.wait();
                  })));
    while (!started)
    {
        std::this_thread::sleep_for(1ms);
    }
    for (int i = 0; i < 3; ++i)
    {
        ASSERT_EQ(BoundedExecutor::Submit::Accepted, executor.trySubmit(job([&] { ++ran; }, [&] { ++rejected; })));
    }

    const auto report = executor.drainUntil(std::chrono::steady_clock::now() + 100ms);

    EXPECT_EQ(3U, report.rejected);
    EXPECT_EQ(3, rejected.load()) << "every unstarted job is answered";
    EXPECT_EQ(1U, report.abandoned);
    gate.open();
    EXPECT_EQ(0, ran.load()) << "a rejected job never runs afterwards";
}

// A job that outlives the deadline is reported, and the executor still waits for it on destruction:
// its owner may destroy what the job uses right after the executor is gone.
TEST(BoundedExecutorTest, DrainReportsAbandonedJobsAndTheDestructorJoinsThem)
{
    std::atomic<bool> started {false};
    std::atomic<bool> finished {false};
    auto executor = std::make_unique<BoundedExecutor>("test", 1, 8);
    ASSERT_EQ(BoundedExecutor::Submit::Accepted,
              executor->trySubmit(job(
                  [&]
                  {
                      started = true;
                      std::this_thread::sleep_for(300ms);
                      finished = true;
                  })));
    while (!started)
    {
        std::this_thread::sleep_for(1ms);
    }

    const auto report = executor->drainUntil(std::chrono::steady_clock::now() + 20ms);
    EXPECT_EQ(1U, report.abandoned);
    EXPECT_FALSE(finished.load());

    executor.reset();
    EXPECT_TRUE(finished.load()) << "the destructor returned before the job ended";
}
