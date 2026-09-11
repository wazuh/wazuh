/*
 * Wazuh content manager - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "contentOnDemand.hpp"
#include "onDemandManager.hpp"

#include "gtest/gtest.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <future>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace
{

using content_manager::OnDemandCode;
using content_manager::OnDemandResult;
using content_manager::RunRequest;

/// Collects the outcomes the lane hands back, from whichever thread produces them.
class Outcomes
{
public:
    void record(OnDemandResult result)
    {
        {
            std::lock_guard<std::mutex> lock {m_mutex};
            m_results.push_back(std::move(result));
        }
        m_cv.notify_all();
    }

    /// @return True when @p count outcomes arrived within the timeout.
    bool waitFor(std::size_t count, std::chrono::milliseconds timeout = std::chrono::seconds {5})
    {
        std::unique_lock<std::mutex> lock {m_mutex};
        return m_cv.wait_for(lock, timeout, [this, count] { return m_results.size() >= count; });
    }

    std::vector<OnDemandResult> snapshot()
    {
        std::lock_guard<std::mutex> lock {m_mutex};
        return m_results;
    }

private:
    std::mutex m_mutex;
    std::condition_variable m_cv;
    std::vector<OnDemandResult> m_results;
};

content_manager::CycleOutcome outcomeOf(content_manager::CycleStatus status, std::string detail = {})
{
    content_manager::CycleOutcome outcome;
    outcome.status = status;
    outcome.detail = std::move(detail);
    return outcome;
}

class OnDemandManagerTest : public ::testing::Test
{
protected:
    void TearDown() override
    {
        OnDemandManager::instance().clearEndpoints();
    }
};

} // namespace

TEST_F(OnDemandManagerTest, UnknownTopicIsRejectedInline)
{
    Outcomes outcomes;

    // No queue slot is spent on a request that can never run.
    content_manager::requestOnDemand("nope", {}, [&outcomes](OnDemandResult r) { outcomes.record(std::move(r)); });

    const auto results = outcomes.snapshot();
    ASSERT_EQ(results.size(), 1U);
    EXPECT_EQ(results.front().code, OnDemandCode::UnknownTopic);
}

TEST_F(OnDemandManagerTest, RunsARegisteredTopicAndReportsCompletion)
{
    RunRequest seen;
    OnDemandManager::instance().addEndpoint("topic",
                                            [&seen](RunRequest request)
                                            {
                                                seen = request;
                                                return OnDemandManager::RunResult {
                                                    true, outcomeOf(content_manager::CycleStatus::Updated, "done")};
                                            });

    Outcomes outcomes;
    content_manager::requestOnDemand(
        "topic", RunRequest {true, false}, [&outcomes](OnDemandResult r) { outcomes.record(std::move(r)); });

    ASSERT_TRUE(outcomes.waitFor(1));
    const auto results = outcomes.snapshot();
    EXPECT_EQ(results.front().code, OnDemandCode::Completed);
    EXPECT_EQ(results.front().detail, "done");

    EXPECT_TRUE(seen.forceFullReload);
    // requestOnDemand forces this, so a host cannot accidentally queue a "scheduled" cycle.
    EXPECT_TRUE(seen.onDemand);
}

TEST_F(OnDemandManagerTest, ATopicAlreadyRunningIsReportedHonestly)
{
    OnDemandManager::instance().addEndpoint(
        "topic", [](RunRequest) { return OnDemandManager::RunResult {false, {}}; });

    Outcomes outcomes;
    content_manager::requestOnDemand("topic", {}, [&outcomes](OnDemandResult r) { outcomes.record(std::move(r)); });

    ASSERT_TRUE(outcomes.waitFor(1));
    // The pre-lane server answered success to requests it had silently dropped; coalescing is the
    // design working, but it has to be visible.
    EXPECT_EQ(outcomes.snapshot().front().code, OnDemandCode::AlreadyRunning);
}

TEST_F(OnDemandManagerTest, AFailedCycleIsReportedAsFailed)
{
    OnDemandManager::instance().addEndpoint(
        "topic",
        [](RunRequest)
        {
            return OnDemandManager::RunResult {true,
                                               outcomeOf(content_manager::CycleStatus::FailedTransport, "no indexer")};
        });

    Outcomes outcomes;
    content_manager::requestOnDemand("topic", {}, [&outcomes](OnDemandResult r) { outcomes.record(std::move(r)); });

    ASSERT_TRUE(outcomes.waitFor(1));
    EXPECT_EQ(outcomes.snapshot().front().code, OnDemandCode::Failed);
}

TEST_F(OnDemandManagerTest, ASkippedCycleIsNotAFailure)
{
    OnDemandManager::instance().addEndpoint(
        "topic",
        [](RunRequest)
        {
            return OnDemandManager::RunResult {
                true, outcomeOf(content_manager::CycleStatus::SkippedConsumerNotReady, "consumer busy")};
        });

    Outcomes outcomes;
    content_manager::requestOnDemand("topic", {}, [&outcomes](OnDemandResult r) { outcomes.record(std::move(r)); });

    ASSERT_TRUE(outcomes.waitFor(1));
    // The update ran to completion; it just had nothing to do. That is a 200, not a 500.
    EXPECT_EQ(outcomes.snapshot().front().code, OnDemandCode::Completed);
}

TEST_F(OnDemandManagerTest, AThrowingCallbackIsReportedAsFailed)
{
    OnDemandManager::instance().addEndpoint("topic",
                                            [](RunRequest) -> OnDemandManager::RunResult
                                            { throw std::runtime_error("boom"); });

    Outcomes outcomes;
    content_manager::requestOnDemand("topic", {}, [&outcomes](OnDemandResult r) { outcomes.record(std::move(r)); });

    ASSERT_TRUE(outcomes.waitFor(1));
    EXPECT_EQ(outcomes.snapshot().front().code, OnDemandCode::Failed);
}

TEST_F(OnDemandManagerTest, RemoveEndpointWaitsForAnInFlightCallback)
{
    std::promise<void> entered;
    std::promise<void> release;
    auto releaseFuture = release.get_future();

    OnDemandManager::instance().addEndpoint("topic",
                                            [&entered, &releaseFuture](RunRequest)
                                            {
                                                entered.set_value();
                                                releaseFuture.wait();
                                                return OnDemandManager::RunResult {
                                                    true, outcomeOf(content_manager::CycleStatus::Updated)};
                                            });

    Outcomes outcomes;
    content_manager::requestOnDemand("topic", {}, [&outcomes](OnDemandResult r) { outcomes.record(std::move(r)); });

    entered.get_future().wait();

    // removeEndpoint must not return while a callback of that topic is still running: topic
    // teardown builds its "nothing of mine is still executing" guarantee on exactly this.
    std::atomic<bool> removed {false};
    std::thread remover(
        [&removed]
        {
            OnDemandManager::instance().removeEndpoint("topic");
            removed = true;
        });

    std::this_thread::sleep_for(std::chrono::milliseconds {50});
    EXPECT_FALSE(removed.load());

    release.set_value();
    remover.join();
    EXPECT_TRUE(removed.load());
    EXPECT_TRUE(outcomes.waitFor(1));
}

TEST_F(OnDemandManagerTest, ARequestWithNoCompletionIsAccepted)
{
    OnDemandManager::instance().addEndpoint(
        "topic",
        [](RunRequest) { return OnDemandManager::RunResult {true, outcomeOf(content_manager::CycleStatus::Updated)}; });

    // Fire and forget: a host that does not care about the outcome must not have to invent a
    // callback to say so.
    EXPECT_NO_THROW(content_manager::requestOnDemand("topic", {}, {}));
}
