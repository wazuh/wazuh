/*
 * Wazuh content manager - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "action.hpp"
#include "components/consumerGate.hpp"
#include "fakes/fakeIndexerQueryPort.hpp"
#include "gtest/gtest.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using content_manager::CycleStatus;
using fakes::FakeIndexerQueryPort;
using fakes::MemoryTokenStore;

namespace
{

constexpr auto TOPIC = "action.topic";

/// A sink that counts committed cycles and lets a test wait for one.
class SignallingSink final : public content_manager::IContentSink
{
public:
    content_manager::SessionDecision beginSession(const content_manager::SessionInfo&) noexcept override
    {
        return content_manager::SessionDecision::Proceed;
    }

    content_manager::PageAck acceptPage(const content_manager::ContentPage&) noexcept override
    {
        return content_manager::PageAck {};
    }

    content_manager::CommitResult commit(const content_manager::CommitInfo&) noexcept override
    {
        {
            std::lock_guard<std::mutex> lock {m_mutex};
            ++m_commits;
        }
        m_cv.notify_all();
        return content_manager::CommitResult {};
    }

    void abort(content_manager::AbortReason, const std::string&) noexcept override {}

    /// @return True when at least @p count cycles committed within the timeout.
    bool waitForCommits(std::size_t count, std::chrono::milliseconds timeout)
    {
        std::unique_lock<std::mutex> lock {m_mutex};
        return m_cv.wait_for(lock, timeout, [this, count] { return m_commits >= count; });
    }

    std::size_t commits()
    {
        std::lock_guard<std::mutex> lock {m_mutex};
        return m_commits;
    }

private:
    std::mutex m_mutex;
    std::condition_variable m_cv;
    std::size_t m_commits {0};
};

nlohmann::json statusHits(const std::string& status)
{
    return nlohmann::json {
        {"hits", nlohmann::json::array({nlohmann::json {{"_id", "consumer:1"}, {"_source", {{"status", status}}}}})}};
}

/// Parameters mirroring VD's: a 60-minute interval, with a one-second consumer retry.
nlohmann::json parameters(std::size_t consumerRetrySeconds = 1)
{
    return nlohmann::json {{"topicName", TOPIC},
                           {"configData",
                            {{"consumerName", "Action Test"},
                             {"changeDetection", "cursor"},
                             {"consumerRetryIntervalSeconds", consumerRetrySeconds},
                             {"indexer",
                              {{"index", "data-index"},
                               {"consumerStatusIndex", ".consumers"},
                               {"consumerStatusId", "consumer:1"},
                               {"consumerStatusCacheSeconds", 0},
                               {"cursorField", "offset"},
                               {"pageSize", 10},
                               {"numSlices", 1}}}}}};
}

/// A port whose consumer reports `running` for the first @p busyProbes cycles, then `ready`.
std::shared_ptr<FakeIndexerQueryPort> portBusyFor(std::size_t busyProbes)
{
    auto port = std::make_shared<FakeIndexerQueryPort>();
    auto probes = std::make_shared<std::atomic<std::size_t>>(0);

    port->state()->onSearchIndex = [probes, busyProbes](std::string_view, const nlohmann::json&)
    {
        const auto seen = probes->fetch_add(1);
        return nlohmann::json {{"hits", statusHits(seen < busyProbes ? "running" : "ready")}};
    };
    // Only reached once the pre-flight passes: answer the in-PIT probe `ready`, then run dry.
    port->state()->onSearch = [](const auto&, std::size_t call) -> nlohmann::json
    { return call == 0 ? statusHits("ready") : FakeIndexerQueryPort::emptyHits(); };

    return port;
}

class ActionTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        ConsumerGate::resetCache();
        m_sink = std::make_shared<SignallingSink>();
        m_tokens = std::make_shared<MemoryTokenStore>();
    }

    void TearDown() override
    {
        ConsumerGate::resetCache();
    }

    std::shared_ptr<SignallingSink> m_sink;
    std::shared_ptr<MemoryTokenStore> m_tokens;
};

} // namespace

TEST_F(ActionTest, TheDriverRetriesOnRetryAfterNotOnTheConfiguredInterval)
{
    // This is the regression the bounded consumer gate would otherwise be. VD's default
    // feed-update-interval is 60 minutes. Before, the cycle itself polled the consumer every minute
    // and proceeded the moment it turned ready. If the driver ignored `retryAfter` and simply slept
    // for its interval, a manager booting while the indexer is mid-update would sit for an hour with
    // no CVE data at all.
    auto port = portBusyFor(2);
    Action action {TOPIC, parameters(/*consumerRetrySeconds=*/1), m_sink, m_tokens, port};

    constexpr std::size_t SIXTY_MINUTES = 3600;
    action.startActionScheduler(SIXTY_MINUTES);

    // Two deferred cycles at ~1 s each, then the real one. Nowhere near 3600 s.
    EXPECT_TRUE(m_sink->waitForCommits(1, std::chrono::seconds {20}))
        << "the driver waited for its interval instead of honouring retryAfter";

    action.stopActionScheduler();
}

TEST_F(ActionTest, AReadyConsumerRunsImmediatelyOnStart)
{
    auto port = portBusyFor(0);
    Action action {TOPIC, parameters(), m_sink, m_tokens, port};

    action.startActionScheduler(3600);

    // The first cycle does not wait for the interval to elapse.
    EXPECT_TRUE(m_sink->waitForCommits(1, std::chrono::seconds {10}));

    action.stopActionScheduler();
}

TEST_F(ActionTest, RunOnceReportsTheOutcomeAndWhetherItRan)
{
    auto port = portBusyFor(0);
    Action action {TOPIC, parameters(), m_sink, m_tokens, port};

    bool ran = false;
    const auto outcome = action.runOnce({}, ran);

    EXPECT_TRUE(ran);
    EXPECT_EQ(outcome.status, CycleStatus::Unchanged);
    EXPECT_EQ(outcome.retryAfter, std::chrono::seconds {0}) << "a healthy cycle must use the configured interval";
}

TEST_F(ActionTest, ADeferredCycleAsksToComeBackSoon)
{
    auto port = portBusyFor(100);
    Action action {TOPIC, parameters(/*consumerRetrySeconds=*/7), m_sink, m_tokens, port};

    bool ran = false;
    const auto outcome = action.runOnce({}, ran);

    EXPECT_TRUE(ran);
    EXPECT_EQ(outcome.status, CycleStatus::SkippedConsumerNotReady);
    EXPECT_EQ(outcome.retryAfter, std::chrono::seconds {7});
    EXPECT_EQ(m_sink->commits(), 0U);
}

TEST_F(ActionTest, TransportFailuresBackOffExponentiallyUpToACeiling)
{
    auto port = std::make_shared<FakeIndexerQueryPort>();
    port->state()->onSearchIndex = [](std::string_view, const nlohmann::json&) -> nlohmann::json
    { throw std::runtime_error("connection refused"); };

    Action action {TOPIC, parameters(), m_sink, m_tokens, port};
    // A long interval, so the ceiling under test is the five-minute one and not the interval.
    action.changeSchedulerInterval(3600);

    // A ContentCycle runs once and keeps nothing between runs, so it cannot count consecutive
    // failures; the driver can. 30 s doubling to a five-minute ceiling.
    const std::vector<std::chrono::seconds> expected {std::chrono::seconds {30},
                                                      std::chrono::seconds {60},
                                                      std::chrono::seconds {120},
                                                      std::chrono::seconds {240},
                                                      std::chrono::seconds {300},
                                                      std::chrono::seconds {300}};

    for (std::size_t attempt = 0; attempt < expected.size(); ++attempt)
    {
        ConsumerGate::resetCache();
        bool ran = false;
        const auto outcome = action.runOnce({}, ran);

        ASSERT_EQ(outcome.status, CycleStatus::FailedTransport) << "attempt " << attempt;
        EXPECT_EQ(outcome.retryAfter, expected[attempt]) << "attempt " << attempt;
    }
}

TEST_F(ActionTest, TheBackoffNeverExceedsTheConfiguredInterval)
{
    auto port = std::make_shared<FakeIndexerQueryPort>();
    port->state()->onSearchIndex = [](std::string_view, const nlohmann::json&) -> nlohmann::json
    { throw std::runtime_error("connection refused"); };

    Action action {TOPIC, parameters(), m_sink, m_tokens, port};
    // Backing off past the interval would make the driver slower than simply waiting for the next
    // scheduled run, which is the opposite of what a backoff is for.
    action.changeSchedulerInterval(45);

    for (int attempt = 0; attempt < 5; ++attempt)
    {
        ConsumerGate::resetCache();
        bool ran = false;
        const auto outcome = action.runOnce({}, ran);
        EXPECT_LE(outcome.retryAfter, std::chrono::seconds {45}) << "attempt " << attempt;
    }
}

TEST_F(ActionTest, ASuccessfulCycleResetsTheBackoff)
{
    auto port = std::make_shared<FakeIndexerQueryPort>();
    auto failing = std::make_shared<std::atomic<bool>>(true);

    port->state()->onSearchIndex = [failing](std::string_view, const nlohmann::json&) -> nlohmann::json
    {
        if (failing->load())
        {
            throw std::runtime_error("connection refused");
        }
        return nlohmann::json {{"hits", statusHits("ready")}};
    };
    port->state()->onSearch = [](const auto&, std::size_t call) -> nlohmann::json
    { return call == 0 ? statusHits("ready") : FakeIndexerQueryPort::emptyHits(); };

    Action action {TOPIC, parameters(), m_sink, m_tokens, port};
    action.changeSchedulerInterval(3600);

    bool ran = false;
    ASSERT_EQ(action.runOnce({}, ran).retryAfter, std::chrono::seconds {30});
    ConsumerGate::resetCache();
    ASSERT_EQ(action.runOnce({}, ran).retryAfter, std::chrono::seconds {60});

    // Recovery must not leave the next outage starting from a four-minute wait.
    failing->store(false);
    ConsumerGate::resetCache();
    ASSERT_EQ(action.runOnce({}, ran).status, CycleStatus::Unchanged);

    failing->store(true);
    ConsumerGate::resetCache();
    EXPECT_EQ(action.runOnce({}, ran).retryAfter, std::chrono::seconds {30});
}

TEST_F(ActionTest, OneTopicNeverRunsTwoCyclesAtOnce)
{
    auto port = std::make_shared<FakeIndexerQueryPort>();
    std::mutex entered;
    entered.lock();

    // Hold the first cycle inside the pre-flight probe so the second one is guaranteed to overlap.
    auto blocked = std::make_shared<std::atomic<bool>>(false);
    port->state()->onSearchIndex = [&entered, blocked](std::string_view, const nlohmann::json&)
    {
        if (!blocked->exchange(true))
        {
            std::lock_guard<std::mutex> hold {entered};
        }
        return nlohmann::json {{"hits", statusHits("ready")}};
    };
    port->state()->onSearch = [](const auto&, std::size_t call) -> nlohmann::json
    { return call == 0 ? statusHits("ready") : FakeIndexerQueryPort::emptyHits(); };

    Action action {TOPIC, parameters(), m_sink, m_tokens, port};

    std::thread first(
        [&action]
        {
            bool ran = false;
            action.runOnce({}, ran);
        });

    // Give the first cycle time to reach the blocking probe.
    std::this_thread::sleep_for(std::chrono::milliseconds {100});

    bool secondRan = true;
    const auto outcome = action.runOnce({}, secondRan);

    entered.unlock();
    first.join();

    EXPECT_FALSE(secondRan) << "a second cycle for the same topic was allowed to start";
    // Distinct from SkippedStopRequested: a caller folding this into its own state has to be able
    // to tell "nothing ran, so I observed nothing" from "a cycle ran and found nothing to do".
    EXPECT_EQ(outcome.status, CycleStatus::SkippedAlreadyRunning);
}

TEST_F(ActionTest, RequestStopEndsTheCycleWithoutTouchingTheToken)
{
    auto port = portBusyFor(0);
    m_tokens->token = "42";

    Action action {TOPIC, parameters(), m_sink, m_tokens, port};
    action.requestStop();

    bool ran = false;
    const auto outcome = action.runOnce({}, ran);

    EXPECT_EQ(outcome.status, CycleStatus::SkippedStopRequested);
    EXPECT_TRUE(m_tokens->writes.empty());
    EXPECT_EQ(action.currentToken(), "42");
}
