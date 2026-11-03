/*
 * Wazuh content manager - unit tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#include "components/consumerGate.hpp"
#include "fakes/fakeIndexerQueryPort.hpp"
#include "topicDriver.hpp"
#include "gtest/gtest.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

using content_manager::CycleStatus;
using content_manager::OnDemandCode;
using content_manager::OnDemandResult;
using fakes::FakeIndexerQueryPort;
using fakes::MemoryTokenStore;

namespace
{

    constexpr auto TOPIC = "driver.topic";
    constexpr auto WAIT = std::chrono::seconds {10};

    /// Accepts everything and records every finished cycle, so a test can wait for one.
    class ObservingSink final : public content_manager::IContentSink
    {
    public:
        content_manager::SessionDecision beginSession(const content_manager::SessionInfo&) noexcept override
        {
            return content_manager::SessionDecision::Proceed;
        }

        content_manager::PageAck acceptPage(const content_manager::ContentPage&) noexcept override
        {
            return {};
        }

        content_manager::CommitResult commit(const content_manager::CommitInfo&) noexcept override
        {
            return {};
        }

        void abort(content_manager::AbortReason, const std::string&) noexcept override {}

        void cycleFinished(const content_manager::CycleOutcome& outcome) noexcept override
        {
            {
                std::lock_guard<std::mutex> lock {m_mutex};
                m_finished.push_back(outcome);
            }
            m_cv.notify_all();
        }

        /// @return True when at least @p count cycles finished within the timeout.
        bool waitForCycles(std::size_t count)
        {
            std::unique_lock<std::mutex> lock {m_mutex};
            return m_cv.wait_for(lock, WAIT, [this, count] { return m_finished.size() >= count; });
        }

        std::vector<content_manager::CycleOutcome> finished()
        {
            std::lock_guard<std::mutex> lock {m_mutex};
            return m_finished;
        }

    private:
        std::mutex m_mutex;
        std::condition_variable m_cv;
        std::vector<content_manager::CycleOutcome> m_finished;
    };

    nlohmann::json statusHits(const std::string& status)
    {
        return nlohmann::json {
            {"hits",
             nlohmann::json::array({nlohmann::json {{"_id", "consumer:1"}, {"_source", {{"status", status}}}}})}};
    }

    /// A port whose consumer is ready and whose data index is empty, cycle after cycle.
    std::shared_ptr<FakeIndexerQueryPort> healthyPort()
    {
        auto port = std::make_shared<FakeIndexerQueryPort>();
        port->state()->onSearchIndex = [](std::string_view, const nlohmann::json&)
        {
            return statusHits("ready");
        };
        port->state()->onSearch = [](const FakeIndexerQueryPort::SearchCall& call, std::size_t)
        {
            return call.query.contains("ids") ? statusHits("ready") : FakeIndexerQueryPort::emptyHits();
        };
        return port;
    }

    /// Re-script the pre-flight probe while a driver thread may be using the port.
    void setConsumerStatus(FakeIndexerQueryPort& port, const std::string& status)
    {
        std::lock_guard<std::mutex> lock {port.state()->mutex};
        port.state()->onSearchIndex = [status](std::string_view, const nlohmann::json&)
        {
            return statusHits(status);
        };
    }

    /// A port whose pre-flight consumer probe reports @p status forever.
    std::shared_ptr<FakeIndexerQueryPort> consumerPort(const std::string& status)
    {
        auto port = healthyPort();
        setConsumerStatus(*port, status);
        return port;
    }

    std::shared_ptr<FakeIndexerQueryPort> unreachablePort()
    {
        auto port = std::make_shared<FakeIndexerQueryPort>();
        port->state()->onSearchIndex = [](std::string_view, const nlohmann::json&) -> nlohmann::json
        {
            throw std::runtime_error("connection refused");
        };
        return port;
    }

    content_manager::TopicSpec specWith(std::optional<std::size_t> interval, std::size_t consumerRetrySeconds = 1)
    {
        content_manager::TopicSpec spec;
        spec.schedule.intervalSeconds = interval;
        spec.source.indices = {"data-index"};
        spec.readiness = content_manager::Readiness {".consumers", "consumer:1", consumerRetrySeconds, 0};
        return spec;
    }

    /// Collects completions from whichever thread runs them.
    class Completions
    {
    public:
        TopicDriver::Completion callback()
        {
            return [this](OnDemandResult result)
            {
                {
                    std::lock_guard<std::mutex> lock {m_mutex};
                    m_results.push_back(std::move(result));
                }
                m_cv.notify_all();
            };
        }

        std::optional<OnDemandResult> waitForOne()
        {
            std::unique_lock<std::mutex> lock {m_mutex};
            if (!m_cv.wait_for(lock, WAIT, [this] { return !m_results.empty(); }))
            {
                return std::nullopt;
            }
            return m_results.front();
        }

    private:
        std::mutex m_mutex;
        std::condition_variable m_cv;
        std::vector<OnDemandResult> m_results;
    };

    class TopicDriverTest : public ::testing::Test
    {
    protected:
        void SetUp() override
        {
            ConsumerGate::resetCache();
        }

        void TearDown() override
        {
            ConsumerGate::resetCache();
        }

        std::shared_ptr<ObservingSink> m_sink {std::make_shared<ObservingSink>()};
        std::shared_ptr<MemoryTokenStore> m_tokens {std::make_shared<MemoryTokenStore>()};
    };

} // namespace

TEST_F(TopicDriverTest, RejectsAMissingSinkOrIndexerAndAnInvalidSpec)
{
    EXPECT_THROW(TopicDriver(TOPIC, specWith(std::nullopt), nullptr, healthyPort(), m_tokens), std::invalid_argument);
    EXPECT_THROW(TopicDriver(TOPIC, specWith(std::nullopt), m_sink, nullptr, m_tokens), std::invalid_argument);

    auto invalid = specWith(std::nullopt);
    invalid.source.indices.clear();
    EXPECT_THROW(TopicDriver(TOPIC, invalid, m_sink, healthyPort(), m_tokens), std::invalid_argument);
}

TEST_F(TopicDriverTest, ResetOnRegisterClearsTheStoredToken)
{
    m_tokens->token = "42";
    auto spec = specWith(std::nullopt);
    spec.state.resetOnRegister = true;

    TopicDriver driver {TOPIC, spec, m_sink, healthyPort(), m_tokens};

    EXPECT_EQ(driver.currentToken(), "");
}

TEST_F(TopicDriverTest, TheDriverRetriesOnRetryAfterNotOnTheConfiguredInterval)
{
    // VD's default interval is 60 minutes. A driver that slept its interval after a deferral would
    // leave a manager that booted during an indexer content update with no feed for an hour.
    auto port = consumerPort("running");
    TopicDriver driver {TOPIC, specWith(3600, /*consumerRetrySeconds=*/1), m_sink, port, m_tokens};

    ASSERT_TRUE(m_sink->waitForCycles(1));
    setConsumerStatus(*port, "ready");

    ASSERT_TRUE(m_sink->waitForCycles(2)) << "the driver waited for its interval instead of honouring retryAfter";
    EXPECT_EQ(m_sink->finished().front().status, CycleStatus::SkippedConsumerNotReady);
    EXPECT_EQ(m_sink->finished().back().status, CycleStatus::Unchanged);
}

TEST_F(TopicDriverTest, TheFirstCycleRunsAtStart)
{
    TopicDriver driver {TOPIC, specWith(3600), m_sink, healthyPort(), m_tokens};

    EXPECT_TRUE(m_sink->waitForCycles(1)) << "the first cycle waited for the interval";
}

TEST_F(TopicDriverTest, RunOnceReportsTheOutcomeAndTellsTheSink)
{
    TopicDriver driver {TOPIC, specWith(std::nullopt), m_sink, healthyPort(), m_tokens};

    const auto outcome = driver.runOnce({});

    EXPECT_EQ(outcome.status, CycleStatus::Unchanged);
    EXPECT_EQ(outcome.retryAfter, std::chrono::seconds {0}) << "a healthy cycle uses the configured interval";
    ASSERT_EQ(m_sink->finished().size(), 1U);
    EXPECT_EQ(m_sink->finished().front().status, CycleStatus::Unchanged);
}

TEST_F(TopicDriverTest, AGatedCycleStillReachesTheSink)
{
    // A sink that reports status has to see deferrals and transport failures too, not only the
    // cycles that reached beginSession.
    TopicDriver deferred {
        TOPIC, specWith(std::nullopt, /*consumerRetrySeconds=*/7), m_sink, consumerPort("running"), m_tokens};
    const auto outcome = deferred.runOnce({});

    EXPECT_EQ(outcome.status, CycleStatus::SkippedConsumerNotReady);
    EXPECT_EQ(outcome.retryAfter, std::chrono::seconds {7});
    ASSERT_EQ(m_sink->finished().size(), 1U);
    EXPECT_EQ(m_sink->finished().front().status, CycleStatus::SkippedConsumerNotReady);
}

TEST_F(TopicDriverTest, TransportFailuresBackOffExponentiallyUpToACeiling)
{
    TopicDriver driver {TOPIC, specWith(std::nullopt), m_sink, unreachablePort(), m_tokens};

    const std::vector<std::chrono::seconds> expected {std::chrono::seconds {30},
                                                      std::chrono::seconds {60},
                                                      std::chrono::seconds {120},
                                                      std::chrono::seconds {240},
                                                      std::chrono::seconds {300},
                                                      std::chrono::seconds {300}};
    for (std::size_t attempt = 0; attempt < expected.size(); ++attempt)
    {
        const auto outcome = driver.runOnce({});
        ASSERT_EQ(outcome.status, CycleStatus::FailedTransport) << "attempt " << attempt;
        EXPECT_EQ(outcome.retryAfter, expected[attempt]) << "attempt " << attempt;
    }
}

TEST_F(TopicDriverTest, TheBackoffNeverExceedsTheInterval)
{
    // Backing off past the interval would make the driver slower than simply waiting for the next
    // scheduled run.
    TopicDriver driver {TOPIC, specWith(10), m_sink, unreachablePort(), m_tokens};

    ASSERT_TRUE(m_sink->waitForCycles(1));
    EXPECT_EQ(m_sink->finished().front().retryAfter, std::chrono::seconds {10});
}

TEST_F(TopicDriverTest, ASuccessfulCycleResetsTheBackoff)
{
    auto port = unreachablePort();
    TopicDriver driver {TOPIC, specWith(std::nullopt), m_sink, port, m_tokens};

    ASSERT_EQ(driver.runOnce({}).retryAfter, std::chrono::seconds {30});
    ASSERT_EQ(driver.runOnce({}).retryAfter, std::chrono::seconds {60});

    port->state()->onSearchIndex = [](std::string_view, const nlohmann::json&)
    {
        return statusHits("ready");
    };
    port->state()->onSearch = healthyPort()->state()->onSearch;
    ASSERT_EQ(driver.runOnce({}).status, CycleStatus::Unchanged);

    port->state()->onSearchIndex = unreachablePort()->state()->onSearchIndex;
    EXPECT_EQ(driver.runOnce({}).retryAfter, std::chrono::seconds {30}) << "recovery must reset the backoff";
}

TEST_F(TopicDriverTest, OneTopicNeverRunsTwoCyclesAtOnce)
{
    auto port = healthyPort();
    std::promise<void> entered;
    std::promise<void> release;
    auto releaseFuture = release.get_future().share();
    auto first = std::make_shared<std::atomic<bool>>(true);
    port->state()->onSearchIndex = [&entered, releaseFuture, first](std::string_view, const nlohmann::json&)
    {
        if (first->exchange(false))
        {
            entered.set_value();
            releaseFuture.wait();
        }
        return statusHits("ready");
    };

    TopicDriver driver {TOPIC, specWith(std::nullopt), m_sink, port, m_tokens};
    auto running = std::async(std::launch::async, [&driver] { return driver.runOnce({}); });
    entered.get_future().wait();

    const auto second = driver.runOnce({});

    release.set_value();
    running.wait();

    // Distinct from SkippedStopRequested: "nothing ran, so I observed nothing".
    EXPECT_EQ(second.status, CycleStatus::SkippedAlreadyRunning);
    EXPECT_EQ(m_sink->finished().size(), 1U) << "a cycle that did not run must not reach the sink";
}

TEST_F(TopicDriverTest, RequestStopIsStickyAndLeavesTheTokenAlone)
{
    m_tokens->token = "42";
    TopicDriver driver {TOPIC, specWith(std::nullopt), m_sink, healthyPort(), m_tokens};

    driver.requestStop();

    EXPECT_EQ(driver.runOnce({}).status, CycleStatus::SkippedStopRequested);
    EXPECT_EQ(driver.runOnce({}).status, CycleStatus::SkippedStopRequested);
    EXPECT_TRUE(m_tokens->writes.empty());
    EXPECT_EQ(driver.currentToken(), "42");
}

TEST_F(TopicDriverTest, AHostDrivenTopicRefusesRequestsInline)
{
    TopicDriver driver {TOPIC, specWith(std::nullopt), m_sink, healthyPort(), m_tokens};

    Completions completions;
    driver.requestRun({}, completions.callback());

    const auto result = completions.waitForOne();
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->code, OnDemandCode::Failed);
}

TEST_F(TopicDriverTest, ARequestRunsOnTheDriverThreadWithItsOwnRequest)
{
    m_tokens->token = "42";
    TopicDriver driver {TOPIC, specWith(3600), m_sink, healthyPort(), m_tokens};
    ASSERT_TRUE(m_sink->waitForCycles(1));

    Completions completions;
    driver.requestRun(content_manager::RunRequest {/*forceFullReload=*/true}, completions.callback());

    const auto result = completions.waitForOne();
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->code, OnDemandCode::Completed);
    EXPECT_EQ(result->outcome.status, CycleStatus::Unchanged);
    // The forced reload reached the cycle: it cleared the stored token once the sink accepted it.
    EXPECT_EQ(driver.currentToken(), "");
}

TEST_F(TopicDriverTest, ADeferredRequestIsReportedAsDeferredNotCompleted)
{
    auto port = healthyPort();
    TopicDriver driver {TOPIC, specWith(3600, /*consumerRetrySeconds=*/3600), m_sink, port, m_tokens};
    ASSERT_TRUE(m_sink->waitForCycles(1));

    setConsumerStatus(*port, "running");
    Completions completions;
    driver.requestRun({}, completions.callback());

    // Nothing was downloaded, so a handler must not answer "ok".
    const auto result = completions.waitForOne();
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->code, OnDemandCode::Deferred);
    EXPECT_EQ(result->outcome.status, CycleStatus::SkippedConsumerNotReady);
}

TEST_F(TopicDriverTest, ARequestWhileACycleRunsIsAlreadyRunning)
{
    auto port = healthyPort();
    std::promise<void> entered;
    std::promise<void> release;
    auto releaseFuture = release.get_future().share();
    auto first = std::make_shared<std::atomic<bool>>(true);
    port->state()->onSearchIndex = [&entered, releaseFuture, first](std::string_view, const nlohmann::json&)
    {
        if (first->exchange(false))
        {
            entered.set_value();
            releaseFuture.wait();
        }
        return statusHits("ready");
    };

    TopicDriver driver {TOPIC, specWith(3600), m_sink, port, m_tokens};
    entered.get_future().wait();

    Completions completions;
    driver.requestRun({}, completions.callback());
    const auto result = completions.waitForOne();

    release.set_value();

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->code, OnDemandCode::AlreadyRunning);
}

TEST_F(TopicDriverTest, ARequestAfterAStopIsShuttingDown)
{
    TopicDriver driver {TOPIC, specWith(3600), m_sink, healthyPort(), m_tokens};
    ASSERT_TRUE(m_sink->waitForCycles(1));
    driver.requestStop();

    Completions completions;
    driver.requestRun({}, completions.callback());

    const auto result = completions.waitForOne();
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->code, OnDemandCode::ShuttingDown);
}

TEST_F(TopicDriverTest, AThrowingCompletionIsContained)
{
    TopicDriver driver {TOPIC, specWith(std::nullopt), m_sink, healthyPort(), m_tokens};

    EXPECT_NO_THROW(driver.requestRun({}, [](OnDemandResult) { throw std::runtime_error("host bug"); }));
    EXPECT_NO_THROW(driver.requestRun({}, {})) << "a request with no completion is fire and forget";
}

TEST(TopicDriverResultTest, EveryCycleStatusMapsToTheAnswerAHandlerGives)
{
    const std::vector<std::pair<CycleStatus, OnDemandCode>> cases {
        {CycleStatus::Updated, OnDemandCode::Completed},
        {CycleStatus::Unchanged, OnDemandCode::Completed},
        {CycleStatus::SkippedConsumerNotReady, OnDemandCode::Deferred},
        {CycleStatus::SkippedPreconditionUnmet, OnDemandCode::Deferred},
        {CycleStatus::SkippedAlreadyRunning, OnDemandCode::AlreadyRunning},
        {CycleStatus::SkippedStopRequested, OnDemandCode::ShuttingDown},
        {CycleStatus::FailedTransport, OnDemandCode::Failed},
        {CycleStatus::FailedSink, OnDemandCode::Failed},
        {CycleStatus::FailedConfig, OnDemandCode::Failed}};

    for (const auto& [status, code] : cases)
    {
        content_manager::CycleOutcome outcome;
        outcome.status = status;
        outcome.detail = "detail";

        const auto result = TopicDriver::toResult(outcome);
        EXPECT_EQ(result.code, code) << static_cast<int>(status);
        EXPECT_EQ(result.detail, "detail");
        EXPECT_EQ(result.outcome.status, status);
    }
}
