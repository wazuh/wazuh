/*
 * Wazuh content manager - Component Tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 *
 * Drives whole registrations through the public `ContentRegister` API against a scripted indexer,
 * rather than against a fake HTTP server. Only the far end of the production path is substituted.
 */

#include "components/consumerGate.hpp"
#include "contentIndexer.hpp"
#include "contentRegister.hpp"
#include "contentSink.hpp"
#include "contentTokenStore.hpp"
#include "contentTypes.hpp"

#include "gtest/gtest.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace
{

    using content_manager::CycleStatus;

    constexpr auto TOPIC = "component.topic";

    /// A scripted indexer. Every answer is queued in advance, in the order the cycle will ask for them.
    class ScriptedPort final : public content_manager::IContentIndexer
    {
    public:
        struct Script
        {
            std::mutex mutex;
            std::vector<std::string> consumerStatuses; ///< One per pre-flight probe; the last repeats.
            std::size_t preflightCalls {0};
            std::vector<std::string> inPitStatuses; ///< One per in-PIT probe; the last repeats.
            std::size_t inPitCalls {0};
            std::vector<nlohmann::json> dataPages; ///< One per data search; exhaustion ends the fetch.
            std::size_t dataCalls {0};
            std::size_t pitsOpened {0};

            /// Called at the top of every search, before any lock is taken, so a test can hold a cycle
            /// open and observe what the rest of the library can still do while it is.
            std::function<void()> beforeSearch;
        };

        ScriptedPort()
            : m_script {std::make_shared<Script>()}
        {
        }

        explicit ScriptedPort(std::shared_ptr<Script> script)
            : m_script {std::move(script)}
        {
        }

        const std::shared_ptr<Script>& script() const noexcept
        {
            return m_script;
        }

        content_manager::ContentPit openPit(const std::vector<std::string>&, std::string_view keepAlive, bool) override
        {
            std::lock_guard<std::mutex> lock {m_script->mutex};
            ++m_script->pitsOpened;
            return content_manager::ContentPit {"pit", 0, std::string {keepAlive}};
        }

        void closePit(const content_manager::ContentPit&) noexcept override {}

        nlohmann::json search(const content_manager::ContentPit&,
                              std::size_t,
                              const nlohmann::json&,
                              const nlohmann::json&,
                              const std::optional<nlohmann::json>&,
                              const std::optional<nlohmann::json>&,
                              const std::optional<nlohmann::json>&) override
        {
            if (m_script->beforeSearch)
            {
                m_script->beforeSearch();
            }

            std::lock_guard<std::mutex> lock {m_script->mutex};

            if (!m_script->inPitStatuses.empty() &&
                (m_script->inPitCalls < m_script->inPitStatuses.size() || m_inPitPending))
            {
                m_inPitPending = false;
                const auto index = std::min(m_script->inPitCalls, m_script->inPitStatuses.size() - 1);
                const auto status = m_script->inPitStatuses[index];
                ++m_script->inPitCalls;
                return statusHits(status);
            }

            if (m_script->dataCalls < m_script->dataPages.size())
            {
                return m_script->dataPages[m_script->dataCalls++];
            }
            return nlohmann::json {{"hits", nlohmann::json::array()}};
        }

        nlohmann::json
        searchIndex(std::string_view, std::size_t, const nlohmann::json&, const std::optional<nlohmann::json>&) override
        {
            std::lock_guard<std::mutex> lock {m_script->mutex};
            if (m_script->consumerStatuses.empty())
            {
                return statusHits("ready");
            }
            const auto index = std::min(m_script->preflightCalls, m_script->consumerStatuses.size() - 1);
            const auto status = m_script->consumerStatuses[index];
            ++m_script->preflightCalls;
            // The next PIT search is the in-PIT readiness probe.
            m_inPitPending = true;
            return statusHits(status);
        }

        static nlohmann::json statusHits(const std::string& status)
        {
            if (status.empty())
            {
                return nlohmann::json {{"hits", nlohmann::json::array()}};
            }
            return nlohmann::json {
                {"hits",
                 nlohmann::json::array({nlohmann::json {{"_id", "consumer:1"}, {"_source", {{"status", status}}}}})}};
        }

        static nlohmann::json page(const std::vector<std::pair<std::string, std::uint64_t>>& docs)
        {
            auto hits = nlohmann::json::array();
            for (const auto& [id, offset] : docs)
            {
                hits.push_back(
                    nlohmann::json {{"_id", id},
                                    {"_index", "data-index"},
                                    {"_source", {{"offset", offset}, {"type", "CVE"}, {"document", {{"a", 1}}}}},
                                    {"sort", nlohmann::json::array({offset, id})}});
            }
            return nlohmann::json {{"hits", std::move(hits)}};
        }

    private:
        std::shared_ptr<Script> m_script;
        bool m_inPitPending {false};
    };

    /// Records what the library delivered.
    class CountingSink final : public content_manager::IContentSink
    {
    public:
        std::atomic<std::size_t> documents {0};
        std::atomic<std::size_t> commits {0};
        std::vector<content_manager::SessionKind> kinds;
        std::mutex mutex;

        content_manager::SessionDecision beginSession(const content_manager::SessionInfo& info) noexcept override
        {
            std::lock_guard<std::mutex> lock {mutex};
            kinds.push_back(info.kind);
            return content_manager::SessionDecision::Proceed;
        }

        content_manager::PageAck acceptPage(const content_manager::ContentPage& page) noexcept override
        {
            documents += page.hits != nullptr ? page.hits->size() : 0;
            return content_manager::PageAck {content_manager::PageStatus::Durable, {}};
        }

        content_manager::CommitResult commit(const content_manager::CommitInfo&) noexcept override
        {
            ++commits;
            return content_manager::CommitResult {};
        }

        void abort(content_manager::AbortReason, const std::string&) noexcept override {}
    };

    /// A token store that simply remembers, so a test can restart a "process" by keeping it around.
    class MemoryTokens final : public content_manager::IContentTokenStore
    {
    public:
        std::string token;

        std::string load(std::string_view) noexcept override
        {
            return token;
        }
        bool store(std::string_view, std::string_view value) noexcept override
        {
            token = std::string {value};
            return true;
        }
        bool clear(std::string_view) noexcept override
        {
            token.clear();
            return true;
        }
    };

    content_manager::TopicSpec spec(std::optional<std::size_t> interval = std::nullopt)
    {
        content_manager::TopicSpec spec;
        spec.schedule.intervalSeconds = interval;
        spec.source.indices = {"data-index"};
        spec.source.pageSize = 10;
        spec.readiness = content_manager::Readiness {".consumers", "consumer:1", 1, 0};
        spec.detection = content_manager::CursorDetection {};
        return spec;
    }

    class ContentRegistrationTest : public ::testing::Test
    {
    protected:
        void SetUp() override
        {
            ConsumerGate::resetCache();
            m_sink = std::make_shared<CountingSink>();
            m_tokens = std::make_shared<MemoryTokens>();
        }

        void TearDown() override
        {
            m_registration.reset();
        }

        /// Register the topic with a scripted indexer behind it.
        std::shared_ptr<ScriptedPort::Script> registerTopic(std::vector<std::string> preflight,
                                                            std::vector<std::string> inPit,
                                                            std::vector<nlohmann::json> pages,
                                                            std::optional<std::size_t> interval = std::nullopt)
        {
            auto port = std::make_shared<ScriptedPort>();
            port->script()->consumerStatuses = std::move(preflight);
            port->script()->inPitStatuses = std::move(inPit);
            port->script()->dataPages = std::move(pages);

            m_registration = std::make_unique<ContentRegister>(TOPIC, spec(interval), m_sink, port, m_tokens);
            return port->script();
        }

        std::shared_ptr<CountingSink> m_sink;
        std::shared_ptr<MemoryTokens> m_tokens;
        std::unique_ptr<ContentRegister> m_registration;
    };

} // namespace

TEST_F(ContentRegistrationTest, ConsumerRunningSkipsWithNoSinkCalls)
{
    auto script = registerTopic({"running"}, {"running"}, {});

    const auto outcome = m_registration->runOnce();

    EXPECT_EQ(outcome.status, CycleStatus::SkippedConsumerNotReady);
    EXPECT_EQ(m_sink->documents.load(), 0U);
    EXPECT_EQ(m_sink->commits.load(), 0U);
    // The pre-flight is the cost gate: no lease is taken over an index the consumer is rewriting.
    EXPECT_EQ(script->pitsOpened, 0U);
}

TEST_F(ContentRegistrationTest, ConsumerFlippingBetweenPreflightAndPitStillSkips)
{
    // The case the in-PIT check exists for: the pre-flight sees `ready`, and by the time the
    // snapshot is open the indexer has started rewriting.
    auto script = registerTopic({"ready"}, {"running"}, {ScriptedPort::page({{"CVE-1", 1}})});

    const auto outcome = m_registration->runOnce();

    EXPECT_EQ(outcome.status, CycleStatus::SkippedConsumerNotReady);
    EXPECT_EQ(script->pitsOpened, 1U);
    EXPECT_EQ(m_sink->documents.load(), 0U);
    EXPECT_TRUE(m_tokens->token.empty());
}

TEST_F(ContentRegistrationTest, FullLoadThenIncrementalReusesTheStoredToken)
{
    registerTopic({"ready"}, {"ready"}, {ScriptedPort::page({{"CVE-1", 1}, {"CVE-2", 7}})});

    auto first = m_registration->runOnce();
    EXPECT_EQ(first.status, CycleStatus::Updated);
    EXPECT_EQ(first.token, "7");
    EXPECT_EQ(m_sink->documents.load(), 2U);
    EXPECT_EQ(m_registration->currentToken(), "7");

    auto second = m_registration->runOnce();
    EXPECT_EQ(second.status, CycleStatus::Unchanged);

    ASSERT_EQ(m_sink->kinds.size(), 2U);
    EXPECT_EQ(m_sink->kinds[0], content_manager::SessionKind::FullReload);
    EXPECT_EQ(m_sink->kinds[1], content_manager::SessionKind::Incremental);
}

TEST_F(ContentRegistrationTest, ForcedReloadReloadsEverything)
{
    registerTopic({"ready"}, {"ready"}, {ScriptedPort::page({{"CVE-1", 5}})});
    ASSERT_EQ(m_registration->runOnce().status, CycleStatus::Updated);
    ASSERT_EQ(m_tokens->token, "5");

    m_registration->runOnce(content_manager::RunRequest {/*forceFullReload=*/true});

    ASSERT_EQ(m_sink->kinds.size(), 2U);
    EXPECT_EQ(m_sink->kinds[1], content_manager::SessionKind::FullReload);
}

TEST_F(ContentRegistrationTest, RunOnceReturnsPromptlyWhileTheConsumerStaysBusy)
{
    // The bounded-gate guarantee: a cycle never parks its caller polling for readiness.
    auto script = registerTopic({"running"}, {"running"}, {});

    const auto started = std::chrono::steady_clock::now();
    const auto outcome = m_registration->runOnce();
    const auto elapsed = std::chrono::steady_clock::now() - started;

    EXPECT_EQ(outcome.status, CycleStatus::SkippedConsumerNotReady);
    EXPECT_LT(elapsed, std::chrono::seconds {2});
    // And it tells the driver to come back soon rather than at the next scheduler period.
    EXPECT_GT(outcome.retryAfter.count(), 0);
    EXPECT_EQ(script->preflightCalls, 1U);
}

TEST_F(ContentRegistrationTest, ARequestedRunDrivesTheSameCycle)
{
    // The first page goes to the start-up cycle; the requested one then finds the content current.
    registerTopic({"ready"}, {"ready"}, {ScriptedPort::page({{"CVE-1", 3}})}, /*interval=*/3600);

    std::mutex mutex;
    std::condition_variable cv;
    std::vector<content_manager::OnDemandResult> received;
    const auto request = [&]
    {
        m_registration->requestRun({},
                                   [&](content_manager::OnDemandResult result)
                                   {
                                       {
                                           std::lock_guard<std::mutex> lock {mutex};
                                           received.push_back(std::move(result));
                                       }
                                       cv.notify_all();
                                   });
    };

    // Retried while the start-up cycle holds the slot: that answer is AlreadyRunning, not a queue.
    std::unique_lock<std::mutex> lock {mutex};
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds {10};
    while (std::chrono::steady_clock::now() < deadline &&
           (received.empty() || received.back().code == content_manager::OnDemandCode::AlreadyRunning))
    {
        lock.unlock();
        request();
        lock.lock();
        cv.wait_for(lock, std::chrono::milliseconds {100}, [&] { return !received.empty(); });
    }

    ASSERT_FALSE(received.empty());
    EXPECT_EQ(received.back().code, content_manager::OnDemandCode::Completed);
    EXPECT_EQ(m_sink->documents.load(), 1U);
}

TEST_F(ContentRegistrationTest, AnInvalidSpecIsRefusedAtRegistration)
{
    auto broken = spec();
    broken.readiness->consumerIndex = ".consumers-*";

    // Caught once, at registration, instead of becoming a failure on every cycle forever.
    EXPECT_THROW((ContentRegister {"broken.topic", broken, m_sink, std::make_shared<ScriptedPort>(), m_tokens}),
                 std::invalid_argument);
}

TEST_F(ContentRegistrationTest, ARegistrationWithoutTheHostsIndexerIsRefused)
{
    // The library never opens a connection of its own (D1).
    EXPECT_THROW((ContentRegister {"no.indexer", spec(), m_sink, nullptr, m_tokens}), std::invalid_argument);
}

TEST_F(ContentRegistrationTest, DestroyingARegistrationWaitsForItsCycle)
{
    // What lets a host destroy its sink right after the registration: nothing of the topic's is
    // still running once the destructor returns.
    std::mutex gateMutex;
    std::condition_variable gate;
    bool released = false;
    bool cycleStarted = false;
    std::atomic<bool> cycleFinished {false};

    auto script = registerTopic({"ready"}, {"ready"}, {ScriptedPort::page({{"CVE-1", 1}})});
    script->beforeSearch = [&]
    {
        std::unique_lock<std::mutex> lock {gateMutex};
        cycleStarted = true;
        gate.notify_all();
        gate.wait(lock, [&] { return released; });
    };

    std::thread runner(
        [&]
        {
            m_registration->runOnce();
            cycleFinished = true;
        });

    {
        std::unique_lock<std::mutex> lock {gateMutex};
        ASSERT_TRUE(gate.wait_for(lock, std::chrono::seconds {10}, [&] { return cycleStarted; }));
    }

    std::thread destroyer([this] { m_registration.reset(); });

    std::this_thread::sleep_for(std::chrono::milliseconds {200});
    EXPECT_FALSE(cycleFinished.load()) << "the cycle ended on its own; the test is not measuring the drain";

    {
        std::lock_guard<std::mutex> lock {gateMutex};
        released = true;
    }
    gate.notify_all();

    destroyer.join();
    EXPECT_TRUE(cycleFinished.load()) << "the registration was destroyed while its cycle was still running";
    runner.join();
}
