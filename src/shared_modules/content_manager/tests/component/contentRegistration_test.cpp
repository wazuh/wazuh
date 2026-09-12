/*
 * Wazuh content manager - Component Tests
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Drives a whole registration — facade, provider, driver, cycle — against a scripted indexer,
 * rather than against a fake HTTP server. The seam these tests go through is the same one the
 * production path uses; only the far end of it is substituted.
 */

#include "components/consumerGate.hpp"
#include "components/indexerQueryPort.hpp"
#include "contentModuleFacade.hpp"
#include "contentOnDemand.hpp"
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
constexpr auto OTHER_TOPIC = "component.topic.other";

/// A scripted indexer. Every answer is queued in advance, in the order the cycle will ask for them.
class ScriptedPort final : public IIndexerQueryPort
{
public:
    struct Script
    {
        std::mutex mutex;
        std::vector<std::string> consumerStatuses; ///< One per pre-flight probe; the last repeats.
        std::size_t preflightCalls {0};
        std::vector<std::string> inPitStatuses;    ///< One per in-PIT probe; the last repeats.
        std::size_t inPitCalls {0};
        std::vector<nlohmann::json> dataPages;     ///< One per data search; exhaustion ends the fetch.
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

    PointInTime openPit(const std::vector<std::string>&, std::string_view keepAlive, bool) override
    {
        std::lock_guard<std::mutex> lock {m_script->mutex};
        ++m_script->pitsOpened;
        return PointInTime {"pit", 0, keepAlive};
    }

    void closePit(const PointInTime&) noexcept override {}

    nlohmann::json search(const PointInTime&,
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

        if (!m_script->inPitStatuses.empty() && (m_script->inPitCalls < m_script->inPitStatuses.size() || m_inPitPending))
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

    nlohmann::json searchIndex(std::string_view, const nlohmann::json&) override
    {
        std::lock_guard<std::mutex> lock {m_script->mutex};
        if (m_script->consumerStatuses.empty())
        {
            return nlohmann::json {{"hits", statusHits("ready")}};
        }
        const auto index = std::min(m_script->preflightCalls, m_script->consumerStatuses.size() - 1);
        const auto status = m_script->consumerStatuses[index];
        ++m_script->preflightCalls;
        // The next PIT search is the in-PIT readiness probe.
        m_inPitPending = true;
        return nlohmann::json {{"hits", statusHits(status)}};
    }

    std::unique_ptr<IIndexerQueryPort> clone() const override
    {
        return std::make_unique<ScriptedPort>(m_script);
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
            hits.push_back(nlohmann::json {{"_id", id},
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

    std::string load(std::string_view) noexcept override { return token; }
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

nlohmann::json parameters()
{
    return nlohmann::json {{"topicName", TOPIC},
                           {"ondemand", true},
                           {"configData",
                            {{"consumerName", "Component Test"},
                             {"changeDetection", "cursor"},
                             {"consumerRetryIntervalSeconds", 1},
                             {"indexer",
                              {{"index", "data-index"},
                               {"consumerStatusIndex", ".consumers"},
                               {"consumerStatusId", "consumer:1"},
                               {"consumerStatusCacheSeconds", 0},
                               {"cursorField", "offset"},
                               {"pageSize", 10},
                               {"numSlices", 1}}}}}};
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
        // Unconditional, and for both: a test that fails a fatal assertion skips its own cleanup,
        // and a topic left registered makes every later test fail with "Provider already exist".
        ContentModuleFacade::instance().removeProvider(TOPIC);
        ContentModuleFacade::instance().removeProvider(OTHER_TOPIC);
    }

    /// Register the topic with a scripted indexer behind it.
    std::shared_ptr<ScriptedPort::Script> registerTopic(std::vector<std::string> preflight,
                                                        std::vector<std::string> inPit,
                                                        std::vector<nlohmann::json> pages)
    {
        auto port = std::make_shared<ScriptedPort>();
        port->script()->consumerStatuses = std::move(preflight);
        port->script()->inPitStatuses = std::move(inPit);
        port->script()->dataPages = std::move(pages);

        ContentModuleFacade::instance().addProvider(TOPIC, parameters(), m_sink, m_tokens, port);
        return port->script();
    }

    std::shared_ptr<CountingSink> m_sink;
    std::shared_ptr<MemoryTokens> m_tokens;
};

} // namespace

TEST_F(ContentRegistrationTest, ConsumerRunningSkipsWithNoSinkCalls)
{
    auto script = registerTopic({"running"}, {"running"}, {});

    const auto outcome = ContentModuleFacade::instance().runOnce(TOPIC, {});

    EXPECT_EQ(outcome.status, CycleStatus::SkippedConsumerNotReady);
    EXPECT_EQ(m_sink->documents.load(), 0U);
    EXPECT_EQ(m_sink->commits.load(), 0U);
    // The pre-flight is the cost gate: no lease is taken over an index the consumer is rewriting.
    EXPECT_EQ(script->pitsOpened, 0U);
}

TEST_F(ContentRegistrationTest, ConsumerFlippingBetweenPreflightAndPitStillSkips)
{
    // This is the case the in-PIT check exists for and that the previous design could not express:
    // the pre-flight sees `ready`, and by the time the snapshot is open the indexer has started
    // rewriting. A check outside the PIT would have proceeded to read content mid-rewrite.
    auto script = registerTopic({"ready"}, {"running"}, {ScriptedPort::page({{"CVE-1", 1}})});

    const auto outcome = ContentModuleFacade::instance().runOnce(TOPIC, {});

    EXPECT_EQ(outcome.status, CycleStatus::SkippedConsumerNotReady);
    EXPECT_EQ(script->pitsOpened, 1U);
    EXPECT_EQ(m_sink->documents.load(), 0U);
    EXPECT_TRUE(m_tokens->token.empty());
}

TEST_F(ContentRegistrationTest, FullLoadThenIncrementalReusesTheStoredToken)
{
    registerTopic({"ready"}, {"ready"}, {ScriptedPort::page({{"CVE-1", 1}, {"CVE-2", 7}})});

    auto first = ContentModuleFacade::instance().runOnce(TOPIC, {});
    EXPECT_EQ(first.status, CycleStatus::Updated);
    EXPECT_EQ(first.token, "7");
    EXPECT_EQ(m_sink->documents.load(), 2U);
    EXPECT_EQ(m_tokens->token, "7");

    auto second = ContentModuleFacade::instance().runOnce(TOPIC, {});
    EXPECT_EQ(second.status, CycleStatus::Unchanged);

    ASSERT_EQ(m_sink->kinds.size(), 2U);
    EXPECT_EQ(m_sink->kinds[0], content_manager::SessionKind::FullReload);
    EXPECT_EQ(m_sink->kinds[1], content_manager::SessionKind::Incremental);
}

TEST_F(ContentRegistrationTest, ForcedReloadClearsTheTokenAndReloads)
{
    registerTopic({"ready"}, {"ready"}, {ScriptedPort::page({{"CVE-1", 5}})});
    ASSERT_EQ(ContentModuleFacade::instance().runOnce(TOPIC, {}).status, CycleStatus::Updated);
    ASSERT_EQ(m_tokens->token, "5");

    ContentModuleFacade::instance().runOnce(TOPIC, content_manager::RunRequest {true, true});

    ASSERT_EQ(m_sink->kinds.size(), 2U);
    EXPECT_EQ(m_sink->kinds[1], content_manager::SessionKind::FullReload);
}

TEST_F(ContentRegistrationTest, RunOnceReturnsPromptlyWhileTheConsumerStaysBusy)
{
    // The bounded-gate guarantee: a cycle never parks its caller polling for readiness. The old
    // in-cycle loop would still be sleeping when this assertion runs.
    auto script = registerTopic({"running"}, {"running"}, {});

    const auto started = std::chrono::steady_clock::now();
    const auto outcome = ContentModuleFacade::instance().runOnce(TOPIC, {});
    const auto elapsed = std::chrono::steady_clock::now() - started;

    EXPECT_EQ(outcome.status, CycleStatus::SkippedConsumerNotReady);
    EXPECT_LT(elapsed, std::chrono::seconds {2});
    // And it tells the driver to come back soon rather than at the next scheduler period.
    EXPECT_GT(outcome.retryAfter.count(), 0);
    EXPECT_EQ(script->preflightCalls, 1U);
}

TEST_F(ContentRegistrationTest, UnknownTopicIsAConfigFailureNotACrash)
{
    const auto outcome = ContentModuleFacade::instance().runOnce("no.such.topic", {});
    EXPECT_EQ(outcome.status, CycleStatus::FailedConfig);
}

TEST_F(ContentRegistrationTest, OnDemandDrivesTheSameCycle)
{
    registerTopic({"ready"}, {"ready"}, {ScriptedPort::page({{"CVE-1", 3}})});
    ContentModuleFacade::instance().startOndemand(TOPIC);

    std::mutex mutex;
    std::condition_variable cv;
    bool answered {false};
    content_manager::OnDemandResult received;

    content_manager::requestOnDemand(TOPIC,
                                     {},
                                     [&](content_manager::OnDemandResult result)
                                     {
                                         {
                                             std::lock_guard<std::mutex> lock {mutex};
                                             received = std::move(result);
                                             answered = true;
                                         }
                                         cv.notify_all();
                                     });

    std::unique_lock<std::mutex> lock {mutex};
    ASSERT_TRUE(cv.wait_for(lock, std::chrono::seconds {5}, [&answered] { return answered; }));
    EXPECT_EQ(received.code, content_manager::OnDemandCode::Completed);
    EXPECT_EQ(m_sink->documents.load(), 1U);
}

TEST_F(ContentRegistrationTest, RegisteringTheSameTopicTwiceIsRefused)
{
    registerTopic({"ready"}, {"ready"}, {});

    auto port = std::make_shared<ScriptedPort>();
    port->script()->consumerStatuses = {"ready"};
    port->script()->inPitStatuses = {"ready"};

    EXPECT_THROW(ContentModuleFacade::instance().addProvider(TOPIC, parameters(), m_sink, m_tokens, port),
                 std::runtime_error);
}

TEST_F(ContentRegistrationTest, AnInvalidConfigurationIsRefusedAtRegistration)
{
    auto broken = parameters();
    broken["configData"]["indexer"]["consumerStatusIndex"] = ".consumers-*";

    auto port = std::make_shared<ScriptedPort>();
    port->script()->consumerStatuses = {"ready"};
    port->script()->inPitStatuses = {"ready"};

    // Caught once, at registration, instead of becoming a FailedConfig on every cycle forever.
    EXPECT_THROW(ContentModuleFacade::instance().addProvider("broken.topic", broken, m_sink, m_tokens, port),
                 std::invalid_argument);
}

TEST_F(ContentRegistrationTest, RegisteringATopicDoesNotWaitForAnotherTopicsCycle)
{
    // The registry lock is held only long enough to find a topic and claim its run slot, never for
    // the download. Held across the cycle instead — as it was — registering or removing ANY topic
    // waits for whatever else happens to be downloading, which for a full vulnerability feed is
    // minutes; and a reader-preferring shared_mutex can starve that writer indefinitely under a
    // steady stream of cycles.
    std::mutex gateMutex;
    std::condition_variable gate;
    bool released = false;
    bool cycleStarted = false;

    auto script = registerTopic({"ready"}, {"ready"}, {ScriptedPort::page({{"CVE-1", 1}})});
    script->beforeSearch = [&]
    {
        std::unique_lock<std::mutex> lock {gateMutex};
        cycleStarted = true;
        gate.notify_all();
        gate.wait(lock, [&] { return released; });
    };

    std::thread runner([] { ContentModuleFacade::instance().runOnce(TOPIC, {}); });

    {
        std::unique_lock<std::mutex> lock {gateMutex};
        ASSERT_TRUE(gate.wait_for(lock, std::chrono::seconds {10}, [&] { return cycleStarted; }))
            << "the cycle never reached the indexer";
    }

    // The cycle is now parked inside the library. Registering an unrelated topic must still work.
    auto otherParameters = parameters();
    otherParameters["topicName"] = OTHER_TOPIC;
    auto otherPort = std::make_shared<ScriptedPort>();
    otherPort->script()->consumerStatuses = {"ready"};
    otherPort->script()->inPitStatuses = {"ready"};

    const auto startedAt = std::chrono::steady_clock::now();
    ContentModuleFacade::instance().addProvider(
        OTHER_TOPIC, otherParameters, std::make_shared<CountingSink>(), std::make_shared<MemoryTokens>(), otherPort);
    const auto elapsed = std::chrono::steady_clock::now() - startedAt;

    EXPECT_LT(elapsed, std::chrono::seconds {5}) << "registering a topic waited for an unrelated topic's cycle";

    {
        std::lock_guard<std::mutex> lock {gateMutex};
        released = true;
    }
    gate.notify_all();
    runner.join();

    // The hook captures this function's locals by reference and the port outlives it (TearDown is
    // what unregisters the topic). Nothing calls it after this point, but leaving a dangling
    // capture in a live object is not a thing to rely on being unreachable.
    script->beforeSearch = nullptr;

    ContentModuleFacade::instance().removeProvider(OTHER_TOPIC);
}

TEST_F(ContentRegistrationTest, RemovingATopicWaitsForItsOwnCycleToDrain)
{
    // The other half of the same contract: the short lock hold must not weaken the guarantee that
    // nothing of this topic's is still running once removeProvider returns — which is what the
    // host relies on to then destroy the sink. A cycle either claims its run slot before the erase
    // — and is waited for — or never finds the topic at all.
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
            ContentModuleFacade::instance().runOnce(TOPIC, {});
            cycleFinished = true;
        });

    {
        std::unique_lock<std::mutex> lock {gateMutex};
        ASSERT_TRUE(gate.wait_for(lock, std::chrono::seconds {10}, [&] { return cycleStarted; }));
    }

    std::thread remover([] { ContentModuleFacade::instance().removeProvider(TOPIC); });

    // Give the remover a moment to get as far as it can, which must not be all the way.
    std::this_thread::sleep_for(std::chrono::milliseconds {200});
    EXPECT_FALSE(cycleFinished.load()) << "the cycle ended on its own; the test is not measuring the drain";

    {
        std::lock_guard<std::mutex> lock {gateMutex};
        released = true;
    }
    gate.notify_all();

    remover.join();
    EXPECT_TRUE(cycleFinished.load()) << "removeProvider returned while a cycle for that topic was still running";
    runner.join();

    script->beforeSearch = nullptr;
}
