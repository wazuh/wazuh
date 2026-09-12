/*
 * Wazuh content manager - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "components/contentCycle.hpp"
#include "fakes/fakeIndexerQueryPort.hpp"
#include "gtest/gtest.h"
#include <atomic>
#include <memory>
#include <string>

using content_manager::CycleStatus;
using fakes::FakeIndexerQueryPort;
using fakes::MemoryTokenStore;
using fakes::RecordingSink;

namespace
{

constexpr auto TOPIC = "test.topic";

/// Answers the readiness probe with `ready`, then hands the rest to @p rest.
std::function<nlohmann::json(const FakeIndexerQueryPort::SearchCall&, std::size_t)>
readyThen(std::function<nlohmann::json(const FakeIndexerQueryPort::SearchCall&, std::size_t)> rest)
{
    return [rest = std::move(rest)](const FakeIndexerQueryPort::SearchCall& call, std::size_t ordinal)
    {
        if (ordinal == 0)
        {
            return nlohmann::json {
                {"hits",
                 nlohmann::json::array({nlohmann::json {{"_id", "consumer:1"}, {"_source", {{"status", "ready"}}}}})}};
        }
        return rest ? rest(call, ordinal - 1) : FakeIndexerQueryPort::emptyHits();
    };
}

/// Test harness: a cursor-mode cycle over one data index with a consumer to validate.
struct Harness
{
    std::shared_ptr<FakeIndexerQueryPort> port {std::make_shared<FakeIndexerQueryPort>()};
    std::shared_ptr<RecordingSink> sink {std::make_shared<RecordingSink>()};
    std::shared_ptr<MemoryTokenStore> tokens {std::make_shared<MemoryTokenStore>()};
    std::shared_ptr<ConditionSync> stop {std::make_shared<ConditionSync>(false)};
    ContentCycle::Config config;

    Harness()
    {
        config.topic = TOPIC;
        config.pit.dataIndices = {"data-index"};
        config.pit.consumerStatusIndex = ".consumers";
        config.pit.consumerStatusId = "consumer:1";
        config.fetchTemplate.sort = nlohmann::json::array({nlohmann::json {{"offset", "asc"}}});
        config.fetchTemplate.pageSize = 10;
        config.consumerRetryInterval = std::chrono::seconds {60};
        // Zero-length cache so each test probes for itself: the cache is process-wide.
        config.consumerCacheTtl = std::chrono::seconds {0};
    }

    std::unique_ptr<ContentCycle> build()
    {
        ConsumerGate::resetCache();
        return std::make_unique<ContentCycle>(
            config, port, std::make_unique<OffsetCursorDetector>("offset"), sink, tokens, stop);
    }

    /// Make the pre-flight (non-PIT) probe answer with a status.
    void preflight(const std::string& status)
    {
        port->state()->onSearchIndex = [status](std::string_view, const nlohmann::json&)
        {
            return nlohmann::json {
                {"hits",
                 {{"hits",
                   nlohmann::json::array({nlohmann::json {{"_id", "consumer:1"}, {"_source", {{"status", status}}}}})}}}};
        };
    }
};

} // namespace

TEST(ContentCycleTest, FullLoadCommitsAndPersistsTheToken)
{
    Harness harness;
    harness.preflight("ready");
    harness.port->state()->onSearch = readyThen(
        [](const auto&, std::size_t call) -> nlohmann::json
        {
            if (call > 0)
            {
                return FakeIndexerQueryPort::emptyHits();
            }
            return FakeIndexerQueryPort::hitsOf(
                nlohmann::json::array({FakeIndexerQueryPort::hit("CVE-1", 1), FakeIndexerQueryPort::hit("CVE-2", 5)}));
        });

    const auto outcome = harness.build()->run({});

    EXPECT_EQ(outcome.status, CycleStatus::Updated);
    EXPECT_EQ(outcome.documentsDelivered, 2U);
    EXPECT_EQ(outcome.token, "5");
    EXPECT_EQ(outcome.retryAfter, std::chrono::seconds {0});

    ASSERT_EQ(harness.sink->sessions.size(), 1U);
    EXPECT_EQ(harness.sink->sessions.front().kind, content_manager::SessionKind::FullReload);
    ASSERT_EQ(harness.sink->commits.size(), 1U);
    EXPECT_EQ(harness.sink->commits.front().finalToken, "5");
    EXPECT_TRUE(harness.sink->commits.front().changed);

    // Exactly one write, at commit: nothing was acked Durable in this cycle.
    EXPECT_EQ(harness.tokens->writes, (std::vector<std::string> {"5"}));
}

TEST(ContentCycleTest, StoredCursorProducesAnIncrementalSession)
{
    Harness harness;
    harness.preflight("ready");
    harness.tokens->token = "100";
    harness.port->state()->onSearch = readyThen(nullptr);

    const auto outcome = harness.build()->run({});

    ASSERT_EQ(harness.sink->sessions.size(), 1U);
    EXPECT_EQ(harness.sink->sessions.front().kind, content_manager::SessionKind::Incremental);
    EXPECT_EQ(harness.sink->sessions.front().localToken, "100");
    // Nothing new to fetch, but the sink still gets its commit so it can act on every cycle.
    EXPECT_EQ(outcome.status, CycleStatus::Unchanged);
}

TEST(ContentCycleTest, ForceFullReloadClearsTheTokenBeforeProbing)
{
    Harness harness;
    harness.preflight("ready");
    harness.tokens->token = "100";
    harness.port->state()->onSearch = readyThen(nullptr);

    harness.build()->run({/*forceFullReload=*/true, /*onDemand=*/true});

    ASSERT_FALSE(harness.tokens->writes.empty());
    // The clear is the FIRST write and it happens before the probe: a crash mid-reload must start
    // over on the next boot rather than resume from a cursor whose content was overwritten.
    EXPECT_TRUE(harness.tokens->writes.front().empty());

    ASSERT_EQ(harness.sink->sessions.size(), 1U);
    EXPECT_EQ(harness.sink->sessions.front().kind, content_manager::SessionKind::FullReload);
    EXPECT_TRUE(harness.sink->sessions.front().localToken.empty());
    EXPECT_TRUE(harness.sink->sessions.front().onDemand);
}

TEST(ContentCycleTest, PreflightNotReadySkipsWithABoundedRetry)
{
    Harness harness;
    harness.preflight("running");

    const auto outcome = harness.build()->run({});

    EXPECT_EQ(outcome.status, CycleStatus::SkippedConsumerNotReady);
    // The whole point of bounding the gate: a deferred cycle comes back in a minute, not at the
    // next scheduler tick, which for VD's default interval would be an hour.
    EXPECT_EQ(outcome.retryAfter, std::chrono::seconds {60});
    EXPECT_TRUE(harness.sink->sessions.empty());
    EXPECT_TRUE(harness.tokens->writes.empty());
    // No PIT was opened: the pre-flight exists precisely to avoid paying for one.
    EXPECT_EQ(harness.port->state()->openedPits, 0U);
}

TEST(ContentCycleTest, InPitNotReadySkipsAfterThePreflightPassed)
{
    Harness harness;
    // The pre-flight sees a ready consumer; by the time the snapshot is open it is running again.
    // This is the window the in-PIT check exists to close, and it is inexpressible with a check
    // that happens before the PIT is opened.
    harness.preflight("ready");
    harness.port->state()->onSearch = [](const auto&, std::size_t)
    {
        return nlohmann::json {
            {"hits",
             nlohmann::json::array({nlohmann::json {{"_id", "consumer:1"}, {"_source", {{"status", "running"}}}}})}};
    };

    const auto outcome = harness.build()->run({});

    EXPECT_EQ(outcome.status, CycleStatus::SkippedConsumerNotReady);
    EXPECT_EQ(harness.port->state()->openedPits, 1U);
    EXPECT_EQ(harness.port->state()->closedPits, 1U);
    EXPECT_TRUE(harness.sink->sessions.empty());
}

TEST(ContentCycleTest, MissingConsumerDocumentIsASkipNotAnError)
{
    Harness harness;
    harness.preflight("ready");
    harness.port->state()->onSearch = [](const auto&, std::size_t) { return FakeIndexerQueryPort::emptyHits(); };

    const auto outcome = harness.build()->run({});

    // A fresh install has no consumer document yet. Throwing here would turn every cold start into
    // an error.
    EXPECT_EQ(outcome.status, CycleStatus::SkippedConsumerNotReady);
    EXPECT_EQ(outcome.retryAfter, std::chrono::seconds {60});
}

TEST(ContentCycleTest, UnsatisfiedPreconditionDefersTheFullLoad)
{
    Harness harness;
    harness.preflight("ready");
    harness.config.requiredDocumentIds = nlohmann::json::array({"FEED-GLOBAL", "OSCPE-GLOBAL", "CNA-MAPPING-GLOBAL"});
    harness.port->state()->onSearch = readyThen(
        [](const auto&, std::size_t) -> nlohmann::json
        {
            // Only one of the three required documents is present.
            return FakeIndexerQueryPort::hitsOf(nlohmann::json::array({nlohmann::json {{"_id", "FEED-GLOBAL"}}}));
        });

    const auto outcome = harness.build()->run({});

    EXPECT_EQ(outcome.status, CycleStatus::SkippedPreconditionUnmet);
    EXPECT_EQ(outcome.retryAfter, std::chrono::seconds {60});
    // Checked before the session opens, so the sink is never told about a cycle that cannot run.
    EXPECT_TRUE(harness.sink->sessions.empty());
}

TEST(ContentCycleTest, PreconditionIsNotCheckedOnAnIncrementalPlan)
{
    Harness harness;
    harness.preflight("ready");
    harness.tokens->token = "100";
    harness.config.requiredDocumentIds = nlohmann::json::array({"FEED-GLOBAL"});
    harness.port->state()->onSearch = readyThen(nullptr);

    const auto outcome = harness.build()->run({});

    // An incremental run implies a previous cycle committed with the documents present. Paying a
    // probe per cycle to detect something the commit path already handles is not worth it.
    EXPECT_NE(outcome.status, CycleStatus::SkippedPreconditionUnmet);
}

TEST(ContentCycleTest, SinkSkipLeavesTheTokenAlone)
{
    Harness harness;
    harness.preflight("ready");
    harness.tokens->token = "42";
    harness.sink->decision = content_manager::SessionDecision::Skip;
    harness.port->state()->onSearch = readyThen(nullptr);

    const auto outcome = harness.build()->run({});

    EXPECT_EQ(outcome.status, CycleStatus::Unchanged);
    EXPECT_EQ(outcome.token, "42");
    EXPECT_TRUE(harness.tokens->writes.empty());
    EXPECT_TRUE(harness.sink->commits.empty());
}

TEST(ContentCycleTest, SinkAbortIsATransientSinkFailure)
{
    Harness harness;
    harness.preflight("ready");
    harness.sink->decision = content_manager::SessionDecision::Abort;
    harness.port->state()->onSearch = readyThen(nullptr);

    const auto outcome = harness.build()->run({});

    EXPECT_EQ(outcome.status, CycleStatus::FailedSink);
    EXPECT_EQ(outcome.retryAfter, std::chrono::seconds {30});
    EXPECT_TRUE(harness.tokens->writes.empty());
}

TEST(ContentCycleTest, RejectedPageAbortsTheSessionAndKeepsTheToken)
{
    Harness harness;
    harness.preflight("ready");
    harness.tokens->token = "7";
    harness.sink->pageStatus = content_manager::PageStatus::Reject;
    harness.port->state()->onSearch = readyThen(
        [](const auto&, std::size_t) -> nlohmann::json
        { return FakeIndexerQueryPort::hitsOf(nlohmann::json::array({FakeIndexerQueryPort::hit("CVE-1", 9)})); });

    const auto outcome = harness.build()->run({});

    EXPECT_EQ(outcome.status, CycleStatus::FailedSink);
    ASSERT_EQ(harness.sink->aborts.size(), 1U);
    EXPECT_EQ(harness.sink->aborts.front(), content_manager::AbortReason::SinkRejectedPage);
    EXPECT_TRUE(harness.sink->commits.empty());
    EXPECT_TRUE(harness.tokens->writes.empty());
}

TEST(ContentCycleTest, RejectedRetryFullClearsTheToken)
{
    Harness harness;
    harness.preflight("ready");
    harness.tokens->token = "7";
    harness.sink->commitStatus = content_manager::CommitStatus::RejectedRetryFull;
    harness.port->state()->onSearch = readyThen(nullptr);

    const auto outcome = harness.build()->run({});

    EXPECT_EQ(outcome.status, CycleStatus::FailedSink);
    // Clearing is what makes the NEXT cycle a full reload rather than an incremental one on top of
    // content the sink just declared unusable.
    ASSERT_EQ(harness.tokens->writes.size(), 1U);
    EXPECT_TRUE(harness.tokens->writes.front().empty());
    EXPECT_TRUE(harness.tokens->token.empty());
}

TEST(ContentCycleTest, RejectedRetrySameKeepsTheToken)
{
    Harness harness;
    harness.preflight("ready");
    harness.tokens->token = "7";
    harness.sink->commitStatus = content_manager::CommitStatus::RejectedRetrySame;
    harness.port->state()->onSearch = readyThen(nullptr);

    const auto outcome = harness.build()->run({});

    EXPECT_EQ(outcome.status, CycleStatus::FailedSink);
    EXPECT_TRUE(harness.tokens->writes.empty());
    EXPECT_EQ(harness.tokens->token, "7");
}

TEST(ContentCycleTest, FailedTokenPersistenceAfterCommitIsReportedNotAborted)
{
    Harness harness;
    harness.preflight("ready");
    harness.tokens->storeSucceeds = false;
    harness.port->state()->onSearch = readyThen(
        [](const auto&, std::size_t call) -> nlohmann::json
        {
            if (call > 0)
            {
                return FakeIndexerQueryPort::emptyHits();
            }
            return FakeIndexerQueryPort::hitsOf(nlohmann::json::array({FakeIndexerQueryPort::hit("CVE-1", 3)}));
        });

    const auto outcome = harness.build()->run({});

    EXPECT_EQ(outcome.status, CycleStatus::FailedSink);
    EXPECT_EQ(outcome.retryAfter, std::chrono::seconds {30});
    // The content is live: aborting the sink here would throw away a promotion that already
    // happened. Re-fetching next cycle is the safe direction.
    EXPECT_TRUE(harness.sink->aborts.empty());
    ASSERT_EQ(harness.sink->commits.size(), 1U);
}

TEST(ContentCycleTest, StopRequestBeforeTheCycleSkipsEverything)
{
    Harness harness;
    harness.stop->set(true);

    const auto outcome = harness.build()->run({});

    EXPECT_EQ(outcome.status, CycleStatus::SkippedStopRequested);
    EXPECT_EQ(outcome.retryAfter, std::chrono::seconds {0});
    EXPECT_TRUE(harness.sink->sessions.empty());
    EXPECT_EQ(harness.port->state()->openedPits, 0U);
}

TEST(ContentCycleTest, AThrowingPitOpenSurfacesAsATransportFailure)
{
    Harness harness;
    harness.preflight("ready");
    harness.port->state()->openPitError = "cannot open PIT";

    // PitSession's constructor opens the PIT and can throw, while run() is noexcept. The session is
    // therefore built inside the cycle's own try — this is the one path that could otherwise unwind
    // across the DSO boundary.
    const auto outcome = harness.build()->run({});

    EXPECT_EQ(outcome.status, CycleStatus::FailedTransport);
    EXPECT_EQ(outcome.detail, "cannot open PIT");
    EXPECT_EQ(outcome.retryAfter, std::chrono::seconds {30});
}

TEST(ContentCycleTest, AnUnreachableIndexerIsATransportFailure)
{
    Harness harness;
    harness.port->state()->onSearchIndex = [](std::string_view, const nlohmann::json&) -> nlohmann::json
    { throw std::runtime_error("connection refused"); };

    const auto outcome = harness.build()->run({});

    EXPECT_EQ(outcome.status, CycleStatus::FailedTransport);
    EXPECT_EQ(outcome.retryAfter, std::chrono::seconds {30});
}

TEST(ContentCycleTest, SlicesAreUsedOnFullLoadsOnly)
{
    Harness harness;
    harness.preflight("ready");
    harness.config.fullSlices = 3;
    harness.tokens->token = "100";
    harness.port->state()->onSearch = readyThen(nullptr);

    harness.build()->run({});

    // Slicing discards per-page durability, so it is only used where there is none to lose. An
    // incremental fetch has a resume point worth keeping.
    for (const auto& call : harness.port->state()->searches)
    {
        EXPECT_FALSE(call.slice.has_value());
    }
    EXPECT_EQ(harness.port->state()->clones, 0U);
}

TEST(ContentCycleTest, DurableAckPersistsImmediatelyAndCommitFinalises)
{
    Harness harness;
    harness.preflight("ready");
    harness.sink->pageStatus = content_manager::PageStatus::Durable;
    harness.port->state()->onSearch = readyThen(
        [](const auto&, std::size_t call) -> nlohmann::json
        {
            if (call == 0)
            {
                return FakeIndexerQueryPort::hitsOf(
                    nlohmann::json::array({FakeIndexerQueryPort::hit("CVE-1", 1), FakeIndexerQueryPort::hit("CVE-2", 2)}));
            }
            return FakeIndexerQueryPort::hitsOf(nlohmann::json::array({FakeIndexerQueryPort::hit("CVE-3", 3)}));
        });
    harness.config.fetchTemplate.pageSize = 2;

    const auto outcome = harness.build()->run({});

    EXPECT_EQ(outcome.status, CycleStatus::Updated);
    // One write per durable page, then the final one at commit. Persisting only at the end would
    // throw away the crash-resume point the sink went to the trouble of guaranteeing.
    EXPECT_EQ(harness.tokens->writes, (std::vector<std::string> {"2", "3", "3"}));
}

TEST(ContentCycleTest, AnAmbiguousProbeIsAConfigFailureNotATransportOne)
{
    Harness harness;
    harness.preflight("ready");

    ContentHashDetector::Config detectorConfig;
    detectorConfig.hashIndex = "policies";
    detectorConfig.hashQuery = nlohmann::json {{"term", {{"space.name", "standard"}}}};
    detectorConfig.hashPointers = {"/space/hash/sha256"};
    detectorConfig.dataQuery = nlohmann::json::object();

    harness.port->state()->onSearch = readyThen(
        [](const auto&, std::size_t) -> nlohmann::json
        {
            const auto policy = [](const char* hash)
            { return nlohmann::json {{"_source", {{"space", {{"hash", {{"sha256", hash}}}}}}}}; };
            return nlohmann::json {{"hits", nlohmann::json::array({policy("a"), policy("b")})}};
        });

    ConsumerGate::resetCache();
    ContentCycle cycle {harness.config,
                        harness.port,
                        std::make_unique<ContentHashDetector>(detectorConfig),
                        harness.sink,
                        harness.tokens,
                        harness.stop};

    const auto outcome = cycle.run({});

    // Retrying cannot fix a query that is not selective enough, so it must not be reported as
    // something the driver should come back for.
    EXPECT_EQ(outcome.status, CycleStatus::FailedConfig);
    EXPECT_EQ(outcome.retryAfter, std::chrono::seconds {0});
    EXPECT_TRUE(harness.sink->sessions.empty()) << "the sink must not be told about a cycle that cannot run";
    EXPECT_TRUE(harness.tokens->writes.empty());
}

TEST(ContentCycleTest, ASliceRejectionEndsTheOtherSlices)
{
    constexpr std::size_t SLICES = 4;
    // Far above what a correct run needs, and low enough that a broken one still terminates: a
    // regression here must fail the assertion, not hang CI.
    constexpr std::size_t PAGE_BUDGET = 200;

    Harness harness;
    harness.preflight("ready");
    harness.config.fullSlices = SLICES;
    harness.config.fetchTemplate.pageSize = 1;
    harness.sink->pageStatus = content_manager::PageStatus::Reject;

    // Endless work for every slice, so a slice that ignores its sibling's rejection keeps paging
    // rather than merely wasting one request. Keyed on the slice parameter rather than on a call
    // ordinal, because each clone counts its own calls from zero.
    std::atomic<std::size_t> slicePages {0};
    harness.port->state()->onSearch =
        [&slicePages](const FakeIndexerQueryPort::SearchCall& call, std::size_t) -> nlohmann::json
    {
        if (!call.slice.has_value())
        {
            return nlohmann::json {
                {"hits",
                 nlohmann::json::array({nlohmann::json {{"_id", "consumer:1"}, {"_source", {{"status", "ready"}}}}})}};
        }

        const auto page = slicePages.fetch_add(1);
        if (page >= PAGE_BUDGET)
        {
            return FakeIndexerQueryPort::emptyHits();
        }
        return FakeIndexerQueryPort::hitsOf(
            nlohmann::json::array({FakeIndexerQueryPort::hit("CVE-" + std::to_string(page), page + 1)}));
    };

    const auto outcome = harness.build()->run({});

    EXPECT_EQ(outcome.status, CycleStatus::FailedSink);
    EXPECT_TRUE(harness.tokens->writes.empty());
    ASSERT_EQ(harness.sink->aborts.size(), 1U);
    EXPECT_EQ(harness.sink->aborts.front(), content_manager::AbortReason::SinkRejectedPage);

    // Each slice may already be mid-request when the first rejection lands, so one page apiece is
    // the honest bound. What must not happen is the other three draining the whole budget into a
    // sink that has already torn its staging state down.
    EXPECT_LE(slicePages.load(), SLICES) << "slices kept fetching after a sibling rejected a page";
}
