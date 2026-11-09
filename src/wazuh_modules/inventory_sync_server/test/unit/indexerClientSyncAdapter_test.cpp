/*
 * Wazuh inventory sync server module - unit tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// The sync seam over indexer_client (E7b): the failure table (I135), the bucket and budget derivations
// from the module's options (I138, I137b, I145), and the adapter itself on a REAL runtime of the client
// library served by the library's own in-process fake indexer (IC/tests/fake): per-session results,
// chunking against the quota, the per-key barrier, the by-query barrier, deadlines and cancellation.
#include "indexer/connectorFailure.hpp"
#include "indexer/indexerClientSyncAdapter.hpp"
#include "inventory_sync_server.h"

#include <indexer_client/keyValueConfigSource.hpp>
#include <indexer_client/runtime.hpp>

#include "bulkResponder.hpp"
#include "fakeIndexer.hpp"
#include "healthRules.hpp"

#include <json.hpp>

#include <gtest/gtest.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using invsync::indexer::AdapterOptions;
using invsync::indexer::Budgets;
using invsync::indexer::ConnectorError;
using invsync::indexer::SessionOutcome;
using Adapter = invsync::indexer::IndexerClientSyncAdapter;
using indexer_client::testing::BulkItem;
using indexer_client::testing::BulkOp;
using indexer_client::testing::BulkResponder;
using indexer_client::testing::BulkScript;
using indexer_client::testing::FakeIndexer;
using indexer_client::testing::FakeIndexerOptions;
using indexer_client::testing::Rule;

namespace
{
    using Clock = std::chrono::steady_clock;
    using namespace std::chrono_literals;

    constexpr auto INDEX {"wazuh-states-inventory-packages"};
    constexpr std::uint64_t MIB {1024 * 1024};
    constexpr std::uint64_t GLOBAL_QUOTA {256 * MIB};

    std::int64_t millisSince(Clock::time_point start)
    {
        return std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - start).count();
    }

    bool waitFor(const std::function<bool()>& condition, std::chrono::milliseconds timeout = 5000ms)
    {
        const auto deadline = Clock::now() + timeout;
        while (!condition())
        {
            if (Clock::now() >= deadline)
            {
                return condition();
            }
            std::this_thread::sleep_for(2ms);
        }
        return true;
    }

    /// A loopback port with nothing listening (bound, then closed): connecting to it is refused at once.
    int closedPort()
    {
        const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        sockaddr_in address {};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        socklen_t length = sizeof(address);
        ::bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address));
        ::getsockname(fd, reinterpret_cast<sockaddr*>(&address), &length);
        ::close(fd);
        return ntohs(address.sin_port);
    }

    /// A compact JSON document of exactly `size` payload bytes inside its `v` member.
    std::string document(char tag, std::size_t size = 64)
    {
        return std::string {R"({"v":")"} + std::string(size, tag) + "\"}";
    }

    /// The module's options with every retry knob at its "no opinion" value (< 0), i.e. the defaults.
    inventory_sync_server_config_t noOpinionConfig()
    {
        inventory_sync_server_config_t config {};
        config.indexer_sync_connector_max_bulk_size = -1;
        config.indexer_sync_max_retry_attempts = -1;
        config.indexer_sync_max_retry_duration_seconds = -1;
        config.indexer_sync_max_retry_delay_seconds = -1;
        return config;
    }

    Rule queryRule(const std::string& route, std::string body)
    {
        Rule rule;
        rule.method = "POST";
        rule.pathRegex = "(/[^/]+)?/" + route;
        rule.body = std::move(body);
        return rule;
    }

    constexpr auto DBQ_OK {R"({"took":1,"timed_out":false,"deleted":1,"version_conflicts":0,"failures":[]})"};
    constexpr auto DBQ_CONFLICTS {R"({"took":1,"timed_out":false,"deleted":0,"version_conflicts":2,"failures":[]})"};

    struct Node
    {
        std::shared_ptr<FakeIndexer> fake;
        std::shared_ptr<BulkResponder> bulk;
        std::size_t dbqRule {0}; ///< Index of its `_delete_by_query` rule, for FakeIndexer::hits().
    };
} // namespace

// ---- The failure table (CA-E7b-1) ------------------------------------------------------------

/// I135 in one place: the code and body of every cause the seam can carry, `Retry-After` only for a
/// by-query's exhausted conflicts, and the metric suffix each one counts under.
TEST(ConnectorFailure, ResponseForEveryCause)
{
    using Cause = ConnectorError::Cause;
    struct Row
    {
        Cause cause;
        int status;
        const char* body;
        bool retryAfter;
        const char* metric;
    };
    // Unavailable is the last enumerator: a member added after it is a member without a row here.
    const std::vector<Row> table {
        {Cause::Other, 500, invsync::indexer::FAILURE_INTERNAL_BODY, false, "other"},
        {Cause::DocumentRejected, 500, invsync::indexer::FAILURE_INTERNAL_BODY, false, "documents"},
        {Cause::RetryExhausted, 503, invsync::indexer::FAILURE_UNAVAILABLE_BODY, false, "exhausted"},
        {Cause::ConflictsExhausted, 503, invsync::indexer::FAILURE_CONTENTION_BODY, true, "documents"},
        {Cause::Unavailable, 503, invsync::indexer::FAILURE_UNAVAILABLE_BODY, false, "unavailable"},
    };
    ASSERT_EQ(static_cast<std::size_t>(Cause::Unavailable) + 1, table.size()) << "a cause without a row";

    for (const auto& row : table)
    {
        const auto response = invsync::indexer::failureResponse(row.cause, 15);
        EXPECT_EQ(row.status, response.status) << static_cast<int>(row.cause);
        EXPECT_STREQ(row.body, response.body) << static_cast<int>(row.cause);
        EXPECT_EQ(row.retryAfter, response.retryAfter.has_value()) << static_cast<int>(row.cause);
        if (row.retryAfter)
        {
            EXPECT_EQ("15", *response.retryAfter);
        }
        EXPECT_STREQ(row.metric, invsync::indexer::failureMetric(row.cause)) << static_cast<int>(row.cause);
    }
}

// ---- Derivations from the module's options (CA-E7b-9) ----------------------------------------

class IndexerClientSyncAdapter : public ::testing::Test
{
protected:
    /// A fake indexer node: green (or throttled) health, `_bulk` answered by `script`, and a
    /// `_delete_by_query` that answers `dbq`.
    Node startNode(BulkScript script = BulkScript::items(),
                   bool throttled = false,
                   std::string dbq = DBQ_OK,
                   std::chrono::milliseconds dbqLatency = 0ms)
    {
        FakeIndexerOptions options;
        options.recordBodies = true;
        Node node;
        node.fake = std::make_shared<FakeIndexer>(options);
        node.bulk = std::make_shared<BulkResponder>(std::move(script));
        node.fake->addRule(throttled
                               ? indexer_client::testing::throttledRule(indexer_client::testing::Durability::Transient)
                               : indexer_client::testing::healthRule("green"));
        node.fake->addRule(indexer_client::testing::bulkRule(node.bulk));
        auto dbqRule = queryRule("_delete_by_query", std::move(dbq));
        dbqRule.latency = dbqLatency;
        node.dbqRule = node.fake->addRule(std::move(dbqRule));
        node.fake->addRule(queryRule("_update_by_query", R"({"updated":0,"version_conflicts":0,"failures":[]})"));
        node.fake->start();
        m_nodes.push_back(node);
        return node;
    }

    void startRuntimeOn(const std::vector<std::string>& hosts, const std::string& extra = {})
    {
        std::string text = "wazuh_modules.indexer_client_network_threads=1\n"
                           "wazuh_modules.indexer_client_cpu_threads=2\n"
                           "wazuh_modules.indexer_client_probe_interval_ms=200\n" +
                           extra;
        std::string json = "{\"hosts\":[";
        for (std::size_t i = 0; i < hosts.size(); ++i)
        {
            json += (i == 0 ? "\"" : ",\"") + hosts[i] + "\"";
        }
        json += "]}";
        auto source =
            indexer_client::KeyValueConfigSource::parse(text, json, indexer_client::Credentials {"admin", "admin"});
        ASSERT_TRUE(source.ok()) << source.reason;
        auto started = indexer_client::RuntimeOwner::start(indexer_client::ProcessId::Modulesd, source.value);
        ASSERT_TRUE(started.ok()) << indexer_client::toString(started.cause) << ": " << started.reason;
        m_ref = started.value;
        m_runtimeStarted = true;
    }

    /// The runtime on the nodes started so far.
    void startRuntime(const std::string& extra = {})
    {
        std::vector<std::string> hosts;
        for (const auto& node : m_nodes)
        {
            hosts.push_back(node.fake->baseUrl());
        }
        startRuntimeOn(hosts, extra);
    }

    /// The module's own bucket for `config`, tuned for a test: quick retries, a bucket whose pending
    /// ops wait long enough for the test to look at them.
    static indexer_client::BucketSpec testSpec(const inventory_sync_server_config_t& config = noOpinionConfig())
    {
        auto spec = invsync::indexer::inventoryBucketSpec(config, GLOBAL_QUOTA, 2000ms);
        spec.retry.base = 20ms;
        spec.bulk.maxAge = 60s;
        return spec;
    }

    void makeClient(const indexer_client::BucketSpec& spec, bool waitAvailable = true)
    {
        auto outcome = m_ref.client(invsync::indexer::INDEXER_CLIENT_CONSUMER, {spec});
        ASSERT_TRUE(outcome.ok()) << indexer_client::toString(outcome.cause) << ": " << outcome.reason;
        m_client = outcome.value;
        if (waitAvailable)
        {
            // The first probe round decides: until a node is Available every write answers Unavailable.
            ASSERT_TRUE(waitFor([this] { return m_client->health().anyAvailable(); })) << "no node became Available";
        }
    }

    /// Runtime on the started nodes + the module's bucket + one adapter: the common start of a test.
    Adapter& startAll(const indexer_client::BucketSpec& spec, const AdapterOptions& options)
    {
        startRuntime();
        makeClient(spec);
        return makeAdapter(options);
    }

    Adapter& makeAdapter(const AdapterOptions& options, const std::string& tag = "w0")
    {
        m_adapters.push_back(std::make_unique<Adapter>(m_client, options, m_closing, tag));
        return *m_adapters.back();
    }

    static AdapterOptions options(std::size_t capBytes,
                                  const inventory_sync_server_config_t& config = noOpinionConfig())
    {
        AdapterOptions result;
        result.capBytes = capBytes;
        result.budgets = invsync::indexer::budgets(config);
        return result;
    }

    std::uint64_t charge() const
    {
        const auto metrics = m_client->metrics();
        return metrics.buckets.empty() ? 0 : metrics.buckets.front().charge;
    }

    std::uint64_t rejected(indexer_client::RejectCause cause) const
    {
        const auto metrics = m_client->metrics();
        return metrics.buckets.empty() ? 0 : metrics.buckets.front().rejected[static_cast<std::size_t>(cause)];
    }

    /// Every op of every `_bulk` the nodes received, in arrival order.
    std::vector<BulkOp> receivedOps(const Node& node) const
    {
        std::vector<BulkOp> ops;
        for (const auto& request : node.bulk->received())
        {
            ops.insert(ops.end(), request.begin(), request.end());
        }
        return ops;
    }

    /// The `source` of every op with `id`, in the order the fake received them.
    std::vector<std::string> sourcesOf(const Node& node, const std::string& id) const
    {
        std::vector<std::string> sources;
        for (const auto& op : receivedOps(node))
        {
            if (op.id && *op.id == id)
            {
                sources.push_back(op.source);
            }
        }
        return sources;
    }

    static void stage(Adapter& adapter, const std::string& id, const std::string& body)
    {
        adapter.bulkIndex(id, INDEX, body);
    }

    void TearDown() override
    {
        m_closing->store(true);
        for (auto& node : m_nodes)
        {
            node.fake->releaseHeld(); // Nothing may wait on a response the test never released.
        }
        m_adapters.clear();
        if (m_client)
        {
            if (auto writer = m_client->writer(invsync::indexer::INVENTORY_BUCKET))
            {
                writer->cancel("occ");
            }
            m_client->requestClose();
            m_client->awaitClosed(Clock::now() + 3s);
            m_client.reset();
        }
        if (m_runtimeStarted)
        {
            indexer_client::RuntimeOwner::beginShutdown(Clock::now() + 5s);
            indexer_client::RuntimeOwner::shutdown();
        }
        m_nodes.clear(); // The fakes outlive the runtime.
    }

    std::vector<Node> m_nodes;
    indexer_client::RuntimeRef m_ref;
    bool m_runtimeStarted {false};
    std::shared_ptr<indexer_client::Client> m_client;
    std::shared_ptr<std::atomic<bool>> m_closing {std::make_shared<std::atomic<bool>>(false)};
    std::vector<std::unique_ptr<Adapter>> m_adapters;
};

/// Every library cause maps to exactly one seam class, and the HTTP answer that class gets is the
/// I135 table's: 503 for everything transient (Throttled included), 500 for a rejection a re-send
/// alone will not fix.
TEST_F(IndexerClientSyncAdapter, TranslatesEveryCause)
{
    using C = indexer_client::Cause;
    using S = ConnectorError::Cause;
    const std::vector<std::pair<C, S>> table {
        {C::None, S::Other},
        {C::TransportTimeout, S::Unavailable},
        {C::TransportConnect, S::Unavailable},
        {C::TransportTls, S::Unavailable},
        {C::Throttled, S::Unavailable},
        {C::PayloadTooLarge, S::DocumentRejected},
        {C::Server5xx, S::Unavailable},
        {C::Client4xx, S::DocumentRejected},
        {C::ItemRetryable, S::Unavailable},
        {C::ItemPermanent, S::DocumentRejected},
        {C::VersionConflict, S::ConflictsExhausted},
        {C::Unavailable, S::Unavailable},
        {C::QueueFull, S::Unavailable},
        {C::SubmitTimeout, S::Unavailable},
        {C::WaitTimeout, S::Unavailable},
        {C::GroupTooLarge, S::DocumentRejected},
        {C::RetryExhausted, S::RetryExhausted},
        {C::Shutdown, S::Unavailable},
        {C::ClientClosed, S::Unavailable},
        {C::Cancelled, S::Unavailable},
        {C::Reentrancy, S::Other},
        {C::PitExpired, S::Other},
        {C::PitStaleGeneration, S::Other},
        {C::NotFound, S::Other},
        {C::InvalidConfig, S::Other},
        {C::InvalidArgument, S::Other},
        {C::InvalidState, S::Other},
        {C::UsageError, S::Other},
        {C::Ambiguous, S::Other},
    };
    // Ambiguous is the last enumerator: a cause added after it is a cause without a row here.
    ASSERT_EQ(static_cast<std::size_t>(C::Ambiguous) + 1, table.size()) << "a library cause without a row";

    for (const auto& [library, seam] : table)
    {
        EXPECT_EQ(seam, invsync::indexer::translateCause(library)) << indexer_client::toString(library);
    }

    // The code each cause finally answers: the 503 set of I135 and nothing else.
    const std::vector<C> answered503 {C::Unavailable,
                                      C::Throttled,
                                      C::QueueFull,
                                      C::SubmitTimeout,
                                      C::RetryExhausted,
                                      C::TransportTimeout,
                                      C::TransportConnect,
                                      C::TransportTls,
                                      C::Server5xx,
                                      C::Shutdown,
                                      C::ClientClosed,
                                      C::Cancelled,
                                      C::WaitTimeout,
                                      C::ItemRetryable,
                                      C::VersionConflict};
    for (const auto& [library, seam] : table)
    {
        const auto expected =
            std::find(answered503.begin(), answered503.end(), library) != answered503.end() ? 503 : 500;
        EXPECT_EQ(expected, invsync::indexer::failureResponse(seam, 15).status) << indexer_client::toString(library);
    }
}

TEST_F(IndexerClientSyncAdapter, BucketSpecFromConfig)
{
    const auto spec = invsync::indexer::inventoryBucketSpec(noOpinionConfig(), GLOBAL_QUOTA, 2000ms);

    // Defaults: the v1's 10 MiB request cap, a quota that holds one bulk with headroom, 5 attempts for
    // 15 s, delays capped at 15 s, a bounded block, 409 a success, an ambiguous 5xx retried, unordered.
    EXPECT_EQ("inventory", spec.name);
    EXPECT_EQ(10 * MIB, spec.bulk.maxBytes);
    EXPECT_EQ(64 * MIB, spec.quotaBytes);
    ASSERT_TRUE(spec.retry.maxAttempts.has_value());
    EXPECT_EQ(5U, *spec.retry.maxAttempts);
    ASSERT_TRUE(spec.retry.maxDuration.has_value());
    EXPECT_EQ(15000ms, *spec.retry.maxDuration);
    EXPECT_EQ(15000ms, spec.retry.cap);
    EXPECT_EQ(indexer_client::Overflow::Kind::Block, spec.overflow.kind);
    EXPECT_EQ(2000ms, spec.overflow.blockTimeout);
    EXPECT_EQ(indexer_client::ConflictPolicy::Kind::Success, spec.onConflict.kind);
    EXPECT_EQ(indexer_client::AmbiguousPolicy::Retry, spec.onAmbiguous5xx);
    EXPECT_FALSE(spec.ordered);

    // 100 MiB: the quota grows with the request cap (cap + result reserve + 1 MiB), no warning.
    auto big = noOpinionConfig();
    big.indexer_sync_connector_max_bulk_size = static_cast<int>(100 * MIB);
    std::string warning;
    const auto bigSpec = invsync::indexer::inventoryBucketSpec(big, GLOBAL_QUOTA, 2000ms, &warning);
    EXPECT_EQ(100 * MIB, bigSpec.bulk.maxBytes);
    EXPECT_EQ(101 * MIB + invsync::indexer::RESULT_RESERVE_BYTES, bigSpec.quotaBytes);
    EXPECT_TRUE(warning.empty()) << warning;

    // A global quota of 32 MiB cannot hold that bulk: the quota is the global one, the cap is clipped
    // to fit and the operator is told.
    warning.clear();
    const auto clipped = invsync::indexer::inventoryBucketSpec(big, 32 * MIB, 2000ms, &warning);
    EXPECT_EQ(32 * MIB, clipped.quotaBytes);
    EXPECT_LT(clipped.bulk.maxBytes, 32 * MIB);
    EXPECT_LE(clipped.bulk.maxBytes + invsync::indexer::RESULT_RESERVE_BYTES, clipped.quotaBytes);
    EXPECT_FALSE(warning.empty());

    // Zero attempts and zero duration mean "no bound" for the operator: no attempt cap; the bucket's own
    // series stays under the stateful budget (15 s), never unbounded.
    auto unbounded = noOpinionConfig();
    unbounded.indexer_sync_max_retry_attempts = 0;
    unbounded.indexer_sync_max_retry_duration_seconds = 0;
    const auto unboundedSpec = invsync::indexer::inventoryBucketSpec(unbounded, GLOBAL_QUOTA, 2000ms);
    EXPECT_FALSE(unboundedSpec.retry.maxAttempts.has_value());
    ASSERT_TRUE(unboundedSpec.retry.maxDuration.has_value());
    EXPECT_EQ(15000ms, *unboundedSpec.retry.maxDuration);

    // And the runtime accepts every one of them.
    auto fake = startNode();
    startRuntime();
    for (const auto& candidate : {spec, bigSpec, unboundedSpec})
    {
        auto client = m_ref.client(invsync::indexer::INDEXER_CLIENT_CONSUMER, {candidate});
        EXPECT_TRUE(client.ok()) << indexer_client::toString(client.cause) << ": " << client.reason;
        if (client.value)
        {
            client.value->requestClose();
            client.value->awaitClosed(Clock::now() + 3s);
        }
    }
}

TEST_F(IndexerClientSyncAdapter, Budgets)
{
    // Defaults and "0 = no bound": 18 s for a /stateful batch (under remoted's 20 s window), 70 s for a
    // whole-agent deletion; a long operator duration only moves the deletion, up to 540 s.
    for (const int seconds : {-1, 0})
    {
        auto config = noOpinionConfig();
        config.indexer_sync_max_retry_duration_seconds = seconds;
        const auto result = invsync::indexer::budgets(config);
        EXPECT_EQ(18000ms, result.stateful) << seconds;
        EXPECT_EQ(70000ms, result.deletion) << seconds;
        EXPECT_EQ(15000ms, result.statefulRetry) << seconds;
    }

    auto longDuration = noOpinionConfig();
    longDuration.indexer_sync_max_retry_duration_seconds = 3600;
    const auto longBudgets = invsync::indexer::budgets(longDuration);
    EXPECT_EQ(18000ms, longBudgets.stateful);
    EXPECT_EQ(540000ms, longBudgets.deletion);

    // The retry series always ends 3 s before its budget, so a by-query's ConflictsExhausted arrives
    // before the deadline: 15 s with a duration of 30 s and with none.
    for (const int seconds : {30, 0})
    {
        auto config = noOpinionConfig();
        config.indexer_sync_max_retry_duration_seconds = seconds;
        const auto spec = invsync::indexer::inventoryBucketSpec(config, GLOBAL_QUOTA, 2000ms);
        ASSERT_TRUE(spec.retry.maxDuration.has_value());
        EXPECT_EQ(15000ms, *spec.retry.maxDuration) << seconds;
        EXPECT_EQ(15000ms, invsync::indexer::budgets(config).statefulRetry) << seconds;
    }
}

TEST_F(IndexerClientSyncAdapter, ChunkCapIsEightyPercentOfTheQuotaPerLane)
{
    EXPECT_EQ(209715U, invsync::indexer::chunkCap(1 * MIB, 2)); // 0.8 * 1 MiB / (2 * 2)
    EXPECT_EQ(1U, invsync::indexer::chunkCap(0, 4));
    EXPECT_EQ(invsync::indexer::chunkCap(1 * MIB, 1), invsync::indexer::chunkCap(1 * MIB, 0))
        << "no lanes counts as one";
}

TEST_F(IndexerClientSyncAdapter, AvailabilityIsAnyUsable)
{
    // A throttled node is usable: the lenient aggregate keeps the sync endpoint admitting (I52-e).
    startNode(BulkScript::items(), /*throttled=*/true);
    startRuntime();
    makeClient(testSpec(), /*waitAvailable=*/false);
    ASSERT_TRUE(waitFor(
        [this]
        {
            const auto view = m_client->health();
            return !view.nodes.empty() && view.nodes.front().state == indexer_client::HealthView::NodeState::Throttled;
        }))
        << "the node never became Throttled";
    auto& adapter = makeAdapter(options(1 * MIB));
    EXPECT_TRUE(adapter.isAvailable());
}

TEST_F(IndexerClientSyncAdapter, AvailabilityIsFalseWithEveryNodeDown)
{
    startRuntimeOn({"http://127.0.0.1:" + std::to_string(closedPort())});
    makeClient(testSpec(), /*waitAvailable=*/false);
    auto& adapter = makeAdapter(options(1 * MIB));
    std::this_thread::sleep_for(500ms); // At least one probe round has failed.
    EXPECT_FALSE(adapter.isAvailable());
}

// ---- Session results (CA-E7b-2) ----------------------------------------------------------------

TEST_F(IndexerClientSyncAdapter, SessionRangesMapToResults)
{
    // Three sessions of two ops; the indexer rejects the first op of the second (position 2 of the bulk).
    auto node = startNode(BulkScript::items({{2, BulkItem::failed(400, "mapper_parsing_exception", "bad field")}}));
    auto& adapter = startAll(testSpec(), options(1 * MIB));

    for (int session = 0; session < 3; ++session)
    {
        for (int op = 0; op < 2; ++op)
        {
            stage(adapter, "s" + std::to_string(session) + "-" + std::to_string(op), document('a'));
        }
        adapter.endSession();
    }
    const auto outcomes = adapter.flushSessions(3);

    ASSERT_EQ(3U, outcomes.size());
    EXPECT_TRUE(outcomes[0].ok) << outcomes[0].reason;
    EXPECT_FALSE(outcomes[1].ok);
    EXPECT_EQ(ConnectorError::Cause::DocumentRejected, outcomes[1].cause);
    EXPECT_FALSE(outcomes[1].reason.empty());
    EXPECT_TRUE(outcomes[2].ok) << outcomes[2].reason;
    EXPECT_EQ(6U, receivedOps(node).size());
}

TEST_F(IndexerClientSyncAdapter, SessionRangesMapToResultsWhenASessionSpansChunks)
{
    // Chunks of two ops: [a, b0] [b1, b2] [c]; the second session is split between the first two chunks
    // and the indexer rejects the first op of the SECOND chunk, which is the second session's.
    auto node = startNode();
    node.bulk->push(BulkScript::items());
    node.bulk->push(BulkScript::items({{0, BulkItem::failed(400, "mapper_parsing_exception", "bad field")}}));
    auto& adapter = startAll(testSpec(), options(8000));

    stage(adapter, "a", document('a', 1000));
    adapter.endSession();
    for (const auto* id : {"b0", "b1", "b2"})
    {
        stage(adapter, id, document('b', 1000));
    }
    adapter.endSession();
    stage(adapter, "c", document('c', 1000));
    adapter.endSession();
    const auto outcomes = adapter.flushSessions(3);

    ASSERT_EQ(3U, outcomes.size());
    EXPECT_TRUE(outcomes[0].ok) << outcomes[0].reason;
    EXPECT_FALSE(outcomes[1].ok);
    EXPECT_EQ(ConnectorError::Cause::DocumentRejected, outcomes[1].cause);
    EXPECT_TRUE(outcomes[2].ok) << outcomes[2].reason;
    EXPECT_GE(node.bulk->received().size(), 2U) << "the second session really spanned chunks";
}

// ---- Version conflicts of the versioned upsert (5.0.0 #41191) ------------------------------------

namespace
{
    /// The bodies of every `_bulk` the node received, in arrival order.
    std::vector<std::string> bulkBodies(const FakeIndexer& fake)
    {
        std::vector<std::string> bodies;
        for (const auto& request : fake.requests())
        {
            if (request.path.size() >= 6 && request.path.compare(request.path.size() - 6, 6, "/_bulk") == 0)
            {
                bodies.push_back(request.body);
            }
        }
        return bodies;
    }
} // namespace

TEST_F(IndexerClientSyncAdapter, OnlyTheVersionedUpsertCarriesRetryOnConflict)
{
    auto node = startNode();
    auto& adapter = startAll(testSpec(), options(1 * MIB));

    adapter.bulkIndex("v", INDEX, document('v'), "7");
    stage(adapter, "i", document('i'));
    adapter.bulkDelete("d", INDEX);
    adapter.endSession();
    const auto outcomes = adapter.flushSessions(1);

    ASSERT_EQ(1U, outcomes.size());
    EXPECT_TRUE(outcomes[0].ok) << outcomes[0].reason;
    const auto bodies = bulkBodies(*node.fake);
    ASSERT_EQ(1U, bodies.size());
    const std::string update = std::string(R"({"update":{"_index":")") + INDEX + R"(","_id":"v","retry_on_conflict":)" +
                               std::to_string(invsync::indexer::UPDATE_RETRY_ON_CONFLICT) + "}}\n";
    EXPECT_NE(std::string::npos, bodies[0].find(update)) << bodies[0];
    EXPECT_NE(std::string::npos, bodies[0].find(std::string(R"({"index":{"_index":")") + INDEX + R"(","_id":"i"}})"))
        << bodies[0];
    EXPECT_NE(std::string::npos, bodies[0].find(std::string(R"({"delete":{"_index":")") + INDEX + R"(","_id":"d"}})"))
        << bodies[0];
    std::size_t carriers {0};
    for (auto at = bodies[0].find("retry_on_conflict"); at != std::string::npos;
         at = bodies[0].find("retry_on_conflict", at + 1))
    {
        ++carriers;
    }
    EXPECT_EQ(1U, carriers) << "only the update line carries retry_on_conflict: " << bodies[0];
}

TEST_F(IndexerClientSyncAdapter, ConflictOnTheVersionedUpsertIsSentAgain)
{
    // The indexer still answers 409 after its own retry_on_conflict: the value is sent again, never reported stored.
    auto node = startNode();
    node.bulk->push(BulkScript::items({{0, BulkItem::conflict()}}));
    auto& adapter = startAll(testSpec(), options(1 * MIB));

    adapter.bulkIndex("K", INDEX, R"({"v":"A"})", "7");
    adapter.endSession();
    const auto outcomes = adapter.flushSessions(1);

    ASSERT_EQ(1U, outcomes.size());
    EXPECT_TRUE(outcomes[0].ok) << outcomes[0].reason;
    EXPECT_EQ(2U, sourcesOf(node, "K").size()) << "the conflicted update was not sent again";
}

TEST_F(IndexerClientSyncAdapter, PersistentConflictOnTheVersionedUpsertFailsTheSession)
{
    // Every attempt conflicts: once the bucket's retry budget is spent the session fails (the agent re-sends it)
    // instead of being answered as stored.
    auto node = startNode(BulkScript::all(BulkItem::conflict()));
    auto& adapter = startAll(testSpec(), options(1 * MIB));

    adapter.bulkIndex("K", INDEX, R"({"v":"A"})", "7");
    adapter.endSession();
    const auto outcomes = adapter.flushSessions(1);

    ASSERT_EQ(1U, outcomes.size());
    EXPECT_FALSE(outcomes[0].ok);
    EXPECT_EQ(ConnectorError::Cause::RetryExhausted, outcomes[0].cause) << outcomes[0].reason;
    EXPECT_GE(sourcesOf(node, "K").size(), 2U);
}

TEST_F(IndexerClientSyncAdapter, ConflictOnIndexOrDeleteStaysSuccess)
{
    // An `index` or `delete` answered 409 keeps the bucket's Success policy: stored as it was, sent once.
    auto node = startNode(BulkScript::all(BulkItem::conflict()));
    auto& adapter = startAll(testSpec(), options(1 * MIB));

    stage(adapter, "i", document('i'));
    adapter.bulkDelete("d", INDEX);
    adapter.endSession();
    const auto outcomes = adapter.flushSessions(1);

    ASSERT_EQ(1U, outcomes.size());
    EXPECT_TRUE(outcomes[0].ok) << outcomes[0].reason;
    EXPECT_EQ(2U, receivedOps(node).size());
}

TEST_F(IndexerClientSyncAdapter, AddRefusalFailsOnlyItsSession)
{
    // A small bucket whose room is almost all taken by other writers' held ops: the first and the last
    // session's small op fit, the middle session's large one is refused by the library (QueueFull or
    // SubmitTimeout). The refusal is that session's result, not an exception, and it spares the others.
    auto node = startNode(BulkScript::items().held());
    auto spec = testSpec();
    spec.quotaBytes = 32 * 1024;
    spec.bulk.maxBytes = 16 * 1024;
    spec.overflow.blockTimeout = 200ms;
    auto& adapter = startAll(spec, options(1 * MIB));

    auto writer = m_client->writer(invsync::indexer::INVENTORY_BUCKET);
    ASSERT_NE(nullptr, writer);
    for (int i = 0; charge() < spec.quotaBytes - 9000; ++i)
    {
        indexer_client::Op occupant;
        occupant.index = INDEX;
        occupant.id = "occ-" + std::to_string(i);
        occupant.body = document('o', 2000);
        occupant.tag = "occ";
        ASSERT_TRUE(writer->post(std::move(occupant)).accepted);
    }

    stage(adapter, "first", document('a', 100));
    adapter.endSession();
    EXPECT_NO_THROW(stage(adapter, "refused", document('b', 8000)));
    adapter.endSession();
    stage(adapter, "last", document('c', 100));
    adapter.endSession();

    node.fake->releaseHeld();
    const auto outcomes = adapter.flushSessions(3);

    ASSERT_EQ(3U, outcomes.size());
    EXPECT_TRUE(outcomes[0].ok) << outcomes[0].reason;
    EXPECT_FALSE(outcomes[1].ok);
    EXPECT_EQ(ConnectorError::Cause::Unavailable, outcomes[1].cause) << outcomes[1].reason;
    EXPECT_TRUE(outcomes[2].ok) << outcomes[2].reason;
}

// ---- Chunking against the quota (CA-E7b-3) -----------------------------------------------------

// CA-E11b-1 (D88): the cuts of a fixed sequence (index, delete and versioned ops, one `_id` that escapes) under a fixed
// cap. Pinned on the adapter's own chunkCap/estimateCharge before they moved to indexer_client/chunking.hpp; the
// extraction keeps them. Each committed chunk is one `_bulk`.
TEST_F(IndexerClientSyncAdapter, CharacterizationChunkCuts)
{
    auto node = startNode();
    auto& adapter = startAll(testSpec(), options(12000));

    for (int i = 0; i < 24; ++i)
    {
        const auto id = (i == 7 ? std::string {"c\""} : std::string {"c"}) + (i < 10 ? "0" : "") + std::to_string(i);
        switch (i % 3)
        {
            case 0: adapter.bulkIndex(id, INDEX, document('a', 200 + static_cast<std::size_t>(i) * 50)); break;
            case 1: adapter.bulkDelete(id, INDEX); break;
            default: adapter.bulkIndex(id, INDEX, document('v', 300), "7"); break;
        }
    }
    adapter.endSession();
    const auto outcomes = adapter.flushSessions(1);
    ASSERT_EQ(1U, outcomes.size());
    EXPECT_TRUE(outcomes[0].ok) << outcomes[0].reason;

    std::vector<std::size_t> cuts;
    for (const auto& request : node.bulk->received())
    {
        cuts.push_back(request.size());
    }
    EXPECT_EQ((std::vector<std::size_t> {4, 4, 4, 4, 4, 3, 1}), cuts);
}

TEST_F(IndexerClientSyncAdapter, ReservesDoNotStarveBatch)
{
    // A 1 MiB bucket and two lanes; the ops' result reserves alone (2 048 B each) add up to over three
    // times the quota. Chunks of at most the lane's share, one unresolved at a time, keep it flowing.
    startNode();
    auto spec = testSpec();
    spec.quotaBytes = 1 * MIB;
    spec.bulk.maxBytes = 512 * 1024;
    auto& adapter = startAll(spec, options(invsync::indexer::chunkCap(1 * MIB, 2)));

    std::atomic<bool> running {true};
    std::atomic<std::uint64_t> peak {0};
    std::thread sampler {[&]
                         {
                             while (running.load())
                             {
                                 const auto now = charge();
                                 auto seen = peak.load();
                                 while (now > seen && !peak.compare_exchange_weak(seen, now))
                                 {
                                 }
                                 std::this_thread::sleep_for(1ms);
                             }
                         }};

    constexpr int SESSIONS {16};
    constexpr int OPS_PER_SESSION {100};
    for (int session = 0; session < SESSIONS; ++session)
    {
        for (int op = 0; op < OPS_PER_SESSION; ++op)
        {
            stage(adapter, "s" + std::to_string(session) + "-" + std::to_string(op), document('a'));
        }
        adapter.endSession();
    }
    const auto outcomes = adapter.flushSessions(SESSIONS);
    running.store(false);
    sampler.join();

    ASSERT_EQ(static_cast<std::size_t>(SESSIONS), outcomes.size());
    for (std::size_t i = 0; i < outcomes.size(); ++i)
    {
        EXPECT_TRUE(outcomes[i].ok) << "session " << i << ": " << outcomes[i].reason;
    }
    EXPECT_GE(static_cast<std::uint64_t>(SESSIONS) * OPS_PER_SESSION * invsync::indexer::RESULT_RESERVE_BYTES, 3 * MIB);
    EXPECT_EQ(0U, rejected(indexer_client::RejectCause::SubmitTimeout));
    EXPECT_LE(peak.load(), spec.quotaBytes * 8 / 10) << "the bucket was driven past 0.8 of its quota";
}

TEST_F(IndexerClientSyncAdapter, VersionedEstimateMatchesCharge)
{
    startNode();
    startRuntime();
    makeClient(testSpec());

    // What the library charges for one versioned op (payload as encoded + result reserve), read while
    // its group is still open.
    std::uint64_t perOp {0};
    {
        auto& lone = makeAdapter(options(1 * MIB));
        lone.bulkIndex("probe", INDEX, document('v', 2000), "7");
        ASSERT_TRUE(waitFor([this] { return charge() > 0; }));
        perOp = charge();
        lone.discard();
        m_adapters.clear();
        ASSERT_TRUE(waitFor([this] { return charge() == 0; })) << "the abandoned group never returned its reserve";
    }
    ASSERT_GT(perOp, 4000U) << "a versioned op is encoded twice";

    // With a cap of 3.5 ops the adapter must cut after three: an estimate below the real charge would let
    // a fourth in, and a chunk would pass its cap. One chunk is one `_bulk` here (one unresolved at a time).
    auto node = m_nodes.front();
    auto& adapter = makeAdapter(options(perOp * 7 / 2));
    for (int i = 0; i < 12; ++i)
    {
        adapter.bulkIndex("v" + std::to_string(i), INDEX, document('v', 2000), "7");
    }
    adapter.endSession();
    const auto outcomes = adapter.flushSessions(1);

    ASSERT_EQ(1U, outcomes.size());
    EXPECT_TRUE(outcomes[0].ok) << outcomes[0].reason;
    std::size_t total {0};
    for (const auto& request : node.bulk->received())
    {
        EXPECT_LE(request.size(), 3U) << "a chunk estimated below what the library charges for it";
        total += request.size();
    }
    EXPECT_EQ(12U, total);
}

TEST_F(IndexerClientSyncAdapter, OpLargerThanCapGoesAlone)
{
    auto node = startNode();
    auto& adapter = startAll(testSpec(), options(3000));

    stage(adapter, "small-1", document('a', 100));
    stage(adapter, "big", document('b', 6000));
    stage(adapter, "small-2", document('c', 100));
    adapter.endSession();
    const auto outcomes = adapter.flushSessions(1);

    ASSERT_EQ(1U, outcomes.size());
    EXPECT_TRUE(outcomes[0].ok) << outcomes[0].reason;
    const auto requests = node.bulk->received();
    ASSERT_EQ(3U, requests.size()) << "the op above the cap must not share a chunk";
    for (const auto& request : requests)
    {
        EXPECT_EQ(1U, request.size());
    }
}

TEST_F(IndexerClientSyncAdapter, BlockTimeoutIsUnavailable)
{
    // The cap is forced past half the quota, which the production cap formula never does: the committed
    // chunk keeps the room (the fake holds it), the next one cannot grow and the add gives up at the
    // bucket's block timeout.
    startNode(BulkScript::items().held());
    auto spec = testSpec();
    spec.quotaBytes = 16 * 1024;
    spec.bulk.maxBytes = 8 * 1024;
    spec.overflow.blockTimeout = 200ms;
    auto opts = options(12 * 1024);
    opts.budgets.stateful = 3000ms;
    auto& adapter = startAll(spec, opts);

    const auto started = Clock::now();
    for (int i = 0; i < 8; ++i)
    {
        EXPECT_NO_THROW(stage(adapter, "k" + std::to_string(i), document('a', 1000)));
    }
    adapter.endSession();
    const auto outcomes = adapter.flushSessions(1);

    ASSERT_EQ(1U, outcomes.size());
    EXPECT_FALSE(outcomes[0].ok);
    EXPECT_EQ(ConnectorError::Cause::Unavailable, outcomes[0].cause) << outcomes[0].reason;
    EXPECT_LT(millisSince(started), 5000);
}

// ---- Per-key order and the abandoned chunk (CA-E7b-4) -------------------------------------------

TEST_F(IndexerClientSyncAdapter, RepeatedKeyWaitsRetry)
{
    // The same (index, _id) in two sessions of one batch; the indexer answers the first with a 429 item,
    // which the library retries. The second K must not leave before the first one resolved.
    auto node = startNode();
    node.bulk->push(BulkScript::items({{0, BulkItem::rejected()}}));
    auto& adapter = startAll(testSpec(), options(1 * MIB));

    stage(adapter, "K", R"({"v":"A"})");
    adapter.endSession();
    stage(adapter, "K", R"({"v":"B"})");
    adapter.endSession();
    const auto outcomes = adapter.flushSessions(2);

    ASSERT_EQ(2U, outcomes.size());
    EXPECT_TRUE(outcomes[0].ok) << outcomes[0].reason;
    EXPECT_TRUE(outcomes[1].ok) << outcomes[1].reason;
    const std::vector<std::string> expected {R"({"v":"A"})", R"({"v":"A"})", R"({"v":"B"})"};
    EXPECT_EQ(expected, sourcesOf(node, "K")) << "the older write of a key reached the indexer after the newer one";
}

TEST_F(IndexerClientSyncAdapter, GiveUpNeverReordersKey)
{
    // The first batch gives up while the indexer holds its write of K. A later session of K waits for that
    // write to resolve instead of overtaking it.
    auto node = startNode(BulkScript::items().held());
    auto opts = options(1 * MIB);
    opts.budgets.stateful = 1000ms;
    opts.budgets.statefulRetry = 500ms;
    auto& adapter = startAll(testSpec(), opts);

    stage(adapter, "K", R"({"v":"A"})");
    adapter.endSession();
    const auto first = adapter.flushSessions(1);
    ASSERT_EQ(1U, first.size());
    EXPECT_FALSE(first[0].ok);
    EXPECT_EQ(ConnectorError::Cause::Unavailable, first[0].cause);

    Clock::time_point releasedAt;
    std::thread releaser {[&]
                          {
                              std::this_thread::sleep_for(400ms);
                              releasedAt = Clock::now();
                              node.fake->releaseHeld();
                          }};
    stage(adapter, "K", R"({"v":"B"})");
    adapter.endSession();
    const auto second = adapter.flushSessions(1);
    releaser.join();

    ASSERT_EQ(1U, second.size());
    EXPECT_TRUE(second[0].ok) << second[0].reason;
    bool sawNewer {false};
    for (const auto& request : node.fake->requests())
    {
        if (request.path.size() >= 6 && request.path.compare(request.path.size() - 6, 6, "/_bulk") == 0 &&
            request.body.find(R"({"v":"B"})") != std::string::npos)
        {
            sawNewer = true;
            EXPECT_GE(request.receivedAt, releasedAt) << "the newer write of K left before the older one resolved";
        }
    }
    EXPECT_TRUE(sawNewer);
}

TEST_F(IndexerClientSyncAdapter, GiveUpDoesNotBlockOtherKeys)
{
    auto node = startNode(BulkScript::items().held());
    auto opts = options(1 * MIB);
    opts.budgets.stateful = 1000ms;
    opts.budgets.statefulRetry = 500ms;
    auto& adapter = startAll(testSpec(), opts);

    stage(adapter, "K", R"({"v":"A"})");
    adapter.endSession();
    const auto first = adapter.flushSessions(1);
    ASSERT_EQ(1U, first.size());
    ASSERT_FALSE(first[0].ok);

    // A different key stages at once, with the abandoned write of K still held by the indexer.
    const auto started = Clock::now();
    EXPECT_NO_THROW(stage(adapter, "J", R"({"v":"C"})"));
    EXPECT_LT(millisSince(started), 500) << "staging another key waited for the abandoned chunk";
    adapter.endSession();

    node.fake->releaseHeld();
    const auto second = adapter.flushSessions(1);
    ASSERT_EQ(1U, second.size());
    EXPECT_TRUE(second[0].ok) << second[0].reason;
    EXPECT_EQ(1U, sourcesOf(node, "J").size());
}

TEST_F(IndexerClientSyncAdapter, DiscardKeepsPendingKeys)
{
    // The poisoned-batch path: discard() drops the open chunk but a committed one is still in the
    // indexer's hands, and a later write of its key must not overtake it.
    auto node = startNode(BulkScript::items().held());
    auto& adapter = startAll(testSpec(), options(8000));

    stage(adapter, "K", document('A', 1000)); // Committed by the add of J: it would pass the cap.
    stage(adapter, "J", document('J', 6000));
    adapter.endSession();
    ASSERT_TRUE(waitFor([&] { return !node.bulk->received().empty(); })) << "the chunk of K was never committed";
    adapter.discard();

    Clock::time_point releasedAt;
    std::thread releaser {[&]
                          {
                              std::this_thread::sleep_for(400ms);
                              releasedAt = Clock::now();
                              node.fake->releaseHeld();
                          }};
    const auto started = Clock::now();
    stage(adapter, "K", document('B', 1000));
    const auto waited = millisSince(started);
    adapter.endSession();
    const auto outcomes = adapter.flushSessions(1);
    releaser.join();

    EXPECT_GE(waited, 300) << "the second K did not wait for the first one";
    ASSERT_EQ(1U, outcomes.size());
    EXPECT_TRUE(outcomes[0].ok) << outcomes[0].reason;
    for (const auto& request : node.fake->requests())
    {
        if (request.body.find(std::string(1000, 'B')) != std::string::npos)
        {
            EXPECT_GE(request.receivedAt, releasedAt) << "the newer write of K left before the older one resolved";
        }
    }
}

TEST_F(IndexerClientSyncAdapter, AbandonedChunkNeverTouchesTheNextBatch)
{
    // A chunk abandoned by discard() resolves later, after a new batch began: its failure belongs to
    // sessions already answered, never to the new batch's (the generation guard of harvest()).
    auto node = startNode(); // Every bulk answers ok but the first, held and rejecting K for good.
    node.bulk->push(BulkScript::items({{0, BulkItem::failed(400, "mapper_parsing_exception", "bad field")}}).held());
    auto& adapter = startAll(testSpec(), options(8000));

    stage(adapter, "K", document('A', 1000)); // Committed by the add of J: it would pass the cap.
    stage(adapter, "J", document('J', 6000));
    adapter.endSession();
    ASSERT_TRUE(waitFor([&] { return !node.bulk->received().empty(); })) << "the chunk of K was never committed";
    adapter.discard();

    std::thread releaser {[&]
                          {
                              std::this_thread::sleep_for(300ms);
                              node.fake->releaseHeld();
                          }};
    stage(adapter, "Z", document('Z', 1000));
    adapter.endSession();
    const auto outcomes = adapter.flushSessions(1);
    releaser.join();

    ASSERT_EQ(1U, outcomes.size());
    EXPECT_TRUE(outcomes[0].ok) << "the abandoned chunk's rejection leaked into the new batch: " << outcomes[0].reason;
}

TEST_F(IndexerClientSyncAdapter, NoCommitWhileAbandonedUnresolved)
{
    // The indexer holds everything. Each batch gives up at its own deadline; the abandoned chunk stays
    // unresolved and counts: no further chunk is committed behind it, so the bucket never holds more than
    // one pending and one open chunk, and the third batch fails at ITS deadline, not later.
    startNode(BulkScript::items().held());
    auto spec = testSpec();
    spec.quotaBytes = 1 * MIB;
    spec.bulk.maxBytes = 512 * 1024;
    auto opts = options(450 * 1024);
    opts.budgets.stateful = 1000ms;
    opts.budgets.statefulRetry = 500ms;
    auto& adapter = startAll(spec, opts);

    std::atomic<bool> running {true};
    std::atomic<std::uint64_t> peak {0};
    std::thread sampler {[&]
                         {
                             while (running.load())
                             {
                                 const auto now = charge();
                                 auto seen = peak.load();
                                 while (now > seen && !peak.compare_exchange_weak(seen, now))
                                 {
                                 }
                                 std::this_thread::sleep_for(1ms);
                             }
                         }};

    std::int64_t thirdMillis {0};
    std::vector<SessionOutcome> last;
    for (int batch = 0; batch < 3; ++batch)
    {
        const auto started = Clock::now();
        for (int op = 0; op < 17; ++op)
        {
            stage(adapter, "b" + std::to_string(batch) + "-" + std::to_string(op), document('x', 20000));
        }
        adapter.endSession();
        last = adapter.flushSessions(1);
        thirdMillis = millisSince(started);
        ASSERT_EQ(1U, last.size());
        EXPECT_FALSE(last[0].ok) << "batch " << batch;
        EXPECT_EQ(ConnectorError::Cause::Unavailable, last[0].cause) << "batch " << batch;
    }
    running.store(false);
    sampler.join();

    EXPECT_LE(peak.load(), spec.quotaBytes * 8 / 10) << "a chunk was committed behind an unresolved one";
    EXPECT_LE(charge(), spec.quotaBytes * 8 / 10);
    EXPECT_LT(thirdMillis, 1000 + 2000) << "the third batch outlived its own deadline";
}

// ---- By-query calls (CA-E7b-5, 6) --------------------------------------------------------------

TEST_F(IndexerClientSyncAdapter, DeleteByQueryAfterPendingWrites)
{
    // D49: a by-query first waits for every write the adapter already handed to the library, so a delete
    // cannot overtake the documents it is meant to remove. The bulk answers after 400 ms.
    BulkScript slow;
    slow.latency = 400ms;
    auto node = startNode(std::move(slow));
    auto& adapter = startAll(testSpec(), options(1 * MIB));

    for (int i = 0; i < 3; ++i)
    {
        stage(adapter, "d" + std::to_string(i), document('a'));
    }
    adapter.endSession();
    adapter.deleteByQuery(INDEX, "007", "c1");

    std::optional<Clock::time_point> bulkAt;
    std::optional<Clock::time_point> dbqAt;
    for (const auto& request : node.fake->requests())
    {
        const auto ends = [&request](const char* suffix)
        {
            const std::string tail {suffix};
            return request.path.size() >= tail.size() &&
                   request.path.compare(request.path.size() - tail.size(), tail.size(), tail) == 0;
        };
        if (ends("/_bulk") && !bulkAt)
        {
            bulkAt = request.receivedAt;
        }
        if (ends("/_delete_by_query") && !dbqAt)
        {
            dbqAt = request.receivedAt;
        }
    }
    ASSERT_TRUE(bulkAt.has_value()) << "the staged writes never reached the indexer";
    ASSERT_TRUE(dbqAt.has_value());
    EXPECT_GE(std::chrono::duration_cast<std::chrono::milliseconds>(*dbqAt - *bulkAt).count(), 300)
        << "the delete-by-query left before the bulk was answered";
}

TEST_F(IndexerClientSyncAdapter, DbqBodyMatchesV1)
{
    auto node = startNode();
    auto& adapter = startAll(testSpec(), options(1 * MIB));

    adapter.deleteByQuery(INDEX, "007", "c1");
    adapter.deleteByQuery(INDEX, "008", "");

    std::vector<std::pair<std::string, nlohmann::json>> sent;
    for (const auto& request : node.fake->requests())
    {
        if (request.path == std::string {"/"} + INDEX + "/_delete_by_query")
        {
            EXPECT_NE(std::string::npos, request.target.find("conflicts=proceed")) << request.target;
            const auto body = nlohmann::json::parse(request.body);
            sent.emplace_back(request.target, body.contains("query") ? body.at("query") : body);
        }
    }
    ASSERT_EQ(2U, sent.size());

    // With a cluster: the agent clause and the cluster clause, as the v1 builds them.
    const auto scoped = nlohmann::json::parse(
        R"({"bool":{"filter":[{"terms":{"wazuh.agent.id":["007"]}},{"term":{"wazuh.cluster.name":"c1"}}]}})");
    EXPECT_EQ(scoped, sent[0].second);
    // Without one: the agent alone.
    const auto unscoped = nlohmann::json::parse(R"({"bool":{"filter":{"terms":{"wazuh.agent.id":["008"]}}}})");
    EXPECT_EQ(unscoped, sent[1].second);
}

/// Slow (>= 9 s of real conflict budget: 3 attempts, 3 s then 6 s apart); it runs once, with an operator
/// duration of 30 s, which must not turn the exhausted conflicts into a deadline failure.
TEST_F(IndexerClientSyncAdapter, DbqConflictsExhausted)
{
    auto node = startNode(BulkScript::items(), false, DBQ_CONFLICTS);
    auto config = noOpinionConfig();
    config.indexer_sync_max_retry_duration_seconds = 30;
    auto& adapter = startAll(testSpec(config), options(1 * MIB, config));

    const auto started = Clock::now();
    std::optional<ConnectorError::Cause> cause;
    try
    {
        adapter.deleteByQuery(INDEX, "007", "c1");
    }
    catch (const ConnectorError& error)
    {
        cause = error.cause();
    }
    const auto elapsed = millisSince(started);

    ASSERT_TRUE(cause.has_value()) << "a by-query that never stops conflicting must fail";
    EXPECT_EQ(ConnectorError::Cause::ConflictsExhausted, *cause);
    EXPECT_GE(elapsed, 8000) << "the conflict budget is 3 attempts with 3 s and 6 s between them";
    EXPECT_LT(elapsed, 18000) << "exhausted conflicts must arrive before the stateful deadline";
    EXPECT_EQ(3U, node.fake->hits(node.dbqRule));
}

// ---- Deadlines, closing and cancellation (CA-E7b-7) ---------------------------------------------

TEST_F(IndexerClientSyncAdapter, ClosingWakesWaitingFlush)
{
    startNode(BulkScript::items().held());
    auto& adapter = startAll(testSpec(), options(1 * MIB));

    stage(adapter, "K", document('a'));
    adapter.endSession();

    Clock::time_point closedAt;
    std::thread closer {[&]
                        {
                            std::this_thread::sleep_for(300ms);
                            closedAt = Clock::now();
                            m_closing->store(true);
                        }};
    const auto outcomes = adapter.flushSessions(1);
    const auto returnedAt = Clock::now();
    closer.join();

    ASSERT_EQ(1U, outcomes.size());
    EXPECT_FALSE(outcomes[0].ok);
    EXPECT_EQ(ConnectorError::Cause::Unavailable, outcomes[0].cause) << outcomes[0].reason;
    EXPECT_LE(std::chrono::duration_cast<std::chrono::milliseconds>(returnedAt - closedAt).count(), 2000)
        << "a closing module must not wait out the batch deadline";
}

TEST_F(IndexerClientSyncAdapter, BatchDeadlineFromFirstAdd)
{
    startNode(BulkScript::items().held());
    auto opts = options(1 * MIB);
    opts.budgets.stateful = 1000ms;
    opts.budgets.statefulRetry = 500ms;
    auto& adapter = startAll(testSpec(), opts);

    const auto started = Clock::now();
    stage(adapter, "K", document('a'));
    adapter.endSession();
    const auto outcomes = adapter.flushSessions(1);
    const auto elapsed = millisSince(started);

    ASSERT_EQ(1U, outcomes.size());
    EXPECT_FALSE(outcomes[0].ok);
    EXPECT_EQ(ConnectorError::Cause::Unavailable, outcomes[0].cause) << outcomes[0].reason;
    EXPECT_GE(elapsed, 800) << "the batch gave up before its budget";
    EXPECT_LT(elapsed, 1000 + 3000) << "the batch outlived its budget from the first add";
}

TEST_F(IndexerClientSyncAdapter, DeleteAgentUsesLongBudget)
{
    // The indexer takes 3 s to answer the delete-by-query. With a /stateful budget of 1 s a deleteByQuery
    // gives up; the whole-agent deletion, whose caller waits for minutes, waits it out.
    startNode(BulkScript::items(), false, DBQ_OK, 3000ms);
    auto opts = options(1 * MIB);
    opts.budgets.stateful = 1000ms;
    opts.budgets.statefulRetry = 500ms;
    opts.budgets.deletion = 20000ms;
    opts.budgets.deletionRetry = 15000ms;
    auto& adapter = startAll(testSpec(), opts);

    const auto shortStarted = Clock::now();
    std::optional<ConnectorError::Cause> shortCause;
    try
    {
        adapter.deleteByQuery(INDEX, "007", "c1");
    }
    catch (const ConnectorError& error)
    {
        shortCause = error.cause();
    }
    ASSERT_TRUE(shortCause.has_value()) << "the /stateful budget did not bound a by-query";
    EXPECT_EQ(ConnectorError::Cause::Unavailable, *shortCause);
    EXPECT_LT(millisSince(shortStarted), 2900);

    const auto started = Clock::now();
    EXPECT_NO_THROW(adapter.deleteAgentByQuery(INDEX, "007", "c1"));
    EXPECT_GE(millisSince(started), 2900) << "the fake answers after 3 s";
}

TEST_F(IndexerClientSyncAdapter, ExpiryKeepsResolvedSessions)
{
    // Each session is its own chunk. The first resolves, the second is held by the indexer, the third is
    // still open when the batch deadline passes: only the unresolved sessions fail, and the next batch
    // starts a fresh deadline once the indexer lets go of the abandoned chunk.
    auto node = startNode();
    node.bulk->push(BulkScript::items());
    node.bulk->push(BulkScript::items().held());
    auto opts = options(4000);
    opts.budgets.stateful = 1000ms;
    opts.budgets.statefulRetry = 500ms;
    auto& adapter = startAll(testSpec(), opts);

    for (const auto* id : {"s1", "s2", "s3"})
    {
        stage(adapter, id, document('a', 1000));
        adapter.endSession();
    }
    const auto first = adapter.flushSessions(3);

    ASSERT_EQ(3U, first.size());
    EXPECT_TRUE(first[0].ok) << first[0].reason;
    EXPECT_FALSE(first[1].ok);
    EXPECT_EQ(ConnectorError::Cause::Unavailable, first[1].cause) << first[1].reason;
    EXPECT_FALSE(first[2].ok);
    EXPECT_EQ(ConnectorError::Cause::Unavailable, first[2].cause) << first[2].reason;

    node.fake->releaseHeld(); // The indexer lets go once the abandonment (cancel) has reached it.

    const auto started = Clock::now();
    stage(adapter, "s4", document('a', 1000));
    adapter.endSession();
    const auto second = adapter.flushSessions(1);

    ASSERT_EQ(1U, second.size());
    EXPECT_TRUE(second[0].ok) << second[0].reason;
    EXPECT_LT(millisSince(started), 1000) << "the next batch did not get a fresh deadline";
}

TEST_F(IndexerClientSyncAdapter, ExpiryCancelsHeldChunk)
{
    // The indexer holds the first _bulk and, once let go, answers 503 (retryable). The batch expires while it
    // is held: the adapter cancels the chunk, so the library never re-sends its ops after the 503.
    auto node = startNode(BulkScript::request(503, std::string {}).held());
    auto opts = options(1 * MIB);
    opts.budgets.stateful = 500ms;
    opts.budgets.statefulRetry = 500ms;
    auto& adapter = startAll(testSpec(), opts);

    stage(adapter, "K", document('a'));
    adapter.endSession();
    const auto outcomes = adapter.flushSessions(1);
    ASSERT_EQ(1U, outcomes.size());
    EXPECT_FALSE(outcomes[0].ok);
    EXPECT_EQ(ConnectorError::Cause::Unavailable, outcomes[0].cause) << outcomes[0].reason;

    node.fake->releaseHeld(); // Answers the held request with 503.
    EXPECT_TRUE(waitFor(
        [&]
        {
            const auto metrics = m_client->metrics();
            return !metrics.buckets.empty() &&
                   metrics.buckets[0].dropped[static_cast<std::size_t>(indexer_client::DropCause::Cancelled)] >= 1;
        }))
        << "the abandoned chunk was never counted as cancelled";

    std::this_thread::sleep_for(600ms); // Several retry periods (base 20 ms): a retry would have been sent by now.
    EXPECT_EQ(1U, node.bulk->answered()) << "the cancelled chunk was sent again";
    EXPECT_EQ(1U, receivedOps(node).size());
}

TEST_F(IndexerClientSyncAdapter, QueryBarrierAfterBatchExpiry)
{
    // s1 is committed and held by the indexer, s2 stays open behind it. The batch deadline passes, then a
    // by-query arrives (its own, later deadline): the barrier expires the batch, keeps waiting for the abandoned
    // chunk, finds the open chunk gone and sends the query. No hang, no crash; both sessions fail.
    auto node = startNode();
    node.bulk->push(BulkScript::items().held());
    auto opts = options(4000);
    opts.budgets.stateful = 500ms;
    opts.budgets.statefulRetry = 500ms;
    auto& adapter = startAll(testSpec(), opts);

    for (const auto* id : {"s1", "s2"})
    {
        stage(adapter, id, document('a', 1000));
        adapter.endSession();
    }
    std::this_thread::sleep_for(700ms); // The batch deadline (500 ms from the first add) has passed.

    std::thread releaser {[&]
                          {
                              std::this_thread::sleep_for(300ms);
                              node.fake->releaseHeld();
                          }};
    EXPECT_NO_THROW(adapter.deleteByQuery(INDEX, "007", "c1"));
    releaser.join();
    EXPECT_EQ(1U, node.fake->hits(node.dbqRule)) << "the by-query did not go out after the pending chunk resolved";

    const auto outcomes = adapter.flushSessions(2);
    ASSERT_EQ(2U, outcomes.size());
    EXPECT_FALSE(outcomes[0].ok);
    EXPECT_FALSE(outcomes[1].ok);
    EXPECT_EQ(ConnectorError::Cause::Unavailable, outcomes[1].cause) << outcomes[1].reason;
}

// ---- A chunk abandoned on the wire (settleAbandoned) ------------------------------------------------

/// The scan lane's failure path over two real adapters: `vd0` gives its held chunk up (batch deadline), then
/// settles it before the agent is released; only then may `w0` (a pipeline worker, whose barrier cannot see
/// `vd0`) send the agent's delete-by-query. Without the wait the by-query reaches the indexer first, and the
/// late `_bulk` brings the deleted documents back.
TEST_F(IndexerClientSyncAdapter, SettleAbandonedWaitsForChunkOnTheWire)
{
    auto node = startNode(BulkScript::items().held()); // Held, then answered 200 with every item ok.
    startRuntime();
    makeClient(testSpec());
    auto opts = options(1 * MIB);
    opts.budgets.stateful = 500ms;
    opts.budgets.statefulRetry = 500ms;
    opts.runtime = m_ref;
    auto& lane = makeAdapter(opts, "vd0");
    auto& pipeline = makeAdapter(opts, "w0");

    stage(lane, "K", document('a'));
    lane.endSession();
    EXPECT_THROW(lane.flush(), ConnectorError) << "the batch deadline gives the held chunk up";
    ASSERT_EQ(1U, node.bulk->received().size()) << "the chunk never reached the wire";
    lane.discard();

    Clock::time_point releasedAt;
    std::thread releaser {[&]
                          {
                              std::this_thread::sleep_for(700ms);
                              releasedAt = Clock::now();
                              node.fake->releaseHeld();
                          }};
    const auto started = Clock::now();
    const auto settled = lane.settleAbandoned();
    const auto waited = millisSince(started);
    pipeline.deleteByQuery(INDEX, "007", "c1"); // What the pipeline runs once the agent is released.
    releaser.join();

    EXPECT_EQ(invsync::indexer::AbandonedWrite::Settled, settled);
    EXPECT_GE(waited, 600) << "settleAbandoned() returned before the indexer answered the chunk";
    EXPECT_EQ(1U, node.bulk->answered());
    ASSERT_EQ(1U, node.fake->hits(node.dbqRule));
    for (const auto& request : node.fake->requests())
    {
        if (request.path.find("_delete_by_query") != std::string::npos)
        {
            EXPECT_GE(request.receivedAt, releasedAt) << "the by-query overtook the abandoned _bulk";
        }
    }
    EXPECT_EQ(invsync::indexer::AbandonedWrite::Settled, lane.settleAbandoned()) << "nothing is left pending";
}

/// The bound: one request at most (a cancelled op is never sent again), so the request timeout ends the wait.
TEST_F(IndexerClientSyncAdapter, SettleAbandonedEndsWithTheRequest)
{
    auto node = startNode(BulkScript::items().held()); // Never released by the test.
    startRuntime("wazuh_modules.indexer_client_request_timeout_ms=1000\n");
    makeClient(testSpec());
    auto opts = options(1 * MIB);
    opts.budgets.stateful = 300ms;
    opts.budgets.statefulRetry = 300ms;
    opts.runtime = m_ref;
    auto& lane = makeAdapter(opts, "vd0");

    stage(lane, "K", document('a'));
    lane.endSession();
    EXPECT_THROW(lane.flush(), ConnectorError);
    lane.discard();

    const auto started = Clock::now();
    EXPECT_EQ(invsync::indexer::AbandonedWrite::Settled, lane.settleAbandoned());
    const auto waited = millisSince(started);
    EXPECT_GE(waited, 300) << "it did not wait for the request at all";
    EXPECT_LT(waited, 1000 + 5000) << "it outlived the request timeout plus the margin";
    std::this_thread::sleep_for(300ms);
    EXPECT_EQ(1U, node.bulk->received().size()) << "the cancelled chunk was sent again";
}

/// A closing module never waits for the abandoned chunk.
TEST_F(IndexerClientSyncAdapter, ClosingCutsSettleAbandoned)
{
    startNode(BulkScript::items().held());
    startRuntime();
    makeClient(testSpec());
    auto opts = options(1 * MIB);
    opts.budgets.stateful = 300ms;
    opts.budgets.statefulRetry = 300ms;
    opts.runtime = m_ref;
    auto& lane = makeAdapter(opts, "vd0");

    stage(lane, "K", document('a'));
    lane.endSession();
    EXPECT_THROW(lane.flush(), ConnectorError);
    lane.discard();

    Clock::time_point closedAt;
    std::thread closer {[&]
                        {
                            std::this_thread::sleep_for(300ms);
                            closedAt = Clock::now();
                            m_closing->store(true);
                        }};
    const auto settled = lane.settleAbandoned();
    const auto returnedAt = Clock::now();
    closer.join();

    EXPECT_EQ(invsync::indexer::AbandonedWrite::Closing, settled);
    EXPECT_LE(std::chrono::duration_cast<std::chrono::milliseconds>(returnedAt - closedAt).count(), 500)
        << "closing must cut the wait within one slice";
}

/// What the pipeline polls (never waits on): true while the abandoned `_bulk` is unresolved, false once the indexer
/// answers it, and false as soon as the module closes.
TEST_F(IndexerClientSyncAdapter, HoldsAbandonedWriteUntilItResolves)
{
    auto node = startNode(BulkScript::items().held());
    startRuntime();
    makeClient(testSpec());
    auto opts = options(1 * MIB);
    opts.budgets.stateful = 300ms;
    opts.budgets.statefulRetry = 300ms;
    auto& adapter = makeAdapter(opts, "w0");

    EXPECT_FALSE(adapter.holdsAbandonedWrite());
    stage(adapter, "K", document('a'));
    adapter.endSession();
    const auto outcomes = adapter.flushSessions(1);
    ASSERT_EQ(1U, outcomes.size());
    EXPECT_FALSE(outcomes[0].ok);
    EXPECT_TRUE(adapter.holdsAbandonedWrite()) << "the held _bulk is still on the wire";

    m_closing->store(true);
    EXPECT_FALSE(adapter.holdsAbandonedWrite()) << "a closing module keeps nothing held";
    m_closing->store(false);
    EXPECT_TRUE(adapter.holdsAbandonedWrite());

    node.fake->releaseHeld();
    EXPECT_TRUE(waitFor([&] { return !adapter.holdsAbandonedWrite(); })) << "never let go once the indexer answered";
}
