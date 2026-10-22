/*
 * Wazuh indexer client
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

// The metrics snapshot over the runtime (plan-E5c §Tests, CA-15, CA-12, I100-I104, D48): every counter of the catalog
// moves with its own cause, the two scopes, the sanitized and stable names, the latency buckets end to end, the late
// results, the query response bytes in flight and the memory bound with queries and a close.
//
// The closed sets of a bucket run over the TestSink (writeFixture.hpp): the sink stands in for the bulk sender, so a
// case resolves an op with any (Status, Cause) and requeues it with any last error through Bucket::requeue. That is how
// failed.server_5xx and failed.invalid_state move: the production sender never resolves Failed(Server5xx) (a 5xx goes
// to the retry lane until RetryExhausted) nor a cause outside FailCause (the default slot), so only this seam reaches
// them.

#include <malloc.h>

#include <atomic>
#include <cstdio>
#include <functional>
#include <future>
#include <map>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "bulkFixture.hpp"
#include "indexer_client/metrics.hpp"
#include "query/engine.hpp"
#include "query/queryResponse.hpp"
#include "queryFixture.hpp"
#include "write/scheduler.hpp"

#if defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_THREAD__)
#define METRICS_HEAP_MEASURE 0
#elif defined(__has_feature)
#if __has_feature(address_sanitizer) || __has_feature(thread_sanitizer)
#define METRICS_HEAP_MEASURE 0
#else
#define METRICS_HEAP_MEASURE 1
#endif
#else
#define METRICS_HEAP_MEASURE 1
#endif

using namespace write_component;
using bulk_component::BulkItem;
using bulk_component::BulkScript;
using component::eventually;

namespace
{
    using Values = std::map<std::string, double>;

    Values collect(const ic::ClientMetrics& m)
    {
        Values out;
        ic::forEachMetric(m,
                          [&out](std::string_view name, ic::MetricKind, double value)
                          { EXPECT_TRUE(out.emplace(std::string(name), value).second) << name; });
        return out;
    }

    Values collect(const ic::MetricsSnapshot& s)
    {
        Values out;
        ic::forEachMetric(s,
                          [&out](std::string_view name, ic::MetricKind, double value)
                          { EXPECT_TRUE(out.emplace(std::string(name), value).second) << name; });
        return out;
    }

    std::set<std::string> names(const Values& values)
    {
        std::set<std::string> out;
        for (const auto& [name, value] : values)
        {
            out.insert(name);
        }
        return out;
    }

    double get(const Values& v, const std::string& name)
    {
        const auto it = v.find(name);
        EXPECT_NE(it, v.end()) << name;
        return it == v.end() ? -1 : it->second;
    }

    /// A name of one of the four closed sets of a bucket (rejected, dropped, failed, retries).
    bool causeName(const std::string& name)
    {
        for (const auto* set : {".rejected.", ".dropped.", ".failed.", ".retries."})
        {
            if (name.find(set) != std::string::npos)
            {
                return true;
            }
        }
        return false;
    }

    /// The cause names whose value changed from `before` to `after`, with the change.
    std::map<std::string, double> movedCauses(const Values& before, const Values& after)
    {
        std::map<std::string, double> out;
        for (const auto& [name, value] : after)
        {
            const auto it = before.find(name);
            const double was = it == before.end() ? 0 : it->second;
            if (causeName(name) && value != was)
            {
                out[name] = value - was;
            }
        }
        return out;
    }

    std::string show(const std::map<std::string, double>& moved)
    {
        std::string out;
        for (const auto& [name, delta] : moved)
        {
            out += "\n  " + name + " +" + std::to_string(delta);
        }
        return out.empty() ? " (none)" : out;
    }

    ic::OpResult result(ic::Status status, ic::Cause cause)
    {
        ic::OpResult r;
        r.status = status;
        r.cause = cause;
        return r;
    }

    ic::BucketSpec fast(std::string name, std::size_t maxDocs = 1, std::optional<std::uint32_t> attempts = 5)
    {
        auto spec = bucketSpec(std::move(name), 4u << 20, ic::Overflow::Kind::Reject, 0, maxDocs);
        spec.retry.maxAttempts = attempts;
        spec.retry.maxDuration.reset();
        spec.retry.base = ic::Duration {5};
        spec.retry.cap = ic::Duration {20};
        spec.retry.jitter = 0.0;
        return spec;
    }

    // Client::m_state (the ClientState a query engine call needs), through the explicit-instantiation access rule.
    struct ClientStateTag final
    {
        using type = std::shared_ptr<ic::detail::ClientState> ic::Client::*;
    };
    template<class Tag, typename Tag::type Member>
    struct Expose final
    {
        friend typename Tag::type member(Tag) // NOLINT(readability-inconsistent-declaration-parameter-name)
        {
            return Member;
        }
    };
    template struct Expose<ClientStateTag, &ic::Client::m_state>;
    ClientStateTag::type member(ClientStateTag);

    std::shared_ptr<ic::detail::ClientState> stateOf(ic::Client& c)
    {
        return c.*member(ClientStateTag {});
    }
} // namespace

/// The TestSink cases: a runtime without the probe, the sink holding every batch.
class MetricsTest : public WriteTest
{
protected:
    /// Every cause name of `c`'s buckets that moved while `action` ran must be exactly `expected` (+ `by` each).
    void expectOnly(ic::Client& c,
                    const std::function<void()>& action,
                    const std::map<std::string, double>& expected,
                    const std::string& scenario)
    {
        SCOPED_TRACE(scenario);
        const auto before = collect(c.metrics());
        action();
        const auto moved = movedCauses(before, collect(c.metrics()));
        EXPECT_EQ(moved, expected) << "moved:" << show(moved);
    }

    /// Waits for `count` more dispatches of the sink and resolves what it holds with `r`.
    void resolveNext(std::size_t& dispatched, std::size_t count, const ic::OpResult& r = TestSink::ok())
    {
        dispatched += count;
        ASSERT_TRUE(m_sink->waitDispatched(dispatched));
        m_sink->resolveHeld(r);
    }
};

// CA-15 (EveryCatalogCounterMoves †, closed sets): one scenario per member of RejectCause, DropCause, FailCause and
// RetryCause; each moves its own name by one and no other cause name of the client. Mutant: failed[] never incremented.
TEST_F(MetricsTest, EveryCatalogCounterMoves)
{
    ASSERT_NO_FATAL_FAILURE(start());
    installSink(TestSink::Mode::Hold);
    const auto one = indexOp("k0000");
    const std::uint64_t charge = wireSize(one) + wr::RESULT_RESERVE;
    auto block = bucketSpec("blk", charge, ic::Overflow::Kind::Block, 0, 1);
    block.overflow.blockTimeout = ic::Duration {50};
    auto c = client("c",
                    {fast("b"),
                     bucketSpec("r", charge, ic::Overflow::Kind::Reject, 0, 1),
                     bucketSpec("dn", charge, ic::Overflow::Kind::DropNewest, 0, 1),
                     block,
                     bucketSpec("g", 2 * charge, ic::Overflow::Kind::Reject, 0, 1)});
    const std::string b = "indexer_client.bucket.c.";
    std::size_t dispatched = 0;
    std::uint64_t k = 0;
    const auto op = [&k]
    {
        return indexOp("k" + std::to_string(1000 + k++));
    };

    // RejectCause.
    expectOnly(
        *c,
        [&]
        {
            ASSERT_TRUE(c->writer("r")->submit(op()).accepted);
            EXPECT_EQ(c->writer("r")->submit(op()).cause, ic::Cause::QueueFull);
        },
        {{b + "r.rejected.queue_full", 1}},
        "rejected.queue_full");
    {
        // The gauges while the op is delivered and held: payload retained, everything charged, and the runtime's sums.
        const auto held = collect(c->metrics());
        EXPECT_EQ(get(held, b + "r.retained_bytes"), static_cast<double>(wireSize(one)));
        EXPECT_EQ(get(held, b + "r.charge_bytes"), static_cast<double>(charge));
        EXPECT_EQ(get(held, b + "r.quota_bytes"), static_cast<double>(charge));
        const auto runtime = collect(m_ref.snapshot());
        EXPECT_EQ(get(runtime, "indexer_client.runtime.retained_bytes"), static_cast<double>(wireSize(one)));
        EXPECT_EQ(get(runtime, "indexer_client.runtime.global_charge_bytes"), static_cast<double>(charge));
        EXPECT_EQ(get(runtime, "indexer_client.runtime.clients"), 1);
    }
    resolveNext(dispatched, 1);
    ASSERT_TRUE(eventually(
        [&]
        {
            const auto v = collect(m_ref.snapshot());
            return get(v, "indexer_client.runtime.retained_bytes") == 0 &&
                   get(v, "indexer_client.runtime.global_charge_bytes") == 0;
        },
        5s));
    EXPECT_EQ(get(collect(c->metrics()), b + "r.charge_bytes"), 0);
    expectOnly(
        *c,
        [&]
        {
            ASSERT_TRUE(c->writer("blk")->submit(op()).accepted);
            EXPECT_EQ(c->writer("blk")->submit(op()).cause, ic::Cause::SubmitTimeout);
        },
        {{b + "blk.rejected.submit_timeout", 1}},
        "rejected.submit_timeout");
    expectOnly(
        *c,
        [&]
        {
            std::promise<ic::Cause> refused;
            auto writer = c->writer("blk");
            ASSERT_TRUE(ic::detail::testing::postToPool(
                [&refused, writer] { refused.set_value(writer->submit(indexOp("kpool")).cause); }));
            EXPECT_EQ(refused.get_future().get(), ic::Cause::Reentrancy);
        },
        {{b + "blk.rejected.reentrancy", 1}},
        "rejected.reentrancy");
    resolveNext(dispatched, 1);
    expectOnly(
        *c,
        [&] { EXPECT_EQ(c->writer("b")->submit(indexOp("big", 5u << 20)).cause, ic::Cause::PayloadTooLarge); },
        {{b + "b.rejected.payload_too_large", 1}},
        "rejected.payload_too_large");
    expectOnly(
        *c,
        [&]
        {
            auto bad = op();
            bad.index.clear();
            EXPECT_EQ(c->writer("b")->submit(std::move(bad)).cause, ic::Cause::InvalidArgument);
        },
        {{b + "b.rejected.invalid_argument", 1}},
        "rejected.invalid_argument");
    expectOnly(
        *c,
        [&]
        {
            auto group = c->writer("g")->group();
            ASSERT_EQ(group.add(op()), ic::Cause::None);
            ASSERT_EQ(group.add(op()), ic::Cause::None);
            EXPECT_EQ(group.add(op()), ic::Cause::GroupTooLarge);
            group.commit();
        },
        {{b + "g.rejected.group_too_large", 1}},
        "rejected.group_too_large");
    resolveNext(dispatched, 2);

    // DropCause: DropNewest without a callback; queue-held ops at a close; a cancel by tag.
    expectOnly(
        *c,
        [&]
        {
            ASSERT_TRUE(c->writer("dn")->submit(op()).accepted);
            EXPECT_TRUE(c->writer("dn")->submit(op()).accepted); // Dropped(QueueFull), no callback.
        },
        {{b + "dn.dropped.queue_full", 1}},
        "dropped.queue_full");
    resolveNext(dispatched, 1);
    m_sink->setCapacity(0); // From here on the ops stay queued in their bucket.
    expectOnly(
        *c,
        [&]
        {
            auto tagged = op();
            tagged.tag = "t";
            ASSERT_TRUE(c->writer("b")->submit(std::move(tagged)).accepted);
            ASSERT_TRUE(c->writer("b")->cancel("t").wait(now() + 5s).ok());
        },
        {{b + "b.dropped.cancelled", 1}},
        "dropped.cancelled");
    m_sink->grant(TestSink::UNLIMITED);

    // FailCause: every member, resolved by the sink.
    for (const auto& [cause, name] :
         std::vector<std::pair<ic::Cause, std::string>> {{ic::Cause::ItemPermanent, "item_permanent"},
                                                         {ic::Cause::RetryExhausted, "retry_exhausted"},
                                                         {ic::Cause::Client4xx, "client_4xx"},
                                                         {ic::Cause::Server5xx, "server_5xx"},
                                                         {ic::Cause::Unavailable, "unavailable"},
                                                         {ic::Cause::InvalidState, "invalid_state"}})
    {
        expectOnly(
            *c,
            [&, cause = cause]
            {
                ASSERT_TRUE(c->writer("b")->submit(op()).accepted);
                resolveNext(dispatched, 1, result(ic::Status::Failed, cause));
            },
            {{b + "b.failed." + name, 1}},
            "failed." + name);
    }

    // RetryCause: the held op requeued with that last error (one counted attempt), then resolved Ok.
    for (const auto& [cause, name] :
         std::vector<std::pair<ic::Cause, std::string>> {{ic::Cause::ItemRetryable, "item_retryable"},
                                                         {ic::Cause::VersionConflict, "version_conflict"},
                                                         {ic::Cause::Server5xx, "server_5xx"},
                                                         {ic::Cause::TransportConnect, "transport"},
                                                         {ic::Cause::Throttled, "other"}})
    {
        expectOnly(
            *c,
            [&, cause = cause]
            {
                ASSERT_TRUE(c->writer("b")->submit(op()).accepted);
                dispatched += 1;
                ASSERT_TRUE(m_sink->waitDispatched(dispatched));
                auto held = m_sink->take();
                ASSERT_EQ(held.size(), 1u);
                std::vector<wr::RequeueOp> ops;
                for (const auto& state : held[0].ops)
                {
                    ops.push_back(wr::RequeueOp {state, wr::LastError {cause, 0, "x", "y"}});
                }
                wr::RequeueSpec spec;
                spec.delay = wr::RequeueSpec::Delay::Now;
                const auto requeued = held[0].bucket->requeue(std::move(ops), spec, now());
                EXPECT_TRUE(requeued.exhausted.empty());
                if (requeued.notify)
                {
                    m_path->scheduler()->notify(held[0].bucket);
                }
                resolveNext(dispatched, 1);
            },
            {{b + "b.retries." + name, 1}},
            "retries." + name);
    }

    // DropCause at a close: queued ⇒ client_closed; held by the sink ⇒ shutdown (two clients, one cause each).
    {
        auto queued = client("q", {fast("b")});
        m_sink->setCapacity(0);
        expectOnly(
            *queued,
            [&]
            {
                ASSERT_TRUE(queued->writer("b")->submit(op()).accepted);
                closeNow(*queued, 1s);
            },
            {{"indexer_client.bucket.q.b.dropped.client_closed", 1}},
            "dropped.client_closed");
        m_sink->grant(TestSink::UNLIMITED);
        auto held = client("h", {fast("b")});
        auto heldWriter = held->writer("b"); // A closed client hands out no writer: keep this one.
        expectOnly(
            *held,
            [&]
            {
                ASSERT_TRUE(held->writer("b")->submit(op()).accepted);
                dispatched += 1;
                ASSERT_TRUE(m_sink->waitDispatched(dispatched));
                closeNow(*held, 1s);
            },
            {{"indexer_client.bucket.h.b.dropped.shutdown", 1}},
            "dropped.shutdown");
        // A refusal by the closed admission.
        expectOnly(
            *held,
            [&] { EXPECT_EQ(heldWriter->submit(op()).cause, ic::Cause::ClientClosed); },
            {{"indexer_client.bucket.h.b.rejected.client_closed", 1}},
            "rejected.client_closed");
        m_sink->take(); // Resolved by the close; nothing left to resolve.
    }

    // RejectCause::Shutdown: a refusal once the runtime is gone.
    auto writer = c->writer("b");
    ASSERT_EQ(ic::RuntimeOwner::shutdown(), ic::Cause::None);
    expectOnly(
        *c,
        [&] { EXPECT_EQ(writer->submit(op()).cause, ic::Cause::Shutdown); },
        {{b + "b.rejected.shutdown", 1}},
        "rejected.shutdown");

    // Every member of the four sets moved in some bucket of c, q or h: none is dead in the catalog.
    std::set<std::string> members;
    for (const auto& [name, value] : collect(c->metrics()))
    {
        if (causeName(name))
        {
            members.insert(name.substr(name.find('.', b.size()) + 1));
        }
    }
    EXPECT_EQ(members.size(), 8u + 4u + 6u + 5u);
    m_path.reset(); // Shut down above: nothing is left to drain.
}

// CA-15 (EveryCatalogCounterMoves †, runtime side): over the fake, each step moves the node, query, PIT and bucket
// counters it names (a node counter moves with others: requests with every answer, so only "moved" is checked here).
class MetricsBulkTest : public BulkTest
{
};

TEST_F(MetricsBulkTest, EveryCatalogCounterMoves)
{
    auto a = startNode(BulkScript::items(),
                       "green",
                       {},
                       [](const httplib::Request&, indexer_client::testing::Rule& reply)
                       {
                           if (reply.status == 299) // A scripted transport failure: the body is cut.
                           {
                               reply.status = 200;
                               reply.cutAfter = 1;
                           }
                       });
    a.fake->addRule(indexer_client::testing::Rule {
        "POST", ".*/_search", 200, R"({"hits":{"hits":[]},"pad":")" + std::string(4000, 'x') + "\"}"});
    ASSERT_NO_FATAL_FAILURE(startOn(
        {a.url()}, std::chrono::milliseconds(3600000), {{"pace_initial_ms", "10"}, {"callback_budget_ms", "5"}}));
    auto results = Results::create();
    auto c = client("c", {fast("b"), fast("one", 1, 1)});
    std::uint64_t key = 0;
    const auto all = [&]
    {
        auto values = collect(c->metrics());
        for (auto& entry : collect(m_ref.snapshot()))
        {
            values.insert(entry);
        }
        return values;
    };
    const auto step = [&](const std::string& what, const std::function<void()>& action, std::vector<std::string> moved)
    {
        SCOPED_TRACE(what);
        const auto before = all();
        action();
        const auto after = all();
        for (const auto& name : moved)
        {
            EXPECT_GT(get(after, name), get(before, name)) << name;
        }
    };
    const auto submitOne = [&](const std::string& bucket, ic::Op op)
    {
        const auto before = results->total();
        ASSERT_TRUE(c->writer(bucket)->submit(std::move(op), results->callback(key++)).accepted);
        ASSERT_TRUE(results->waitTotal(before + 1, 10s));
    };
    const std::string b = "indexer_client.bucket.c.b.";
    const std::string n = "indexer_client.node.0.";

    step("ok",
         [&] { submitOne("b", indexOp("ok")); },
         {b + "accepted",
          b + "ok",
          b + "bulk_requests",
          b + "bulk_bytes",
          b + "latency.count",
          n + "requests",
          n + "latency.count"});
    step("5xx then ok",
         [&]
         {
             a.bulk->push(BulkScript::serverError());
             submitOne("b", indexOp("s"));
         },
         {b + "retries.server_5xx", n + "server_5xx"});
    step("429 then ok",
         [&]
         {
             a.bulk->push(BulkScript::throttled());
             submitOne("b", indexOp("t"));
         },
         {n + "throttled", n + "decreases.429"});
    step("cut body then ok",
         [&]
         {
             a.bulk->push(BulkScript::request(299, R"({"cut":")" + std::string(1000, 'x') + "\"}"));
             const auto before = results->total();
             ASSERT_TRUE(c->writer("b")->submit(indexOp("x"), results->callback(key++)).accepted);
             // The failure takes the node Down until the next probe (every hour here): probe now.
             ASSERT_TRUE(eventually([&] { return nodeState(0) == ic::HealthView::NodeState::Down; }, 5s));
             ASSERT_TRUE(probeNowAndWait());
             ASSERT_TRUE(results->waitTotal(before + 1, 10s));
         },
         {b + "retries.transport", n + "failures"});
    step("retry exhausted",
         [&]
         {
             a.bulk->push(BulkScript::items({{0, BulkItem::rejected()}}));
             submitOne("one", indexOp("e"));
         },
         {"indexer_client.bucket.c.one.failed.retry_exhausted"});
    step("callback overrun",
         [&]
         {
             std::promise<void> ran;
             ASSERT_TRUE(c->writer("b")
                             ->submit(indexOp("slow"),
                                      [&ran](const ic::OpResult&)
                                      {
                                          std::this_thread::sleep_for(std::chrono::milliseconds(20));
                                          ran.set_value();
                                      })
                             .accepted);
             ran.get_future().wait();
             ASSERT_TRUE(eventually([&] { return c->metrics().callbackOverruns >= 1; }, 2s));
         },
         {"indexer_client.client.c.callback_overruns", "indexer_client.client.c.callback_max_duration_ms"});
    step("query",
         [&]
         {
             const auto found = c->query()->search("idx", nlohmann::json::object(), {}, now() + 5s);
             EXPECT_TRUE(found.ok()) << found.reason;
         },
         {"indexer_client.query.requests"});
    step("pit created and deleted",
         [&]
         {
             a.fake->addRule(indexer_client::testing::Rule {
                 "POST", "/idx/_search/point_in_time", 200, R"({"pit_id":"pit-metrics"})"});
             a.fake->addRule(indexer_client::testing::Rule {"DELETE", "/_search/point_in_time", 200, "{}"});
             const auto before = ic::detail::query::pitStats().deletesConfirmed;
             {
                 auto pit = c->query()->pit({"idx"}, {}, {}, now() + 5s);
                 ASSERT_TRUE(pit.ok()) << pit.reason;
             }
             ASSERT_TRUE(eventually([&] { return ic::detail::query::pitStats().deletesConfirmed > before; }, 5s));
         },
         {"indexer_client.pit.created", "indexer_client.pit.deletes_confirmed"});
    step("usage error",
         [&]
         {
             // A Client destroyed on a runtime thread: logged, counted, closed without waiting (I37).
             auto other = client("u", {});
             std::promise<void> done;
             auto holder = std::make_shared<std::shared_ptr<ic::Client>>(std::move(other));
             ASSERT_TRUE(ic::detail::testing::postToPool(
                 [holder, &done]
                 {
                     holder->reset();
                     done.set_value();
                 }));
             done.get_future().wait();
         },
         {"indexer_client.runtime.usage_errors"});
}

// CA-15, I101: Client::metrics() brings only that consumer's buckets; RuntimeRef::snapshot() the nodes, the queries
// and the PITs and no bucket; traffic on one consumer leaves the other's counters at 0.
TEST_F(MetricsBulkTest, ClientMetricsOnlyOwnBuckets)
{
    const auto a = startNode();
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto first = client("a", {fast("x"), fast("y")});
    auto second = client("b", {fast("z")});
    auto results = Results::create();
    ASSERT_TRUE(first->writer("x")->submit(indexOp("1"), results->callback(1)).accepted);
    ASSERT_TRUE(results->waitTotal(1));

    const auto mFirst = first->metrics();
    EXPECT_EQ(mFirst.consumer, "a");
    ASSERT_EQ(mFirst.buckets.size(), 2u);
    EXPECT_EQ(mFirst.buckets[0].bucket, "x");
    EXPECT_EQ(mFirst.buckets[1].bucket, "y");
    EXPECT_EQ(mFirst.buckets[0].ok, 1u);
    const auto mSecond = second->metrics();
    EXPECT_EQ(mSecond.consumer, "b");
    ASSERT_EQ(mSecond.buckets.size(), 1u);
    EXPECT_EQ(mSecond.buckets[0].bucket, "z");
    for (const auto& [name, value] : collect(mFirst))
    {
        EXPECT_TRUE(name.rfind("indexer_client.bucket.a.", 0) == 0 || name.rfind("indexer_client.client.a.", 0) == 0)
            << name;
    }
    for (const auto& [name, value] : collect(mSecond))
    {
        EXPECT_TRUE(name.rfind("indexer_client.bucket.b.", 0) == 0 || name.rfind("indexer_client.client.b.", 0) == 0)
            << name;
        if (name.find(".quota_bytes") == std::string::npos)
        {
            EXPECT_EQ(value, 0) << "traffic of 'a' moved 'b': " << name;
        }
    }

    const auto snapshot = m_ref.snapshot();
    EXPECT_EQ(snapshot.clients, 2u);
    ASSERT_EQ(snapshot.nodes.size(), 1u);
    EXPECT_EQ(snapshot.nodes[0].host, a.url());
    EXPECT_GE(snapshot.nodes[0].requests, 1u);
    std::set<std::string> prefixes;
    for (const auto& [name, value] : collect(snapshot))
    {
        EXPECT_EQ(name.find("indexer_client.bucket."), std::string::npos) << name;
        EXPECT_EQ(name.find("indexer_client.client."), std::string::npos) << name;
        prefixes.insert(name.substr(0, name.find('.', std::string("indexer_client.").size())));
    }
    EXPECT_EQ(prefixes,
              (std::set<std::string> {
                  "indexer_client.node", "indexer_client.pit", "indexer_client.query", "indexer_client.runtime"}));
}

// I100 (component part): sanitized names, the clashes refused naming the field, and the set of names of a fresh
// snapshot equal to the one after traffic.
TEST_F(MetricsBulkTest, CatalogNamesAreSaneAndStable)
{
    const auto a = startNode();
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("VD-Scanner", {fast("states.v2"), fast("---")});
    const auto fresh = collect(c->metrics());
    EXPECT_EQ(fresh.size(), 2u * 50u + 3u);
    EXPECT_EQ(get(fresh, "indexer_client.bucket.vd_scanner.states_v2.rejected.queue_full"), 0);
    EXPECT_EQ(get(fresh, "indexer_client.bucket.vd_scanner._.latency.le_32768"), 0);
    EXPECT_EQ(get(fresh, "indexer_client.client.vd_scanner.callback_overruns"), 0);
    const auto snap = collect(m_ref.snapshot());
    EXPECT_EQ(snap.size(), 7u + 8u + 10u + 31u);

    // vd-scanner, then vd_scanner: the second clashes with the first; so does VD_SCANNER.
    auto lower = m_ref.client("vd-scanner", {fast("x")});
    EXPECT_EQ(lower.cause, ic::Cause::InvalidArgument);
    for (const auto* consumer : {"vd_scanner", "VD_SCANNER"})
    {
        auto clash = m_ref.client(consumer, {fast("x")});
        EXPECT_EQ(clash.cause, ic::Cause::InvalidArgument) << consumer;
        EXPECT_NE(clash.reason.find("consumer"), std::string::npos) << clash.reason;
        EXPECT_NE(clash.reason.find("same metric name"), std::string::npos) << clash.reason;
    }
    auto buckets = m_ref.client("other", {fast("a.b"), fast("a-b")});
    EXPECT_EQ(buckets.cause, ic::Cause::InvalidArgument);
    EXPECT_NE(buckets.reason.find("buckets[1].name"), std::string::npos) << buckets.reason;
    EXPECT_EQ(m_ref.snapshot().clients, 1u);

    // A name freed by its client's destruction can be taken again.
    {
        auto x = client("tmp-x", {fast("b")});
        ASSERT_NE(x, nullptr);
    }
    auto again = m_ref.client("tmp_x", {fast("b")});
    EXPECT_TRUE(again.ok()) << again.reason;
    again.value.reset();

    auto results = Results::create();
    ASSERT_TRUE(c->writer("states.v2")->submit(indexOp("k1"), results->callback(1)).accepted);
    ASSERT_TRUE(results->waitTotal(1));
    const auto after = collect(c->metrics());
    EXPECT_EQ(names(after), names(fresh));
    EXPECT_EQ(names(collect(m_ref.snapshot())), names(snap));
    EXPECT_EQ(get(after, "indexer_client.bucket.vd_scanner.states_v2.ok"), 1);

    ic::Client empty;
    EXPECT_TRUE(empty.metrics().consumer.empty());
    EXPECT_TRUE(collect(empty.metrics()).empty());
    ic::Client moved(std::move(*c));
    EXPECT_TRUE(collect(c->metrics()).empty()) << "a moved-from client has no names (N27)";
    EXPECT_EQ(names(collect(moved.metrics())), names(fresh));
}

// I103 (component part of LatencyHistogramBuckets †): bulk answers at 0, 40 and 300 ms; the bucket publishes them
// cumulative (coarse values: le_64 >= 2, le_512 = 3, le_inf = 3), with their sum and number.
TEST_F(MetricsBulkTest, LatencyHistogramBuckets)
{
    const auto a = startNode();
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {fast("b")});
    auto results = Results::create();
    std::uint64_t key = 0;
    for (const auto latency : {0, 40, 300})
    {
        auto script = BulkScript::items();
        script.latency = std::chrono::milliseconds(latency);
        a.bulk->push(std::move(script));
        ASSERT_TRUE(c->writer("b")->submit(indexOp("l" + std::to_string(latency)), results->callback(key++)).accepted);
        ASSERT_TRUE(results->waitTotal(key, 10s));
    }
    const auto v = collect(c->metrics());
    const std::string p = "indexer_client.bucket.c.b.latency.";
    EXPECT_GE(get(v, p + "le_64"), 2);
    EXPECT_EQ(get(v, p + "le_512"), 3);
    EXPECT_EQ(get(v, p + "le_inf"), 3);
    EXPECT_EQ(get(v, p + "count"), 3);
    EXPECT_GE(get(v, p + "sum_micros"), 340000);
    EXPECT_LE(get(v, p + "le_32"), get(v, p + "le_64"));
    EXPECT_LT(get(v, p + "le_256"), 3) << "the 300 ms answer is above le_256";
    // The node publishes the same samples (and the probe's, not counted in a bucket).
    EXPECT_GE(get(collect(m_ref.snapshot()), "indexer_client.node.0.latency.le_inf"), 3);
}

// obj. 2 (LateResultCounted †): a completion with a 200 parked in seams::beforeCompletion(), the client closed and
// swept meanwhile; once released, its op counts as a late result, not as Ok. Mutant: lateResults never counted.
TEST_F(MetricsBulkTest, LateResultCounted)
{
    const auto a = startNode();
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()})); // cpu_threads = 2: the completion parks one, the close runs.
    auto parked = std::make_shared<std::promise<void>>();
    auto release = std::make_shared<std::promise<void>>();
    auto releaseFuture = release->get_future().share();
    auto once = std::make_shared<std::atomic<bool>>(true);
    ic::testing_hooks::setBeforeCompletion(
        [parked, releaseFuture, once]()
        {
            if (once->exchange(false))
            {
                parked->set_value();
                releaseFuture.wait();
            }
        });
    auto results = Results::create();
    auto c = client("c", {fast("b")});
    ASSERT_TRUE(c->writer("b")->submit(indexOp("late"), results->callback(0)).accepted);
    ASSERT_EQ(parked->get_future().wait_for(5s), std::future_status::ready);
    c->requestClose();
    const auto report = c->awaitClosed(now() + 1s);
    ASSERT_TRUE(report.ok());
    EXPECT_EQ(report.value.droppedShutdown, 1u);
    release->set_value();
    ASSERT_TRUE(
        eventually([&] { return get(collect(c->metrics()), "indexer_client.bucket.c.b.late_results") == 1; }, 3s))
        << "late_results " << get(collect(c->metrics()), "indexer_client.bucket.c.b.late_results");
    const auto m = collect(c->metrics());
    EXPECT_EQ(get(m, "indexer_client.bucket.c.b.dropped.shutdown"), 1);
    EXPECT_EQ(get(m, "indexer_client.bucket.c.b.ok"), 0);
    EXPECT_EQ(results->countWith(ic::Status::Dropped, ic::Cause::Shutdown), 1u);
}

// D48 (QueryResponseBytesInFlight): a 1 MiB answer, observed through the engine's observer hook (engine.hpp
// EngineHooks) between its delivery and the return to the consumer: the gauge holds it, is 0 afterwards, and the
// peak keeps it.
class MetricsQueryTest : public QueryTest
{
};

TEST_F(MetricsQueryTest, QueryResponseBytesInFlight)
{
    constexpr std::size_t MIB = 1u << 20;
    const auto body = query_component::searchResponse(nlohmann::json::array()).substr(1);
    const std::string response = R"({"pad":")" + std::string(MIB, 'x') + "\"," + body;
    const auto node = fake({query_component::rule("POST", "/idx/_search", 200, response)});
    ASSERT_NO_FATAL_FAILURE(start({node->baseUrl()}));
    auto c = client();
    const auto state = stateOf(*c);
    ASSERT_NE(state, nullptr);

    std::uint64_t inside = 0;
    std::uint64_t insideSnapshot = 0;
    namespace q = ic::detail::query;
    q::EngineHooks hooks;
    hooks.observer = [&](const q::AttemptEvent& event)
    {
        if (event.kind == q::AttemptEvent::Kind::Answered)
        {
            inside = q::queryStats().responseBytesInFlight;
            insideSnapshot = m_ref.snapshot().queries.responseBytesInFlight;
        }
    };
    q::RouteSpec route;
    route.method = ic::detail::HttpMethod::Post;
    route.target = "/idx/_search";
    route.body = std::make_shared<const std::string>("{}");
    const auto out = q::execute(
        state,
        query_component::fastOptions(),
        query_component::in(5s),
        route,
        [](const ic::detail::HttpResult& r) { return q::classifySearch(r, 64u << 20); },
        hooks);
    ASSERT_TRUE(out.ok()) << ic::toString(out.cause) << ": " << out.reason;
    EXPECT_GE(inside, MIB);
    EXPECT_EQ(insideSnapshot, inside);
    const auto after = m_ref.snapshot().queries;
    EXPECT_EQ(after.responseBytesInFlight, 0u);
    EXPECT_GE(after.peakResponseBytesInFlight, MIB);

    // The public path returns it too: 0 in flight once search() returned.
    const auto found = c->query()->search("idx", nlohmann::json::object(), {}, query_component::in(5s));
    ASSERT_TRUE(found.ok()) << found.reason;
    EXPECT_EQ(m_ref.snapshot().queries.responseBytesInFlight, 0u);
}

// CA-12 (MemoryBoundWithQueriesAndClose): the indexer down, every quota full, queries waiting for a node and a client
// closed halfway; the live heap (mallinfo2: in-use bytes of every arena plus mmapped blocks) measured against the
// baseline before the load never exceeds Σ quotas (the charges' ceiling) + nodes × window × (bulk.maxBytes +
// max_response_bytes) + MARGIN. MARGIN (2 MiB) is the fixed overhead of the scenario: thread-local parser buffers, curl
// handles, query and close state and the sampler's vector. The in-flight term is RF-12's formula and only an upper
// bound here (no bulk leaves for a down node). The test prints the measured peak and the bound. Skipped under the
// sanitizers.
TEST_F(MetricsBulkTest, MemoryBoundWithQueriesAndClose)
{
#if !METRICS_HEAP_MEASURE
    GTEST_SKIP() << "the sanitizers own the allocator";
#else
    constexpr std::uint64_t KIB = 1024;
    constexpr std::uint64_t MIB = 1024 * KIB;
    constexpr std::uint64_t RESPONSE = MIB;
    constexpr std::uint64_t BULK = 256 * KIB;
    constexpr std::uint64_t WINDOW = 2;
    constexpr std::uint64_t NODES = 1;
    constexpr std::uint64_t QUOTA = 4 * MIB;
    constexpr std::uint64_t MARGIN = 2 * MIB;
    const auto heap = []
    {
        const auto info = mallinfo2();
        return static_cast<std::int64_t>(info.uordblks + info.hblkhd);
    };

    const std::string down = "http://127.0.0.1:" + std::to_string(component::closedPort());
    ASSERT_NO_FATAL_FAILURE(startOn({down},
                                    std::chrono::milliseconds(3600000),
                                    {{"max_response_bytes", std::to_string(RESPONSE)},
                                     {"node_window_max", std::to_string(WINDOW)},
                                     {"global_quota_bytes", std::to_string(3 * QUOTA)}}));
    const auto spec = [&](const std::string& name)
    {
        auto s = bucketSpec(name, QUOTA, ic::Overflow::Kind::Reject, BULK, 1000000, ic::Duration {50});
        return s;
    };
    auto c = client("c", {spec("a"), spec("b")});
    auto d = client("d", {spec("a")});
    auto query = c->query();
    for (auto* writer : {c->writer("a").get(), c->writer("b").get(), d->writer("a").get()})
    {
        ASSERT_NE(writer, nullptr);
    }
    const auto baseline = heap();

    std::atomic<bool> sampling {true};
    std::atomic<std::int64_t> peak {baseline};
    std::thread sampler(
        [&]
        {
            while (sampling.load())
            {
                const auto now = heap();
                auto seen = peak.load();
                while (now > seen && !peak.compare_exchange_weak(seen, now))
                {
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        });

    // Queries in flight: no usable node, so they wait until their deadline.
    std::vector<std::thread> queries;
    for (int i = 0; i < 2; ++i)
    {
        queries.emplace_back(
            [query]
            {
                const auto found = query->search("idx", nlohmann::json::object(), {}, now() + 1500ms);
                EXPECT_FALSE(found.ok());
            });
    }
    // Every quota full (8 KiB documents until QueueFull).
    std::uint64_t accepted = 0;
    for (const auto& [owner, bucket] :
         std::vector<std::pair<ic::Client*, std::string>> {{c.get(), "a"}, {c.get(), "b"}, {d.get(), "a"}})
    {
        auto writer = owner->writer(bucket);
        for (int i = 0;; ++i)
        {
            const auto submitted = writer->submit(indexOp(bucket + std::to_string(i), 8 * KIB));
            if (!submitted.accepted)
            {
                EXPECT_EQ(submitted.cause, ic::Cause::QueueFull);
                break;
            }
            ++accepted;
        }
    }
    const auto fullCharge = m_ref.snapshot().globalCharge;
    // A close halfway: d's ops are dropped at its drain end while the queries still wait.
    std::thread closer([&d] { EXPECT_TRUE(d->awaitClosed(now() + 600ms).ok()); });
    closer.join();
    for (auto& t : queries)
    {
        t.join();
    }
    sampling = false;
    sampler.join();

    const std::uint64_t measured = static_cast<std::uint64_t>(std::max<std::int64_t>(0, peak.load() - baseline));
    const std::uint64_t charges = 3 * QUOTA;
    const std::uint64_t inFlight = NODES * WINDOW * (BULK + RESPONSE);
    const std::uint64_t bound = charges + inFlight + MARGIN;
    std::printf("CA-12: accepted %llu ops, global charge at full %llu, measured peak %llu, bound %llu "
                "(charges %llu + in flight %llu + margin %llu)\n",
                static_cast<unsigned long long>(accepted),
                static_cast<unsigned long long>(fullCharge),
                static_cast<unsigned long long>(measured),
                static_cast<unsigned long long>(bound),
                static_cast<unsigned long long>(charges),
                static_cast<unsigned long long>(inFlight),
                static_cast<unsigned long long>(MARGIN));
    EXPECT_GE(fullCharge, 3 * QUOTA - 3 * (8 * KIB + wr::RESULT_RESERVE + 64)) << "the quotas were not full";
    EXPECT_LE(measured, bound);
    EXPECT_GE(measured, fullCharge / 2) << "the heap read does not see the retained payload: the method is broken";

    closeNow(*c, 600ms);
#endif
}
