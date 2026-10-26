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

// CA-E6e-1 (plan 18, stage E6e, A): WritePath::resolveBulk, the bulk resolution of the ops of post, against the
// per-op WritePath::resolve: the same counters, charge and CloseReport, the payload and RESULT_RESERVE released once,
// `drained` read per chunk before its release (I99), a throw in the middle that still settles every claimed op, and
// the ops it won as the only ones a bulk counts. G-diff E6e P3-2/P3-3: the cancel(tag) waiter completed by the bulk
// settlement, a settlement that throws twice (Bucket::settleBulk's catch, then the per-op fallback), a bucket with no
// client, and the ambiguous count driven by the real sender (failBatch → countAmbiguous and its WARN).

#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <mutex>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "bulkFixture.hpp"
#include "transport/seams.hpp"

using namespace write_component;
using component::eventually;

namespace
{
    constexpr auto R = wr::RESULT_RESERVE;

    std::string id(std::uint64_t key)
    {
        return "doc-" + std::to_string(key);
    }

    ic::OpResult result(ic::Status status,
                        ic::Cause cause = ic::Cause::None,
                        int httpStatus = 0,
                        std::string itemErrorType = {},
                        std::string reason = {})
    {
        ic::OpResult r;
        r.status = status;
        r.cause = cause;
        r.httpStatus = httpStatus;
        r.itemErrorType = std::move(itemErrorType);
        r.reason = std::move(reason);
        return r;
    }

    /// A mix of every kind of result a bulk resolution sees: Ok (a conflict resolved Ok keeps its 409), Permanent,
    /// RetryExhausted, the sweep's Dropped and an ambiguous failure; reason and item error type above their caps.
    std::vector<ic::OpResult> mixedResults()
    {
        std::vector<ic::OpResult> results;
        results.push_back(result(ic::Status::Ok, ic::Cause::None, 201));
        results.push_back(result(ic::Status::Ok, ic::Cause::None, 409, "version_conflict_engine_exception", "exists"));
        results.push_back(result(ic::Status::Failed,
                                 ic::Cause::ItemPermanent,
                                 400,
                                 "mapper_parsing_exception",
                                 std::string(ic::OpResult::MAX_REASON + 100, 'r')));
        results.push_back(result(ic::Status::Failed,
                                 ic::Cause::RetryExhausted,
                                 429,
                                 std::string(ic::OpResult::MAX_ITEM_ERROR_TYPE + 10, 'e'),
                                 "too many"));
        results.push_back(result(ic::Status::Dropped, ic::Cause::Shutdown));
        results.push_back(result(ic::Status::Dropped, ic::Cause::ClientClosed));
        results.push_back(result(ic::Status::Failed, ic::Cause::Ambiguous, 502, {}, "ambiguous HTTP 502"));
        results.push_back(result(ic::Status::Dropped, ic::Cause::Cancelled)); // `cancelled` too (I80).
        return results;
    }

    /// Every counter of the snapshot but the names, for equality.
    std::string counters(const wr::BucketStats& s)
    {
        std::string out = describe(s);
        out.erase(0, out.find(':'));
        out += " cancelled " + std::to_string(s.cancelled) + " lateResults " + std::to_string(s.lateResults) +
               " retainedBytes " + std::to_string(s.retainedBytes) + " rejectedShutdown " +
               std::to_string(s.rejectedShutdown);
        for (const auto value : s.dropped)
        {
            out += " d" + std::to_string(value);
        }
        for (const auto value : s.failed)
        {
            out += " f" + std::to_string(value);
        }
        return out;
    }

    std::string interval(const wr::LogInterval& i)
    {
        std::string out = "ok " + std::to_string(i.ok) + " failed " + std::to_string(i.failed) + " dropped " +
                          std::to_string(i.dropped) + " other " + std::to_string(i.other) + " sample " +
                          std::to_string(i.sampleReason.size()) + "/" + ic::toString(i.sampleCause) + "/" +
                          i.sampleItemErrorType;
        for (const auto& key : i.keys)
        {
            out += " [" + std::string(ic::toString(key.cause)) + "," + key.itemErrorType + "," +
                   std::to_string(key.count) + "]";
        }
        return out;
    }

    std::string describe(const ic::CloseReport& r)
    {
        return "drained " + std::to_string(r.drained) + " droppedClientClosed " +
               std::to_string(r.droppedClientClosed) + " droppedShutdown " + std::to_string(r.droppedShutdown);
    }

    // loggerHelper.h's WARN as the library passes it to the log function.
    constexpr int WARN = 2;

    /// The process log function of the case: every WARN line, formatted.
    class WarnLines final
    {
    public:
        indexer_client::LogFunction function()
        {
            return
                [this](
                    const int level, const char*, const char*, const int, const char*, const char* format, va_list args)
            {
                if (level != WARN)
                {
                    return;
                }
                va_list copy;
                va_copy(copy, args);
                char buffer[4096];
                std::vsnprintf(buffer, sizeof(buffer), format, copy);
                va_end(copy);
                std::lock_guard<std::mutex> lock(m_mutex);
                m_lines.emplace_back(buffer);
            };
        }

        std::size_t count(const std::string& part) const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            std::size_t n = 0;
            for (const auto& line : m_lines)
            {
                n += line.find(part) != std::string::npos ? 1 : 0;
            }
            return n;
        }

    private:
        mutable std::mutex m_mutex;
        std::vector<std::string> m_lines;
    };

    // Client::m_state (the buckets' state), through the explicit-instantiation access rule (as metrics_test).
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

    std::shared_ptr<wr::Bucket> bucketNamed(ic::Client& c, const std::string& name)
    {
        const auto state = c.*member(ClientStateTag {});
        for (const auto& bucket : state->bucketStates)
        {
            if (bucket->spec().name == name)
            {
                return bucket;
            }
        }
        ADD_FAILURE() << "no bucket " << name;
        return nullptr;
    }
} // namespace

/// Posts `count` ops into `writer` (a Reject bucket: admitted one by one, staged never) and returns the batch the
/// held sink got for them (one batch: maxDocs = count). On the bulk fixture: AmbiguousCountsResolvedOnly runs the
/// production sender against a fake; the other cases install the test sink.
class WriteResolveBulk : public BulkTest
{
protected:
    WarnLines m_warns;

    void SetUp() override
    {
        BulkTest::SetUp();
        indexer_client::setLogFunction(m_warns.function()); // Valid only while no runtime runs (I56).
    }

    void TearDown() override
    {
        BulkTest::TearDown();
        indexer_client::setLogFunction({});
    }

    wr::Batch postAndTake(ic::IWriter& writer, std::size_t count, std::uint64_t firstKey = 0)
    {
        const auto before = m_sink->dispatched();
        for (std::size_t k = 0; k < count; ++k)
        {
            const auto posted = writer.post(indexOp(id(firstKey + k), 64));
            EXPECT_TRUE(posted.accepted) << ic::toString(posted.cause);
        }
        EXPECT_TRUE(m_sink->waitDispatched(before + 1));
        auto batches = m_sink->take();
        EXPECT_EQ(batches.size(), 1u);
        if (batches.empty())
        {
            return {};
        }
        EXPECT_EQ(batches.front().ops.size(), count);
        return std::move(batches.front());
    }

    static std::vector<wr::BulkItem> items(const wr::Batch& batch, const std::vector<ic::OpResult>& results)
    {
        std::vector<wr::BulkItem> out;
        for (std::size_t i = 0; i < batch.ops.size(); ++i)
        {
            out.push_back(wr::BulkItem {batch.ops[i].get(), results[i % results.size()]});
        }
        return out;
    }

    static ic::BucketSpec spec(std::size_t ops)
    {
        // Room for every op (64-byte bodies), one batch of exactly `ops` ops, no age-based batch.
        return bucketSpec("w", ops * (R + 256) + R, ic::Overflow::Kind::Reject, 0, ops);
    }
};

// CA-E6e-1: one bucket resolved op by op, another with the same results in one bulk: the same snapshot (every
// counter), the same interval keys and sample, the same CloseReport; charge and global charge back to 0.
TEST_F(WriteResolveBulk, SameCountsAsPerOp)
{
    ASSERT_NO_FATAL_FAILURE(start());
    installSink();
    const auto results = mixedResults();
    const std::size_t count = 3 * results.size();
    auto perOp = client("perop", {spec(count)});
    auto bulk = client("bulk", {spec(count)});

    const auto batchA = postAndTake(*perOp->writer("w"), count, 100); // Ids of the same length: same charge.
    const auto batchB = postAndTake(*bulk->writer("w"), count, 200);
    ASSERT_EQ(batchA.ops.size(), count);
    ASSERT_EQ(batchB.ops.size(), count);

    std::size_t wonA = 0;
    for (std::size_t i = 0; i < count; ++i)
    {
        wonA += m_path->resolve(bucketOf(*batchA.ops[i]), batchA.ops[i], results[i % results.size()]) ? 1 : 0;
    }
    auto itemsB = items(batchB, results);
    const auto wonB = m_path->resolveBulk(batchB.bucket, itemsB);
    EXPECT_EQ(wonA, count);
    EXPECT_EQ(wonB, count);

    EXPECT_EQ(counters(stats("w", "perop")), counters(stats("w", "bulk")));
    EXPECT_EQ(interval(batchA.bucket->takeLogInterval()), interval(batchB.bucket->takeLogInterval()));
    EXPECT_EQ(stats("w", "bulk").charge, 0u);
    EXPECT_EQ(stats("w", "bulk").retained, 0u);
    expectInvariants(stats("w", "bulk"));

    const auto reportA = perOp->awaitClosed(now() + 1s);
    const auto reportB = bulk->awaitClosed(now() + 1s);
    ASSERT_TRUE(reportA.ok());
    ASSERT_TRUE(reportB.ok());
    EXPECT_EQ(describe(reportA.value), describe(reportB.value));
    EXPECT_EQ(reportB.value.droppedShutdown, 3u);
    EXPECT_EQ(reportB.value.droppedClientClosed, 3u);
    EXPECT_TRUE(eventually([&] { return globalCharge() == 0; }, 5s)) << write_component::describe(m_path->stats());
}

// CA-E6e-1: an op already resolved (a sweep won it) is late for the bulk; the bulk releases the payload and the
// RESULT_RESERVE of the others exactly once (a second bulk over the same ops wins none and moves no charge).
TEST_F(WriteResolveBulk, ChargeAndReserveReleasedOnce)
{
    ASSERT_NO_FATAL_FAILURE(start());
    installSink();
    auto c = client("c", {spec(5)});
    const auto batch = postAndTake(*c->writer("w"), 5);
    ASSERT_EQ(batch.ops.size(), 5u);
    const auto charged = stats("w").charge;
    ASSERT_GT(charged, 5 * R);

    ASSERT_TRUE(
        m_path->resolve(bucketOf(*batch.ops[1]), batch.ops[1], result(ic::Status::Dropped, ic::Cause::Shutdown)));
    auto first = items(batch, {TestSink::ok()});
    EXPECT_EQ(m_path->resolveBulk(batch.bucket, first), 4u);
    EXPECT_EQ(stats("w").charge, 0u);
    EXPECT_EQ(stats("w").retained, 0u);
    EXPECT_EQ(stats("w").retainedBytes, 0u);
    EXPECT_EQ(globalCharge(), 0u);

    auto second = items(batch, {TestSink::ok()});
    EXPECT_EQ(m_path->resolveBulk(batch.bucket, second), 0u);
    EXPECT_EQ(stats("w").charge, 0u);
    EXPECT_EQ(globalCharge(), 0u);
    EXPECT_EQ(stats("w").resolvedOk, 4u);
    EXPECT_EQ(stats("w").resolvedDropped, 1u);
    expectInvariants(stats("w"));
}

// CA-E6e-1 (I99): requestClose() lands between two chunks of one bulk (seam midBulkSettle, SETTLE_CHUNK + TAIL ops,
// TAIL < SETTLE_CHUNK): the first chunk was resolved before the close, the second after it, so CloseReport::drained
// counts exactly the TAIL.
TEST_F(WriteResolveBulk, DrainedCountedWhenCloseMidBulk)
{
    ASSERT_NO_FATAL_FAILURE(start());
    installSink();
    constexpr std::size_t TAIL = wr::SETTLE_CHUNK / 2 + 1;
    constexpr std::size_t COUNT = wr::SETTLE_CHUNK + TAIL;
    auto c = client("c", {spec(COUNT)});
    const auto batch = postAndTake(*c->writer("w"), COUNT);
    ASSERT_EQ(batch.ops.size(), COUNT);

    std::atomic<int> calls {0};
    ic::testing_hooks::setMidBulkSettle(
        [&]
        {
            if (++calls == 2)
            {
                c->requestClose();
            }
        });
    auto all = items(batch, {TestSink::ok()});
    EXPECT_EQ(m_path->resolveBulk(batch.bucket, all), COUNT);
    ic::testing_hooks::setMidBulkSettle({});
    EXPECT_EQ(calls.load(), 2);

    const auto report = c->awaitClosed(now() + 2s);
    ASSERT_TRUE(report.ok());
    EXPECT_EQ(report.value.drained, TAIL) << describe(report.value);
    EXPECT_EQ(report.value.droppedClientClosed, 0u);
    EXPECT_EQ(report.value.droppedShutdown, 0u);
    expectInvariants(stats("w"));
    EXPECT_EQ(stats("w").retained, 0u);
}

// CA-E6e-1: a throw in the middle of a bulk (seam midBulkSettle, before the first and before the second chunk) still
// settles every op it claimed — none stays claimed and retained — and the exception reaches the caller (the
// completion's fallback); `retained`, charge and the global charge end at 0.
TEST_F(WriteResolveBulk, ThrowMidBulkReleasesClaimed)
{
    ASSERT_NO_FATAL_FAILURE(start());
    installSink();
    constexpr std::size_t COUNT = wr::SETTLE_CHUNK + 88;
    auto c = client("c", {spec(COUNT)});
    auto writer = c->writer("w");
    for (const int throwAt : {1, 2})
    {
        SCOPED_TRACE(throwAt);
        const auto batch = postAndTake(*writer, COUNT, static_cast<std::uint64_t>(throwAt) * 10000);
        ASSERT_EQ(batch.ops.size(), COUNT);
        std::atomic<int> calls {0};
        ic::testing_hooks::setMidBulkSettle(
            [&]
            {
                if (++calls == throwAt)
                {
                    throw std::runtime_error("midBulkSettle");
                }
            });
        auto all = items(batch, {TestSink::ok()});
        EXPECT_THROW(m_path->resolveBulk(batch.bucket, all), std::runtime_error);
        ic::testing_hooks::setMidBulkSettle({});
        for (const auto& op : batch.ops)
        {
            EXPECT_TRUE(op->claimed.load());
            EXPECT_FALSE(op->payloadCharged);
        }
        EXPECT_EQ(stats("w").retained, 0u);
        EXPECT_EQ(stats("w").charge, 0u);
        EXPECT_EQ(globalCharge(), 0u);
        expectInvariants(stats("w"));
    }
    EXPECT_EQ(stats("w").resolvedOk, 2 * COUNT);
}

// CA-E6e-1 (I105b), G-diff E6e P3-3: through the production sender. A bucket with onAmbiguous5xx = Fail posts five
// ops; the fake answers their bulk 502; before the completion handles it (seam beforeCompletion) a sweep wins two of
// them (Dropped(Shutdown)). failBatch's bulk resolution wins only the other three, which are the only Failed(Ambiguous)
// in the snapshot, the count of countAmbiguous (its WARN says 3, not 5) and the complement of the two late results.
// Mutant: countAmbiguous(httpStatus, batch.ops.size()).
TEST_F(WriteResolveBulk, AmbiguousCountsResolvedOnly)
{
    const auto node = startNode();
    node.bulk->push(bulk_component::BulkScript::serverError(502));
    ASSERT_NO_FATAL_FAILURE(startOn({node.url()}));
    auto bucketSpecW = spec(5);
    bucketSpecW.onAmbiguous5xx = ic::AmbiguousPolicy::Fail;
    auto c = client("c", {bucketSpecW});
    auto bucket = bucketNamed(*c, "w");
    ASSERT_NE(bucket, nullptr);
    auto path = m_path;
    auto swept = std::make_shared<std::atomic<int>>(0);
    ic::testing_hooks::setBeforeCompletion(
        [bucket, path, swept]
        {
            if (swept->exchange(-1) != 0)
            {
                return; // Only the first bulk completion.
            }
            int won = 0;
            for (const auto& op : bucket->delivered())
            {
                if (won == 2)
                {
                    break;
                }
                won += path->resolve(bucket, op, result(ic::Status::Dropped, ic::Cause::Shutdown)) ? 1 : 0;
            }
            swept->store(won);
        });
    auto writer = c->writer("w");
    for (std::uint64_t k = 0; k < 5; ++k)
    {
        ASSERT_TRUE(writer->post(indexOp(id(k), 64)).accepted);
    }
    const std::string warn = "Indexer client bucket 'c/w' got an ambiguous HTTP 502 for a bulk of ";
    ASSERT_TRUE(eventually([&] { return m_warns.count(warn) == 1; }, 5s)) << describe(stats("w"));
    ic::testing_hooks::setBeforeCompletion({});
    EXPECT_EQ(swept->load(), 2);
    EXPECT_EQ(m_warns.count(warn + "3 operations"), 1u) << "countAmbiguous counts only the ops the bulk resolved";
    const auto s = stats("w");
    EXPECT_EQ(s.failed[static_cast<std::size_t>(ic::FailCause::Ambiguous)], 3u);
    EXPECT_EQ(s.resolvedFailed, 3u);
    EXPECT_EQ(s.resolvedDropped, 2u);
    EXPECT_EQ(s.lateResults, 2u);
    EXPECT_EQ(s.charge, 0u);
    EXPECT_EQ(node.bulk->answered(), 1u) << "an ambiguous 502 is never resent";
    expectInvariants(s);
}

// G-diff E6e P3-2: a cancel(tag) that marks a delivered op after resolveBulk claimed it (seam midBulkSettle, before
// the chunk is settled) registers a waiter that only Bucket::settleBulk's decrement completes: the ticket is ready
// once resolveBulk returns. Mutant: settleBulk without its loop over the completed waiters.
TEST_F(WriteResolveBulk, CancelWaiterCompletedBySettleBulk)
{
    ASSERT_NO_FATAL_FAILURE(start());
    installSink();
    auto c = client("c", {spec(3)});
    auto writer = c->writer("w");
    const auto before = m_sink->dispatched();
    for (std::uint64_t k = 0; k < 3; ++k)
    {
        auto op = indexOp(id(k), 64);
        op.tag = k == 1 ? "batch-9" : "";
        ASSERT_TRUE(writer->post(std::move(op)).accepted);
    }
    ASSERT_TRUE(m_sink->waitDispatched(before + 1));
    auto batches = m_sink->take();
    ASSERT_EQ(batches.size(), 1u);
    const auto batch = std::move(batches.front());
    ASSERT_EQ(batch.ops.size(), 3u);

    ic::CancelTicket cancel;
    bool readyBeforeSettle = true;
    ic::testing_hooks::setMidBulkSettle(
        [&]
        {
            cancel = writer->cancel("batch-9"); // Marks the delivered, claimed op: one waiter.
            readyBeforeSettle = cancel.ready();
        });
    auto all = items(batch, {TestSink::ok()});
    EXPECT_EQ(m_path->resolveBulk(batch.bucket, all), 3u);
    ic::testing_hooks::setMidBulkSettle({});
    EXPECT_FALSE(readyBeforeSettle) << "the waiter must wait for the op's settlement";
    EXPECT_TRUE(cancel.ready()) << "settleBulk did not complete the cancel(tag) waiter";
    const auto s = stats("w");
    EXPECT_EQ(s.resolvedOk, 3u) << "the op was claimed before the cancel: it keeps its result";
    EXPECT_EQ(s.cancelled, 0u);
    EXPECT_EQ(s.retained, 0u);
    EXPECT_EQ(s.charge, 0u);
    expectInvariants(s);
}

// G-diff E6e P3-2: Bucket::settleBulk throws twice (seam inSettleBulk on the 3rd and 4th op counted): the first
// throw is caught inside it (the two ops settled so far are released all the same) and escapes resolveBulk; its
// settlement's destructor retries the chunk, which throws again, and settles that op alone by the per-op calls
// (settleOneAlone) before the rest goes by chunk. Every claimed op ends settled once. Mutant: settleOneAlone empty.
TEST_F(WriteResolveBulk, SettleThrowsTwiceFallsBackPerOp)
{
    ASSERT_NO_FATAL_FAILURE(start());
    installSink();
    auto c = client("c", {spec(6)});
    const auto batch = postAndTake(*c->writer("w"), 6);
    ASSERT_EQ(batch.ops.size(), 6u);
    std::atomic<int> calls {0};
    ic::testing_hooks::setInSettleBulk(
        [&calls]
        {
            const int call = ++calls;
            if (call == 3 || call == 4)
            {
                throw std::runtime_error("inSettleBulk");
            }
        });
    auto all = items(batch, {TestSink::ok()});
    EXPECT_THROW(m_path->resolveBulk(batch.bucket, all), std::runtime_error);
    ic::testing_hooks::setInSettleBulk({});
    // 2 settled + throw (3); retry throws (4); op 3 alone (no seam); ops 4-6 by chunk (5-7).
    EXPECT_EQ(calls.load(), 7);
    for (const auto& op : batch.ops)
    {
        EXPECT_TRUE(op->claimed.load());
        EXPECT_FALSE(op->payloadCharged);
    }
    const auto s = stats("w");
    EXPECT_EQ(s.resolvedOk, 6u);
    EXPECT_EQ(s.retained, 0u);
    EXPECT_EQ(s.charge, 0u);
    EXPECT_EQ(globalCharge(), 0u);
    expectInvariants(s);
}

// G-diff E6e P3-2: a bucket with no client (built directly) settles through resolveBulk all the same: no client
// accounting (the no-client branch), the ops released once with their RESULT_RESERVE.
TEST_F(WriteResolveBulk, BucketWithoutClientSettles)
{
    ASSERT_NO_FATAL_FAILURE(start());
    wr::GlobalBudget budget(1u << 30);
    auto bucket = std::make_shared<wr::Bucket>("direct", spec(3), budget);
    for (std::uint64_t k = 0; k < 3; ++k)
    {
        auto encoded = wr::encode(indexOp(id(k), 64), ic::ConflictPolicy {});
        ASSERT_TRUE(encoded.ok()) << encoded.reason;
        auto op = std::make_shared<wr::OpState>();
        op->head = std::move(encoded.value.head);
        op->body = std::move(encoded.value.body);
        op->payload = wr::chargeSize(op->headView(), op->body);
        op->reserveCharged = true;
        ASSERT_EQ(bucket->admit(op, now(), now()).cause, ic::Cause::None);
    }
    auto batch = bucket->slice(now());
    ASSERT_EQ(batch.ops.size(), 3u);
    batch.bucket = bucket;
    auto all = items(batch,
                     {TestSink::ok(),
                      result(ic::Status::Dropped, ic::Cause::ClientClosed),
                      result(ic::Status::Dropped, ic::Cause::Shutdown)});
    EXPECT_EQ(m_path->resolveBulk(bucket, all), 3u);
    const auto s = bucket->stats();
    EXPECT_EQ(s.resolvedOk, 1u);
    EXPECT_EQ(s.resolvedDropped, 2u);
    EXPECT_EQ(s.retained, 0u);
    EXPECT_EQ(s.charge, 0u);
    EXPECT_EQ(budget.charge(), 0u);
    expectInvariants(s);
}
