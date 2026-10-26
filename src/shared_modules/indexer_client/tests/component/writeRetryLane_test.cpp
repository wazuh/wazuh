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

// The bucket's retry lane (plan-E3b-1 §Tests: I66, CA-8, CA-10, RF-6, RF-9): requeue specs, backoff and exhaustion,
// maxDuration from the first send, split halves, close and the sweep, DropOldest, nextDue/empty, the lane ahead of the
// pending queue through the real scheduler, and the E3a invariants under a race.
//
// Ops are admitted through a real runtime and handed to the test sink (Hold). The sink's capacity is 0 once the case
// holds its batch, so the scheduler never slices again unless the case grants capacity: the case drives slice() and
// requeue() itself with chosen instants and reads an op's fields only from its own thread, after the call that wrote
// them (or after resolving it). Every case ends with its ops resolved and the charge and retained ops at 0 (TearDown).

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <random>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "writeFixture.hpp"

using namespace write_component;
using component::eventually;

namespace
{
    constexpr std::uint64_t R = wr::RESULT_RESERVE;
    constexpr std::uint64_t ALL = std::numeric_limits<std::uint64_t>::max();
    using Spec = wr::RequeueSpec;
    using Delay = wr::RequeueSpec::Delay;
    using OpPtr = std::shared_ptr<wr::OpState>;

    /// Fixed-width ids, so ops with the same body have the same wire size.
    std::string id(std::uint64_t key)
    {
        char buffer[16];
        std::snprintf(buffer, sizeof(buffer), "k%07llu", static_cast<unsigned long long>(key));
        return buffer;
    }

    /// The key an op was submitted with (from its action line).
    std::uint64_t keyOf(const wr::OpState& op)
    {
        const auto at = op.head.find("\"_id\":\"k");
        return at == std::string::npos ? ALL : std::stoull(op.head.substr(at + 8, 7));
    }

    std::vector<std::uint64_t> keysOf(const std::vector<OpPtr>& ops)
    {
        std::vector<std::uint64_t> keys;
        for (const auto& op : ops)
        {
            keys.push_back(keyOf(*op));
        }
        return keys;
    }

    Spec spec(bool countAttempt, Delay delay, ic::TimePoint at = {}, bool toHead = false, bool halve = false)
    {
        Spec out;
        out.countAttempt = countAttempt;
        out.delay = delay;
        out.at = at;
        out.toHead = toHead;
        out.halve = halve;
        return out;
    }

    std::vector<wr::RequeueOp> requeueOps(const std::vector<OpPtr>& ops,
                                          ic::Cause cause = ic::Cause::Server5xx,
                                          int status = 503,
                                          const std::string& type = "unavailable_shards_exception",
                                          const std::string& reason = "primary shard is not active")
    {
        std::vector<wr::RequeueOp> out;
        for (const auto& op : ops)
        {
            out.push_back(wr::RequeueOp {op, wr::LastError {cause, status, type, reason}});
        }
        return out;
    }

    ic::OpResult resultOf(ic::Status status, ic::Cause cause)
    {
        ic::OpResult result;
        result.status = status;
        result.cause = cause;
        return result;
    }

    long long msBetween(ic::TimePoint from, ic::TimePoint to)
    {
        return std::chrono::duration_cast<std::chrono::milliseconds>(to - from).count();
    }

    ic::RetryPolicy retryPolicy(std::optional<std::uint32_t> maxAttempts,
                                std::optional<ic::Duration> maxDuration,
                                ic::Duration base,
                                ic::Duration cap,
                                double jitter)
    {
        ic::RetryPolicy retry;
        retry.maxAttempts = maxAttempts;
        retry.maxDuration = maxDuration;
        retry.base = base;
        retry.cap = cap;
        retry.jitter = jitter;
        return retry;
    }
} // namespace

class WriteRetryLaneTest : public WriteTest
{
protected:
    /// Submits `count` ops (keys firstKey..) and holds the single batch the bucket forms (its bulk.maxDocs or
    /// bulk.maxBytes must be reached by exactly these ops). The sink's capacity is 0 again afterwards.
    wr::Batch deliver(const std::shared_ptr<ic::IWriter>& writer,
                      const std::shared_ptr<Results>& results,
                      std::uint64_t firstKey,
                      std::size_t count,
                      std::size_t bodyBytes = 100)
    {
        const auto before = m_sink->dispatched();
        m_sink->setCapacity(1);
        for (std::size_t i = 0; i < count; ++i)
        {
            const auto submit = writer->submit(indexOp(id(firstKey + i), bodyBytes), results->callback(firstKey + i));
            EXPECT_TRUE(submit.accepted) << ic::toString(submit.cause);
        }
        EXPECT_TRUE(m_sink->waitDispatched(before + 1));
        auto held = m_sink->take();
        EXPECT_EQ(held.size(), 1U);
        if (held.size() != 1)
        {
            return {};
        }
        EXPECT_EQ(held[0].ops.size(), count);
        EXPECT_EQ(m_sink->capacity(), 0U);
        return std::move(held[0]);
    }

    /// Resolves `op` through the single resolution path (false if someone else resolved it first).
    bool resolve(const OpPtr& op, ic::Status status = ic::Status::Ok, ic::Cause cause = ic::Cause::None)
    {
        return m_path->resolve(bucketOf(*op), op, resultOf(status, cause));
    }

    /// Takes everything still queued in `bucket` (lane and pending) and every op still delivered, and resolves it.
    void drain(const std::shared_ptr<wr::Bucket>& bucket, const std::vector<OpPtr>& also = {})
    {
        const auto far = now() + std::chrono::hours(24);
        for (int i = 0; i < 10000 && !bucket->empty(); ++i)
        {
            for (const auto& op : bucket->slice(far).ops)
            {
                resolve(op);
            }
        }
        for (const auto& op : bucket->delivered())
        {
            resolve(op);
        }
        for (const auto& op : also)
        {
            resolve(op);
        }
    }
};

// CA-8, I66: Backoff puts notBefore in [d(1 - j), min(cap, d(1 + j))] with d = min(cap, base * 2^(attempts - 1)); at
// maxAttempts the op is exhausted with its last error (still delivered until resolved); an unlimited bucket goes
// through 40 requeues at d = cap without exhausting (and without overflowing the exponent).
TEST_F(WriteRetryLaneTest, RequeueBackoffAndExhaust)
{
    ASSERT_NO_FATAL_FAILURE(start());
    installSink(TestSink::Mode::Hold, 0);
    const ic::Duration base {100};
    const ic::Duration cap {1600};
    auto limited = bucketSpec("limited", 1U << 20, ic::Overflow::Kind::Reject, 0, 1);
    limited.retry = retryPolicy(5, std::nullopt, base, cap, 0.5);
    auto exact = bucketSpec("exact", 1U << 20, ic::Overflow::Kind::Reject, 0, 1);
    exact.retry = retryPolicy(std::nullopt, std::nullopt, base, cap, 0.0);
    auto unlimited = bucketSpec("unlimited", 1U << 20, ic::Overflow::Kind::Reject, 0, 1);
    unlimited.retry = retryPolicy(std::nullopt, std::nullopt, base, cap, 0.5);
    auto c = client("c", {limited, exact, unlimited});
    auto results = Results::create();

    // Limited: four backoffs in range, the fifth attempt exhausts.
    auto batch = deliver(c->writer("limited"), results, 0, 1);
    ASSERT_EQ(batch.ops.size(), 1U);
    auto bucket = batch.bucket;
    const auto op = batch.ops[0];
    auto t = now();
    for (std::uint32_t attempt = 1; attempt <= 5; ++attempt)
    {
        SCOPED_TRACE("attempt " + std::to_string(attempt));
        const auto result = bucket->requeue(requeueOps({op},
                                                       ic::Cause::Server5xx,
                                                       500 + static_cast<int>(attempt),
                                                       "type-" + std::to_string(attempt),
                                                       "reason-" + std::to_string(attempt)),
                                            spec(true, Delay::Backoff),
                                            t);
        EXPECT_TRUE(result.closed.empty());
        EXPECT_EQ(op->attempts, attempt);
        if (attempt == 5)
        {
            ASSERT_EQ(result.exhausted.size(), 1U) << "maxAttempts = 5 reached";
            EXPECT_EQ(result.exhausted[0], op);
            EXPECT_EQ(op->lastCause, ic::Cause::Server5xx);
            EXPECT_EQ(op->lastHttpStatus, 505);
            EXPECT_EQ(op->lastItemErrorType, "type-5");
            EXPECT_EQ(op->lastReason, "reason-5");
            EXPECT_TRUE(bucket->empty()) << "an exhausted op does not enter the lane";
            EXPECT_EQ(bucket->delivered().size(), 1U) << "still delivered until resolved";
            break;
        }
        ASSERT_TRUE(result.exhausted.empty()) << "exhausted before maxAttempts";
        EXPECT_TRUE(result.notify) << "the lane was empty";
        const auto d = std::min<long long>(cap.count(), base.count() << (attempt - 1));
        const auto delay = msBetween(t, op->notBefore);
        EXPECT_GE(delay, d / 2 - 1);
        EXPECT_LE(delay, std::min<long long>(cap.count(), d * 3 / 2));
        EXPECT_FALSE(bucket->empty());
        EXPECT_EQ(bucket->headBytes(op->notBefore), op->wire());
        const auto again = bucket->slice(op->notBefore);
        ASSERT_EQ(again.ops.size(), 1U);
        t = op->notBefore;
    }
    EXPECT_TRUE(resolve(op, ic::Status::Failed, ic::Cause::RetryExhausted));
    ASSERT_TRUE(results->waitTotal(1));
    EXPECT_EQ(results->count(0), 1);

    // Exact (jitter 0): d doubles from base up to cap and stays there for 40 requeues; never exhausted.
    for (const char* name : {"exact", "unlimited"})
    {
        SCOPED_TRACE(name);
        const bool exactDelays = std::string(name) == "exact";
        const std::uint64_t key = exactDelays ? 1 : 2;
        batch = deliver(c->writer(name), results, key, 1);
        ASSERT_EQ(batch.ops.size(), 1U);
        bucket = batch.bucket;
        const auto one = batch.ops[0];
        t = now();
        for (std::uint32_t attempt = 1; attempt <= 40; ++attempt)
        {
            const auto result = bucket->requeue(requeueOps({one}), spec(true, Delay::Backoff), t);
            ASSERT_TRUE(result.exhausted.empty()) << "attempt " << attempt;
            const auto d = attempt >= 5 ? cap.count() : std::min<long long>(cap.count(), base.count() << (attempt - 1));
            const auto delay = msBetween(t, one->notBefore);
            if (exactDelays)
            {
                ASSERT_EQ(delay, d) << "attempt " << attempt;
            }
            else
            {
                ASSERT_GE(delay, d / 2 - 1) << "attempt " << attempt;
                ASSERT_LE(delay, cap.count()) << "attempt " << attempt;
            }
            ASSERT_EQ(bucket->slice(one->notBefore).ops.size(), 1U) << "attempt " << attempt;
            t = one->notBefore;
        }
        EXPECT_EQ(one->attempts, 40U);
        EXPECT_TRUE(resolve(one));
    }
    ASSERT_TRUE(results->waitTotal(3));
}

// I66: maxDuration counts from the first send (the first slice), not from the submit: an op held in the queue longer
// than maxDuration still has its budget at its first retry, and is exhausted maxDuration after its first send.
TEST_F(WriteRetryLaneTest, MaxDurationCountsFromFirstSend)
{
    ASSERT_NO_FATAL_FAILURE(start());
    installSink(TestSink::Mode::Hold, 0);
    auto bucketSpecWithDuration = bucketSpec("b", 1U << 20, ic::Overflow::Kind::Reject, 0, 1);
    bucketSpecWithDuration.retry =
        retryPolicy(std::nullopt, ic::Duration {300}, ic::Duration {10}, ic::Duration {20}, 0);
    auto c = client("c", {bucketSpecWithDuration});
    auto results = Results::create();
    auto writer = c->writer("b");

    ASSERT_TRUE(writer->submit(indexOp(id(0)), results->callback(0)).accepted);
    // Measured window: the op waits in the queue (no sink capacity) longer than maxDuration.
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    EXPECT_EQ(m_sink->dispatched(), 0U);
    m_sink->grant(1);
    ASSERT_TRUE(m_sink->waitDispatched(1));
    auto held = m_sink->take();
    ASSERT_EQ(held.size(), 1U);
    auto bucket = held[0].bucket;
    const auto op = held[0].ops.at(0);
    const auto firstAttempt = op->firstAttempt;
    ASSERT_GE(msBetween(op->firstSubmit, firstAttempt), 300) << "precondition: queued longer than maxDuration";

    auto result =
        bucket->requeue(requeueOps({op}), spec(true, Delay::Now), firstAttempt + std::chrono::milliseconds(1));
    EXPECT_TRUE(result.exhausted.empty()) << "the first retry still has its maxDuration budget";
    ASSERT_EQ(bucket->slice(firstAttempt + std::chrono::milliseconds(2)).ops.size(), 1U);
    EXPECT_EQ(op->firstAttempt, firstAttempt) << "a later slice keeps the first send";
    result = bucket->requeue(requeueOps({op}), spec(false, Delay::Now), firstAttempt + std::chrono::milliseconds(299));
    EXPECT_TRUE(result.exhausted.empty()) << "299 ms after the first send";
    ASSERT_EQ(bucket->slice(firstAttempt + std::chrono::milliseconds(299)).ops.size(), 1U);
    result = bucket->requeue(requeueOps({op}), spec(false, Delay::Now), firstAttempt + std::chrono::milliseconds(300));
    EXPECT_EQ(result.exhausted.size(), 1U) << "300 ms after the first send, also without a counted attempt";

    drain(bucket, {op});
    ASSERT_TRUE(results->waitTotal(1));
}

// G-diff E3b-2 obj. 3: a requeue whose LastError has cause None (none of the sender's requeues does since that
// objection, but the bucket must not depend on it) keeps the op's previous last error, so a maxDuration exhaustion
// inside it still reports the real error; the exhausted op's error is handed out copied (exhaustedErrors), and the
// resolution frees the op's last-error strings (obj. 1). Mutant: requeue overwrites last* with an empty error.
TEST_F(WriteRetryLaneTest, RequeueWithoutErrorKeepsLastError)
{
    ASSERT_NO_FATAL_FAILURE(start());
    installSink(TestSink::Mode::Hold, 0);
    auto withDuration = bucketSpec("b", 1U << 20, ic::Overflow::Kind::Reject, 0, 1);
    withDuration.retry = retryPolicy(std::nullopt, ic::Duration {300}, ic::Duration {10}, ic::Duration {20}, 0);
    auto c = client("c", {withDuration});
    auto results = Results::create();
    auto batch = deliver(c->writer("b"), results, 0, 1);
    ASSERT_EQ(batch.ops.size(), 1U);
    auto bucket = batch.bucket;
    const auto op = batch.ops[0];
    const auto t = op->firstAttempt;

    auto result = bucket->requeue(requeueOps({op}), spec(false, Delay::Now), t + std::chrono::milliseconds(1));
    ASSERT_TRUE(result.exhausted.empty());
    ASSERT_EQ(bucket->slice(t + std::chrono::milliseconds(1)).ops.size(), 1U);
    std::vector<wr::RequeueOp> noError;
    noError.push_back(wr::RequeueOp {op, wr::LastError {}});
    result = bucket->requeue(std::move(noError), spec(false, Delay::Now), t + std::chrono::milliseconds(300));
    ASSERT_EQ(result.exhausted.size(), 1U) << "maxDuration spent inside the requeue without an error";
    ASSERT_EQ(result.exhaustedErrors.size(), 1U);
    EXPECT_EQ(result.exhaustedErrors[0].cause, ic::Cause::Server5xx);
    EXPECT_EQ(result.exhaustedErrors[0].httpStatus, 503);
    EXPECT_EQ(result.exhaustedErrors[0].itemErrorType, "unavailable_shards_exception");
    EXPECT_EQ(result.exhaustedErrors[0].reason, "primary shard is not active");
    EXPECT_EQ(op->lastCause, ic::Cause::Server5xx) << "the previous last error is kept";
    EXPECT_EQ(op->lastReason, "primary shard is not active");

    ASSERT_TRUE(resolve(op, ic::Status::Failed, ic::Cause::RetryExhausted));
    EXPECT_TRUE(op->lastReason.empty()) << "the resolution frees the last-error strings";
    EXPECT_TRUE(op->lastItemErrorType.empty());
    ASSERT_TRUE(results->waitTotal(1));
    drain(bucket);
}

// I66: Now with and without an attempt, At(t) waits for t, toHead goes before every other lane op; the lane is
// ordered by notBefore (stable) and `notify` is set when the lane was empty or its head moved earlier.
TEST_F(WriteRetryLaneTest, RequeueSpecs)
{
    ASSERT_NO_FATAL_FAILURE(start());
    installSink(TestSink::Mode::Hold, 0);
    auto c = client("c", {bucketSpec("b", 1U << 20, ic::Overflow::Kind::Reject, 0, 4)});
    auto results = Results::create();
    auto batch = deliver(c->writer("b"), results, 0, 4);
    ASSERT_EQ(batch.ops.size(), 4U);
    auto bucket = batch.bucket;
    const auto o = batch.ops;
    const auto t = now();
    const auto ms = [](int n)
    {
        return std::chrono::milliseconds(n);
    };

    auto r = bucket->requeue(requeueOps({o[0]}), spec(false, Delay::At, t + ms(5000)), t);
    EXPECT_TRUE(r.notify) << "the lane was empty";
    EXPECT_EQ(o[0]->attempts, 0U);
    EXPECT_EQ(o[0]->notBefore, t + ms(5000));
    r = bucket->requeue(requeueOps({o[1]}), spec(true, Delay::Now), t);
    EXPECT_TRUE(r.notify) << "the head moved earlier";
    EXPECT_EQ(o[1]->attempts, 1U);
    EXPECT_EQ(o[1]->notBefore, t);
    r = bucket->requeue(requeueOps({o[2]}), spec(false, Delay::Now), t);
    EXPECT_FALSE(r.notify) << "same head instant";
    EXPECT_EQ(o[2]->attempts, 0U);
    r = bucket->requeue(requeueOps({o[3]}), spec(false, Delay::Now, {}, true), t + ms(1));
    EXPECT_FALSE(r.notify);
    EXPECT_EQ(o[3]->notBefore, t + ms(1));
    for (const auto& op : o)
    {
        EXPECT_EQ(op->lastCause, ic::Cause::Server5xx);
        EXPECT_EQ(op->lastHttpStatus, 503);
        EXPECT_EQ(op->lastReason, "primary shard is not active");
    }

    EXPECT_EQ(bucket->headBytes(t + ms(1)), o[3]->wire());
    auto first = bucket->slice(t + ms(1));
    EXPECT_EQ(keysOf(first.ops), (std::vector<std::uint64_t> {3, 1, 2})) << "toHead first, then by notBefore (stable)";
    EXPECT_FALSE(bucket->eligible(t + ms(4999))) << "At(t) is not due before t";
    EXPECT_TRUE(bucket->slice(t + ms(4999)).ops.empty());
    EXPECT_TRUE(bucket->eligible(t + ms(5000)));
    auto second = bucket->slice(t + ms(5000));
    EXPECT_EQ(keysOf(second.ops), (std::vector<std::uint64_t> {0}));

    drain(bucket, o);
    ASSERT_TRUE(results->waitTotal(4));
}

// RF-9, I66: a batch of 4 split once (halve: batchCap = ceil(bytes / 2)) comes back as 2 + 2, never 4, even with a
// pending op behind; a half split again comes back one by one.
TEST_F(WriteRetryLaneTest, SplitHalvesNeverRemerge)
{
    ASSERT_NO_FATAL_FAILURE(start());
    installSink(TestSink::Mode::Hold, 0);
    auto c = client("c", {bucketSpec("b", 1U << 20, ic::Overflow::Kind::Reject, 0, 4)});
    auto results = Results::create();
    auto writer = c->writer("b");
    auto batch = deliver(writer, results, 0, 4);
    ASSERT_EQ(batch.ops.size(), 4U);
    auto bucket = batch.bucket;
    const auto size = batch.ops[0]->wire();
    ASSERT_EQ(batch.bytes, 4 * size);
    const auto t = now();

    auto r = bucket->requeue(requeueOps(batch.ops, ic::Cause::PayloadTooLarge, 413, "", "HTTP 413"),
                             spec(false, Delay::Now, {}, true, true),
                             t);
    EXPECT_TRUE(r.exhausted.empty());
    for (const auto& op : batch.ops)
    {
        EXPECT_EQ(op->batchCap, 2 * size);
        EXPECT_EQ(op->attempts, 0U) << "a split is not an attempt";
    }
    ASSERT_TRUE(writer->submit(indexOp(id(4)), results->callback(4)).accepted); // A pending op behind the lane.

    auto h1 = bucket->slice(t);
    EXPECT_EQ(keysOf(h1.ops), (std::vector<std::uint64_t> {0, 1})) << "first half only";
    r = bucket->requeue(
        requeueOps(h1.ops, ic::Cause::PayloadTooLarge, 413), spec(false, Delay::Now, {}, true, true), t);
    EXPECT_EQ(h1.ops.at(0)->batchCap, size);
    std::vector<std::vector<std::uint64_t>> next;
    for (int i = 0; i < 4; ++i)
    {
        next.push_back(keysOf(bucket->slice(t).ops));
    }
    EXPECT_EQ(next, (std::vector<std::vector<std::uint64_t>> {{0}, {1}, {2, 3}, {4}}))
        << "quarters, then the second half, then the pending op";

    drain(bucket, batch.ops);
    ASSERT_TRUE(results->waitTotal(5));
}

// I66, RF-6: close() hands back the retry lane and then the pending queue (not the delivered ops).
TEST_F(WriteRetryLaneTest, CloseReturnsLaneAndPending)
{
    ASSERT_NO_FATAL_FAILURE(start());
    installSink(TestSink::Mode::Hold, 0);
    auto c = client("c", {bucketSpec("b", 1U << 20, ic::Overflow::Kind::Reject, 0, 2)});
    auto results = Results::create();
    auto writer = c->writer("b");
    auto batch = deliver(writer, results, 0, 2);
    ASSERT_EQ(batch.ops.size(), 2U);
    auto bucket = batch.bucket;
    const auto t = now();
    bucket->requeue(requeueOps({batch.ops[0]}), spec(true, Delay::At, t + std::chrono::hours(1)), t);
    bucket->requeue(requeueOps({batch.ops[1]}), spec(true, Delay::Now), t);
    ASSERT_TRUE(writer->submit(indexOp(id(2)), results->callback(2)).accepted);
    ASSERT_TRUE(writer->submit(indexOp(id(3)), results->callback(3)).accepted);

    const auto closed = bucket->close(ic::Cause::ClientClosed);
    EXPECT_EQ(keysOf(closed), (std::vector<std::uint64_t> {1, 0, 2, 3})) << "lane (by notBefore), then pending";
    EXPECT_TRUE(bucket->empty());
    EXPECT_TRUE(bucket->closedCause() == ic::Cause::ClientClosed);
    for (const auto& op : closed)
    {
        EXPECT_TRUE(resolve(op, ic::Status::Dropped, ic::Cause::ClientClosed));
    }
    drain(bucket, batch.ops);
    ASSERT_TRUE(results->waitTotal(4));
    EXPECT_EQ(results->countWith(ic::Status::Dropped, ic::Cause::ClientClosed), closed.size());
}

// I66, RF-6: a requeue after the close returns the ops in `closed` (still delivered, for the caller or the sweep to
// resolve) and never puts them in the lane; an op already claimed is skipped.
TEST_F(WriteRetryLaneTest, RequeueOnClosedBucket)
{
    ASSERT_NO_FATAL_FAILURE(start());
    installSink(TestSink::Mode::Hold, 0);
    auto c = client("c", {bucketSpec("b", 1U << 20, ic::Overflow::Kind::Reject, 0, 3)});
    auto results = Results::create();
    auto batch = deliver(c->writer("b"), results, 0, 3);
    ASSERT_EQ(batch.ops.size(), 3U);
    auto bucket = batch.bucket;
    EXPECT_TRUE(bucket->close(ic::Cause::ClientClosed).empty()) << "every op is delivered";

    batch.ops[1]->claimed.store(true); // Being resolved by someone else.
    const auto result = bucket->requeue(requeueOps(batch.ops), spec(true, Delay::Backoff), now());
    batch.ops[1]->claimed.store(false);
    EXPECT_EQ(keysOf(result.closed), (std::vector<std::uint64_t> {0, 2}));
    EXPECT_TRUE(result.exhausted.empty());
    EXPECT_FALSE(result.notify);
    EXPECT_TRUE(bucket->empty()) << "nothing entered the lane";
    EXPECT_EQ(bucket->delivered().size(), 3U) << "still delivered until resolved";
    EXPECT_EQ(batch.ops[0]->lastCause, ic::Cause::Server5xx);

    for (const auto& op : batch.ops)
    {
        EXPECT_TRUE(resolve(op, ic::Status::Dropped, ic::Cause::ClientClosed));
    }
    drain(bucket);
    ASSERT_TRUE(results->waitTotal(3));
}

// CA-10, I66: with the retry lane holding half the quota, DropOldest evicts only pending ops (oldest first), never a
// lane op.
TEST_F(WriteRetryLaneTest, DropOldestSparesRetryLane)
{
    ASSERT_NO_FATAL_FAILURE(start());
    installSink(TestSink::Mode::Hold, 0);
    const auto size = wireSize(indexOp(id(0), 1000));
    const auto quota = 4 * (size + R) + R; // Room for one reserve: one eviction makes room for one op.
    auto c = client("c", {bucketSpec("b", quota, ic::Overflow::Kind::DropOldest, 0, 2)});
    auto results = Results::create();
    auto writer = c->writer("b");
    auto batch = deliver(writer, results, 0, 2, 1000);
    ASSERT_EQ(batch.ops.size(), 2U);
    auto bucket = batch.bucket;
    const auto t = now();
    bucket->requeue(requeueOps(batch.ops), spec(true, Delay::At, t + std::chrono::hours(1)), t);
    for (std::uint64_t key = 2; key < 4; ++key)
    {
        ASSERT_TRUE(writer->submit(indexOp(id(key), 1000), results->callback(key)).accepted);
    }
    ASSERT_EQ(stats("b").charge, quota - R) << "full: two in the lane, two pending";

    // Each new op evicts the oldest pending one; the lane stays.
    for (std::uint64_t key = 4; key < 7; ++key)
    {
        ASSERT_TRUE(writer->submit(indexOp(id(key), 1000), results->callback(key)).accepted);
        const auto evicted = key - 2; // 2, 3, then 4.
        ASSERT_TRUE(eventually([&] { return results->count(evicted) == 1; }, std::chrono::seconds(5)))
            << "key " << evicted << " evicted";
        ASSERT_TRUE(eventually([&] { return stats("b").charge == quota - R; }, std::chrono::seconds(5)))
            << describe(stats("b"));
    }
    EXPECT_EQ(results->count(0), 0) << "lane op evicted";
    EXPECT_EQ(results->count(1), 0) << "lane op evicted";
    EXPECT_EQ(results->countWith(ic::Status::Dropped, ic::Cause::QueueFull), 3U);
    EXPECT_EQ(stats("b").droppedOldest, 3U);
    const auto lane = bucket->slice(t + std::chrono::hours(1));
    EXPECT_EQ(keysOf(lane.ops), (std::vector<std::uint64_t> {0, 1})) << "the lane is intact";

    drain(bucket, batch.ops);
    ASSERT_TRUE(results->waitTotal(7));
    expectInvariants(stats("b"));
}

// I66: nextDue = min(oldest pending + maxAge, lane head notBefore); empty() is false with only the lane.
TEST_F(WriteRetryLaneTest, NextDueAndEmpty)
{
    ASSERT_NO_FATAL_FAILURE(start());
    installSink(TestSink::Mode::Hold, 0);
    const ic::Duration maxAge {60000};
    auto c = client("c", {bucketSpec("b", 1U << 20, ic::Overflow::Kind::Reject, 0, 1, maxAge)});
    auto results = Results::create();
    auto writer = c->writer("b");
    auto batch = deliver(writer, results, 0, 1);
    ASSERT_EQ(batch.ops.size(), 1U);
    auto bucket = batch.bucket;
    const auto op = batch.ops[0];
    EXPECT_TRUE(bucket->empty());
    EXPECT_FALSE(bucket->nextDue(now()).has_value());

    const auto t = now();
    bucket->requeue(requeueOps({op}), spec(true, Delay::At, t + std::chrono::seconds(10)), t);
    EXPECT_FALSE(bucket->empty()) << "only the lane";
    EXPECT_TRUE(bucket->nextDue(t) == t + std::chrono::seconds(10));
    EXPECT_FALSE(bucket->eligible(t));
    EXPECT_EQ(bucket->headBytes(t), 0U) << "a lane head that is not due is not the head";

    const auto before = now();
    ASSERT_TRUE(writer->submit(indexOp(id(1)), results->callback(1)).accepted);
    const auto after = now();
    EXPECT_TRUE(bucket->nextDue(t) == t + std::chrono::seconds(10)) << "the lane head is earlier";

    ASSERT_EQ(keysOf(bucket->slice(t + std::chrono::seconds(10)).ops), (std::vector<std::uint64_t> {0}));
    bucket->requeue(requeueOps({op}), spec(true, Delay::At, t + std::chrono::seconds(120)), t);
    const auto due = bucket->nextDue(t);
    ASSERT_TRUE(due.has_value());
    EXPECT_GE(*due, before + maxAge) << "the oldest pending + maxAge is earlier";
    EXPECT_LE(*due, after + maxAge);

    drain(bucket, {op});
    EXPECT_TRUE(bucket->empty());
    EXPECT_FALSE(bucket->nextDue(now()).has_value());
    ASSERT_TRUE(results->waitTotal(2));
}

// I66, through the real scheduler: a due lane op leaves before the pending ones; a lane that is not due does not make
// the bucket eligible, and a bucket holding only a lane op is not dropped from the scheduler for good (its timer
// brings it back at notBefore).
TEST_F(WriteRetryLaneTest, LaneBeforePending)
{
    ASSERT_NO_FATAL_FAILURE(start());
    installSink(TestSink::Mode::Hold, 0);
    auto c = client("c",
                    {bucketSpec("b", 1U << 20, ic::Overflow::Kind::Reject, 0, 1),
                     bucketSpec("late", 1U << 20, ic::Overflow::Kind::Reject, 0, 1)});
    auto results = Results::create();
    auto writer = c->writer("b");
    // The lane op is due at t0, taken before anything is submitted: a scheduler pass takes its `now` once, so a
    // notBefore of the requeue's own now() could still be later than the `now` of a pass already running (D68).
    const auto t0 = now();
    auto batch = deliver(writer, results, 0, 1);
    ASSERT_EQ(batch.ops.size(), 1U);
    auto bucket = batch.bucket;
    const auto laneOp = batch.ops[0];

    ASSERT_TRUE(writer->submit(indexOp(id(1)), results->callback(1)).accepted); // Pending and eligible (maxDocs 1).
    const auto r = bucket->requeue(requeueOps({laneOp}), spec(true, Delay::At, t0), now());
    EXPECT_TRUE(r.notify);
    m_sink->grant(1);
    ASSERT_TRUE(m_sink->waitDispatched(2));
    auto held = m_sink->take();
    ASSERT_EQ(held.size(), 1U);
    EXPECT_EQ(keysOf(held[0].ops), (std::vector<std::uint64_t> {0})) << "the due lane op goes first";
    m_sink->grant(1);
    ASSERT_TRUE(m_sink->waitDispatched(3));
    auto pending = m_sink->take();
    ASSERT_EQ(pending.size(), 1U);
    EXPECT_EQ(keysOf(pending[0].ops), (std::vector<std::uint64_t> {1}));
    for (const auto* one : {&held, &pending})
    {
        for (const auto& op : (*one)[0].ops)
        {
            EXPECT_TRUE(resolve(op));
        }
    }

    // A lane op due in 400 ms on a bucket with nothing else.
    auto lateBatch = deliver(c->writer("late"), results, 2, 1);
    ASSERT_EQ(lateBatch.ops.size(), 1U);
    auto late = lateBatch.bucket;
    const auto lateOp = lateBatch.ops[0];
    const auto t = now();
    const auto notBefore = t + std::chrono::milliseconds(400);
    EXPECT_TRUE(late->requeue(requeueOps({lateOp}), spec(true, Delay::At, notBefore), t).notify);
    EXPECT_FALSE(late->eligible(t)) << "a lane that is not due does not make the bucket eligible";
    const auto dispatchedBefore = m_sink->dispatched();
    m_path->scheduler()->notify(late);
    m_sink->grant(TestSink::UNLIMITED);
    ASSERT_TRUE(m_sink->waitDispatched(dispatchedBefore + 1, std::chrono::seconds(5)))
        << "the bucket with only a lane op came back";
    const auto log = m_sink->log();
    EXPECT_EQ(log.back().bucket, "late");
    EXPECT_GE(log.back().at, notBefore) << "not before its notBefore";
    auto lateHeld = m_sink->take();
    ASSERT_EQ(lateHeld.size(), 1U);
    EXPECT_EQ(keysOf(lateHeld[0].ops), (std::vector<std::uint64_t> {2}));
    for (const auto& op : lateHeld[0].ops)
    {
        EXPECT_TRUE(resolve(op));
    }
    ASSERT_TRUE(results->waitTotal(3));
    drain(bucket, {laneOp});
    drain(late, {lateOp});
}

// I66: 8 threads — 2 producers, 4 workers slicing and then resolving or requeueing with random specs (resolving
// what comes back exhausted or closed), a sweeper resolving delivered ops and a closer — keep the E3a invariants:
// every accepted op gets exactly one callback, and the charge and retained ops return to 0.
TEST_F(WriteRetryLaneTest, RetryLaneInvariantsUnderRace)
{
    ASSERT_NO_FATAL_FAILURE(start(1, 2));
    installSink(TestSink::Mode::Hold, 0);
    const std::uint64_t maxBytes = 4096;
    const auto overhead = wireSize(indexOp(id(0), 100)) - 100;
    auto raceSpec = bucketSpec("b", 4U << 20, ic::Overflow::Kind::Reject, maxBytes, 1000000);
    raceSpec.retry = retryPolicy(4, std::nullopt, ic::Duration {1}, ic::Duration {2}, 0.5);
    auto c = client("c", {raceSpec});
    auto results = Results::create();
    // One op of exactly bulk.maxBytes forms the first batch, which gives the test the bucket.
    auto batch = deliver(c->writer("b"), results, 0, 1, maxBytes - overhead);
    ASSERT_EQ(batch.ops.size(), 1U);
    auto bucket = batch.bucket;
    EXPECT_TRUE(resolve(batch.ops[0]));

    std::atomic<bool> stop {false};
    std::atomic<std::uint64_t> nextKey {1};
    std::atomic<std::uint64_t> accepted {1};
    std::atomic<std::uint64_t> requeued {0};
    std::atomic<std::uint64_t> exhausted {0};
    std::atomic<std::uint64_t> closedBack {0};
    std::vector<std::thread> threads;
    for (int p = 0; p < 2; ++p)
    {
        threads.emplace_back(
            [&, writer = c->writer("b")]
            {
                while (!stop.load())
                {
                    const auto key = nextKey.fetch_add(1);
                    if (writer->submit(indexOp(id(key), 100), results->callback(key)).accepted)
                    {
                        accepted.fetch_add(1);
                    }
                    else
                    {
                        std::this_thread::yield();
                    }
                }
            });
    }
    for (int w = 0; w < 4; ++w)
    {
        threads.emplace_back(
            [&, w]
            {
                std::mt19937 rng(static_cast<unsigned>(w) + 1);
                while (!stop.load())
                {
                    const auto t = now();
                    auto slice = bucket->slice(t);
                    if (slice.ops.empty())
                    {
                        std::this_thread::yield();
                        continue;
                    }
                    if (rng() % 3 == 0)
                    {
                        for (const auto& op : slice.ops)
                        {
                            resolve(op);
                        }
                        continue;
                    }
                    const auto pick = rng() % 3;
                    const auto delay = pick == 0 ? Delay::Backoff : (pick == 1 ? Delay::Now : Delay::At);
                    auto result = bucket->requeue(
                        requeueOps(slice.ops),
                        spec(rng() % 2 == 0, delay, t + std::chrono::milliseconds(1), rng() % 2 == 0, rng() % 4 == 0),
                        t);
                    requeued.fetch_add(slice.ops.size());
                    for (const auto& op : result.exhausted)
                    {
                        exhausted.fetch_add(resolve(op, ic::Status::Failed, ic::Cause::RetryExhausted) ? 1 : 0);
                    }
                    for (const auto& op : result.closed)
                    {
                        closedBack.fetch_add(resolve(op, ic::Status::Dropped, ic::Cause::ClientClosed) ? 1 : 0);
                    }
                }
            });
    }
    threads.emplace_back(
        [&]
        {
            std::mt19937 rng(99);
            while (!stop.load())
            {
                for (const auto& op : bucket->delivered())
                {
                    if (rng() % 5 == 0)
                    {
                        resolve(op, ic::Status::Dropped, ic::Cause::Cancelled);
                    }
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        });
    threads.emplace_back(
        [&]
        {
            // Close while everything runs; the workers keep requeueing what they hold.
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            c->requestClose();
        });
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));
    stop.store(true);
    for (auto& thread : threads)
    {
        thread.join();
    }

    for (const auto& op : bucket->close(ic::Cause::ClientClosed))
    {
        resolve(op, ic::Status::Dropped, ic::Cause::ClientClosed);
    }
    for (const auto& op : bucket->delivered())
    {
        resolve(op, ic::Status::Dropped, ic::Cause::ClientClosed);
    }
    EXPECT_TRUE(bucket->empty());
    EXPECT_TRUE(bucket->delivered().empty());
    ASSERT_TRUE(results->waitTotal(accepted.load(), std::chrono::seconds(10)))
        << results->total() << " callbacks for " << accepted.load() << " accepted ops";
    for (const auto& [key, count] : results->counts())
    {
        ASSERT_EQ(count, 1) << "key " << key;
    }
    EXPECT_EQ(results->total(), accepted.load());
    EXPECT_GT(requeued.load(), 0U);
    EXPECT_GT(exhausted.load(), 0U);
    expectInvariants(stats("b"));
    const auto s = stats("b");
    EXPECT_EQ(s.accepted, accepted.load()) << describe(s);
    EXPECT_EQ(s.retained, 0U) << describe(s);
}

// G-diff E3b-1 obj. 3: `toHead` implies Now: a head op asked to wait (At later) is due now, so the lane head stays the
// minimum notBefore and nothing due hides behind it.
TEST_F(WriteRetryLaneTest, ToHeadIsAlwaysDueNow)
{
    ASSERT_NO_FATAL_FAILURE(start());
    installSink(TestSink::Mode::Hold, 0);
    auto c = client("c", {bucketSpec("b", 1U << 20, ic::Overflow::Kind::Reject, 0, 2)});
    auto results = Results::create();
    auto batch = deliver(c->writer("b"), results, 0, 2);
    ASSERT_EQ(batch.ops.size(), 2U);
    auto bucket = batch.bucket;
    const auto o = batch.ops;
    const auto t = now();
    bucket->requeue(requeueOps({o[0]}), spec(false, Delay::Now), t);
    bucket->requeue(requeueOps({o[1]}), spec(false, Delay::At, t + std::chrono::hours(1), true), t);
    EXPECT_EQ(o[1]->notBefore, t) << "toHead forces Now";
    EXPECT_TRUE(bucket->eligible(t));
    EXPECT_EQ(keysOf(bucket->slice(t).ops), (std::vector<std::uint64_t> {1, 0}));
    for (const auto& op : o)
    {
        resolve(op);
    }
}

// G-diff E3b-1 obj. 4: an op resolved while it waits in the retry lane (e.g. claimed by a sweep from an older
// delivered() snapshot) leaves the lane: it is never sliced and sent again, and nothing stays charged.
TEST_F(WriteRetryLaneTest, ResolveWhileInLaneLeavesIt)
{
    ASSERT_NO_FATAL_FAILURE(start());
    installSink(TestSink::Mode::Hold, 0);
    auto c = client("c", {bucketSpec("b", 1U << 20, ic::Overflow::Kind::Reject, 0, 1)});
    auto results = Results::create();
    auto batch = deliver(c->writer("b"), results, 0, 1);
    ASSERT_EQ(batch.ops.size(), 1U);
    auto bucket = batch.bucket;
    const auto op = batch.ops.at(0);
    const auto t = now();
    bucket->requeue(requeueOps({op}), spec(false, Delay::At, t + std::chrono::hours(1)), t);
    EXPECT_FALSE(bucket->empty()) << "waiting in the lane";
    ASSERT_TRUE(resolve(op));
    EXPECT_TRUE(bucket->empty()) << "the resolved op left the lane";
    EXPECT_TRUE(bucket->slice(t + std::chrono::hours(2)).ops.empty()) << "never sent again";
    EXPECT_EQ(stats("b", "c").retained, 0U);
}
