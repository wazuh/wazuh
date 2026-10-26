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

// The ambiguous 5xx of a bucket (plan-E6a §Tests CA-E6a-2, I105/I105b): a `_bulk` answered 500, 502 or 504 may have
// been applied, so a bucket with onAmbiguous5xx = Fail resolves its ops Failed(Ambiguous) without resending them and
// logs one WARN per edge (the first one after a 2xx bulk); 503 stays retried and Retry keeps the previous behaviour.
// Every case runs the production sink over the real transport against one fake (bulkFixture.hpp); the WARN is written
// by the completion after its ops are resolved (it counts the ops it resolved, G-diff E6a obj. 4), so the cases wait
// for it (warned()) instead of reading it as soon as the results are in.

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include "bulkFixture.hpp"
#include "write/sender.hpp"

using namespace write_component;
using bulk_component::BulkScript;
using component::eventually;

namespace
{
    // loggerHelper.h's WARN as the library passes it to the log function.
    constexpr int WARN = 2;

    /// The process log function of the case: every line, formatted, with its level.
    class LogLines final
    {
    public:
        indexer_client::LogFunction function()
        {
            return
                [this](
                    const int level, const char*, const char*, const int, const char*, const char* format, va_list args)
            {
                va_list copy;
                va_copy(copy, args);
                char buffer[4096];
                std::vsnprintf(buffer, sizeof(buffer), format, copy);
                va_end(copy);
                std::lock_guard<std::mutex> lock(m_mutex);
                m_lines.emplace_back(level, buffer);
            };
        }

        /// Waits up to 3 s for exactly `n` lines at `level` containing `part` (the completion writes the line after
        /// resolving the ops); true once there are.
        bool warned(int level, const std::string& part, std::size_t n) const
        {
            return eventually([&] { return count(level, part) == n; }, 3s);
        }

        /// Lines at `level` containing `part`.
        std::size_t count(int level, const std::string& part) const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            std::size_t n = 0;
            for (const auto& [lineLevel, text] : m_lines)
            {
                n += (lineLevel == level && text.find(part) != std::string::npos) ? 1 : 0;
            }
            return n;
        }

    private:
        mutable std::mutex m_mutex;
        std::vector<std::pair<int, std::string>> m_lines;
    };

    /// A bucket of `maxDocs`-op batches with a fast retry (5 ms, capped at 20 ms, no jitter, 5 attempts) and `policy`.
    ic::BucketSpec ambiguousBucket(std::string name, std::size_t maxDocs, ic::AmbiguousPolicy policy)
    {
        auto spec = bucketSpec(std::move(name), 4u << 20, ic::Overflow::Kind::Reject, 0, maxDocs);
        spec.retry.maxAttempts = 5u;
        spec.retry.maxDuration.reset();
        spec.retry.base = ic::Duration {5};
        spec.retry.cap = ic::Duration {20};
        spec.retry.jitter = 0.0;
        spec.onAmbiguous5xx = policy;
        return spec;
    }

    /// failed.ambiguous of `bucket` in `c`'s metrics.
    std::uint64_t failedAmbiguous(ic::Client& c, const std::string& bucket)
    {
        for (const auto& b : c.metrics().buckets)
        {
            if (b.bucket == bucket)
            {
                return b.failed[static_cast<std::size_t>(ic::FailCause::Ambiguous)];
            }
        }
        ADD_FAILURE() << "no bucket " << bucket;
        return 0;
    }

    /// The WARN of the ambiguous edge of `bucket` (consumer "c").
    std::string warnOf(const std::string& bucket)
    {
        return "Indexer client bucket 'c/" + bucket + "' got an ambiguous HTTP ";
    }
} // namespace

class BulkAmbiguousTest : public BulkTest
{
protected:
    LogLines m_logs;

    void SetUp() override
    {
        BulkTest::SetUp();
        indexer_client::setLogFunction(m_logs.function()); // Valid only while no runtime runs (I56).
    }

    void TearDown() override
    {
        BulkTest::TearDown();
        indexer_client::setLogFunction({});
    }

    /// Submits `count` ops (keys from `key`) to `bucket` and waits for their results.
    void submitAndWait(ic::Client& c,
                       const std::string& bucket,
                       const std::shared_ptr<Results>& results,
                       std::uint64_t& key,
                       std::size_t count)
    {
        const auto before = results->total();
        auto writer = c.writer(bucket);
        for (std::size_t i = 0; i < count; ++i, ++key)
        {
            ASSERT_TRUE(writer->submit(indexOp("k" + std::to_string(key)), results->callback(key)).accepted);
        }
        ASSERT_TRUE(results->waitTotal(before + count, 10s));
    }
};

// CA-E6a-2: a bucket with onAmbiguous5xx = Fail and a bulk of 4 ops answered 500, 502 or 504 ⇒ the 4 ops
// Failed(Ambiguous) with that httpStatus, exactly one request (never resent), failed.ambiguous = 4 and one WARN naming
// the bucket, the status and the ops. Mutant: the Fail policy ignored (the 5xx retried until it succeeds).
TEST_F(BulkAmbiguousTest, FailPolicyResolves500502504)
{
    constexpr std::size_t OPS = 4;
    const auto a = startNode();
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c",
                    {ambiguousBucket("b500", OPS, ic::AmbiguousPolicy::Fail),
                     ambiguousBucket("b502", OPS, ic::AmbiguousPolicy::Fail),
                     ambiguousBucket("b504", OPS, ic::AmbiguousPolicy::Fail)});
    auto results = Results::create();
    std::uint64_t key = 0;
    for (const int status : {500, 502, 504})
    {
        SCOPED_TRACE(status);
        const std::string bucket = "b" + std::to_string(status);
        const auto requests = a.bulk->answered();
        const auto first = key;
        a.bulk->push(BulkScript::serverError(status));
        ASSERT_NO_FATAL_FAILURE(submitAndWait(*c, bucket, results, key, OPS));
        for (auto k = first; k < key; ++k)
        {
            const auto result = results->result(k);
            ASSERT_TRUE(result.has_value()) << k;
            EXPECT_EQ(result->status, ic::Status::Failed) << k << ": " << ic::toString(result->cause);
            EXPECT_EQ(result->cause, ic::Cause::Ambiguous) << k << ": " << result->reason;
            EXPECT_EQ(result->httpStatus, status) << k;
            EXPECT_EQ(result->reason, "ambiguous HTTP " + std::to_string(status) + " (not resent)") << k;
            EXPECT_EQ(results->count(k), 1) << k;
        }
        EXPECT_EQ(a.bulk->answered(), requests + 1);
        EXPECT_FALSE(eventually([&] { return a.bulk->answered() > requests + 1; }, 200ms)) << "resent";
        EXPECT_EQ(failedAmbiguous(*c, bucket), OPS);
        EXPECT_TRUE(m_logs.warned(WARN, warnOf(bucket) + std::to_string(status) + " for a bulk of 4 operations", 1u));
    }
}

// CA-E6a-2: 503 is not ambiguous: a Fail bucket retries it (three 503, then 200 ⇒ Ok after four requests), with no
// failed.ambiguous and no WARN.
TEST_F(BulkAmbiguousTest, FailPolicyStillRetries503)
{
    const auto a = startNode();
    for (int i = 0; i < 3; ++i)
    {
        a.bulk->push(BulkScript::serverError(503));
    }
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {ambiguousBucket("b", 2, ic::AmbiguousPolicy::Fail)});
    auto results = Results::create();
    std::uint64_t key = 0;
    ASSERT_NO_FATAL_FAILURE(submitAndWait(*c, "b", results, key, 2));
    EXPECT_EQ(results->countWith(ic::Status::Ok, ic::Cause::None), 2u);
    EXPECT_EQ(a.bulk->answered(), 4u);
    EXPECT_EQ(failedAmbiguous(*c, "b"), 0u);
    EXPECT_EQ(m_logs.count(WARN, warnOf("b")), 0u);
}

// CA-E6a-2: the default policy (Retry) keeps resending an ambiguous 5xx: three 502, then 200 ⇒ Ok after four requests,
// with no failed.ambiguous and no WARN.
TEST_F(BulkAmbiguousTest, RetryPolicyUnchanged)
{
    const auto a = startNode();
    for (int i = 0; i < 3; ++i)
    {
        a.bulk->push(BulkScript::serverError(502));
    }
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto spec = ambiguousBucket("b", 2, ic::AmbiguousPolicy::Retry);
    EXPECT_EQ(spec.onAmbiguous5xx, ic::BucketSpec {}.onAmbiguous5xx) << "Retry is the default";
    auto c = client("c", {spec});
    auto results = Results::create();
    std::uint64_t key = 0;
    ASSERT_NO_FATAL_FAILURE(submitAndWait(*c, "b", results, key, 2));
    EXPECT_EQ(results->countWith(ic::Status::Ok, ic::Cause::None), 2u);
    EXPECT_EQ(a.bulk->answered(), 4u);
    EXPECT_EQ(failedAmbiguous(*c, "b"), 0u);
    EXPECT_EQ(m_logs.count(WARN, warnOf("b")), 0u);
}

// CA-E6a-2, I105b: the WARN is an edge. Fail, 2xx, Fail ⇒ two WARN (the 2xx re-arms it); Fail, Fail ⇒ one, while
// failed.ambiguous counts every op. Mutant: a 2xx that never re-arms (one WARN in the first bucket).
TEST_F(BulkAmbiguousTest, WarnRearmsAfter2xx)
{
    const auto a = startNode();
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c",
                    {ambiguousBucket("rearm", 1, ic::AmbiguousPolicy::Fail),
                     ambiguousBucket("twice", 1, ic::AmbiguousPolicy::Fail)});
    auto results = Results::create();
    std::uint64_t key = 0;

    a.bulk->push(BulkScript::serverError(502));
    ASSERT_NO_FATAL_FAILURE(submitAndWait(*c, "rearm", results, key, 1));
    EXPECT_TRUE(m_logs.warned(WARN, warnOf("rearm"), 1u));
    ASSERT_NO_FATAL_FAILURE(submitAndWait(*c, "rearm", results, key, 1)); // 2xx.
    EXPECT_EQ(results->countWith(ic::Status::Ok, ic::Cause::None), 1u);
    EXPECT_EQ(m_logs.count(WARN, warnOf("rearm")), 1u) << "a 2xx logs nothing";
    a.bulk->push(BulkScript::serverError(504));
    ASSERT_NO_FATAL_FAILURE(submitAndWait(*c, "rearm", results, key, 1));
    EXPECT_TRUE(m_logs.warned(WARN, warnOf("rearm"), 2u));
    EXPECT_EQ(m_logs.count(WARN, warnOf("rearm") + "504 for a bulk of 1 operations"), 1u);
    EXPECT_EQ(failedAmbiguous(*c, "rearm"), 2u);

    for (int i = 0; i < 2; ++i)
    {
        a.bulk->push(BulkScript::serverError(500));
        ASSERT_NO_FATAL_FAILURE(submitAndWait(*c, "twice", results, key, 1));
        EXPECT_TRUE(m_logs.warned(WARN, warnOf("twice"), 1u)) << i;
    }
    EXPECT_FALSE(eventually([&] { return m_logs.count(WARN, warnOf("twice")) > 1; }, 200ms))
        << "no 2xx in between: one edge";
    EXPECT_EQ(failedAmbiguous(*c, "twice"), 2u);
    EXPECT_EQ(results->countWith(ic::Status::Failed, ic::Cause::Ambiguous), 4u);
}

// G-diff E6a obj. 4: the Fail decision is taken before the completion's exception guard, so a completion that throws
// (seam beforeCompletion) resolves the batch Failed(Ambiguous) instead of the usual requeue with an attempt: exactly
// one request, never resent. Mutant: the catch requeues an ambiguous batch (requeueAfterFailure; the op ends Ok after a
// second request).
TEST_F(BulkAmbiguousTest, FailPolicyNeverResentAfterCompletionException)
{
    const auto a = startNode();
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto throwNext = std::make_shared<std::atomic<int>>(1);
    ic::testing_hooks::setBeforeCompletion(
        [throwNext]()
        {
            if (throwNext->load() > 0)
            {
                throwNext->fetch_sub(1);
                throw std::runtime_error("injected");
            }
        });
    auto c = client("c", {ambiguousBucket("b", 2, ic::AmbiguousPolicy::Fail)});
    auto results = Results::create();
    std::uint64_t key = 0;
    a.bulk->push(BulkScript::serverError(502));
    ASSERT_NO_FATAL_FAILURE(submitAndWait(*c, "b", results, key, 2));
    EXPECT_EQ(throwNext->load(), 0) << "the seam did not run";
    for (std::uint64_t k = 0; k < key; ++k)
    {
        const auto result = results->result(k);
        ASSERT_TRUE(result.has_value()) << k;
        EXPECT_EQ(result->status, ic::Status::Failed) << k << ": " << ic::toString(result->cause);
        EXPECT_EQ(result->cause, ic::Cause::Ambiguous) << k << ": " << result->reason;
        EXPECT_EQ(result->httpStatus, 502) << k;
        EXPECT_EQ(result->reason, "ambiguous HTTP 502 (not resent)") << k;
        EXPECT_EQ(results->count(k), 1) << k;
    }
    EXPECT_EQ(a.bulk->answered(), 1u);
    EXPECT_FALSE(eventually([&] { return a.bulk->answered() > 1u; }, 200ms)) << "resent";
    EXPECT_EQ(failedAmbiguous(*c, "b"), 2u);
    EXPECT_TRUE(m_logs.warned(WARN, warnOf("b") + "502 for a bulk of 2 operations", 1u));
}

// G-rama round 2 (plan 18, Codex): a `_bulk` whose response goes over max_response_bytes was answered by the node, so
// the indexer may have applied it. A bucket with onAmbiguous5xx = Fail and a bulk of 4 data-stream ops (no `_id`, as
// the engine's events) ⇒ exactly one request, the 4 ops Failed(Ambiguous) with reason "ambiguous response over
// maxResponseBytes (not resent)", failed.ambiguous = 4, no split and one WARN that names the cap (not the status); a
// Retry bucket (ops with `_id`, a resend overwrites) still halves the batch until every answer fits. Mutant: the old
// code (Split under both policies: the halves are resent and the indexer receives every op twice).
TEST_F(BulkAmbiguousTest, ResponseTooLargeFailPolicyNeverResent)
{
    constexpr std::size_t OPS = 4;
    const std::string index = "logs-" + std::string(200, 'i');
    // The cap: one item of either kind fits, two do not; the health body fits.
    const auto render = [&](const std::string& action, std::optional<std::string> docId, std::size_t n)
    {
        std::vector<indexer_client::testing::BulkOp> ops;
        for (std::size_t i = 0; i < n; ++i)
        {
            ops.push_back({action, index, docId, "{}"});
        }
        return indexer_client::testing::BulkResponder::renderItems(ops, BulkScript::items(), 100000).size();
    };
    const auto one = std::max(render("create", std::nullopt, 1), render("index", "k100", 1));
    const auto two = std::min(render("create", std::nullopt, 2), render("index", "k0", 2));
    ASSERT_LT(one + 64, two);
    const auto cap = one + (two - one) / 2;
    ASSERT_LT(indexer_client::testing::healthBody("green").size() + 50, cap) << "the probe must still fit";

    const auto a = startNode();
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}, std::chrono::hours(1), {{"max_response_bytes", std::to_string(cap)}}));
    auto c = client("c",
                    {ambiguousBucket("fail", OPS, ic::AmbiguousPolicy::Fail),
                     ambiguousBucket("retry", OPS, ic::AmbiguousPolicy::Retry)});
    auto results = Results::create();

    // Fail: one request, never split nor resent.
    const auto splits = wr::senderStats().splits;
    auto failWriter = c->writer("fail");
    for (std::uint64_t k = 0; k < OPS; ++k)
    {
        ic::Op op;
        op.kind = ic::Op::Kind::IndexDataStream;
        op.index = index;
        op.body = R"({"p":1})";
        ASSERT_TRUE(failWriter->submit(std::move(op), results->callback(k)).accepted);
    }
    ASSERT_TRUE(results->waitTotal(OPS, 10s));
    for (std::uint64_t k = 0; k < OPS; ++k)
    {
        const auto result = results->result(k);
        ASSERT_TRUE(result.has_value()) << k;
        EXPECT_EQ(result->status, ic::Status::Failed) << k << ": " << ic::toString(result->cause);
        EXPECT_EQ(result->cause, ic::Cause::Ambiguous) << k << ": " << result->reason;
        EXPECT_EQ(result->reason, "ambiguous response over maxResponseBytes (not resent)") << k;
        EXPECT_EQ(results->count(k), 1) << k;
    }
    EXPECT_EQ(a.bulk->answered(), 1u);
    EXPECT_FALSE(eventually([&] { return a.bulk->answered() > 1u; }, 200ms)) << "resent";
    EXPECT_EQ(wr::senderStats().splits, splits) << "a Fail bucket never splits a response over the cap";
    EXPECT_EQ(failedAmbiguous(*c, "fail"), OPS);
    EXPECT_TRUE(m_logs.warned(
        WARN, "Indexer client bucket 'c/fail' got a response over max_response_bytes for a bulk of 4 operations", 1u));
    EXPECT_EQ(m_logs.count(WARN, warnOf("fail")), 0u) << "no misleading status in the WARN";
    EXPECT_EQ(nodeState(0), ic::HealthView::NodeState::Available) << "a response over the cap is not the node's fault";

    // Retry: split as before, every op Ok once its answer fits.
    auto retryWriter = c->writer("retry");
    for (std::uint64_t k = OPS; k < 2 * OPS; ++k)
    {
        ASSERT_TRUE(retryWriter->submit(indexOp("k" + std::to_string(k), 16, index), results->callback(k)).accepted);
    }
    ASSERT_TRUE(results->waitTotal(2 * OPS, 10s));
    for (std::uint64_t k = OPS; k < 2 * OPS; ++k)
    {
        const auto result = results->result(k);
        ASSERT_TRUE(result.has_value()) << k;
        EXPECT_EQ(result->status, ic::Status::Ok) << k << ": " << ic::toString(result->cause) << " " << result->reason;
    }
    EXPECT_GE(wr::senderStats().splits, splits + 1u);
    EXPECT_EQ(failedAmbiguous(*c, "retry"), 0u);
    EXPECT_EQ(m_logs.count(WARN, "bucket 'c/retry'"), 0u);
}
