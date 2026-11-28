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

// The staging of post() in the stripes of a DropNewest, unordered bucket
// (bucket.hpp STAGING): the flushes (64 ops, STRIPE_BYTES, the min(1 ms, maxAge) deadline on loop 0 with or without
// sink capacity, the seal), the seal on every close entry (requestClose, stop, a Client destroyed on a runtime
// thread) and its race with a post, and what never stages (other policies, ordered, a tagged post, submit, a group,
// an op that can never fit, a closing bucket). Loop 0 is wedged (a task parked on it) where a case must see ops
// staged: no scheduler pass, so no deadline flush, runs meanwhile.

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstdarg>
#include <cstdio>
#include <future>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "logSink.hpp"
#include "testTimeScale.hpp"
#include "transport/seams.hpp"
#include "write/scheduler.hpp"
#include "writeFixture.hpp"

using namespace write_component;
using component::eventually;
using indexer_client::testing::scaled;

namespace
{
    constexpr auto R = wr::RESULT_RESERVE;

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

    std::shared_ptr<wr::Bucket> bucketOf(ic::Client& c, const std::string& name)
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

    /// K of bucket.hpp STAGING, as the library computes it (INDEXER_CLIENT_TEST_STRIPES fixes it in a test build).
    std::size_t stripeCount()
    {
        return ic::detail::seams::stripeCount().value_or(
            std::max<std::size_t>(1, std::min<std::size_t>(64, 2 * std::thread::hardware_concurrency())));
    }

    /// What a deadline flush may take beyond min(1 ms, maxAge) — the scheduler's tick and the
    /// sink's dispatch — on the suite's time scale. Far below the 100 ms of a STRIPE_AGE mutant at scale 1; at any
    /// scale DeadlineIsOldestPlusStripeAge pins the deadline itself.
    std::chrono::milliseconds deadlineSlack()
    {
        return scaled(std::chrono::milliseconds(40));
    }

    /// The deadline of the contract: min(1 ms, maxAge); a literal, so a mutant of STRIPE_AGE is seen.
    constexpr std::chrono::milliseconds CONTRACT_AGE {1};

    std::string id(std::uint64_t key)
    {
        return "doc-" + std::to_string(key);
    }

    /// A DropNewest, unordered bucket that stages: 16 MiB (STRIPE_BYTES >= 128 KiB, never reached by these ops), no
    /// age-based batch for a minute unless the case lowers it.
    ic::BucketSpec stagedSpec(std::string name,
                              std::size_t maxDocs = 1000000,
                              ic::Duration maxAge = ic::Duration {60000},
                              std::size_t quota = 16u << 20)
    {
        return bucketSpec(std::move(name), quota, ic::Overflow::Kind::DropNewest, 0, maxDocs, maxAge);
    }

    /// An OpState as WriterImpl::prepare builds it, for the cases on a bucket built directly.
    std::shared_ptr<wr::OpState> makeOp(std::uint64_t key, std::size_t bodyBytes = 64)
    {
        auto encoded = wr::encode(indexOp(id(key), bodyBytes), ic::ConflictPolicy {});
        EXPECT_TRUE(encoded.ok()) << encoded.reason;
        auto op = std::make_shared<wr::OpState>();
        op->head = std::move(encoded.value.head);
        op->cachedHead = encoded.value.cachedHead;
        op->body = std::move(encoded.value.body);
        op->payload = wr::chargeSize(op->headView(), op->body);
        op->reserveCharged = true;
        op->firstSubmit = now();
        return op;
    }

    /// Empties a bucket built directly: close() hands back what is queued, each released with its RESULT_RESERVE.
    void drain(wr::Bucket& bucket)
    {
        for (const auto& op : bucket.close(ic::Cause::Shutdown))
        {
            bucket.countResolved(ic::Status::Dropped, ic::Cause::Shutdown);
            bucket.releasePayload(*op, op->reserveCharged);
        }
        EXPECT_EQ(bucket.stats().charge, 0u);
        expectInvariants(bucket.stats());
    }

    /// Parks a task on network loop 0: no scheduler pass (so no deadline flush) runs until release().
    class Loop0Gate final
    {
    public:
        void wedge()
        {
            auto state = m_state;
            ASSERT_TRUE(ic::detail::testing::postToIoLoop(
                [state]
                {
                    std::unique_lock<std::mutex> lock(state->mutex);
                    state->parked = true;
                    state->cv.notify_all();
                    state->cv.wait(lock, [&] { return state->released; });
                },
                0));
            std::unique_lock<std::mutex> lock(m_state->mutex);
            ASSERT_TRUE(m_state->cv.wait_for(lock, scaled(std::chrono::seconds(5)), [&] { return m_state->parked; }));
        }

        void release()
        {
            {
                std::lock_guard<std::mutex> lock(m_state->mutex);
                m_state->released = true;
            }
            m_state->cv.notify_all();
        }

    private:
        struct State final
        {
            std::mutex mutex;
            std::condition_variable cv;
            bool parked {false};
            bool released {false};
        };
        std::shared_ptr<State> m_state = std::make_shared<State>();
    };

    /// A latch a seam waits on (the producer parks there) until the test opens it.
    struct Latch final
    {
        std::mutex mutex;
        std::condition_variable cv;
        bool reached {false};
        bool open {false};

        void arriveAndWait()
        {
            std::unique_lock<std::mutex> lock(mutex);
            reached = true;
            cv.notify_all();
            cv.wait(lock, [&] { return open; });
        }
        bool waitReached()
        {
            std::unique_lock<std::mutex> lock(mutex);
            return cv.wait_for(lock, scaled(std::chrono::seconds(5)), [&] { return reached; });
        }
        void release()
        {
            {
                std::lock_guard<std::mutex> lock(mutex);
                open = true;
            }
            cv.notify_all();
        }
    };
} // namespace

class WriteLocalBatch : public WriteTest
{
protected:
    void TearDown() override
    {
        m_gate.release(); // Never leave loop 0 parked: shutdown() waits on it.
        WriteTest::TearDown();
    }

    std::uint64_t runs() const
    {
        return m_path->scheduler()->stats().runs;
    }

    /// One post retained behind a pending op of `maxAge`, then a staged post (StripeDeadlineWith*PendingAndNoCapacity).
    void stagedBehindPending(ic::Duration maxAge)
    {
        ASSERT_NO_FATAL_FAILURE(start());
        auto sink = installSink(TestSink::Mode::Hold, 0);
        auto c = client("c", {stagedSpec("w", 1000000, maxAge)});
        auto writer = c->writer("w");
        ASSERT_TRUE(writer->post(indexOp(id(0))).accepted);
        ASSERT_TRUE(eventually([&] { return stats("w").retained == 1; }, scaled(std::chrono::milliseconds(1000))))
            << describe(stats("w"));
        // 100 ms (5 x the 20 ms maxAge of the case): its timer fired and found no capacity (no timer re-armed for it).
        std::this_thread::sleep_for(scaled(std::chrono::milliseconds(100)));
        const auto t0 = now();
        ASSERT_TRUE(writer->post(indexOp(id(1))).accepted);
        EXPECT_TRUE(eventually([&] { return stats("w").retained == 2; }, scaled(std::chrono::milliseconds(1000))))
            << "the staged op waited for sink capacity; " << describe(stats("w"));
        EXPECT_LT(now() - t0, CONTRACT_AGE + deadlineSlack()) << "min(1 ms, maxAge) + a tick, on the time scale";
        EXPECT_EQ(bucketOf(*c, "w")->stagedOps(), 0u);
        // No busy loop: with the stripe flushed nothing is armed (the expired pending op waits for sinkReady()).
        const auto before = runs();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        EXPECT_LE(runs() - before, 5u) << "loop 0 spun with an expired pending op and no capacity";
        EXPECT_EQ(sink->dispatched(), 0u);
        sink->grant(TestSink::UNLIMITED);
        closeNow(*c);
    }

    Loop0Gate m_gate;
};

// ---- The flushes

// 63 posts stay staged (nothing admitted, nothing counted); the 64th flushes the stripe with one admission of all of
// them (and asks for the scheduler: the bucket went non-empty).
TEST_F(WriteLocalBatch, FlushesAt64)
{
    wr::GlobalBudget budget(1u << 30);
    auto bucket = std::make_shared<wr::Bucket>("direct", stagedSpec("w"), budget);
    ASSERT_TRUE(bucket->stages());
    std::uint64_t charge = 0;
    for (std::uint64_t k = 0; k + 1 < wr::STRIPE_OPS; ++k)
    {
        auto op = makeOp(k);
        charge += op->payload + R;
        const auto staged = bucket->stage(op);
        ASSERT_TRUE(staged.staged);
        EXPECT_EQ(staged.notify, k == 0) << "only the stripe's empty -> non-empty transition notifies";
        EXPECT_EQ(op, nullptr) << "moved into the stripe";
    }
    EXPECT_EQ(bucket->stagedOps(), wr::STRIPE_OPS - 1);
    EXPECT_EQ(bucket->stats().submitted, 0u);
    EXPECT_EQ(bucket->stats().charge, 0u);
    EXPECT_TRUE(bucket->empty());
    EXPECT_TRUE(bucket->nextDue(now()).has_value()) << "the stripe's deadline";

    auto last = makeOp(wr::STRIPE_OPS);
    charge += last->payload + R;
    const auto staged = bucket->stage(last);
    EXPECT_TRUE(staged.staged);
    EXPECT_TRUE(staged.notify) << "the flush made the bucket non-empty";
    EXPECT_EQ(bucket->stagedOps(), 0u);
    const auto s = bucket->stats();
    EXPECT_EQ(s.submitted, wr::STRIPE_OPS);
    EXPECT_EQ(s.accepted, wr::STRIPE_OPS);
    EXPECT_EQ(s.retained, wr::STRIPE_OPS);
    EXPECT_EQ(s.charge, charge);
    EXPECT_EQ(budget.charge(), charge);
    EXPECT_FALSE(bucket->empty());
    drain(*bucket);
    EXPECT_EQ(budget.charge(), 0u);
}

// The staged payload reaching STRIPE_BYTES = min(bulk.maxBytes, quotaBytes / (2K)) flushes before 64 ops: with
// STRIPE_BYTES = 3.5 payloads, the 4th op flushes the four. 4 KiB bodies, so that the quota (7K payloads) holds the
// four ops and their RESULT_RESERVEs for every K, 1 included (with 64-byte bodies and K < 8 the
// quota was smaller than the four charges and three were dropped).
TEST_F(WriteLocalBatch, FlushesAtByteThreshold)
{
    constexpr std::size_t BODY = 4096;
    const auto payload = makeOp(0, BODY)->payload; // Same id length and body for every key below 10.
    const auto threshold = 3 * payload + payload / 2;
    const auto quota = 2 * stripeCount() * threshold;
    ASSERT_GE(quota - R, threshold) << "bulk.maxBytes must not be the smaller one";
    wr::GlobalBudget budget(1u << 30);
    ASSERT_GE(quota, 4 * (payload + R)) << "the quota must hold the four ops";
    auto bucket = std::make_shared<wr::Bucket>("direct", stagedSpec("w", 1000000, ic::Duration {60000}, quota), budget);
    for (std::uint64_t k = 1; k <= 3; ++k)
    {
        auto op = makeOp(k, BODY);
        ASSERT_EQ(op->payload, payload);
        ASSERT_TRUE(bucket->stage(op).staged);
    }
    EXPECT_EQ(bucket->stagedOps(), 3u);
    EXPECT_EQ(bucket->stats().submitted, 0u);
    auto fourth = makeOp(4, BODY);
    ASSERT_TRUE(bucket->stage(fourth).staged);
    EXPECT_EQ(bucket->stagedOps(), 0u);
    EXPECT_EQ(bucket->stats().accepted, 4u);
    EXPECT_EQ(bucket->stats().retained, 4u);
    drain(*bucket);
}

// A throw in the middle of a flush (seam midAdmitBatch on the 3rd op of the 64) never reaches the producer: the two
// admitted ops left the stripe, the other 62 stay staged (counted nowhere yet) and the next flush admits them.
TEST_F(WriteLocalBatch, AdmitBatchThrowKeepsRest)
{
    wr::GlobalBudget budget(1u << 30);
    auto bucket = std::make_shared<wr::Bucket>("direct", stagedSpec("w"), budget);
    for (std::uint64_t k = 0; k + 1 < wr::STRIPE_OPS; ++k)
    {
        auto op = makeOp(k);
        ASSERT_TRUE(bucket->stage(op).staged);
    }
    int calls = 0;
    ic::testing_hooks::setMidAdmitBatch(
        [&calls]
        {
            if (++calls == 3)
            {
                throw std::runtime_error("midAdmitBatch");
            }
        });
    const auto errorsBefore = ic::detail::testing::usageErrors();
    auto last = makeOp(wr::STRIPE_OPS);
    wr::StageResult staged;
    EXPECT_NO_THROW(staged = bucket->stage(last));
    ic::testing_hooks::setMidAdmitBatch({});
    EXPECT_TRUE(staged.staged) << "the op is staged even though its flush failed";
    EXPECT_TRUE(staged.notify) << "the deadline must be armed for the rest";
    EXPECT_EQ(ic::detail::testing::usageErrors(), errorsBefore + 1);
    EXPECT_EQ(bucket->stagedOps(), wr::STRIPE_OPS - 2);
    EXPECT_EQ(bucket->stats().submitted, 2u);
    EXPECT_EQ(bucket->stats().retained, 2u);
    expectInvariants(bucket->stats());

    bucket->flushDueStripes(now() + std::chrono::seconds(1)); // The next flush: the deadline's.
    EXPECT_EQ(bucket->stagedOps(), 0u);
    EXPECT_EQ(bucket->stats().submitted, wr::STRIPE_OPS);
    EXPECT_EQ(bucket->stats().retained, wr::STRIPE_OPS);
    drain(*bucket);
}

// The deadline of a stripe is exactly its oldest op's firstSubmit + min(1 ms, maxAge) — what nextDue
// reports and what flushDueStripes honours, not a tick before — whatever the suite's time scale.
TEST_F(WriteLocalBatch, DeadlineIsOldestPlusStripeAge)
{
    EXPECT_EQ(wr::STRIPE_AGE, CONTRACT_AGE);
    wr::GlobalBudget budget(1u << 30);
    auto bucket = std::make_shared<wr::Bucket>("direct", stagedSpec("w"), budget);
    auto first = makeOp(1);
    const auto oldest = first->firstSubmit;
    ASSERT_TRUE(bucket->stage(first).staged);
    auto second = makeOp(2);
    ASSERT_TRUE(bucket->stage(second).staged); // Same thread, same stripe: the oldest stays the first one's.
    const auto due = oldest + CONTRACT_AGE;
    EXPECT_EQ(bucket->nextDue(oldest), due);
    bucket->flushDueStripes(due - std::chrono::steady_clock::duration(1));
    EXPECT_EQ(bucket->stagedOps(), 2u) << "flushed before its deadline";
    bucket->flushDueStripes(due);
    EXPECT_EQ(bucket->stagedOps(), 0u);
    EXPECT_EQ(bucket->stats().submitted, 2u);
    drain(*bucket);
}

// A flush is all-or-nothing per op. The global cap holds one op, so the 2nd and 3rd are DropNewest
// drops; the seam throws right before the 2nd one's interval keys are counted (after reserveLocked counted it): that op
// is undone (submitted, accepted, droppedNewest back), it and the 3rd stay staged, and the next flush counts each
// exactly once. Mutant: no undo (the 2nd counted twice).
TEST_F(WriteLocalBatch, AdmitBatchDropThrowUndone)
{
    const auto charge = makeOp(0)->payload + R;
    wr::GlobalBudget budget(2 * charge - 1);
    auto bucket = std::make_shared<wr::Bucket>("direct", stagedSpec("w"), budget);
    for (std::uint64_t k = 1; k <= 3; ++k)
    {
        auto op = makeOp(k);
        ASSERT_EQ(op->payload + R, charge);
        ASSERT_TRUE(bucket->stage(op).staged);
    }
    int calls = 0;
    ic::testing_hooks::setMidAdmitBatch(
        [&calls]
        {
            if (++calls == 3) // 1st op; 2nd op; 2nd op's drop, before its interval keys.
            {
                throw std::runtime_error("midAdmitBatch");
            }
        });
    const auto errorsBefore = ic::detail::testing::usageErrors();
    bucket->flushDueStripes(now() + std::chrono::seconds(1));
    ic::testing_hooks::setMidAdmitBatch({});
    EXPECT_EQ(calls, 3);
    EXPECT_EQ(ic::detail::testing::usageErrors(), errorsBefore + 1);
    auto s = bucket->stats();
    EXPECT_EQ(bucket->stagedOps(), 2u);
    EXPECT_EQ(s.submitted, 1u);
    EXPECT_EQ(s.accepted, 1u);
    EXPECT_EQ(s.droppedNewest, 0u);
    EXPECT_EQ(s.resolvedDropped, 0u);
    EXPECT_EQ(s.retained, 1u);
    EXPECT_EQ(s.charge, charge);
    expectInvariants(s);

    bucket->flushDueStripes(now() + std::chrono::seconds(1));
    s = bucket->stats();
    EXPECT_EQ(bucket->stagedOps(), 0u);
    EXPECT_EQ(s.submitted, 3u);
    EXPECT_EQ(s.accepted, 3u);
    EXPECT_EQ(s.droppedNewest, 2u);
    EXPECT_EQ(s.resolvedDropped, 2u);
    EXPECT_EQ(s.dropped[static_cast<std::size_t>(ic::DropCause::QueueFull)], 2u);
    EXPECT_EQ(s.retained, 1u);
    expectInvariants(s);
    drain(*bucket);
    EXPECT_EQ(budget.charge(), 0u);
}

// What a throw at the seal leaves out of the stripes (m_unstaged). The seam throws on the 3rd op of
// the seal's flush: two ops were admitted, the other three are kept unstaged — counted nowhere and charged nothing
// (bucket and global charge are the two admitted ops') — and close() hands all five back, counting the three submitted
// and accepted then, with no payload nor RESULT_RESERVE to release (reserveCharged false); resolved
// Dropped(ClientClosed) the snapshot balances and the charge ends at 0.
TEST_F(WriteLocalBatch, UnstagedHandedBackByClose)
{
    wr::GlobalBudget budget(1u << 30);
    auto bucket = std::make_shared<wr::Bucket>("direct", stagedSpec("w"), budget);
    std::uint64_t charge = 0;
    for (std::uint64_t k = 1; k <= 5; ++k)
    {
        auto op = makeOp(k);
        if (k <= 2)
        {
            charge += op->payload + R;
        }
        ASSERT_TRUE(bucket->stage(op).staged);
    }
    int calls = 0;
    ic::testing_hooks::setMidAdmitBatch(
        [&calls]
        {
            if (++calls == 3)
            {
                throw std::runtime_error("midAdmitBatch");
            }
        });
    const auto errorsBefore = ic::detail::testing::usageErrors();
    bucket->closeAdmission(ic::Cause::ClientClosed); // The seal flushes, throws on the 3rd op.
    ic::testing_hooks::setMidAdmitBatch({});
    EXPECT_EQ(ic::detail::testing::usageErrors(), errorsBefore + 1);
    EXPECT_EQ(bucket->stagedOps(), 0u) << "the seal leaves nothing staged";
    auto s = bucket->stats();
    EXPECT_EQ(s.submitted, 2u) << "the unstaged ops are counted only when close() hands them back";
    EXPECT_EQ(s.retained, 2u);
    EXPECT_EQ(s.charge, charge) << "the unstaged ops are charged nothing";
    EXPECT_EQ(budget.charge(), charge);
    expectInvariants(s);

    const auto ops = bucket->close(ic::Cause::ClientClosed);
    ASSERT_EQ(ops.size(), 5u);
    std::size_t unstaged = 0;
    for (const auto& op : ops)
    {
        unstaged += (!op->reserveCharged && !op->payloadCharged) ? 1 : 0;
    }
    EXPECT_EQ(unstaged, 3u);
    s = bucket->stats();
    EXPECT_EQ(s.submitted, 5u);
    EXPECT_EQ(s.accepted, 5u);
    for (const auto& op : ops)
    {
        bucket->countResolved(ic::Status::Dropped, ic::Cause::ClientClosed);
        bucket->releasePayload(*op, op->reserveCharged);
    }
    s = bucket->stats();
    EXPECT_EQ(s.resolvedDropped, 5u);
    EXPECT_EQ(s.dropped[static_cast<std::size_t>(ic::DropCause::ClientClosed)], 5u);
    EXPECT_EQ(s.retained, 0u);
    EXPECT_EQ(s.charge, 0u);
    EXPECT_EQ(budget.charge(), 0u);
    expectInvariants(s);
}

// README «Logging»: no mutex held. The quota edge line a stripe flush crosses is written after the
// stripe's mutex is dropped. The quota holds five 8 KiB ops; the flush that admits the 4th crosses 80 %; while the log
// function runs, another thread must be able to take every stripe's mutex (stagedOps). Mutant: the line written
// inside flushStripeLocked (the stripe's mutex held).
TEST_F(WriteLocalBatch, EdgeLineWrittenOutsideStripeMutex)
{
    const auto charge = makeOp(0, 8192)->payload + R;
    wr::GlobalBudget budget(1u << 30);
    auto bucket =
        std::make_shared<wr::Bucket>("direct", stagedSpec("w", 1000000, ic::Duration {60000}, 5 * charge), budget);
    struct Probe final
    {
        std::mutex mutex;
        std::vector<std::future<std::size_t>> helpers;
        int lines {0};
        int free {0};
    };
    auto probe = std::make_shared<Probe>();
    wr::Bucket* raw = bucket.get();
    indexer_client::setLogFunction(
        [probe, raw](const int, const char*, const char*, const int, const char*, const char* format, va_list args)
        {
            char buffer[1024];
            va_list copy;
            va_copy(copy, args);
            std::vsnprintf(buffer, sizeof(buffer), format, copy);
            va_end(copy);
            if (std::string(buffer).find("reached 80% of its quota") == std::string::npos)
            {
                return;
            }
            auto helper = std::async(std::launch::async, [raw] { return raw->stagedOps(); });
            const bool free = helper.wait_for(scaled(std::chrono::seconds(2))) == std::future_status::ready;
            std::lock_guard<std::mutex> lock(probe->mutex);
            ++probe->lines;
            probe->free += free ? 1 : 0;
            probe->helpers.push_back(std::move(helper)); // Joined by the case, never under a stripe's mutex.
        });
    for (std::uint64_t k = 1; k <= 4; ++k)
    {
        auto op = makeOp(k, 8192);
        ASSERT_EQ(op->payload + R, charge);
        ASSERT_TRUE(bucket->stage(op).staged);
    }
    EXPECT_EQ(bucket->stats().accepted, 4u) << "the 4th op's flush admitted all four";
    for (auto& helper : probe->helpers)
    {
        helper.wait();
    }
    indexer_client::setLogFunction({});
    EXPECT_EQ(probe->lines, 1);
    EXPECT_EQ(probe->free, 1) << "the edge line was written holding a stripe's mutex";
    drain(*bucket);
}

// The dedup WARN of a bucket built directly, with synthetic instants and I = 1 s:
// noteDedupResponse at t0 (k = 3) warns; at t0 + 0.8 I (k = 1) it does not, and moves the mark; at t0 + 1.6 I (k = 2)
// it does not either, since t0 + 0.8 I refreshed the mark; at t0 + 2.7 I (k = 1) it warns again, after 1.1 I without
// any 409 applied and with no clean response in between (the bucket was idle). Two WARN in all, each with its k.
// Mutants (c): the mark not refreshed by a call that does not warn (t0 + 1.6 I warns), a WARN on every call.
TEST_F(WriteLocalBatch, DedupWarnRateLimitedByInterval)
{
    constexpr int WARN = 2; // loggerHelper.h's LOGLEVEL_WARNING, as the library passes it.
    const std::string dedup = "Indexer client bucket 'direct/w': the indexer already had ";
    const ic::Duration interval {1000};
    wr::GlobalBudget budget(1u << 30);
    auto bucket = std::make_shared<wr::Bucket>("direct", bucketSpec("w", 1u << 20), budget);
    // The sink outlives any late call of the log function (shared by the installed lambda).
    auto sink = std::make_shared<log_component::Sink>();
    indexer_client::setLogFunction([sink, write = sink->function()](const int level,
                                                                    const char* tag,
                                                                    const char* file,
                                                                    const int line,
                                                                    const char* function,
                                                                    const char* format,
                                                                    va_list args)
                                   { write(level, tag, file, line, function, format, args); });

    const auto t0 = now();
    const auto at = [t0](std::int64_t ms) // An instant t0 + ms (I = 1000 ms: 800 = 0.8 I).
    {
        return t0 + std::chrono::milliseconds(ms);
    };
    bucket->noteDedupResponse(3, at(0), interval);
    EXPECT_EQ(sink->count(WARN, dedup), 1u) << "t0: the first 409 applied warns" << sink->dump();
    bucket->noteDedupResponse(1, at(800), interval);
    EXPECT_EQ(sink->count(WARN, dedup), 1u) << "t0 + 0.8 I: within the interval" << sink->dump();
    bucket->noteDedupResponse(2, at(1600), interval);
    EXPECT_EQ(sink->count(WARN, dedup), 1u) << "t0 + 1.6 I: 0.8 I after the refreshed mark" << sink->dump();
    bucket->noteDedupResponse(1, at(2700), interval);
    EXPECT_EQ(sink->count(WARN, dedup), 2u) << "t0 + 2.7 I: 1.1 I without a 409 applied" << sink->dump();
    // The bound is inclusive, and a response noted late (an earlier `now`, as with concurrent
    // completions) never moves the mark back.
    bucket->noteDedupResponse(4, at(3700), interval);
    EXPECT_EQ(sink->count(WARN, dedup), 3u) << "t0 + 3.7 I: exactly I after the mark" << sink->dump();
    bucket->noteDedupResponse(1, at(3000), interval);
    EXPECT_EQ(sink->count(WARN, dedup), 3u) << "an earlier now: no WARN" << sink->dump();
    bucket->noteDedupResponse(1, at(4699), interval);
    EXPECT_EQ(sink->count(WARN, dedup), 3u) << "t0 + 4.699 I: the mark stayed at 3.7 I" << sink->dump();
    indexer_client::setLogFunction({});

    const auto warns = sink->atLeast(WARN, dedup);
    EXPECT_EQ(warns.size(), 3u) << sink->dump();
    if (warns.size() == 3)
    {
        EXPECT_NE(warns[0].text.find(dedup + "3 document(s)"), std::string::npos) << warns[0].text;
        EXPECT_NE(warns[1].text.find(dedup + "1 document(s)"), std::string::npos) << warns[1].text;
        EXPECT_NE(warns[2].text.find(dedup + "4 document(s)"), std::string::npos) << warns[2].text;
    }
    EXPECT_EQ(bucket->stats().deduplicated, 0u) << "the WARN counts nothing: the counter is countResolved's";
    expectInvariants(bucket->stats());
}

// Three posts and the producer idle: loop 0 admits them at their oldest + min(1 ms, maxAge), not before; the batch
// (maxDocs = 3) leaves at once after that.
TEST_F(WriteLocalBatch, FlushesByDeadline)
{
    ASSERT_NO_FATAL_FAILURE(start());
    auto sink = installSink();
    auto c = client("c", {stagedSpec("w", 3)});
    auto writer = c->writer("w");
    const auto t0 = now();
    for (std::uint64_t k = 0; k < 3; ++k)
    {
        ASSERT_TRUE(writer->post(indexOp(id(k))).accepted);
    }
    ASSERT_TRUE(sink->waitDispatched(1, scaled(std::chrono::milliseconds(2000))));
    const auto at = sink->log().front().at;
    EXPECT_GE(at - t0, wr::STRIPE_AGE) << "admitted before the stripe's deadline";
    EXPECT_LT(at - t0, CONTRACT_AGE + deadlineSlack()) << "min(1 ms, maxAge) + a tick, on the time scale";
    EXPECT_EQ(sink->log().front().ops, 3u);
    EXPECT_EQ(sink->resolveHeld(), 3u);
}

// The only producer posts and its thread ends; nobody posts again: the timer of loop 0 admits what it left staged.
TEST_F(WriteLocalBatch, LastProducerExitsTimerFlushes)
{
    ASSERT_NO_FATAL_FAILURE(start());
    auto sink = installSink();
    auto c = client("c", {stagedSpec("w", 5)});
    auto writer = c->writer("w");
    const auto t0 = now();
    std::thread producer(
        [writer]
        {
            for (std::uint64_t k = 0; k < 5; ++k)
            {
                EXPECT_TRUE(writer->post(indexOp(id(k))).accepted);
            }
        });
    producer.join();
    ASSERT_TRUE(sink->waitDispatched(1, scaled(std::chrono::milliseconds(2000))));
    EXPECT_LT(sink->log().front().at - t0, CONTRACT_AGE + deadlineSlack());
    EXPECT_EQ(bucketOf(*c, "w")->stagedOps(), 0u);
    EXPECT_EQ(stats("w").submitted, 5u);
    EXPECT_EQ(sink->resolveHeld(), 5u);
}

// With no sink capacity the deadline flush still runs (the pass flushes before drr, whatever the capacity): the ops
// are admitted, charged and retained within the deadline, and leave once the sink has room.
TEST_F(WriteLocalBatch, DeadlineFlushWithoutSinkCapacity)
{
    ASSERT_NO_FATAL_FAILURE(start());
    auto sink = installSink(TestSink::Mode::Hold, 0);
    auto c = client("c", {stagedSpec("w", 3)});
    auto writer = c->writer("w");
    const auto t0 = now();
    for (std::uint64_t k = 0; k < 3; ++k)
    {
        ASSERT_TRUE(writer->post(indexOp(id(k))).accepted);
    }
    EXPECT_TRUE(eventually([&] { return stats("w").retained == 3; }, scaled(std::chrono::milliseconds(1000))))
        << describe(stats("w"));
    EXPECT_LT(now() - t0, CONTRACT_AGE + deadlineSlack()) << "the deadline flush waited for sink capacity";
    EXPECT_EQ(bucketOf(*c, "w")->stagedOps(), 0u);
    EXPECT_GT(stats("w").charge, 3 * R);
    EXPECT_EQ(sink->dispatched(), 0u);
    sink->grant(TestSink::UNLIMITED);
    ASSERT_TRUE(sink->waitDispatched(1));
    EXPECT_EQ(sink->resolveHeld(), 3u);
}

// A pending op past its maxAge with no sink capacity (an indexer outage longer than maxAge) makes
// the bucket's nextDue already due, which armTimer does not arm (it would spin until sinkReady()). The stripes'
// deadline must still be armed on its own: a later post is admitted within min(1 ms, maxAge) + a tick, and loop 0 does
// not spin meanwhile. The control keeps the pending op's maxAge a minute away (nextDue in the future).
TEST_F(WriteLocalBatch, StripeDeadlineWithExpiredPendingAndNoCapacity)
{
    stagedBehindPending(ic::Duration {20});
}

TEST_F(WriteLocalBatch, StripeDeadlineWithLivePendingAndNoCapacity)
{
    stagedBehindPending(ic::Duration {60000});
}

// A stripe's empty -> non-empty transition notifies loop 0 only when no timer is known to fire by its
// deadline. Both halves of the Dekker pair between stage() (store `oldest`, load the armed deadline) and a scheduler
// pass (invalidate the armed deadline, read `oldest`, publish the new one) are raced on purpose; in both the op is
// admitted within min(1 ms, maxAge) + a tick. No sink capacity: what is admitted stays retained, nothing is sent.
//  1. A whole pass between the store and the load (seam beforeArmedDueLoad, the stripe's mutex held): it reads this
//     `oldest` and arms the timer at the stripe's deadline, so the post does not notify (no scheduler post of its own)
//     and the timer admits the op. The pass must finish before the deadline (past it, it would wait for the stripe's
//     mutex); an attempt where it does not is retried.
//  2. A post staged while the timer's pass sits between reading the bucket and publishing its new deadline (seam
//     beforePublishArmedDue): the armed deadline it would see is the one that just fired (earlier than its own),
//     but the pass invalidated it at its start, so the post notifies and the next pass arms its deadline.
TEST_F(WriteLocalBatch, StageRacingPassArmsDeadline)
{
    ASSERT_NO_FATAL_FAILURE(start());
    installSink(TestSink::Mode::Hold, 0);
    auto c = client("c", {stagedSpec("w")});
    auto writer = c->writer("w");
    const auto bucket = bucketOf(*c, "w");
    ASSERT_NE(bucket, nullptr);
    const auto scheduler = m_path->scheduler();
    const auto admittedWithin = [&](ic::TimePoint t0)
    {
        EXPECT_TRUE(eventually([&] { return bucket->stagedOps() == 0; }, scaled(std::chrono::milliseconds(1000))))
            << "the staged op was never admitted: no timer armed by its deadline";
        const auto took = std::chrono::duration_cast<std::chrono::microseconds>(now() - t0);
        const auto bound = std::chrono::duration_cast<std::chrono::microseconds>(CONTRACT_AGE + deadlineSlack());
        EXPECT_LT(took.count(), bound.count()) << "us; min(1 ms, maxAge) + a tick, on the time scale";
    };
    std::uint64_t key = 0;

    // 1. The pass inside the stage window.
    struct Window final
    {
        std::atomic<bool> landed {false};
        std::atomic<std::uint64_t> postsAfterPass {0};
    };
    bool landed = false;
    for (int attempt = 0; attempt < 20 && !landed; ++attempt)
    {
        SCOPED_TRACE("pass inside the stage window, attempt " + std::to_string(attempt));
        auto window = std::make_shared<Window>();
        ic::testing_hooks::setBeforeArmedDueLoad(
            [window, scheduler, bucket]
            {
                scheduler->notify(bucket); // A pass on loop 0, now; then wait until loop 0 has run it.
                auto done = std::make_shared<std::promise<void>>();
                auto finished = done->get_future();
                if (!ic::detail::testing::postToIoLoop([done] { done->set_value(); }, 0))
                {
                    return;
                }
                if (finished.wait_for(std::chrono::milliseconds(100)) == std::future_status::ready)
                {
                    window->postsAfterPass = scheduler->stats().posts;
                    window->landed = true;
                }
            });
        const auto t0 = now();
        std::thread producer([writer, k = key++] { EXPECT_TRUE(writer->post(indexOp(id(k))).accepted); });
        producer.join();
        ic::testing_hooks::setBeforeArmedDueLoad({});
        landed = window->landed;
        if (landed)
        {
            EXPECT_EQ(scheduler->stats().posts, window->postsAfterPass.load())
                << "the post notified although the pass in its window armed the stripe's deadline";
            admittedWithin(t0);
        }
        else
        {
            EXPECT_TRUE(eventually([&] { return bucket->stagedOps() == 0; }, scaled(std::chrono::milliseconds(1000))));
        }
    }
    EXPECT_TRUE(landed) << "no pass completed inside the stage window in 20 attempts (loop 0 too slow for 1 ms)";

    // 2. A post inside the timer pass's read -> publish window.
    struct Race final
    {
        std::uint64_t timerFiresBefore {0};
        std::atomic<bool> fired {false};
        std::atomic<bool> posted {false};      // B's post returned (staged), the pass still before its publish.
        std::atomic<std::int64_t> postedB {0}; // now() of B's post, in ticks.
    };
    auto race = std::make_shared<Race>();
    race->timerFiresBefore = scheduler->stats().timerFires;
    const auto keyA = key++;
    const auto keyB = key++;
    ic::testing_hooks::setBeforePublishArmedDue(
        [race, scheduler, bucket, writer, keyB]
        {
            // The timer's pass of A's stripe, once it admitted A (on loop 0: no stripe's mutex is held here).
            if (race->fired || scheduler->stats().timerFires == race->timerFiresBefore || bucket->stagedOps() != 0)
            {
                return;
            }
            race->fired = true;
            race->postedB = now().time_since_epoch().count();
            std::thread producer([writer, keyB] { EXPECT_TRUE(writer->post(indexOp(id(keyB))).accepted); });
            producer.join();
            race->posted = true;
        });
    const auto tA = now();
    ASSERT_TRUE(writer->post(indexOp(id(keyA))).accepted);
    admittedWithin(tA);
    const bool reached = eventually([&] { return race->posted.load(); }, scaled(std::chrono::milliseconds(2000)));
    ic::testing_hooks::setBeforePublishArmedDue({});
    ASSERT_TRUE(reached) << "the timer's pass never reached armTimer with A admitted";
    admittedWithin(ic::TimePoint(ic::TimePoint::duration(race->postedB.load())));
    EXPECT_EQ(stats("w").retained, key);
    closeNow(*c);
}

// Staged ops do not spin loop 0: the pass arms the stripe's deadline and, once flushed, the pending maxAge (a minute
// away): over 200 ms only a handful of passes run, and nothing is dispatched.
TEST_F(WriteLocalBatch, NoBusyLoopWhileStaged)
{
    ASSERT_NO_FATAL_FAILURE(start());
    auto sink = installSink();
    auto c = client("c", {stagedSpec("w")});
    auto writer = c->writer("w");
    const auto before = runs();
    for (std::uint64_t k = 0; k < 3; ++k)
    {
        ASSERT_TRUE(writer->post(indexOp(id(k))).accepted);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_LE(runs() - before, 10u) << "loop 0 spun while ops were staged";
    EXPECT_EQ(stats("w").retained, 3u);
    EXPECT_EQ(sink->dispatched(), 0u);
    closeNow(*c);
}

// ---- The seal

// Half-filled stripes (loop 0 parked, so no deadline flush) and requestClose(): the seal admits them before the
// admission closes, below the flushSeq it sets, so they drain at once (drained = 10, nothing dropped).
TEST_F(WriteLocalBatch, SealOnRequestClose)
{
    ASSERT_NO_FATAL_FAILURE(start());
    installSink(TestSink::Mode::ResolveOk);
    auto c = client("c", {stagedSpec("w")});
    auto writer = c->writer("w");
    auto bucket = bucketOf(*c, "w");
    ASSERT_NO_FATAL_FAILURE(m_gate.wedge());
    for (std::uint64_t k = 0; k < 10; ++k)
    {
        ASSERT_TRUE(writer->post(indexOp(id(k))).accepted);
    }
    ASSERT_EQ(bucket->stagedOps(), 10u);
    ASSERT_EQ(stats("w").submitted, 0u);

    c->requestClose();
    EXPECT_EQ(bucket->stagedOps(), 0u);
    EXPECT_EQ(stats("w").submitted, 10u);
    EXPECT_EQ(stats("w").accepted, 10u);
    EXPECT_EQ(stats("w").retained, 10u);
    m_gate.release();

    const auto report = c->awaitClosed(now() + scaled(std::chrono::seconds(5)));
    ASSERT_TRUE(report.ok());
    EXPECT_EQ(report.value.drained, 10u);
    EXPECT_EQ(report.value.droppedClientClosed, 0u);
    EXPECT_EQ(report.value.droppedShutdown, 0u);
    EXPECT_EQ(stats("w").resolvedOk, 10u);
    EXPECT_EQ(stats("w").charge, 0u);
    expectInvariants(stats("w"));
}

// Half-filled stripes and the runtime's stop(): its sweep seals (Shutdown) and resolves them Dropped(Shutdown);
// nothing stays staged, charge and global charge end at 0. (stop() waits for loop 0 after the sweep: the gate opens
// once the sweep is seen.)
TEST_F(WriteLocalBatch, SealOnStop)
{
    ASSERT_NO_FATAL_FAILURE(start());
    installSink();
    auto c = client("c", {stagedSpec("w")});
    auto writer = c->writer("w");
    auto bucket = bucketOf(*c, "w");
    ASSERT_NO_FATAL_FAILURE(m_gate.wedge());
    for (std::uint64_t k = 0; k < 10; ++k)
    {
        ASSERT_TRUE(writer->post(indexOp(id(k))).accepted);
    }
    ASSERT_EQ(bucket->stagedOps(), 10u);
    auto path = m_path;
    std::thread stopper([path] { path->stop(); });
    const bool swept = eventually([&] { return stats("w").resolvedDropped == 10; }, scaled(std::chrono::seconds(5)));
    m_gate.release();
    stopper.join();
    EXPECT_TRUE(swept) << describe(stats("w"));
    const auto s = stats("w");
    EXPECT_EQ(bucket->stagedOps(), 0u);
    EXPECT_EQ(s.submitted, 10u);
    EXPECT_EQ(s.dropped[static_cast<std::size_t>(ic::DropCause::Shutdown)], 10u);
    EXPECT_EQ(s.charge, 0u);
    EXPECT_EQ(globalCharge(), 0u);
    expectInvariants(s);
}

// Half-filled stripes and the Client destroyed on a runtime thread (a CPU-pool task drops the last reference): its
// immediate sweep (closeClient with sweep) seals and resolves them Dropped(ClientClosed).
TEST_F(WriteLocalBatch, SealOnClientDestroyedOnRuntimeThread)
{
    ASSERT_NO_FATAL_FAILURE(start());
    installSink();
    auto c = client("c", {stagedSpec("w")});
    auto writer = c->writer("w"); // Keeps the bucket alive for the snapshot.
    auto bucket = bucketOf(*c, "w");
    ASSERT_NO_FATAL_FAILURE(m_gate.wedge());
    for (std::uint64_t k = 0; k < 10; ++k)
    {
        ASSERT_TRUE(writer->post(indexOp(id(k))).accepted);
    }
    ASSERT_EQ(bucket->stagedOps(), 10u);
    auto holder = std::make_shared<std::shared_ptr<ic::Client>>(std::move(c));
    auto done = std::make_shared<std::promise<void>>();
    auto future = done->get_future();
    ASSERT_TRUE(ic::detail::testing::postToPool(
        [holder, done]
        {
            holder->reset();
            done->set_value();
        }));
    ASSERT_EQ(future.wait_for(scaled(std::chrono::seconds(5))), std::future_status::ready);
    const auto s = stats("w");
    EXPECT_EQ(bucket->stagedOps(), 0u);
    EXPECT_EQ(s.submitted, 10u);
    EXPECT_EQ(s.resolvedDropped, 10u);
    EXPECT_EQ(s.dropped[static_cast<std::size_t>(ic::DropCause::ClientClosed)], 10u);
    EXPECT_EQ(s.charge, 0u);
    expectInvariants(s);
    m_gate.release();
}

// A post parked between the relaxed check of `closing` and the stripe's mutex (seam beforeStagePush) while the close
// runs: the re-check under the mutex sees it and the post is refused by admit() exactly as today — ClientClosed after
// requestClose(), Shutdown after stop() — with today's counters (submitted, rejectedClosed / rejectedShutdown).
TEST_F(WriteLocalBatch, PostRacingSeal)
{
    ASSERT_NO_FATAL_FAILURE(start());
    installSink();
    auto c = client("c", {stagedSpec("w")});
    auto s = client("s", {stagedSpec("w")});
    struct Round final
    {
        ic::Client* client;
        std::function<void()> close;
        ic::Cause cause;
    };
    auto path = m_path;
    const std::vector<Round> rounds {{c.get(), [&] { c->requestClose(); }, ic::Cause::ClientClosed},
                                     {s.get(), [path] { path->stop(); }, ic::Cause::Shutdown}};
    for (const auto& round : rounds)
    {
        SCOPED_TRACE(ic::toString(round.cause));
        auto writer = round.client->writer("w");
        auto latch = std::make_shared<Latch>();
        ic::testing_hooks::setBeforeStagePush([latch] { latch->arriveAndWait(); });
        ic::Posted posted;
        std::thread producer([writer, &posted] { posted = writer->post(indexOp(id(1))); });
        ASSERT_TRUE(latch->waitReached());
        round.close();
        ic::testing_hooks::setBeforeStagePush({});
        latch->release();
        producer.join();
        EXPECT_FALSE(posted.accepted);
        EXPECT_EQ(posted.cause, round.cause);
        const auto st = stats("w", round.client == c.get() ? "c" : "s");
        EXPECT_EQ(st.submitted, 1u);
        EXPECT_EQ(st.rejectedClosed, 1u);
        EXPECT_EQ(st.rejectedShutdown, round.cause == ic::Cause::Shutdown ? 1u : 0u);
        EXPECT_EQ(st.accepted, 0u);
        EXPECT_EQ(bucketOf(*round.client, "w")->stagedOps(), 0u);
    }
}

// ---- What never stages, and Posted

// Only DropNewest and not ordered stages; Reject, DropOldest, Block and an ordered DropNewest admit op by op.
TEST_F(WriteLocalBatch, OnlyDropNewestUnordered)
{
    wr::GlobalBudget budget(1u << 30);
    auto ordered = stagedSpec("ordered");
    ordered.ordered = true;
    const std::vector<std::pair<ic::BucketSpec, bool>> cases {
        {bucketSpec("reject", 16u << 20, ic::Overflow::Kind::Reject), false},
        {bucketSpec("oldest", 16u << 20, ic::Overflow::Kind::DropOldest), false},
        {bucketSpec("block", 16u << 20, ic::Overflow::Kind::Block), false},
        {ordered, false},
        {stagedSpec("newest"), true}};
    for (const auto& [spec, stages] : cases)
    {
        SCOPED_TRACE(spec.name);
        auto bucket = std::make_shared<wr::Bucket>("direct", spec, budget);
        EXPECT_EQ(bucket->stages(), stages);
        auto op = makeOp(1);
        const auto staged = bucket->stage(op);
        EXPECT_EQ(staged.staged, stages);
        EXPECT_EQ(op == nullptr, stages);
        EXPECT_EQ(bucket->stagedOps(), stages ? 1u : 0u);
        drain(*bucket);
    }
}

// A tagged post admits by itself (counted at once; loop 0 parked, so no flush could hide it), so cancel(tag) sees it
// and resolves it Dropped(Cancelled); an untagged post on the same bucket is staged.
TEST_F(WriteLocalBatch, TaggedPostNotStaged)
{
    ASSERT_NO_FATAL_FAILURE(start());
    installSink();
    auto c = client("c", {stagedSpec("w")});
    auto writer = c->writer("w");
    auto bucket = bucketOf(*c, "w");
    ASSERT_NO_FATAL_FAILURE(m_gate.wedge());
    auto tagged = indexOp(id(1));
    tagged.tag = "batch-7";
    ASSERT_TRUE(writer->post(std::move(tagged)).accepted);
    EXPECT_EQ(bucket->stagedOps(), 0u);
    EXPECT_EQ(stats("w").submitted, 1u);
    EXPECT_EQ(stats("w").retained, 1u);
    const auto cancel = writer->cancel("batch-7");
    EXPECT_TRUE(cancel.ready());
    EXPECT_EQ(stats("w").cancelled, 1u);
    EXPECT_EQ(stats("w").retained, 0u);

    ASSERT_TRUE(writer->post(indexOp(id(2))).accepted);
    EXPECT_EQ(bucket->stagedOps(), 1u);
    EXPECT_EQ(stats("w").submitted, 1u);
    m_gate.release();
    closeNow(*c);
    expectInvariants(stats("w"));
}

// submit() and a group never stage: counted at once (loop 0 parked); only post() stages.
TEST_F(WriteLocalBatch, SubmitNeverStaged)
{
    ASSERT_NO_FATAL_FAILURE(start());
    installSink();
    auto c = client("c", {stagedSpec("w")});
    auto writer = c->writer("w");
    auto bucket = bucketOf(*c, "w");
    ASSERT_NO_FATAL_FAILURE(m_gate.wedge());
    ASSERT_TRUE(writer->submit(indexOp(id(1))).accepted);
    EXPECT_EQ(bucket->stagedOps(), 0u);
    EXPECT_EQ(stats("w").submitted, 1u);
    {
        auto group = writer->group();
        ASSERT_EQ(group.add(indexOp(id(2))), ic::Cause::None);
        group.commit();
    }
    EXPECT_EQ(bucket->stagedOps(), 0u);
    EXPECT_EQ(stats("w").submitted, 2u);
    EXPECT_EQ(stats("w").retained, 2u);
    ASSERT_TRUE(writer->post(indexOp(id(3))).accepted);
    EXPECT_EQ(bucket->stagedOps(), 1u);
    m_gate.release();
    closeNow(*c);
    expectInvariants(stats("w"));
}

// An op that can never fit is refused PayloadTooLarge by admit(), with today's counters, on a staging bucket: wire
// above bulk.maxBytes, and payload + RESULT_RESERVE above the quota through the body's heap slack alone with
// the wire within bulk.maxBytes. (The global-cap condition cannot be isolated: a quota never exceeds the cap.)
TEST_F(WriteLocalBatch, PostedEagerTooLarge)
{
    ASSERT_NO_FATAL_FAILURE(start());
    installSink();
    const std::size_t n = 2000;
    auto probe = indexOp(id(1), n);
    const auto wire = wireSize(probe);
    auto wireBound = stagedSpec("wire");
    wireBound.bulk.maxBytes = wire - 1;
    const std::size_t slackQuota = R + wire + n / 2; // maxBytes = wire + n/2 >= wire; payload + R = R + wire + n > it.
    auto c = client("c", {wireBound, stagedSpec("slack", 1000000, ic::Duration {60000}, slackQuota)});

    const auto tooWide = c->writer("wire")->post(indexOp(id(1), n));
    EXPECT_FALSE(tooWide.accepted);
    EXPECT_EQ(tooWide.cause, ic::Cause::PayloadTooLarge);
    EXPECT_EQ(stats("wire").submitted, 1u);
    EXPECT_EQ(stats("wire").payloadTooLarge, 1u);

    auto slack = indexOp(id(2), n);
    slack.body.reserve(2 * n);
    ASSERT_GE(slack.body.capacity(), 2 * n);
    ASSERT_LE(wireSize(indexOp(id(2), n)), slackQuota - R) << "precondition: the wire fits bulk.maxBytes";
    const auto tooHeavy = c->writer("slack")->post(std::move(slack));
    EXPECT_FALSE(tooHeavy.accepted);
    EXPECT_EQ(tooHeavy.cause, ic::Cause::PayloadTooLarge);
    EXPECT_EQ(stats("slack").submitted, 1u);
    EXPECT_EQ(stats("slack").payloadTooLarge, 1u);
    EXPECT_EQ(bucketOf(*c, "slack")->stagedOps(), 0u);
    expectInvariants(stats("wire"));
    expectInvariants(stats("slack"));
}

// A post once the bucket is closing goes through admit(): ClientClosed after requestClose() (rejectedClosed) and
// Shutdown after stop() (rejectedShutdown), both under `submitted`, as today.
TEST_F(WriteLocalBatch, ClosingUsesAdmitCounters)
{
    ASSERT_NO_FATAL_FAILURE(start());
    installSink();
    auto c = client("c", {stagedSpec("w")});
    auto s = client("s", {stagedSpec("w")});
    auto writerC = c->writer("w"); // Before the close: a closed client hands out no writer.
    auto writerS = s->writer("w");
    c->requestClose();
    const auto closed = writerC->post(indexOp(id(1)));
    EXPECT_FALSE(closed.accepted);
    EXPECT_EQ(closed.cause, ic::Cause::ClientClosed);
    EXPECT_EQ(stats("w", "c").submitted, 1u);
    EXPECT_EQ(stats("w", "c").rejectedClosed, 1u);
    EXPECT_EQ(stats("w", "c").rejectedShutdown, 0u);

    m_path->stop();
    const auto shut = writerS->post(indexOp(id(2)));
    EXPECT_FALSE(shut.accepted);
    EXPECT_EQ(shut.cause, ic::Cause::Shutdown);
    EXPECT_EQ(stats("w", "s").submitted, 1u);
    EXPECT_EQ(stats("w", "s").rejectedClosed, 1u);
    EXPECT_EQ(stats("w", "s").rejectedShutdown, 1u);
    EXPECT_EQ(bucketOf(*s, "w")->stagedOps(), 0u);
}
