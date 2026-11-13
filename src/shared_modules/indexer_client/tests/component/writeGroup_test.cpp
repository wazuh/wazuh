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

// Confirmable groups (the contract is write/group.hpp): results in add
// order once every op is resolved, reservations that never wait on a Building group, abandonment, GroupTooLarge, the
// commit that flushes now, the overflow policies, close and shutdown, the empty commit and the counters. The WriteTest
// cases run on the programmable sink (writeFixture.hpp); the BulkTest ones on the production sender against a fake
// node (bulkFixture.hpp). Every wait is bounded; every case ends with the charge and the retained ops at 0 (TearDown).

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <future>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "bulkFixture.hpp"
#include "write/budget.hpp"

using namespace write_component;
using bulk_component::BulkItem;
using bulk_component::BulkScript;
using component::AsyncCall;
using component::eventually;

namespace
{
    constexpr std::uint64_t R = wr::RESULT_RESERVE;

    /// Ids of a fixed width: every op of a case has the same wire size.
    std::string key(std::uint64_t n)
    {
        char buffer[16];
        std::snprintf(buffer, sizeof(buffer), "k%07llu", static_cast<unsigned long long>(n));
        return buffer;
    }

    ic::Op op(std::uint64_t n, std::size_t bodyBytes = 1000)
    {
        return indexOp(key(n), bodyBytes);
    }

    ic::Op versionedOp(std::uint64_t n, std::optional<ic::ConflictPolicy> onConflict = std::nullopt)
    {
        ic::Op versioned;
        versioned.kind = ic::Op::Kind::IndexVersionedScript;
        versioned.index = "wazuh-states-test";
        versioned.id = key(n);
        versioned.body = R"({"agent":{"id":"001"}})";
        versioned.version = "3";
        versioned.onConflict = std::move(onConflict);
        return versioned;
    }

    ic::Deadline in(std::chrono::milliseconds timeout)
    {
        return now() + timeout;
    }

    const char* statusName(ic::Status status)
    {
        return status == ic::Status::Ok ? "Ok" : status == ic::Status::Failed ? "Failed" : "Dropped";
    }

    std::string describe(const ic::OpResult& result)
    {
        return std::string(statusName(result.status)) + "/" + ic::toString(result.cause) + " http " +
               std::to_string(result.httpStatus) + " type '" + result.itemErrorType + "' reason '" + result.reason +
               "'";
    }

    /// A bucket of the BulkTest cases: 4 MiB, `maxDocs`-op batches, no age-based batch, a fast retry (5 ms, capped at
    /// 20 ms, no jitter, 5 attempts).
    ic::BucketSpec fastBucket(std::string name, std::size_t maxDocs)
    {
        auto spec = bucketSpec(std::move(name), 4u << 20, ic::Overflow::Kind::Reject, 0, maxDocs);
        spec.retry.maxAttempts = 5;
        spec.retry.maxDuration.reset();
        spec.retry.base = ic::Duration {5};
        spec.retry.cap = ic::Duration {20};
        spec.retry.jitter = 0.0;
        return spec;
    }

    ic::ConflictPolicy retryPolicy(std::uint32_t n)
    {
        ic::ConflictPolicy policy;
        policy.kind = ic::ConflictPolicy::Kind::Retry;
        policy.retryOnConflict = n;
        return policy;
    }

    std::uint64_t globalBuilding(const std::shared_ptr<wr::WritePath>& path)
    {
        return path->budget().building();
    }
} // namespace

// A group of 100 ops in one `_bulk`; the fake rejects op 37 by mapping (400 mapper_parsing_exception) and answers
// the odd positions `updated`: 99 Ok and one Failed(ItemPermanent), each in its add position, once every op is
// resolved. Mutant: the ticket completed before the last resolution.
TEST_F(BulkTest, GroupHundredOneRejected)
{
    constexpr std::size_t N = 100;
    constexpr std::size_t REJECTED = 37;
    std::map<std::size_t, BulkItem> positions;
    for (std::size_t i = 1; i < N; i += 2)
    {
        positions[i] = BulkItem::ok(200, "updated");
    }
    positions[REJECTED] = BulkItem::failed(400, "mapper_parsing_exception", "failed to parse field [p]");
    const auto a = startNode(BulkScript::items(positions));
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {fastBucket("b", 1000)});
    auto group = c->writer("b")->group();
    for (std::uint64_t i = 0; i < N; ++i)
    {
        ASSERT_EQ(group.add(op(i, 32)), ic::Cause::None) << group.lastAddReason();
    }
    const auto ticket = group.commit();
    const auto outcome = ticket.wait(in(5s));
    ASSERT_TRUE(outcome.ok()) << ic::toString(outcome.cause) << ": " << outcome.reason;
    ASSERT_EQ(outcome.value.size(), N);

    const auto received = a.bulk->received();
    ASSERT_EQ(received.size(), 1u) << "one _bulk for the group";
    ASSERT_EQ(received[0].size(), N);
    std::size_t ok = 0;
    for (std::size_t i = 0; i < N; ++i)
    {
        SCOPED_TRACE(i);
        EXPECT_EQ(received[0][i].id, key(i)) << "sent in add order";
        const auto& result = outcome.value[i];
        if (i == REJECTED)
        {
            EXPECT_EQ(result.status, ic::Status::Failed) << describe(result);
            EXPECT_EQ(result.cause, ic::Cause::ItemPermanent) << describe(result);
            EXPECT_EQ(result.httpStatus, 400);
            EXPECT_EQ(result.itemErrorType, "mapper_parsing_exception");
            continue;
        }
        EXPECT_EQ(result.status, ic::Status::Ok) << describe(result);
        EXPECT_EQ(result.outcome, i % 2 == 0 ? ic::ItemOutcome::Created : ic::ItemOutcome::Updated) << describe(result);
        EXPECT_EQ(result.httpStatus, i % 2 == 0 ? 201 : 200) << describe(result);
        ok += result.status == ic::Status::Ok ? 1 : 0;
    }
    EXPECT_EQ(ok, N - 1);
    const auto s = stats("b");
    EXPECT_EQ(s.resolvedOk, N - 1);
    EXPECT_EQ(s.resolvedFailed, 1u);
    expectInvariants(s);
}

// Two groups in Building from two threads, the quota for ~1.5 of them (3 charges; A holds 2, B 1). The
// add that does not fit, from either, is QueueFull before blockTimeout/4 (the room is held by Building groups: never
// waited on); once A is committed and resolved, B goes on. Mutant: waiting for a Building group (the building
// condition removed).
TEST_F(WriteTest, TwoBuildingGroupsDoNotBlock)
{
    ASSERT_NO_FATAL_FAILURE(start());
    installSink(TestSink::Mode::ResolveOk);
    const std::uint64_t charge = wireSize(op(0)) + R;
    auto spec = bucketSpec("b", 3 * charge, ic::Overflow::Kind::Block);
    spec.overflow.blockTimeout = ic::Duration {2000};
    const auto quarter = std::chrono::milliseconds(500);
    auto c = client("c", {spec});
    auto writer = c->writer("b");

    std::promise<void> aBuilt;
    std::promise<std::pair<ic::Cause, std::chrono::nanoseconds>> bRefused;
    std::promise<void> aGone;
    std::promise<std::pair<ic::Cause, ic::Cause>> bFinished; // The add after A, then the commit's outcome.
    auto bFinishedFuture = bFinished.get_future();
    auto bRefusedFuture = bRefused.get_future();
    auto aGoneFuture = aGone.get_future().share();
    auto aBuiltFuture = aBuilt.get_future().share();

    AsyncCall b(
        [&, writer]
        {
            auto groupB = writer->group();
            aBuiltFuture.wait_for(5s);
            const auto first = groupB.add(op(10));
            const auto t0 = now();
            const auto second = groupB.add(op(11));
            bRefused.set_value({first == ic::Cause::None ? second : first, now() - t0});
            if (aGoneFuture.wait_for(5s) != std::future_status::ready)
            {
                bFinished.set_value({ic::Cause::InvalidState, ic::Cause::InvalidState});
                return;
            }
            const auto third = groupB.add(op(12));
            const auto outcome = groupB.commit().wait(in(5s));
            bFinished.set_value({third, outcome.ok() && outcome.value.size() == 2 ? ic::Cause::None : outcome.cause});
        });

    {
        auto groupA = writer->group();
        ASSERT_EQ(groupA.add(op(0)), ic::Cause::None) << groupA.lastAddReason();
        ASSERT_EQ(groupA.add(op(1)), ic::Cause::None) << groupA.lastAddReason();
        aBuilt.set_value();
        ASSERT_EQ(bRefusedFuture.wait_for(5s), std::future_status::ready);
        const auto [refused, waited] = bRefusedFuture.get();
        EXPECT_EQ(refused, ic::Cause::QueueFull) << ic::toString(refused);
        EXPECT_LT(waited, quarter) << "B waited on a Building group";
        EXPECT_EQ(stats("b").charge, 3 * charge);
        EXPECT_EQ(globalBuilding(m_path), 3 * charge);

        const auto t0 = now();
        EXPECT_EQ(groupA.add(op(2)), ic::Cause::QueueFull);
        EXPECT_LT(now() - t0, quarter) << "A waited on a Building group";
        EXPECT_EQ(stats("b").submitTimeout, 0u);

        const auto outcome = groupA.commit().wait(in(5s));
        ASSERT_TRUE(outcome.ok()) << ic::toString(outcome.cause);
        ASSERT_EQ(outcome.value.size(), 2u);
        EXPECT_EQ(outcome.value[0].status, ic::Status::Ok);
        EXPECT_EQ(outcome.value[1].status, ic::Status::Ok);
    } // A's GroupState dies here: its reserves go back.
    EXPECT_TRUE(eventually([&] { return stats("b").charge == charge; }, 5s)) << describe(stats("b"));
    aGone.set_value();
    ASSERT_EQ(bFinishedFuture.wait_for(5s), std::future_status::ready);
    const auto [third, committed] = bFinishedFuture.get();
    EXPECT_EQ(third, ic::Cause::None) << "B goes on once A is gone";
    EXPECT_EQ(committed, ic::Cause::None);
    ASSERT_TRUE(b.wait(5s));
    const auto s = stats("b");
    EXPECT_EQ(s.rejectedQueueFull, 2u);
    EXPECT_EQ(s.submitTimeout, 0u);
    EXPECT_EQ(s.resolvedOk, 4u);
    EXPECT_EQ(s.groupBuilding, 0u);
    EXPECT_EQ(globalBuilding(m_path), 0u);
    expectInvariants(s);
}

// A Block add waits for room held by ops already committed (not by a Building group).
// Group A's 3 ops fill the quota and are committed and held by the sink; B's add from another thread is still waiting
// after 200 ms (QueueFull would mean A's committed room was counted as Building), and gets in before blockTimeout/4
// once A's ops resolve and its state dies. Mutants: heldByGroups always true; `m_building -= reserved` dropped from
// enqueueGroup.
TEST_F(WriteTest, GroupAddWaitsForCommittedRoom)
{
    ASSERT_NO_FATAL_FAILURE(start());
    auto sink = installSink(TestSink::Mode::Hold);
    const std::uint64_t charge = wireSize(op(0)) + R;
    auto spec = bucketSpec("b", 3 * charge, ic::Overflow::Kind::Block);
    spec.overflow.blockTimeout = ic::Duration {2000};
    const auto quarter = std::chrono::milliseconds(500);
    auto c = client("c", {spec});
    auto writer = c->writer("b");
    {
        auto groupA = writer->group();
        for (std::uint64_t i = 0; i < 3; ++i)
        {
            ASSERT_EQ(groupA.add(op(i)), ic::Cause::None) << groupA.lastAddReason();
        }
        const auto dropped = groupA.commit(); // Dropped with the scope: A's state dies with its last op.
    }
    ASSERT_TRUE(sink->waitDispatched(1));
    EXPECT_EQ(stats("b").charge, 3 * charge);
    EXPECT_EQ(globalBuilding(m_path), 0u);

    std::atomic<ic::TimePoint::rep> doneAt {0};
    std::promise<ic::Cause> added;
    auto addedFuture = added.get_future();
    AsyncCall b(
        [&, writer]
        {
            auto groupB = writer->group();
            const auto cause = groupB.add(op(10));
            doneAt = now().time_since_epoch().count();
            added.set_value(cause);
        }); // groupB is abandoned when the thread ends.
    EXPECT_FALSE(eventually([&] { return b.done(); }, 200ms)) << "the add did not wait for the committed room";

    const auto released = now();
    EXPECT_EQ(sink->resolveHeld(), 3u);
    ASSERT_EQ(addedFuture.wait_for(5s), std::future_status::ready);
    EXPECT_EQ(addedFuture.get(), ic::Cause::None);
    EXPECT_LT(ic::TimePoint(ic::TimePoint::duration(doneAt.load())) - released, quarter) << "not woken by the release";
    ASSERT_TRUE(b.wait(5s));
    const auto s = stats("b");
    EXPECT_EQ(s.submitTimeout, 0u);
    EXPECT_EQ(s.rejectedQueueFull, 0u);
    EXPECT_EQ(s.resolvedOk, 3u);
    expectInvariants(s);
}

// The other exit of the same wait: the committed room is never released, so B's add returns
// SubmitTimeout at blockTimeout (counted submitTimeout, nothing charged). Mutants: as GroupAddWaitsForCommittedRoom.
TEST_F(WriteTest, GroupAddTimesOut)
{
    ASSERT_NO_FATAL_FAILURE(start());
    auto sink = installSink(TestSink::Mode::Hold);
    const std::uint64_t charge = wireSize(op(0)) + R;
    auto spec = bucketSpec("b", 3 * charge, ic::Overflow::Kind::Block);
    spec.overflow.blockTimeout = ic::Duration {1000};
    auto c = client("c", {spec});
    auto writer = c->writer("b");
    std::optional<ic::GroupTicket> ticket;
    {
        auto groupA = writer->group();
        for (std::uint64_t i = 0; i < 3; ++i)
        {
            ASSERT_EQ(groupA.add(op(i)), ic::Cause::None) << groupA.lastAddReason();
        }
        ticket.emplace(groupA.commit());
    }
    ASSERT_TRUE(sink->waitDispatched(1));

    auto groupB = writer->group();
    const auto t0 = now();
    EXPECT_EQ(groupB.add(op(10)), ic::Cause::SubmitTimeout) << groupB.lastAddReason();
    EXPECT_GE(now() - t0, std::chrono::milliseconds(900)) << "returned before blockTimeout";
    EXPECT_FALSE(groupB.lastAddReason().empty());
    auto s = stats("b");
    EXPECT_EQ(s.submitTimeout, 1u);
    EXPECT_EQ(s.rejectedQueueFull, 0u);
    EXPECT_EQ(s.charge, 3 * charge) << "nothing charged";
    EXPECT_EQ(s.groupBuilding, 0u);
    expectInvariants(s);

    EXPECT_EQ(sink->resolveHeld(), 3u);
    ASSERT_TRUE(ticket->wait(in(5s)).ok());
}

// A group destroyed without commit gives its whole reservation back at once: charge 0 (never wrapped), building 0
// (bucket and global), groupAbandoned and resolvedDropped counted, and a Block submit waiting for that room gets in.
// Mutants: the reservation never returned; returned twice.
TEST_F(WriteTest, AbandonedGroupReleases)
{
    ASSERT_NO_FATAL_FAILURE(start());
    auto sink = installSink();
    const std::uint64_t charge = wireSize(op(0)) + R;
    auto c = client("c", {bucketSpec("b", 2 * charge, ic::Overflow::Kind::Block)});
    auto writer = c->writer("b");

    std::optional<ic::Group> group(writer->group());
    ASSERT_EQ(group->add(op(0)), ic::Cause::None);
    ASSERT_EQ(group->add(op(1)), ic::Cause::None);
    EXPECT_EQ(stats("b").charge, 2 * charge);
    EXPECT_EQ(stats("b").groupBuilding, 2u);
    EXPECT_EQ(globalBuilding(m_path), 2 * charge);

    std::promise<ic::Submit> blocked;
    auto blockedFuture = blocked.get_future();
    AsyncCall producer([&, writer] { blocked.set_value(writer->submit(op(2))); });
    EXPECT_FALSE(eventually([&] { return producer.done(); }, 200ms)) << "the submit did not wait for room";

    group.reset(); // Abandoned.
    ASSERT_EQ(blockedFuture.wait_for(5s), std::future_status::ready) << "the blocked submit never got in";
    const auto submit = blockedFuture.get();
    EXPECT_TRUE(submit.accepted) << ic::toString(submit.cause);
    ASSERT_TRUE(producer.wait(5s));
    auto s = stats("b");
    EXPECT_EQ(s.charge, charge) << "only the new submit is charged: " << describe(s);
    EXPECT_EQ(m_path->stats().globalCharge, charge);
    EXPECT_EQ(globalBuilding(m_path), 0u);
    EXPECT_EQ(s.groupBuilding, 0u);
    EXPECT_EQ(s.groupAbandoned, 2u);
    EXPECT_EQ(s.resolvedDropped, 2u);
    expectInvariants(s);

    // The new op resolves Dropped(ClientClosed); its reserve goes with its Ticket (TearDown). With no sink
    // capacity it stays queued until the sweep.
    sink->setCapacity(0);
    closeNow(*c);
    const auto closed = submit.ticket.wait(in(5s));
    ASSERT_TRUE(closed.ok());
    EXPECT_EQ(closed.value.cause, ic::Cause::ClientClosed);
    EXPECT_EQ(stats("b").charge, R) << "the payload is released, the ticket's reserve remains";
    expectInvariants(stats("b"));
}

// What the group holds plus the next op above the quota is GroupTooLarge: nothing charged, counted
// rejectedGroupTooLarge (under `submitted`), the group goes on and its commit writes what was added. Mutants: the add
// refused QueueFull; the add charged.
TEST_F(WriteTest, GroupTooLarge)
{
    ASSERT_NO_FATAL_FAILURE(start());
    installSink(TestSink::Mode::ResolveOk);
    const std::uint64_t charge = wireSize(op(0)) + R;
    auto c = client("c", {bucketSpec("b", 3 * charge, ic::Overflow::Kind::Reject)});
    auto group = c->writer("b")->group();
    for (std::uint64_t i = 0; i < 3; ++i)
    {
        ASSERT_EQ(group.add(op(i)), ic::Cause::None) << group.lastAddReason();
    }
    EXPECT_EQ(group.add(op(3)), ic::Cause::GroupTooLarge);
    EXPECT_FALSE(group.lastAddReason().empty());
    auto s = stats("b");
    EXPECT_EQ(s.charge, 3 * charge) << "nothing charged";
    EXPECT_EQ(s.rejectedGroupTooLarge, 1u);
    EXPECT_EQ(s.rejectedQueueFull, 0u);
    EXPECT_EQ(s.groupBuilding, 3u);
    expectInvariants(s);

    const auto outcome = group.commit().wait(in(5s));
    ASSERT_TRUE(outcome.ok()) << ic::toString(outcome.cause);
    ASSERT_EQ(outcome.value.size(), 3u);
    for (const auto& result : outcome.value)
    {
        EXPECT_EQ(result.status, ic::Status::Ok) << describe(result);
    }
    s = stats("b");
    EXPECT_EQ(s.resolvedOk, 3u);
    EXPECT_EQ(s.submitted, 4u);
    expectInvariants(s);
}

// With maxAge 30 s, a high maxDocs and one plain op already pending, a group's commit makes the bucket
// eligible now: one batch with the pending op and the group's leaves in < 1 s. Mutants: enqueueGroup asking for the
// scheduler only when a threshold is crossed; no flushSeq.
TEST_F(WriteTest, CommitFlushesNow)
{
    ASSERT_NO_FATAL_FAILURE(start());
    auto sink = installSink(TestSink::Mode::ResolveOk);
    auto c = client("c", {bucketSpec("b", 1u << 20, ic::Overflow::Kind::Reject, 0, 1000, ic::Duration {30000})});
    auto writer = c->writer("b");
    const auto loose = writer->submit(op(0));
    ASSERT_TRUE(loose.accepted);
    EXPECT_FALSE(eventually([&] { return sink->dispatched() > 0; }, 200ms)) << "the plain op left on its own";

    auto group = writer->group();
    ASSERT_EQ(group.add(op(1)), ic::Cause::None);
    ASSERT_EQ(group.add(op(2)), ic::Cause::None);
    const auto t0 = now();
    const auto ticket = group.commit();
    ASSERT_TRUE(sink->waitDispatched(1, 1s)) << "the commit did not flush the bucket";
    const auto log = sink->log();
    EXPECT_LT(log[0].at - t0, 1s);
    EXPECT_EQ(log[0].ops, 3u) << "the pending op and the group's, in one batch";
    const auto outcome = ticket.wait(in(5s));
    ASSERT_TRUE(outcome.ok());
    EXPECT_EQ(outcome.value.size(), 2u);
    EXPECT_EQ(loose.ticket.wait(in(5s)).value.status, ic::Status::Ok);
    expectInvariants(stats("b"));
}

// An op of the group answered 409 under its own Retry policy, or 429 by item, goes back to the lane; the
// GroupTicket waits for its resend (held by the fake: not ready meanwhile) and completes once, with every result in add
// order. Mutant: the ticket completed when the batch is delivered (the requeued op counted as resolved).
TEST_F(BulkTest, GroupItemRetryCompletesOnce)
{
    const auto a = startNode();
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {fastBucket("b", 1000)});
    auto writer = c->writer("b");

    struct Round final
    {
        const char* name;
        BulkItem first;
        bool versioned; ///< Updates (200 `updated`) whose op 1 has its own Retry; else index ops (201 `created`).
        int okStatus;
    };
    const std::vector<Round> rounds {{"409 Retry", BulkItem::conflict(), true, 200},
                                     {"429 item", BulkItem::rejected(), false, 201}};
    std::uint64_t next = 0;
    std::size_t answered = 0;
    for (const auto& round : rounds)
    {
        SCOPED_TRACE(round.name);
        a.fake->rearmHold();
        a.bulk->push(BulkScript::items({{1, round.first}}));
        a.bulk->push(BulkScript::items().held());
        auto group = writer->group();
        for (int i = 0; i < 3; ++i)
        {
            auto added = round.versioned ? versionedOp(next++, i == 1 ? std::optional(retryPolicy(3)) : std::nullopt)
                                         : op(next++, 32);
            ASSERT_EQ(group.add(std::move(added)), ic::Cause::None) << group.lastAddReason();
        }
        const auto ticket = group.commit();
        ASSERT_TRUE(eventually([&] { return a.bulk->answered() >= answered + 2; }, 5s)) << "no resend";
        const auto received = a.bulk->received();
        ASSERT_EQ(received[answered].size(), 3u);
        ASSERT_EQ(received[answered + 1].size(), 1u) << "only the retried op is sent again";
        EXPECT_EQ(received[answered + 1][0].id, key(next - 2));
        EXPECT_FALSE(eventually([&] { return ticket.ready(); }, 200ms)) << "completed before the resend resolved";
        a.fake->releaseHeld();
        const auto outcome = ticket.wait(in(5s));
        ASSERT_TRUE(outcome.ok()) << ic::toString(outcome.cause);
        ASSERT_EQ(outcome.value.size(), 3u);
        for (std::size_t i = 0; i < 3; ++i)
        {
            SCOPED_TRACE(i);
            EXPECT_EQ(outcome.value[i].status, ic::Status::Ok) << describe(outcome.value[i]);
            EXPECT_EQ(outcome.value[i].httpStatus, round.okStatus) << describe(outcome.value[i]);
        }
        answered += 2;
        EXPECT_FALSE(eventually([&] { return a.bulk->answered() > answered; }, 100ms)) << "sent again";
    }
    const auto s = stats("b");
    EXPECT_EQ(s.resolvedOk, 6u);
    expectInvariants(s);
}

// Split413: a group larger than what the node takes (413 above 2 ops) is split into halves until each is
// accepted; the ticket gets every result in add order (the fake answers op 3 `updated`, wherever its half lands).
TEST_F(BulkTest, GroupAcrossSplit413)
{
    constexpr std::size_t N = 5;
    constexpr std::size_t MARKED = 3;
    const auto marked = key(MARKED);
    const auto a = startNode(BulkScript::tooLargeAbove(2),
                             "green",
                             {},
                             [marked](const httplib::Request&, indexer_client::testing::Rule& reply)
                             {
                                 auto body = nlohmann::json::parse(reply.body, nullptr, false);
                                 if (reply.status != 200 || body.is_discarded() || !body.contains("items"))
                                 {
                                     return;
                                 }
                                 for (auto& item : body["items"])
                                 {
                                     auto& inner = item.begin().value();
                                     if (inner.value("_id", "") == marked)
                                     {
                                         inner["status"] = 200;
                                         inner["result"] = "updated";
                                     }
                                 }
                                 reply.body = body.dump();
                             });
    ASSERT_NO_FATAL_FAILURE(startOn({a.url()}));
    auto c = client("c", {fastBucket("b", 1000)});
    auto group = c->writer("b")->group();
    for (std::uint64_t i = 0; i < N; ++i)
    {
        ASSERT_EQ(group.add(op(i, 32)), ic::Cause::None) << group.lastAddReason();
    }
    const auto outcome = group.commit().wait(in(5s));
    ASSERT_TRUE(outcome.ok()) << ic::toString(outcome.cause);
    ASSERT_EQ(outcome.value.size(), N);
    for (std::size_t i = 0; i < N; ++i)
    {
        SCOPED_TRACE(i);
        const auto& result = outcome.value[i];
        EXPECT_EQ(result.status, ic::Status::Ok) << describe(result);
        EXPECT_EQ(result.httpStatus, i == MARKED ? 200 : 201) << describe(result);
        EXPECT_EQ(result.outcome, i == MARKED ? ic::ItemOutcome::Updated : ic::ItemOutcome::Created);
    }
    std::multiset<std::string> written; // The ids of the accepted requests (the halves may land in any order).
    std::size_t split = 0;
    for (const auto& request : a.bulk->received())
    {
        if (request.size() > 2)
        {
            ++split;
            continue;
        }
        for (const auto& received : request)
        {
            written.insert(received.id.value_or(""));
        }
    }
    EXPECT_GE(split, 1u) << "the whole group answered 413";
    EXPECT_GE(a.bulk->answered(), split + 2) << "written in at least two parts";
    std::multiset<std::string> expected;
    for (std::uint64_t i = 0; i < N; ++i)
    {
        expected.insert(key(i));
    }
    EXPECT_EQ(written, expected) << "each op written once";
    expectInvariants(stats("b"));
}

// DropNewest and DropOldest buckets without room refuse a group's add QueueFull, like Reject: nothing is dropped
// or evicted, the pending ops stay.
TEST_F(WriteTest, GroupDropPoliciesRejectLikeReject)
{
    ASSERT_NO_FATAL_FAILURE(start());
    auto sink = installSink();
    const std::uint64_t charge = wireSize(op(0)) + R;
    auto c = client("c",
                    {bucketSpec("dropNewest", 2 * charge, ic::Overflow::Kind::DropNewest),
                     bucketSpec("dropOldest", 2 * charge, ic::Overflow::Kind::DropOldest)});
    auto results = Results::create();
    std::uint64_t k = 0;
    for (const auto* name : {"dropNewest", "dropOldest"})
    {
        SCOPED_TRACE(name);
        auto writer = c->writer(name);
        for (int i = 0; i < 2; ++i)
        {
            ASSERT_TRUE(writer->submit(op(k), results->callback(k)).accepted);
            ++k;
        }
        auto group = writer->group();
        EXPECT_EQ(group.add(op(100)), ic::Cause::QueueFull);
        EXPECT_FALSE(group.lastAddReason().empty());
        const auto s = stats(name);
        EXPECT_EQ(s.droppedNewest, 0u);
        EXPECT_EQ(s.droppedOldest, 0u);
        EXPECT_EQ(s.rejectedQueueFull, 1u);
        EXPECT_EQ(s.retained, 2u) << "the pending ops stay";
        EXPECT_EQ(s.charge, 2 * charge);
        EXPECT_EQ(s.groupBuilding, 0u);
        expectInvariants(s);
        EXPECT_EQ(results->total(), 0u) << "nothing resolved";
    }
    sink->setCapacity(0); // The pending ops stay queued until the sweep.
    closeNow(*c);
    ASSERT_TRUE(results->waitTotal(4));
    EXPECT_EQ(results->countWith(ic::Status::Dropped, ic::Cause::ClientClosed), 4u);
}

// An add after requestClose() is ClientClosed; a group built before the close and committed after it resolves
// every op Dropped(ClientClosed); after shutdown() the add is refused with the close cause and the commit drops
// Dropped(Shutdown). Nothing stays charged.
TEST_F(WriteTest, GroupAfterCloseAndShutdown)
{
    ASSERT_NO_FATAL_FAILURE(start());
    installSink();
    auto c = client("c", {bucketSpec("b", 1u << 20)});
    auto writer = c->writer("b");
    auto built = writer->group();
    ASSERT_EQ(built.add(op(0)), ic::Cause::None);
    ASSERT_EQ(built.add(op(1)), ic::Cause::None);
    auto late = writer->group();

    c->requestClose();
    EXPECT_EQ(late.add(op(2)), ic::Cause::ClientClosed);
    EXPECT_FALSE(late.lastAddReason().empty());
    EXPECT_EQ(built.add(op(3)), ic::Cause::ClientClosed);
    const auto closed = built.commit().wait(in(5s));
    ASSERT_TRUE(closed.ok()) << ic::toString(closed.cause);
    ASSERT_EQ(closed.value.size(), 2u);
    for (const auto& result : closed.value)
    {
        EXPECT_EQ(result.status, ic::Status::Dropped) << describe(result);
        EXPECT_EQ(result.cause, ic::Cause::ClientClosed) << describe(result);
    }
    EXPECT_TRUE(late.commit().wait(in(5s)).ok()) << "nothing added: the empty commit";
    expectInvariants(stats("b"));

    auto d = client("d", {bucketSpec("b", 1u << 20)});
    auto other = d->writer("b")->group();
    ASSERT_EQ(other.add(op(4)), ic::Cause::None);
    auto afterShutdown = d->writer("b")->group();
    const auto before = stats("b", "d");
    ic::RuntimeOwner::shutdown();
    EXPECT_EQ(afterShutdown.add(op(5)), ic::Cause::Shutdown) << afterShutdown.lastAddReason();
    const auto dropped = other.commit().wait(in(5s));
    ASSERT_TRUE(dropped.ok()) << ic::toString(dropped.cause);
    ASSERT_EQ(dropped.value.size(), 1u);
    EXPECT_EQ(dropped.value[0].status, ic::Status::Dropped) << describe(dropped.value[0]);
    EXPECT_EQ(dropped.value[0].cause, ic::Cause::Shutdown) << describe(dropped.value[0]);
    EXPECT_EQ(before.groupBuilding, 1u);
    expectInvariants(stats("b", "d"));
}

// Lifetime rule (group.hpp): a Group outlives RuntimeOwner::shutdown() while its Client lives and
// no writer is held (the fixture lets go of the write path first, so the runtime owned it alone and its budget died
// with it). The Building group's add is Shutdown, the committed-after-shutdown group resolves Dropped(Shutdown), and
// both die without a bucket call. No sanitizer sees the old bug: make_shared keeps the WritePath's storage while a
// weak_ptr lives (GroupState::path), so the dead budget is still mapped; the guard is the code's (group.hpp, lifetime
// rule).
TEST_F(WriteTest, GroupOutlivesRuntime)
{
    ASSERT_NO_FATAL_FAILURE(start());
    auto c = client("c", {bucketSpec("b", 1u << 20)});
    std::optional<ic::Group> building;
    std::optional<ic::Group> late;
    {
        auto writer = c->writer("b");
        building.emplace(writer->group());
        late.emplace(writer->group());
    } // No IWriter left: nothing but the runtime keeps the write path.
    ASSERT_EQ(building->add(op(0)), ic::Cause::None) << building->lastAddReason();
    ASSERT_EQ(building->add(op(1)), ic::Cause::None) << building->lastAddReason();
    ASSERT_EQ(late->add(op(2)), ic::Cause::None) << late->lastAddReason();
    std::weak_ptr<wr::WritePath> path = m_path;
    m_sink.reset();
    m_path.reset(); // TearDown skips the drain check: the budget it reads is gone.
    ic::RuntimeOwner::shutdown();
    ASSERT_TRUE(path.expired()) << "the write path outlived the runtime";

    EXPECT_EQ(building->add(op(3)), ic::Cause::Shutdown);
    EXPECT_EQ(building->lastAddReason(), "the runtime is shutting down");
    const auto ticket = late->commit();
    EXPECT_TRUE(ticket.ready());
    const auto outcome = ticket.wait(in(1s));
    ASSERT_TRUE(outcome.ok()) << ic::toString(outcome.cause) << ": " << outcome.reason;
    ASSERT_EQ(outcome.value.size(), 1u);
    EXPECT_EQ(outcome.value[0].status, ic::Status::Dropped) << describe(outcome.value[0]);
    EXPECT_EQ(outcome.value[0].cause, ic::Cause::Shutdown) << describe(outcome.value[0]);
    building.reset(); // Abandoned with no budget to return to.
    late.reset();
}

// The dead-bucket paths of the reserve ledger. A group is built, then its Client and writer die
// with the Group alive (the bucket is gone, the write path is not): the whole reservation stays on the global budget;
// the commit resolves every op Dropped(ClientClosed) and returns the payload and `building` at once, the reserves stay
// with the shared group state and go back to the global budget (~GroupState with no bucket) when the ticket and the
// Group die. A null Group's commit has a reason of its own.
TEST_F(WriteTest, GroupReservesReturnedWhenBucketDies)
{
    constexpr std::uint64_t N = 3;
    ASSERT_NO_FATAL_FAILURE(start());
    installSink();
    const std::uint64_t charge = wireSize(op(0)) + R;
    std::optional<ic::Group> group;
    {
        auto c = client("c", {bucketSpec("b", 1u << 20)});
        auto writer = c->writer("b");
        group.emplace(writer->group());
        for (std::uint64_t i = 0; i < N; ++i)
        {
            ASSERT_EQ(group->add(op(i)), ic::Cause::None) << group->lastAddReason();
        }
        EXPECT_EQ(globalCharge(), N * charge);
        writer.reset();
    } // ~Client: the ClientState and its Bucket die; the Group holds them weakly.
    EXPECT_EQ(m_path->stats().buckets.size(), 0u) << "the bucket is gone";
    EXPECT_EQ(globalCharge(), N * charge) << "the reservation is still charged";
    EXPECT_EQ(globalBuilding(m_path), N * charge);

    std::optional<ic::GroupTicket> ticket(group->commit());
    const auto outcome = ticket->wait(in(5s));
    ASSERT_TRUE(outcome.ok()) << ic::toString(outcome.cause) << ": " << outcome.reason;
    ASSERT_EQ(outcome.value.size(), N);
    for (const auto& result : outcome.value)
    {
        EXPECT_EQ(result.status, ic::Status::Dropped) << describe(result);
        EXPECT_EQ(result.cause, ic::Cause::ClientClosed) << describe(result);
    }
    EXPECT_EQ(globalBuilding(m_path), 0u);
    EXPECT_EQ(globalCharge(), N * R) << "payload back, the reserves wait for the group state";
    ticket.reset();
    EXPECT_EQ(globalCharge(), N * R) << "the Group still shares the state";
    group.reset();
    EXPECT_EQ(globalCharge(), 0u) << "the last holder returns the reserves to the global budget";

    ic::Group empty;
    const auto none = empty.commit();
    EXPECT_TRUE(none.ready());
    const auto refused = none.wait(in(1s));
    EXPECT_EQ(refused.cause, ic::Cause::InvalidState);
    EXPECT_EQ(refused.reason, "empty group handle");
}

// A commit without any accepted op is a ready success with an empty vector (also when every add was refused);
// nothing is charged or sent and a second commit is InvalidState.
TEST_F(WriteTest, EmptyCommit)
{
    ASSERT_NO_FATAL_FAILURE(start());
    auto sink = installSink();
    auto c = client("c", {bucketSpec("b", 1u << 20)});
    auto writer = c->writer("b");
    auto empty = writer->group();
    const auto ticket = empty.commit();
    EXPECT_TRUE(ticket.ready());
    const auto outcome = ticket.wait(in(1s));
    ASSERT_TRUE(outcome.ok()) << ic::toString(outcome.cause);
    EXPECT_TRUE(outcome.value.empty());
    EXPECT_EQ(empty.commit().wait(in(1s)).cause, ic::Cause::InvalidState);

    auto refused = writer->group();
    auto invalid = op(0);
    invalid.id.clear();
    EXPECT_EQ(refused.add(invalid), ic::Cause::InvalidArgument);
    const auto none = refused.commit().wait(in(1s));
    ASSERT_TRUE(none.ok()) << ic::toString(none.cause);
    EXPECT_TRUE(none.value.empty());
    EXPECT_FALSE(eventually([&] { return sink->dispatched() > 0; }, 100ms)) << "nothing to send";
    const auto s = stats("b");
    EXPECT_EQ(s.charge, 0u);
    EXPECT_EQ(s.submitted, 1u);
    EXPECT_EQ(s.invalidArgument, 1u);
    expectInvariants(s);
}

// Counters (bucket.hpp): submitted = accepted + rejected* (+ invalidArgument) and accepted = resolved + retained +
// groupBuilding at every step of a group's life: adds, an InvalidArgument, a GroupTooLarge, the commit, the
// resolution, and an abandoned group (groupAbandoned, resolvedDropped).
TEST_F(WriteTest, GroupStatsInvariant)
{
    ASSERT_NO_FATAL_FAILURE(start());
    auto sink = installSink();
    const std::uint64_t charge = wireSize(op(0)) + R;
    auto c = client("c", {bucketSpec("b", 3 * charge, ic::Overflow::Kind::Reject)});
    auto writer = c->writer("b");
    const auto check = [&](const char* step)
    {
        SCOPED_TRACE(step);
        expectInvariants(stats("b"));
    };
    {
        auto group = writer->group();
        ASSERT_EQ(group.add(op(0)), ic::Cause::None);
        check("one add");
        EXPECT_EQ(stats("b").groupBuilding, 1u);
        EXPECT_EQ(stats("b").retained, 0u);
        auto invalid = op(1);
        invalid.id.clear();
        EXPECT_EQ(group.add(invalid), ic::Cause::InvalidArgument);
        check("an InvalidArgument");
        ASSERT_EQ(group.add(op(2)), ic::Cause::None);
        ASSERT_EQ(group.add(op(3)), ic::Cause::None);
        EXPECT_EQ(group.add(op(4)), ic::Cause::GroupTooLarge);
        check("a GroupTooLarge");
        EXPECT_EQ(stats("b").groupBuilding, 3u);
        const auto ticket = group.commit();
        check("committed");
        EXPECT_EQ(stats("b").groupBuilding, 0u);
        EXPECT_EQ(stats("b").retained, 3u);
        ASSERT_TRUE(sink->waitDispatched(1));
        EXPECT_EQ(sink->resolveHeld(), 3u);
        check("resolved");
        ASSERT_TRUE(ticket.wait(in(5s)).ok());
    }
    {
        auto abandoned = writer->group();
        ASSERT_EQ(abandoned.add(op(5)), ic::Cause::None);
        check("building again");
    }
    check("abandoned");
    const auto s = stats("b");
    EXPECT_EQ(s.submitted, 6u);
    EXPECT_EQ(s.accepted, 4u);
    EXPECT_EQ(s.invalidArgument, 1u);
    EXPECT_EQ(s.rejectedGroupTooLarge, 1u);
    EXPECT_EQ(s.resolvedOk, 3u);
    EXPECT_EQ(s.groupAbandoned, 1u);
    EXPECT_EQ(s.resolvedDropped, 1u);
    EXPECT_EQ(s.groupBuilding, 0u);
    EXPECT_EQ(s.charge, 0u);
}

// Group::lastAddReason() says why the last add was refused (InvalidArgument names the field first; QueueFull,
// PayloadTooLarge, GroupTooLarge and InvalidState with a reason of their own) and is empty after an accepted add.
TEST_F(WriteTest, GroupLastAddReason)
{
    ASSERT_NO_FATAL_FAILURE(start());
    installSink();
    const std::uint64_t size = wireSize(op(0));
    const std::uint64_t charge = size + R;
    auto c = client("c",
                    {bucketSpec("full", 3 * charge, ic::Overflow::Kind::Reject, size + 100),
                     bucketSpec("large", 2 * charge, ic::Overflow::Kind::Reject)});
    auto full = c->writer("full");
    ASSERT_TRUE(full->submit(op(0)).accepted);
    ASSERT_TRUE(full->submit(op(1)).accepted);
    auto group = full->group();
    EXPECT_TRUE(group.lastAddReason().empty()) << "nothing refused yet";

    auto invalid = op(2);
    invalid.index = "a b";
    EXPECT_EQ(group.add(invalid), ic::Cause::InvalidArgument);
    EXPECT_EQ(group.lastAddReason().rfind("index:", 0), 0u) << group.lastAddReason();
    EXPECT_EQ(group.add(op(3, size + 100)), ic::Cause::PayloadTooLarge);
    const std::string tooLarge = group.lastAddReason();
    EXPECT_FALSE(tooLarge.empty());
    EXPECT_NE(tooLarge, ic::toString(ic::Cause::PayloadTooLarge));
    ASSERT_EQ(group.add(op(4)), ic::Cause::None);
    EXPECT_TRUE(group.lastAddReason().empty()) << group.lastAddReason();
    EXPECT_EQ(group.add(op(5)), ic::Cause::QueueFull);
    const std::string queueFull = group.lastAddReason();
    EXPECT_FALSE(queueFull.empty());
    EXPECT_NE(queueFull, ic::toString(ic::Cause::QueueFull));

    auto large = c->writer("large")->group();
    ASSERT_EQ(large.add(op(6)), ic::Cause::None);
    ASSERT_EQ(large.add(op(7)), ic::Cause::None);
    EXPECT_EQ(large.add(op(8)), ic::Cause::GroupTooLarge);
    const std::string groupTooLarge = large.lastAddReason();
    EXPECT_FALSE(groupTooLarge.empty());
    EXPECT_NE(groupTooLarge, ic::toString(ic::Cause::GroupTooLarge));
    EXPECT_NE(groupTooLarge, queueFull);

    const auto ticket = group.commit(); // Held by the sink; the close below drops it.
    EXPECT_EQ(group.add(op(9)), ic::Cause::InvalidState);
    EXPECT_FALSE(group.lastAddReason().empty());
    closeNow(*c);
}
