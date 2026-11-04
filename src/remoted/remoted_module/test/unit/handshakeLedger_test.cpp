/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "http_server/handshakeLedger.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using remoted::http::HandshakeLedger;

TEST(HandshakeLedgerTest, StartsEmpty)
{
    HandshakeLedger ledger;
    const auto s = ledger.snapshot();
    EXPECT_EQ(s.open, 0U);
    EXPECT_EQ(s.handshaking, 0U);
    EXPECT_EQ(s.timeoutsTotal, 0U);
    EXPECT_EQ(s.rejectedPerSourceTotal, 0U);
}

// The whole life of an honest connection: counted open and handshaking from the start of the
// handshake, still open once it succeeds, gone when it closes.
TEST(HandshakeLedgerTest, CountsAConnectionFromHandshakeToClose)
{
    HandshakeLedger ledger;

    auto share = ledger.beginHandshake(1, "10.0.0.1");
    ASSERT_TRUE(share);
    EXPECT_EQ(ledger.snapshot().open, 1U);
    EXPECT_EQ(ledger.snapshot().handshaking, 1U);

    share.release();
    EXPECT_EQ(ledger.snapshot().open, 1U);
    EXPECT_EQ(ledger.snapshot().handshaking, 0U);

    ledger.closed(1);
    EXPECT_EQ(ledger.snapshot().open, 0U);
    EXPECT_EQ(ledger.snapshot().handshaking, 0U);
}

// The bug the ledger replaces: RESTinio sends a closed notice for a connection whose handshake
// failed, with no accepted notice before it. A connection closed while still handshaking must
// leave both levels at zero -- never wrap -- and its share must not release anything a second time.
TEST(HandshakeLedgerTest, ClosingWhileHandshakingReleasesBothLevels)
{
    HandshakeLedger ledger;
    auto share = ledger.beginHandshake(7, "10.0.0.1");
    ASSERT_TRUE(share);

    ledger.closed(7);
    share.release();

    const auto s = ledger.snapshot();
    EXPECT_EQ(s.open, 0U);
    EXPECT_EQ(s.handshaking, 0U);
}

// Notices for connections the ledger never counted (or already uncounted) change nothing: this is
// what keeps a duplicate closed notice, or one racing reset(), from underflowing anything.
TEST(HandshakeLedgerTest, UnknownAndRepeatedNoticesAreNoOps)
{
    HandshakeLedger ledger;
    ledger.closed(42);
    EXPECT_EQ(ledger.snapshot().open, 0U);

    auto share = ledger.beginHandshake(1, "10.0.0.1");
    ASSERT_TRUE(share);
    share.release();
    share.release();
    ledger.closed(1);
    ledger.closed(1);

    const auto s = ledger.snapshot();
    EXPECT_EQ(s.open, 0U);
    EXPECT_EQ(s.handshaking, 0U);
}

TEST(HandshakeLedgerTest, PerSourceCapRefusesTheExcessOnly)
{
    HandshakeLedger ledger;
    ledger.setMaxPerSource(2);

    auto first = ledger.beginHandshake(1, "10.0.0.1");
    auto second = ledger.beginHandshake(2, "10.0.0.1");
    auto third = ledger.beginHandshake(3, "10.0.0.1"); // the third from the same address
    auto other = ledger.beginHandshake(4, "10.0.0.2"); // another address is unaffected
    EXPECT_TRUE(first);
    EXPECT_TRUE(second);
    EXPECT_FALSE(third);
    EXPECT_TRUE(other);

    auto s = ledger.snapshot();
    EXPECT_EQ(s.handshaking, 3U);
    // The refused connection still holds its slot until the transport closes it.
    EXPECT_EQ(s.open, 4U);
    EXPECT_EQ(s.rejectedPerSourceTotal, 1U);

    ledger.closed(3);
    s = ledger.snapshot();
    EXPECT_EQ(s.open, 3U);
    EXPECT_EQ(s.handshaking, 3U); // the refused one was never handshaking
}

// Only connections IN THE HANDSHAKE count against the cap: once one finishes, its address may start
// another. This is what keeps a fleet behind one NAT address unaffected.
TEST(HandshakeLedgerTest, AFinishedHandshakeFreesItsShareOfTheCap)
{
    HandshakeLedger ledger;
    ledger.setMaxPerSource(1);

    auto first = ledger.beginHandshake(1, "10.0.0.1");
    ASSERT_TRUE(first);
    EXPECT_FALSE(ledger.beginHandshake(2, "10.0.0.1"));

    first.release(); // established; the connection stays open
    auto third = ledger.beginHandshake(3, "10.0.0.1");
    EXPECT_TRUE(third);
    EXPECT_EQ(ledger.snapshot().open, 3U);
}

TEST(HandshakeLedgerTest, ZeroDisablesTheCap)
{
    HandshakeLedger ledger;
    ledger.setMaxPerSource(0);
    std::vector<HandshakeLedger::Share> shares;
    for (std::uint64_t id = 1; id <= 1000; ++id)
    {
        shares.push_back(ledger.beginHandshake(id, "10.0.0.1"));
        ASSERT_TRUE(shares.back());
    }
    EXPECT_EQ(ledger.snapshot().handshaking, 1000U);
    EXPECT_EQ(ledger.snapshot().rejectedPerSourceTotal, 0U);
}

// The peer address cannot be read once the peer is gone: such a connection is counted, but never
// refused and never charged to a source.
TEST(HandshakeLedgerTest, AnUnknownSourceIsNeverRefused)
{
    HandshakeLedger ledger;
    ledger.setMaxPerSource(1);
    auto first = ledger.beginHandshake(1, "");
    auto second = ledger.beginHandshake(2, "");
    EXPECT_TRUE(first);
    EXPECT_TRUE(second);
    EXPECT_EQ(ledger.snapshot().handshaking, 2U);

    ledger.closed(1);
    ledger.closed(2);
    EXPECT_EQ(ledger.snapshot().handshaking, 0U);
}

TEST(HandshakeLedgerTest, CountsTimeouts)
{
    HandshakeLedger ledger;
    ledger.recordTimeout();
    ledger.recordTimeout();
    EXPECT_EQ(ledger.snapshot().timeoutsTotal, 2U);
}

// reset() starts a new server run: connections and per-source shares are forgotten (connection ids
// restart with the run), the cumulative totals are not, and a share taken before it releases nothing
// of the new run.
TEST(HandshakeLedgerTest, ResetForgetsConnectionsButKeepsTotals)
{
    HandshakeLedger ledger;
    ledger.setMaxPerSource(1);
    auto previousRun = ledger.beginHandshake(1, "10.0.0.1");
    ASSERT_TRUE(previousRun);
    EXPECT_FALSE(ledger.beginHandshake(2, "10.0.0.1"));
    ledger.recordTimeout();

    ledger.reset();

    auto s = ledger.snapshot();
    EXPECT_EQ(s.open, 0U);
    EXPECT_EQ(s.handshaking, 0U);
    EXPECT_EQ(s.timeoutsTotal, 1U);
    EXPECT_EQ(s.rejectedPerSourceTotal, 1U);

    // The address's share went with the reset, and an id of the new run is a new connection.
    auto newRun = ledger.beginHandshake(1, "10.0.0.1");
    EXPECT_TRUE(newRun);
    EXPECT_EQ(ledger.snapshot().open, 1U);

    previousRun.release();
    s = ledger.snapshot();
    EXPECT_EQ(s.handshaking, 1U) << "a share of the previous run released a handshake of this one";
    EXPECT_FALSE(ledger.beginHandshake(3, "10.0.0.1")) << "the address must still be at its cap";
}

// Two connections in the handshake under one id -- what RESTinio's own connection factory could hand
// out -- are two handshakes: both count against their address and both give their unit back.
TEST(HandshakeLedgerTest, TwoHandshakesOnOneIdCountTwice)
{
    HandshakeLedger ledger;
    ledger.setMaxPerSource(2);

    auto a = ledger.beginHandshake(57, "10.0.0.1");
    auto b = ledger.beginHandshake(57, "10.0.0.1");
    ASSERT_TRUE(a);
    ASSERT_TRUE(b);
    EXPECT_EQ(ledger.snapshot().handshaking, 2U);
    EXPECT_FALSE(ledger.beginHandshake(58, "10.0.0.1")) << "the second handshake escaped the cap";

    a.release();
    b.release();
    ledger.closed(57);
    ledger.closed(57);
    ledger.closed(58);

    const auto s = ledger.snapshot();
    EXPECT_EQ(s.open, 0U);
    EXPECT_EQ(s.handshaking, 0U);
    auto next = ledger.beginHandshake(59, "10.0.0.1");
    auto last = ledger.beginHandshake(60, "10.0.0.1");
    EXPECT_TRUE(next);
    EXPECT_TRUE(last) << "the address did not get its whole share back";
}

// The ends of two connections on one id can arrive in any order: each handshake ends (its share is
// released) and each connection closes. Whatever the order, nothing may stay counted -- a unit kept
// here is a slot its address never gets back.
TEST(HandshakeLedgerTest, EveryOrderOfTwoConnectionsOnOneIdLeavesNothingCounted)
{
    enum Event
    {
        ReleaseA,
        ReleaseB,
        Close // both connections' closed notices carry the shared id, so they are the same event
    };
    std::array<Event, 4> events {ReleaseA, ReleaseB, Close, Close};
    std::sort(events.begin(), events.end());

    int orders = 0;
    do
    {
        ++orders;
        HandshakeLedger ledger;
        ledger.setMaxPerSource(2);
        auto a = ledger.beginHandshake(57, "10.0.0.1");
        auto b = ledger.beginHandshake(57, "10.0.0.1");
        ASSERT_TRUE(a);
        ASSERT_TRUE(b);

        for (const auto event : events)
        {
            switch (event)
            {
                case ReleaseA: a.release(); break;
                case ReleaseB: b.release(); break;
                case Close: ledger.closed(57); break;
            }
        }

        const auto s = ledger.snapshot();
        EXPECT_EQ(s.open, 0U) << "order " << orders;
        EXPECT_EQ(s.handshaking, 0U) << "order " << orders;
        auto next = ledger.beginHandshake(1, "10.0.0.1");
        auto last = ledger.beginHandshake(2, "10.0.0.1");
        EXPECT_TRUE(next && last) << "order " << orders << ": the address lost part of its share";
    } while (std::next_permutation(events.begin(), events.end()));

    EXPECT_EQ(orders, 12); // every distinct order of two releases and two identical closes
}

// A handshake whose owner goes away without saying how it ended -- the I/O context destroyed with the
// handshake pending, at shutdown -- is released by the share itself.
TEST(HandshakeLedgerTest, ADroppedShareReleasesItsHandshake)
{
    HandshakeLedger ledger;
    ledger.setMaxPerSource(1);
    {
        auto share = ledger.beginHandshake(1, "10.0.0.1");
        ASSERT_TRUE(share);
        EXPECT_EQ(ledger.snapshot().handshaking, 1U);
    }
    EXPECT_EQ(ledger.snapshot().handshaking, 0U);
    auto next = ledger.beginHandshake(2, "10.0.0.1");
    EXPECT_TRUE(next) << "the dropped share kept its address's slot";
}

// A share is released exactly once, wherever it was moved to.
TEST(HandshakeLedgerTest, AReleasedOrMovedShareReleasesNothingMore)
{
    HandshakeLedger ledger;
    auto kept = ledger.beginHandshake(1, "10.0.0.1");
    auto moved = ledger.beginHandshake(2, "10.0.0.1");
    ASSERT_TRUE(kept);
    ASSERT_TRUE(moved);

    {
        HandshakeLedger::Share owner {std::move(moved)};
        EXPECT_FALSE(moved); // NOLINT(bugprone-use-after-move) -- checking the moved-from state
        EXPECT_TRUE(owner);
        EXPECT_EQ(ledger.snapshot().handshaking, 2U);
    }
    EXPECT_EQ(ledger.snapshot().handshaking, 1U);

    moved.release(); // NOLINT(bugprone-use-after-move) -- a moved-from share releases nothing
    EXPECT_EQ(ledger.snapshot().handshaking, 1U);

    HandshakeLedger::Share assigned;
    assigned = std::move(kept);
    assigned.release();
    assigned.release();
    EXPECT_EQ(ledger.snapshot().handshaking, 0U);
}

// Every I/O thread calls into the ledger; the levels must come back to zero exactly.
TEST(HandshakeLedgerTest, ConcurrentLifecyclesBalance)
{
    HandshakeLedger ledger;
    ledger.setMaxPerSource(0);
    constexpr int kThreads = 8;
    constexpr std::uint64_t kPerThread = 2000;

    std::vector<std::thread> threads;
    for (int t = 0; t < kThreads; ++t)
    {
        threads.emplace_back(
            [&ledger, t]
            {
                const std::string source = "10.0.0." + std::to_string(t % 3);
                for (std::uint64_t i = 0; i < kPerThread; ++i)
                {
                    const auto id = static_cast<std::uint64_t>(t) * kPerThread + i;
                    auto share = ledger.beginHandshake(id, source);
                    if (i % 2 == 0)
                    {
                        share.release(); // established, then closed
                    }
                    ledger.closed(id); // odd ids: closed mid-handshake
                }
            });
    }
    for (auto& thread : threads)
    {
        thread.join();
    }

    const auto s = ledger.snapshot();
    EXPECT_EQ(s.open, 0U);
    EXPECT_EQ(s.handshaking, 0U);
}
