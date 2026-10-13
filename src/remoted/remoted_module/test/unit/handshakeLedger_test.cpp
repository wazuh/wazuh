/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * October 8, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "http_server/handshakeLedger.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <cstdint>
#include <string>
#include <thread>
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

    ASSERT_TRUE(ledger.beginHandshake(1, "10.0.0.1"));
    EXPECT_EQ(ledger.snapshot().open, 1U);
    EXPECT_EQ(ledger.snapshot().handshaking, 1U);

    ledger.finishHandshake(1);
    EXPECT_EQ(ledger.snapshot().open, 1U);
    EXPECT_EQ(ledger.snapshot().handshaking, 0U);

    ledger.closed(1);
    EXPECT_EQ(ledger.snapshot().open, 0U);
    EXPECT_EQ(ledger.snapshot().handshaking, 0U);
}

// The bug the ledger replaces: RESTinio sends a closed notice for a connection whose handshake
// failed, with no accepted notice before it. A connection closed while still handshaking must
// leave both levels at zero -- never wrap.
TEST(HandshakeLedgerTest, ClosingWhileHandshakingReleasesBothLevels)
{
    HandshakeLedger ledger;
    ASSERT_TRUE(ledger.beginHandshake(7, "10.0.0.1"));

    ledger.closed(7);

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
    ledger.finishHandshake(42);
    EXPECT_EQ(ledger.snapshot().open, 0U);

    ASSERT_TRUE(ledger.beginHandshake(1, "10.0.0.1"));
    ledger.finishHandshake(1);
    ledger.finishHandshake(1);
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

    EXPECT_TRUE(ledger.beginHandshake(1, "10.0.0.1"));
    EXPECT_TRUE(ledger.beginHandshake(2, "10.0.0.1"));
    EXPECT_FALSE(ledger.beginHandshake(3, "10.0.0.1")); // the third from the same address
    EXPECT_TRUE(ledger.beginHandshake(4, "10.0.0.2"));  // another address is unaffected

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

    ASSERT_TRUE(ledger.beginHandshake(1, "10.0.0.1"));
    EXPECT_FALSE(ledger.beginHandshake(2, "10.0.0.1"));

    ledger.finishHandshake(1); // established; the connection stays open
    EXPECT_TRUE(ledger.beginHandshake(3, "10.0.0.1"));
    EXPECT_EQ(ledger.snapshot().open, 3U);
}

TEST(HandshakeLedgerTest, ZeroDisablesTheCap)
{
    HandshakeLedger ledger;
    ledger.setMaxPerSource(0);
    for (std::uint64_t id = 1; id <= 1000; ++id)
    {
        ASSERT_TRUE(ledger.beginHandshake(id, "10.0.0.1"));
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
    EXPECT_TRUE(ledger.beginHandshake(1, ""));
    EXPECT_TRUE(ledger.beginHandshake(2, ""));
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
// restart with the run), the cumulative totals are not.
TEST(HandshakeLedgerTest, ResetForgetsConnectionsButKeepsTotals)
{
    HandshakeLedger ledger;
    ledger.setMaxPerSource(1);
    ASSERT_TRUE(ledger.beginHandshake(1, "10.0.0.1"));
    EXPECT_FALSE(ledger.beginHandshake(2, "10.0.0.1"));
    ledger.recordTimeout();

    ledger.reset();

    auto s = ledger.snapshot();
    EXPECT_EQ(s.open, 0U);
    EXPECT_EQ(s.handshaking, 0U);
    EXPECT_EQ(s.timeoutsTotal, 1U);
    EXPECT_EQ(s.rejectedPerSourceTotal, 1U);

    // The address's share went with the reset, and an id of the new run is a new connection.
    EXPECT_TRUE(ledger.beginHandshake(1, "10.0.0.1"));
    EXPECT_EQ(ledger.snapshot().open, 1U);
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
                    ledger.beginHandshake(id, source);
                    if (i % 2 == 0)
                    {
                        ledger.finishHandshake(id); // established, then closed
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
