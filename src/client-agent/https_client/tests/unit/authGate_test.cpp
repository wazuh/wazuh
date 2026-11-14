/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "authGate.hpp"
#include "mockCallbackSink.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <thread>
#include <vector>

using ::testing::NiceMock;

namespace
{
    class AuthGateTest : public ::testing::Test
    {
        protected:
            NiceMock<MockCallbackSink> m_sink;
            int m_wakes {0};
            AuthGate m_gate {m_sink, [this] { m_wakes++; }};
            std::vector<uint64_t> m_seenAtCallback;
    };
} // namespace

TEST_F(AuthGateTest, FirstFailureFiresOnceAndPauses)
{
    EXPECT_CALL(m_sink, onReenrollRequired()).Times(1);
    EXPECT_FALSE(m_gate.paused());
    m_gate.reportAuthFailure();
    EXPECT_TRUE(m_gate.paused());
    EXPECT_EQ(1, m_wakes);
}

TEST_F(AuthGateTest, RepeatedFailuresDoNotRefire)
{
    EXPECT_CALL(m_sink, onReenrollRequired()).Times(1);
    m_gate.reportAuthFailure();
    m_gate.reportAuthFailure();
    m_gate.reportAuthFailure();
    EXPECT_TRUE(m_gate.paused());
    EXPECT_EQ(1, m_wakes); // Only the first report wakes/fires.
}

TEST_F(AuthGateTest, ReleaseUnpausesReArmsAndWakes)
{
    EXPECT_CALL(m_sink, onReenrollRequired()).Times(2);
    m_gate.reportAuthFailure(); // fire 1.
    m_gate.release();
    EXPECT_FALSE(m_gate.paused());
    EXPECT_EQ(2, m_wakes); // report + release.
    m_gate.reportAuthFailure(); // A later dead key fires again.
    EXPECT_TRUE(m_gate.paused());
    EXPECT_EQ(3, m_wakes);
}

TEST_F(AuthGateTest, IncidentsCountEachLatchOnceAndBeforeTheConsumerIsAsked)
{
    // Counted before onReenrollRequired(): a key renewed from inside it must never be seen
    // without its incident (#38329).
    EXPECT_CALL(m_sink, onReenrollRequired())
    .Times(2)
    .WillRepeatedly(::testing::Invoke([this] { m_seenAtCallback.push_back(m_gate.incidents()); }));

    EXPECT_EQ(0u, m_gate.incidents());
    m_gate.reportAuthFailure();
    m_gate.reportAuthFailure(); // Same incident: not counted again.
    EXPECT_EQ(1u, m_gate.incidents());
    m_gate.release();
    EXPECT_EQ(1u, m_gate.incidents()); // A renewal does not erase it.
    m_gate.reportAuthFailure();
    EXPECT_EQ(2u, m_gate.incidents());
    EXPECT_EQ((std::vector<uint64_t> {1, 2}), m_seenAtCallback);
}

TEST_F(AuthGateTest, ConcurrentReportsAndReleasesNeverStrandUnpaused)
{
    // report() and release() ran on independent atomics before, so an
    // interleave could end fired-but-unpaused (a 401 triggered enrollment
    // while traffic kept flowing). With one atomic state, a report ALWAYS
    // ends paused. Hammer both from several threads (the TSan build validates
    // the transitions), then a final report with nothing after it must leave
    // the gate paused.
    std::atomic<int> wakes {0};
    AuthGate gate {m_sink, [&] { wakes.fetch_add(1, std::memory_order_relaxed); }};

    std::atomic<bool> go {false};
    std::vector<std::thread> threads;

    for (int worker = 0; worker < 4; worker++)
    {
        threads.emplace_back([&]
        {
            while (!go.load(std::memory_order_acquire))
            {
                std::this_thread::yield(); // Barrier, not a busy-wait: see sysSeams_test.cpp.
            }

            for (int n = 0; n < 2000; n++)
            {
                gate.reportAuthFailure();
                gate.release();
            }
        });
    }

    go.store(true, std::memory_order_release);

    for (auto& thread : threads)
    {
        thread.join();
    }

    gate.reportAuthFailure(); // No release after this one.
    EXPECT_TRUE(gate.paused());
}

TEST_F(AuthGateTest, AStreamOnAnOlderWindowCannotCloseANewerOne)
{
    const auto t0 = std::chrono::steady_clock::time_point {};
    const auto first = m_gate.joinUnknownAgentWindow(t0, std::chrono::seconds {30});
    ASSERT_TRUE(m_gate.closeUnknownAgentWindow()); // An accepted request ends it.

    const auto second = m_gate.joinUnknownAgentWindow(t0 + std::chrono::seconds {1}, std::chrono::seconds {30});

    EXPECT_TRUE(second.opened);
    EXPECT_NE(first.generation, second.generation);
    EXPECT_FALSE(m_gate.unknownAgentWindowCurrent(first.generation));
    EXPECT_FALSE(m_gate.closeUnknownAgentWindow(first.generation));
    EXPECT_TRUE(m_gate.unknownAgentWindowOpen());
    EXPECT_TRUE(m_gate.closeUnknownAgentWindow(second.generation));
}

TEST_F(AuthGateTest, AnExpiredWindowIsRejoinedWhileUnknownAgentKeepsComing)
{
    const auto t0 = std::chrono::steady_clock::time_point {};
    const auto bound = std::chrono::seconds {30};
    const auto first = m_gate.joinUnknownAgentWindow(t0, bound);
    m_gate.noteUnknownAgent(t0 + std::chrono::seconds {20});

    const auto rejoined = m_gate.joinUnknownAgentWindow(t0 + std::chrono::seconds {40}, bound);

    EXPECT_FALSE(rejoined.opened);
    EXPECT_EQ(first.generation, rejoined.generation);
    EXPECT_EQ(first.deadline, rejoined.deadline);
}

TEST_F(AuthGateTest, AnExpiredWindowWithoutUnknownAgentForABoundIsReplaced)
{
    const auto t0 = std::chrono::steady_clock::time_point {};
    const auto bound = std::chrono::seconds {30};
    const auto first = m_gate.joinUnknownAgentWindow(t0, bound);

    const auto later = t0 + std::chrono::seconds {90};
    const auto fresh = m_gate.joinUnknownAgentWindow(later, bound);

    EXPECT_TRUE(fresh.opened);
    EXPECT_NE(first.generation, fresh.generation);
    EXPECT_EQ(later + bound, fresh.deadline);
}

TEST_F(AuthGateTest, ReleaseDropsAnOpenWindow)
{
    const auto t0 = std::chrono::steady_clock::time_point {};
    m_gate.joinUnknownAgentWindow(t0, std::chrono::seconds {30});
    m_gate.reportAuthFailure();

    m_gate.release();

    EXPECT_FALSE(m_gate.unknownAgentWindowOpen());
    EXPECT_TRUE(m_gate.joinUnknownAgentWindow(t0 + std::chrono::seconds {1}, std::chrono::seconds {30}).opened);
}
