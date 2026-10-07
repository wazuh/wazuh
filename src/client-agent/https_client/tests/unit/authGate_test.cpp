/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 21, 2026.
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
