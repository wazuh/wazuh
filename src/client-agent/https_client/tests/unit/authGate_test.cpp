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

using ::testing::NiceMock;

namespace
{
    class AuthGateTest : public ::testing::Test
    {
        protected:
            NiceMock<MockCallbackSink> m_sink;
            int m_wakes {0};
            AuthGate m_gate {m_sink, [this] { m_wakes++; }};
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
