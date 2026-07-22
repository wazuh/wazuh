/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/*
 * The retry loop uses the REAL CmacSigner plus the fake clock, so the
 * re-sign-on-every-retry property is proven through actually different
 * Authorization headers, not through mock bookkeeping.
 */

#include "fakeSysSeams.hpp"
#include "mockCallbackSink.hpp"
#include "mockHttpPerformer.hpp"
#include "retrySender.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using ::testing::_;
using ::testing::Invoke;
using ::testing::Return;

namespace
{
    HttpResponse response(TransportStatus status, long code, long retryAfter = 0)
    {
        HttpResponse value;
        value.status = status;
        value.httpCode = code;
        value.retryAfterSeconds = retryAfter;
        return value;
    }

    class RetrySenderTest : public ::testing::Test
    {
        protected:
            RetrySenderTest()
                : m_signer("001", m_keyProvider)
                , m_backoff(1000, 60000, m_random)
                , m_sender(m_performer, m_signer, m_clock, m_backoff)
            {
            }

            HttpRequestSpec makeSpec()
            {
                HttpRequestSpec spec;
                spec.target = "/stateless";
                spec.body = reinterpret_cast<const uint8_t*>("body");
                spec.bodyLength = 4;
                return spec;
            }

            ConfigKeyProvider m_keyProvider {"000102030405060708090a0b0c0d0e0f"};
            CmacSigner m_signer;
            FakeClock m_clock;
            ScriptedRandom m_random {{1.0}}; // Jitter always hits the window ceiling.
            Backoff m_backoff;
            MockHttpPerformer m_performer;
            FakeWaiter m_waiter;
            RetrySender m_sender;
    };
} // namespace

TEST_F(RetrySenderTest, SuccessOnFirstAttemptSignsAndResetsBackoff)
{
    std::vector<std::string> seenHeaders;
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & spec)
    {
        seenHeaders = spec.headers;
        return response(TransportStatus::Ok, 200);
    }));

    m_backoff.next(); // Pre-dirty the backoff to observe the reset.
    const auto result = m_sender.send(makeSpec(), m_waiter, 4);

    EXPECT_EQ(OutcomeClass::Ok, result.outcome);
    ASSERT_EQ(2u, seenHeaders.size());
    EXPECT_EQ("protocol-version: 1", seenHeaders[0]);
    EXPECT_EQ(0u, seenHeaders[1].find("Authorization: Wazuh 001:"));
    EXPECT_EQ(1000u, m_backoff.currentCeilingMs()); // Reset on success.
    EXPECT_TRUE(m_waiter.requestedDelays().empty());
}

TEST_F(RetrySenderTest, EveryRetryIsFreshlySigned)
{
    std::vector<std::string> authorizations;
    EXPECT_CALL(m_performer, perform(_))
    .Times(2)
    .WillRepeatedly(Invoke(
                        [&](const HttpRequestSpec & spec)
    {
        authorizations.push_back(spec.headers.back());
        m_clock.advance(std::chrono::seconds {5}); // Time passes between attempts.
        return response(TransportStatus::Ok, 500);
    }));
    m_waiter.script({true});

    const auto result = m_sender.send(makeSpec(), m_waiter, 2);

    EXPECT_EQ(OutcomeClass::Retryable, result.outcome);
    ASSERT_EQ(2u, authorizations.size());
    // Different timestamp -> different ts field AND different MAC.
    EXPECT_NE(authorizations[0], authorizations[1]);
}

TEST_F(RetrySenderTest, ServerRetryAfterWinsWhenLonger)
{
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Return(response(TransportStatus::Ok, 503, 90)))
    .WillOnce(Return(response(TransportStatus::Ok, 200)));
    m_waiter.script({true});

    const auto result = m_sender.send(makeSpec(), m_waiter, 4);

    EXPECT_EQ(OutcomeClass::Ok, result.outcome);
    ASSERT_EQ(1u, m_waiter.requestedDelays().size());
    EXPECT_EQ(90000, m_waiter.requestedDelays()[0].count()); // 90 s > 1 s window.
}

TEST_F(RetrySenderTest, BackoffWinsOverShorterRetryAfter)
{
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Return(response(TransportStatus::Ok, 503, 0))) // Retry-After absent.
    .WillOnce(Return(response(TransportStatus::Ok, 200)));
    m_waiter.script({true});

    m_sender.send(makeSpec(), m_waiter, 4);

    ASSERT_EQ(1u, m_waiter.requestedDelays().size());
    EXPECT_EQ(1000, m_waiter.requestedDelays()[0].count()); // Jittered window ceiling.
}

TEST_F(RetrySenderTest, PermanentOutcomeNeverRetries)
{
    EXPECT_CALL(m_performer, perform(_)).WillOnce(Return(response(TransportStatus::Ok, 400)));
    const auto result = m_sender.send(makeSpec(), m_waiter, 4);
    EXPECT_EQ(OutcomeClass::Permanent, result.outcome);
    EXPECT_TRUE(m_waiter.requestedDelays().empty());
}

TEST_F(RetrySenderTest, PayloadTooLargeReturnsImmediately)
{
    // 413 is non-retryable in the loop; the /stateless stream splits + resends.
    EXPECT_CALL(m_performer, perform(_)).WillOnce(Return(response(TransportStatus::Ok, 413)));
    const auto result = m_sender.send(makeSpec(), m_waiter, 4);
    EXPECT_EQ(OutcomeClass::PayloadTooLarge, result.outcome);
    EXPECT_TRUE(m_waiter.requestedDelays().empty());
}

TEST_F(RetrySenderTest, AuthFailureReturnsImmediately)
{
    EXPECT_CALL(m_performer, perform(_)).WillOnce(Return(response(TransportStatus::Ok, 401)));
    const auto result = m_sender.send(makeSpec(), m_waiter, 4);
    EXPECT_EQ(OutcomeClass::AuthFail, result.outcome); // Re-enroll policy is the caller's.
}

TEST_F(RetrySenderTest, AuthFailureEngagesTheAuthGateButSuccessDoesNot)
{
    ::testing::NiceMock<MockCallbackSink> sink;
    AuthGate gate {sink, [] {}};
    RetrySender guarded {m_performer, m_signer, m_clock, m_backoff, &gate};

    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Return(response(TransportStatus::Ok, 200)))
    .WillOnce(Return(response(TransportStatus::Ok, 401)));

    guarded.send(makeSpec(), m_waiter, 1);
    EXPECT_FALSE(gate.paused()); // 200: no pause.
    guarded.send(makeSpec(), m_waiter, 1);
    EXPECT_TRUE(gate.paused());  // 401: paused.
}

TEST_F(RetrySenderTest, VersionRejectionReturnsImmediately)
{
    EXPECT_CALL(m_performer, perform(_)).WillOnce(Return(response(TransportStatus::Ok, 426)));
    const auto result = m_sender.send(makeSpec(), m_waiter, 4);
    EXPECT_EQ(OutcomeClass::VersionRejected, result.outcome);
}

TEST_F(RetrySenderTest, StopDuringTheDelayInterrupts)
{
    EXPECT_CALL(m_performer, perform(_)).WillOnce(Return(response(TransportStatus::Ok, 500)));
    // Empty script: the first waitFor answers false (stop requested).
    const auto result = m_sender.send(makeSpec(), m_waiter, 4);
    EXPECT_EQ(OutcomeClass::Interrupted, result.outcome);
}

TEST_F(RetrySenderTest, AbortedTransferSurfacesAsInterrupted)
{
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Return(response(TransportStatus::Aborted, 0)));
    const auto result = m_sender.send(makeSpec(), m_waiter, 4);
    EXPECT_EQ(OutcomeClass::Interrupted, result.outcome);
    EXPECT_TRUE(m_waiter.requestedDelays().empty()); // Never waits after an abort.
}

TEST_F(RetrySenderTest, MaxAttemptsBoundsTheLoop)
{
    EXPECT_CALL(m_performer, perform(_))
    .Times(3)
    .WillRepeatedly(Return(response(TransportStatus::Timeout, 0)));
    m_waiter.script({true, true, true});

    const auto result = m_sender.send(makeSpec(), m_waiter, 3);

    EXPECT_EQ(OutcomeClass::Retryable, result.outcome);
    EXPECT_EQ(2u, m_waiter.requestedDelays().size()); // No delay after the last attempt.
}

TEST_F(RetrySenderTest, WaiterStopFlagIsWiredAsTheAbortFlag)
{
    const std::atomic<bool>* seenFlag = nullptr;
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & spec)
    {
        seenFlag = spec.abortFlag;
        return response(TransportStatus::Ok, 200);
    }));
    m_sender.send(makeSpec(), m_waiter, 1);
    EXPECT_EQ(m_waiter.stopFlag(), seenFlag);
}

TEST_F(RetrySenderTest, UnusableCredentialsArePermanentWithoutSending)
{
    const ConfigKeyProvider badProvider {"zz"};
    const CmacSigner badSigner {"001", badProvider};
    RetrySender sender {m_performer, badSigner, m_clock, m_backoff};
    EXPECT_CALL(m_performer, perform(_)).Times(0);

    const auto result = sender.send(makeSpec(), m_waiter, 4);
    EXPECT_EQ(OutcomeClass::Permanent, result.outcome);
}

TEST_F(RetrySenderTest, FileBackedSpecsAreSignedThroughSignFile)
{
    // A file body routes through signFile(); a missing file must therefore be
    // Permanent (unusable), with nothing sent.
    HttpRequestSpec spec;
    spec.target = "/stateful";
    spec.bodyFilePath = "/nonexistent/hc-spool/session.bin";
    EXPECT_CALL(m_performer, perform(_)).Times(0);

    const auto result = m_sender.send(spec, m_waiter, 4);
    EXPECT_EQ(OutcomeClass::Permanent, result.outcome);
}
