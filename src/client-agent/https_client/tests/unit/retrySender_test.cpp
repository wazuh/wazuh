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
 * The retry loop uses the REAL JwtSigner plus the fake clock, so the
 * fresh-token-on-every-attempt property is proven through actually different
 * Authorization headers, not through mock bookkeeping.
 */

#include "fakeSysSeams.hpp"
#include "jwtSigner.hpp"
#include "jwtTestSupport.hpp"
#include "mockCallbackSink.hpp"
#include "mockHttpPerformer.hpp"
#include "retrySender.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <zstd.h>

#include <fstream>

using ::testing::_;
using ::testing::Contains;
using ::testing::Invoke;
using ::testing::Not;
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

    HttpResponse authFailWithServerDate(std::time_t serverDateSeconds)
    {
        HttpResponse value = response(TransportStatus::Ok, 401);
        value.serverDateSeconds = serverDateSeconds;
        return value;
    }

    std::string writeTempFile(const std::string& name, const std::string& contents)
    {
        const std::string path = ::testing::TempDir() + name;
        std::ofstream file {path, std::ios::binary};
        file << contents;
        file.close();
        return path;
    }

    class RetrySenderTest : public ::testing::Test
    {
        protected:
            RetrySenderTest()
                : m_signer("001", m_keyProvider)
                , m_backoff(1000, 60000, m_random)
                , m_sender(m_performer, m_signer, m_clock, m_backoff, false)
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

            ConfigKeyProvider m_keyProvider {testAgentKeyHex()};
            JwtSigner m_signer;
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
    EXPECT_EQ(0u, seenHeaders[1].find("Authorization: Bearer "));
    const auto bearer = decodeBearer(seenHeaders[1], testAgentKeyHex());
    ASSERT_TRUE(bearer.has_value());
    EXPECT_TRUE(bearer->signatureValid);
    EXPECT_EQ("001", bearer->claims.at("sub"));
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

    EXPECT_EQ(OutcomeClass::ServerError, result.outcome); // 500: the manager answered.
    ASSERT_EQ(2u, authorizations.size());
    // Different timestamp -> different iat AND a fresh jti/signature.
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

TEST_F(RetrySenderTest, RepeatedAuthFailureReturnsAuthFail)
{
    // A 401 triggers one fresh-timestamp retry; a second 401 is the verdict.
    EXPECT_CALL(m_performer, perform(_)).Times(2).WillRepeatedly(Return(response(TransportStatus::Ok, 401)));
    const auto result = m_sender.send(makeSpec(), m_waiter, 4);
    EXPECT_EQ(OutcomeClass::AuthFail, result.outcome); // Re-enroll policy is the caller's.
    EXPECT_TRUE(m_waiter.requestedDelays().empty());   // The auth retry is immediate.
}

TEST_F(RetrySenderTest, AuthFailureRecoversWithAFreshTimestamp)
{
    // The first 401 is an edge/expired timestamp; the immediate resign succeeds.
    std::vector<std::string> authorizations;
    EXPECT_CALL(m_performer, perform(_))
    .Times(2)
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & spec)
    {
        authorizations.push_back(spec.headers.back());
        m_clock.advance(std::chrono::seconds {5}); // Clock moves before the retry.
        return response(TransportStatus::Ok, 401);
    }))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & spec)
    {
        authorizations.push_back(spec.headers.back());
        return response(TransportStatus::Ok, 200);
    }));

    const auto result = m_sender.send(makeSpec(), m_waiter, 4);

    EXPECT_EQ(OutcomeClass::Ok, result.outcome);
    ASSERT_EQ(2u, authorizations.size());
    EXPECT_NE(authorizations[0], authorizations[1]); // Retry was freshly signed.
    EXPECT_TRUE(m_waiter.requestedDelays().empty()); // No backoff between the two.
}

TEST_F(RetrySenderTest, SkewedClockIsCorrectedFromServerDateAndRetrySucceeds)
{
    // Agent clock 10 h ahead of the manager (the reported Windows defect: VM
    // snapshot restore / dead CMOS / no NTP). The manager's Date header on the
    // 401 carries its real time; the one-shot retry must land on it.
    m_clock.setWall(1700036000);
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Return(authFailWithServerDate(1700000000)))
    .WillOnce(Return(response(TransportStatus::Ok, 200)));

    const auto result = m_sender.send(makeSpec(), m_waiter, 4);

    EXPECT_EQ(OutcomeClass::Ok, result.outcome);
    EXPECT_EQ(-36000, m_clock.appliedOffsetSeconds());
    EXPECT_EQ(1, m_clock.offsetApplyCount());
    EXPECT_EQ(1700000000, m_clock.wallSeconds()); // Corrected: now matches the manager.
}

TEST_F(RetrySenderTest, BehindClockIsCorrectedForwardFromServerDateAndRetrySucceeds)
{
    // Mirror of the test above with the skew direction reversed: agent clock
    // 10 h BEHIND the manager (e.g. a VM paused/suspended past its snapshot
    // time). The correction must move the clock FORWARD (positive delta) --
    // proves correctClockIfSkewed() doesn't implicitly assume "ahead", since
    // every other coverage in this file (and every live E2E run) only ever
    // exercised the agent-ahead direction.
    m_clock.setWall(1700000000);
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Return(authFailWithServerDate(1700036000)))
    .WillOnce(Return(response(TransportStatus::Ok, 200)));

    const auto result = m_sender.send(makeSpec(), m_waiter, 4);

    EXPECT_EQ(OutcomeClass::Ok, result.outcome);
    EXPECT_EQ(36000, m_clock.appliedOffsetSeconds());
    EXPECT_EQ(1, m_clock.offsetApplyCount());
    EXPECT_EQ(1700036000, m_clock.wallSeconds()); // Corrected: now matches the manager.
}

TEST_F(RetrySenderTest, SmallDateGapWithinNoiseFloorIsNotTreatedAsSkew)
{
    // A 2 s gap is plausibly RTT/Date's 1 s granularity, not real skew: the
    // agent must not perturb its own correct clock over it, and the 401 is
    // left to escalate exactly as before this fix (likely a dead key).
    m_clock.setWall(1700000000);
    EXPECT_CALL(m_performer, perform(_)).Times(2).WillRepeatedly(Return(authFailWithServerDate(1700000002)));

    const auto result = m_sender.send(makeSpec(), m_waiter, 4);

    EXPECT_EQ(OutcomeClass::AuthFail, result.outcome);
    EXPECT_EQ(0, m_clock.offsetApplyCount());
}

TEST_F(RetrySenderTest, MissingServerDateNeverAppliesACorrection)
{
    // No Date captured (old manager, or a proxy stripped it): today's
    // fresh-timestamp-only retry still happens, just uncorrected -- no crash,
    // no spurious offset.
    EXPECT_CALL(m_performer, perform(_))
    .Times(2)
    .WillRepeatedly(Return(response(TransportStatus::Ok, 401))); // serverDateSeconds defaults to 0.

    const auto result = m_sender.send(makeSpec(), m_waiter, 4);

    EXPECT_EQ(OutcomeClass::AuthFail, result.outcome);
    EXPECT_EQ(0, m_clock.offsetApplyCount());
}

TEST_F(RetrySenderTest, CorrectedRetryStillFailingEscalatesAsKeyFailure)
{
    // Real skew corrected (the retry is on an aligned clock), but the
    // corrected retry STILL 401s: clock skew has now been ruled out, so the
    // only remaining explanation is a genuinely bad/revoked key.
    m_clock.setWall(1700036000);
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Return(authFailWithServerDate(1700000000)))
    .WillOnce(Return(authFailWithServerDate(1700000005))); // Corrected retry: still 401.

    const auto result = m_sender.send(makeSpec(), m_waiter, 4);

    EXPECT_EQ(OutcomeClass::AuthFail, result.outcome);
    EXPECT_EQ(1, m_clock.offsetApplyCount());        // Correction applied once (the one-shot retry).
    EXPECT_TRUE(m_waiter.requestedDelays().empty()); // AuthFail is never itself retried with a delay.
}

TEST_F(RetrySenderTest, CorrectionPersistsForSubsequentSendsAfterTheIncidentEnds)
{
    // Step 3 of the target design ("apply the correction to a second query
    // and onward"): once learned, a later, independent send() on the same
    // (shared) clock must never need to re-learn it -- proven here by a
    // second send() that never even sees a 401.
    m_clock.setWall(1700036000);
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Return(authFailWithServerDate(1700000000)))
    .WillOnce(Return(response(TransportStatus::Ok, 200)))
    .WillOnce(Return(response(TransportStatus::Ok, 200)));

    const auto first = m_sender.send(makeSpec(), m_waiter, 4);
    EXPECT_EQ(OutcomeClass::Ok, first.outcome);
    EXPECT_EQ(1700000000, m_clock.wallSeconds());

    const auto second = m_sender.send(makeSpec(), m_waiter, 4);
    EXPECT_EQ(OutcomeClass::Ok, second.outcome);
    EXPECT_EQ(1, m_clock.offsetApplyCount()); // Learned once; never needed to re-learn.
}

TEST_F(RetrySenderTest, SecondIndependentSkewEventConvergesOnTopOfAnExistingCorrection)
{
    // Regression test for a review-caught bug: applying a SECOND correction
    // on top of an already-corrected clock must account for the clock
    // ALREADY including the first offset -- otherwise the second correction
    // under/over-shoots by exactly the magnitude of the first one, which can
    // land the agent right back in the original loop. Uses a REAL
    // SkewCorrectedClock wrapping a fake raw clock (not FakeClock's own
    // bookkeeping) so this exercises the actual production accumulation
    // logic in sysSeams.hpp, not a re-implementation of it.
    FakeClock rawClock;
    rawClock.setWall(1700036000); // Agent's raw clock: 36000s (10h) ahead of true time 1700000000.
    SkewCorrectedClock correctedClock {rawClock};
    RetrySender sender {m_performer, m_signer, correctedClock, m_backoff, false};

    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Return(authFailWithServerDate(1700000000)))
    .WillOnce(Return(response(TransportStatus::Ok, 200)))
    // A second, independent skew event: the raw clock is now only 20000s
    // ahead of a LATER true time (1700010000) -- a smaller, unrelated skew,
    // not a continuation of the first one.
    .WillOnce(Return(authFailWithServerDate(1700010000)))
    .WillOnce(Return(response(TransportStatus::Ok, 200)));

    const auto first = sender.send(makeSpec(), m_waiter, 4);
    ASSERT_EQ(OutcomeClass::Ok, first.outcome);
    ASSERT_EQ(1700000000, correctedClock.wallSeconds()); // Fully corrected after the first event.

    rawClock.setWall(1700030000); // Simulates the underlying clock drifting/jumping again.

    const auto second = sender.send(makeSpec(), m_waiter, 4);
    EXPECT_EQ(OutcomeClass::Ok, second.outcome);
    // Must land on the manager's second reported time, not on
    // 1700000000 + 36000 = 1700036000 (what a REPLACING offset would give:
    // it would silently discard the first correction).
    EXPECT_EQ(1700010000, correctedClock.wallSeconds());
}

TEST_F(RetrySenderTest, AuthGateEscalatesOnlyAfterTheRetryAlsoFails)
{
    ::testing::NiceMock<MockCallbackSink> sink;
    AuthGate gate {sink, [] {
        }};
    RetrySender guarded {m_performer, m_signer, m_clock, m_backoff, false, nullptr, &gate};

    // First send: a 401 then a 200 on the retry -> recovered, no pause.
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Return(response(TransportStatus::Ok, 401)))
    .WillOnce(Return(response(TransportStatus::Ok, 200)))
    // Second send: two 401s -> escalate.
    .WillOnce(Return(response(TransportStatus::Ok, 401)))
    .WillOnce(Return(response(TransportStatus::Ok, 401)));

    guarded.send(makeSpec(), m_waiter, 1);
    EXPECT_FALSE(gate.paused()); // Retry recovered: no pause.
    guarded.send(makeSpec(), m_waiter, 1);
    EXPECT_TRUE(gate.paused()); // Retry also 401: paused.
}

TEST_F(RetrySenderTest, VersionRejectionReturnsImmediately)
{
    EXPECT_CALL(m_performer, perform(_)).WillOnce(Return(response(TransportStatus::Ok, 409)));
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
    EXPECT_CALL(m_performer, perform(_)).WillOnce(Return(response(TransportStatus::Aborted, 0)));
    const auto result = m_sender.send(makeSpec(), m_waiter, 4);
    EXPECT_EQ(OutcomeClass::Interrupted, result.outcome);
    EXPECT_TRUE(m_waiter.requestedDelays().empty()); // Never waits after an abort.
}

TEST_F(RetrySenderTest, MaxAttemptsBoundsTheLoop)
{
    EXPECT_CALL(m_performer, perform(_)).Times(3).WillRepeatedly(Return(response(TransportStatus::Timeout, 0)));
    m_waiter.script({true, true, true});

    const auto result = m_sender.send(makeSpec(), m_waiter, 3);

    EXPECT_EQ(OutcomeClass::Unreachable, result.outcome); // Timeout: no answer at all.
    EXPECT_EQ(2u, m_waiter.requestedDelays().size());     // No delay after the last attempt.
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
    const JwtSigner badSigner {"001", badProvider};
    RetrySender sender {m_performer, badSigner, m_clock, m_backoff, false};
    EXPECT_CALL(m_performer, perform(_)).Times(0);

    const auto result = sender.send(makeSpec(), m_waiter, 4);
    EXPECT_EQ(OutcomeClass::Permanent, result.outcome);
}

TEST_F(RetrySenderTest, FileBackedSpecsGetABearerWithoutReadingTheFile)
{
    // The bearer binds identity only, so a file body is never read to mint it:
    // a missing spool file is the performer's problem, not a credential failure.
    HttpRequestSpec spec;
    spec.target = "/stateful";
    spec.bodyFilePath = "/nonexistent/hc-spool/session.bin";
    std::vector<std::string> seenHeaders;
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & attempt)
    {
        seenHeaders = attempt.headers;
        return response(TransportStatus::Ok, 200);
    }));

    const auto result = m_sender.send(spec, m_waiter, 4);
    EXPECT_EQ(OutcomeClass::Ok, result.outcome);
    ASSERT_EQ(2u, seenHeaders.size());
    EXPECT_TRUE(decodeBearer(seenHeaders[1], testAgentKeyHex())->signatureValid);
}

TEST_F(RetrySenderTest, CompressionDisabledLeavesBodyAndHeadersUnchanged)
{
    // m_sender is built with compressionEnabled=false: the default, and what
    // every test above this one already exercises implicitly.
    std::vector<uint8_t> receivedBody;
    std::vector<std::string> receivedHeaders;
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & spec)
    {
        receivedBody.assign(spec.body, spec.body + spec.bodyLength);
        receivedHeaders = spec.headers;
        return response(TransportStatus::Ok, 200);
    }));

    const auto spec = makeSpec();
    const auto result = m_sender.send(spec, m_waiter, 1);

    EXPECT_EQ(OutcomeClass::Ok, result.outcome);
    EXPECT_THAT(receivedHeaders, Not(Contains("Content-Encoding: zstd")));
    ASSERT_EQ(spec.bodyLength, receivedBody.size());
    EXPECT_TRUE(std::equal(receivedBody.begin(), receivedBody.end(), spec.body));
}

TEST_F(RetrySenderTest, CompressedBodyCarriesAVerifiableBearerIndependentOfTheBytes)
{
    RetrySender compressing {m_performer, m_signer, m_clock, m_backoff, true};

    // A longer, repetitive body: makeSpec()'s 4-byte "body" wouldn't actually
    // shrink under zstd's frame overhead.
    const std::string plain(200, 'a');
    HttpRequestSpec spec = makeSpec();
    spec.body = reinterpret_cast<const uint8_t*>(plain.data());
    spec.bodyLength = plain.size();

    std::vector<uint8_t> receivedBody;
    std::vector<std::string> receivedHeaders;
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & attempt)
    {
        receivedBody.assign(attempt.body, attempt.body + attempt.bodyLength);
        receivedHeaders = attempt.headers;
        return response(TransportStatus::Ok, 200);
    }));

    const auto result = compressing.send(spec, m_waiter, 1);

    EXPECT_EQ(OutcomeClass::Ok, result.outcome);
    EXPECT_THAT(receivedHeaders, Contains("Content-Encoding: zstd"));
    EXPECT_LT(receivedBody.size(), plain.size()); // Actually shrank.

    std::vector<uint8_t> decompressed(plain.size());
    const size_t decompressedSize =
        ZSTD_decompress(decompressed.data(), decompressed.size(), receivedBody.data(), receivedBody.size());
    ASSERT_FALSE(ZSTD_isError(decompressedSize));
    ASSERT_EQ(plain.size(), decompressedSize);
    EXPECT_EQ(plain, std::string(decompressed.begin(), decompressed.end()));

    // The bearer does not cover the body (compressed or not): it is simply a
    // valid token for agent 001 minted at the fake clock's time.
    const auto bearer = decodeBearer(receivedHeaders.back(), testAgentKeyHex());
    ASSERT_TRUE(bearer.has_value());
    EXPECT_TRUE(bearer->signatureValid);
    EXPECT_EQ("001", bearer->claims.at("sub"));
    EXPECT_EQ(m_clock.wallSeconds(), bearer->claims.at("iat").get<std::time_t>());
}

TEST_F(RetrySenderTest, CompressionEnabledSkipsFileBackedBodies)
{
    // Compression on, but no precompressedBodyFilePath set (the caller's job --
    // see CompressedFileBackedAttemptRejectedWith415RetriesOnceUncompressedAndSucceeds
    // below): a file-backed body is sent exactly as-is, no Content-Encoding, and
    // the bearer is minted without touching the file.
    RetrySender compressing {m_performer, m_signer, m_clock, m_backoff, true};
    HttpRequestSpec spec;
    spec.target = "/stateful";
    spec.bodyFilePath = "/nonexistent/hc-spool/session.bin";
    HttpRequestSpec seenSpec;
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & attempt)
    {
        seenSpec = attempt;
        return response(TransportStatus::Ok, 200);
    }));

    const auto result = compressing.send(spec, m_waiter, 4);
    EXPECT_EQ(OutcomeClass::Ok, result.outcome);
    EXPECT_EQ(spec.bodyFilePath, seenSpec.bodyFilePath);
    EXPECT_THAT(seenSpec.headers, Not(Contains("Content-Encoding: zstd")));
    EXPECT_TRUE(decodeBearer(seenSpec.headers.back(), testAgentKeyHex())->signatureValid);
}

TEST_F(RetrySenderTest, CompressedAttemptRejectedWith415RetriesOnceUncompressedAndSucceeds)
{
    CompressionGate gate;
    RetrySender compressing {m_performer, m_signer, m_clock, m_backoff, true, &gate};

    const std::string plain(200, 'a'); // Long enough to actually compress.
    HttpRequestSpec spec = makeSpec();
    spec.body = reinterpret_cast<const uint8_t*>(plain.data());
    spec.bodyLength = plain.size();

    std::vector<std::vector<std::string>> seenHeadersPerAttempt;
    EXPECT_CALL(m_performer, perform(_))
    .Times(2)
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & attempt)
    {
        seenHeadersPerAttempt.push_back(attempt.headers);
        return response(TransportStatus::Ok, 415);
    }))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & attempt)
    {
        seenHeadersPerAttempt.push_back(attempt.headers);
        return response(TransportStatus::Ok, 200);
    }));

    const auto result = compressing.send(spec, m_waiter, 1);

    EXPECT_EQ(OutcomeClass::Ok, result.outcome); // The request itself still succeeded.
    ASSERT_EQ(2u, seenHeadersPerAttempt.size());
    EXPECT_THAT(seenHeadersPerAttempt[0], Contains("Content-Encoding: zstd"));
    EXPECT_THAT(seenHeadersPerAttempt[1], Not(Contains("Content-Encoding: zstd")));
    EXPECT_TRUE(gate.disabled()); // Latched for the rest of this agent's run.
}

TEST_F(RetrySenderTest, CompressionRejectionDisablesTheSharedGateForOtherSenders)
{
    // Two independent RetrySender instances (as two different streams would
    // each own) sharing ONE gate: the first's 415 must stop the second from
    // ever trying to compress, without the second seeing a 415 itself.
    CompressionGate gate;
    RetrySender first {m_performer, m_signer, m_clock, m_backoff, true, &gate};
    RetrySender second {m_performer, m_signer, m_clock, m_backoff, true, &gate};

    const std::string plain(200, 'a');
    HttpRequestSpec spec = makeSpec();
    spec.body = reinterpret_cast<const uint8_t*>(plain.data());
    spec.bodyLength = plain.size();

    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Return(response(TransportStatus::Ok, 415))) // first: rejected.
    .WillOnce(Return(response(TransportStatus::Ok, 200))) // first's retry: uncompressed, succeeds.
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & attempt)
    {
        // second's only attempt: the gate is already disabled, so it never
        // even tries to compress -- no header, no wasted round trip.
        EXPECT_THAT(attempt.headers, Not(Contains("Content-Encoding: zstd")));
        return response(TransportStatus::Ok, 200);
    }));

    first.send(spec, m_waiter, 1);
    ASSERT_TRUE(gate.disabled());
    const auto result = second.send(spec, m_waiter, 1);
    EXPECT_EQ(OutcomeClass::Ok, result.outcome);
}

TEST_F(RetrySenderTest, SecondCompressionRejectionTerminatesWithoutLooping)
{
    // No gate here: nothing disables compression between attempts, so both
    // calls try to compress -- proving the one-shot retry is bounded per
    // send() call regardless, not just because the gate happened to help.
    RetrySender compressing {m_performer, m_signer, m_clock, m_backoff, true};
    EXPECT_CALL(m_performer, perform(_)).Times(2).WillRepeatedly(Return(response(TransportStatus::Ok, 415)));

    const auto result = compressing.send(makeSpec(), m_waiter, 4); // maxAttempts=4, but never a 3rd call.
    EXPECT_EQ(OutcomeClass::CompressionRejected, result.outcome);
}

TEST_F(RetrySenderTest, AuthFailureFromTheCompressionRetryStillGetsItsOwnGraceRetry)
{
    // The 415's one-shot uncompressed retry can itself land a transient 401.
    // That 401 must get its own fresh-timestamp grace retry -- not skip
    // straight past it just because the compression retry already ran.
    ::testing::NiceMock<MockCallbackSink> sink;
    AuthGate authGate {sink, [] {
        }};
    CompressionGate compressionGate;
    RetrySender compressing {m_performer, m_signer, m_clock, m_backoff, true, &compressionGate, &authGate};

    const std::string plain(200, 'a'); // Long enough to actually compress.
    HttpRequestSpec spec = makeSpec();
    spec.body = reinterpret_cast<const uint8_t*>(plain.data());
    spec.bodyLength = plain.size();

    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Return(response(TransportStatus::Ok, 415)))  // Rejected: retry uncompressed.
    .WillOnce(Return(response(TransportStatus::Ok, 401)))  // Uncompressed retry: transient 401.
    .WillOnce(Return(response(TransportStatus::Ok, 200))); // Auth grace retry: recovers.

    const auto result = compressing.send(spec, m_waiter, 1);

    EXPECT_EQ(OutcomeClass::Ok, result.outcome);
    EXPECT_FALSE(authGate.paused()); // Recovered by its own grace retry: never escalated.
}

TEST_F(RetrySenderTest, PrecompressedFileBodyIsUsedWithAFreshBearer)
{
    // /stateful's own caller (StatefulStream) compresses once, up front, and
    // hands the sibling's path/size here -- attemptOnce() must swap it in
    // (the bearer is independent of the bytes either way).
    RetrySender compressing {m_performer, m_signer, m_clock, m_backoff, true};

    const std::string originalPath = writeTempFile("hc_rs_original.bin", "the original body");
    const std::string compressedPath = writeTempFile("hc_rs_precompressed.bin", "zstd-ish bytes");

    HttpRequestSpec spec;
    spec.target = "/stateful";
    spec.bodyFilePath = originalPath;
    spec.bodyFileSize = 17;
    spec.precompressedBodyFilePath = compressedPath;
    spec.precompressedBodyFileSize = 14;

    std::string seenBodyFilePath;
    uint64_t seenBodyFileSize = 0;
    std::vector<std::string> seenHeaders;
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & attempt)
    {
        seenBodyFilePath = attempt.bodyFilePath;
        seenBodyFileSize = attempt.bodyFileSize;
        seenHeaders = attempt.headers;
        return response(TransportStatus::Ok, 200);
    }));

    const auto result = compressing.send(spec, m_waiter, 1);

    EXPECT_EQ(OutcomeClass::Ok, result.outcome);
    EXPECT_EQ(compressedPath, seenBodyFilePath);
    EXPECT_EQ(14u, seenBodyFileSize);
    EXPECT_THAT(seenHeaders, Contains("Content-Encoding: zstd"));

    ASSERT_EQ(3u, seenHeaders.size()); // Content-Encoding + the auth pair.
    EXPECT_TRUE(decodeBearer(seenHeaders.back(), testAgentKeyHex())->signatureValid);
}

TEST_F(RetrySenderTest, CompressedFileBackedAttemptRejectedWith415RetriesOnceUncompressedAndSucceeds)
{
    CompressionGate gate;
    RetrySender compressing {m_performer, m_signer, m_clock, m_backoff, true, &gate};

    const std::string originalPath = writeTempFile("hc_rs_415_original.bin", "the original body");
    const std::string compressedPath = writeTempFile("hc_rs_415_precompressed.bin", "zstd-ish bytes");

    HttpRequestSpec spec;
    spec.target = "/stateful";
    spec.bodyFilePath = originalPath;
    spec.bodyFileSize = 17;
    spec.precompressedBodyFilePath = compressedPath;
    spec.precompressedBodyFileSize = 14;

    std::vector<std::string> firstBodyFilePathAndHeaders;
    std::vector<std::string> secondBodyFilePathAndHeaders;
    EXPECT_CALL(m_performer, perform(_))
    .Times(2)
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & attempt)
    {
        firstBodyFilePathAndHeaders = attempt.headers;
        firstBodyFilePathAndHeaders.push_back(attempt.bodyFilePath);
        return response(TransportStatus::Ok, 415);
    }))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & attempt)
    {
        secondBodyFilePathAndHeaders = attempt.headers;
        secondBodyFilePathAndHeaders.push_back(attempt.bodyFilePath);
        return response(TransportStatus::Ok, 200);
    }));

    const auto result = compressing.send(spec, m_waiter, 1);

    EXPECT_EQ(OutcomeClass::Ok, result.outcome);
    EXPECT_THAT(firstBodyFilePathAndHeaders, Contains("Content-Encoding: zstd"));
    EXPECT_THAT(firstBodyFilePathAndHeaders, Contains(compressedPath));
    EXPECT_THAT(secondBodyFilePathAndHeaders, Not(Contains("Content-Encoding: zstd")));
    EXPECT_THAT(secondBodyFilePathAndHeaders, Contains(originalPath));
    EXPECT_TRUE(gate.disabled());
}

TEST_F(RetrySenderTest, SecondFileBackedCompressionRejectionTerminatesWithoutLooping)
{
    // No gate here: nothing disables compression between attempts, so both
    // calls keep trying the precompressed sibling -- proving the one-shot
    // retry is bounded per send() call for file bodies too, not just because
    // the gate happened to help.
    RetrySender compressing {m_performer, m_signer, m_clock, m_backoff, true};

    const std::string originalPath = writeTempFile("hc_rs_loop_original.bin", "the original body");
    const std::string compressedPath = writeTempFile("hc_rs_loop_precompressed.bin", "zstd-ish bytes");

    HttpRequestSpec spec;
    spec.target = "/stateful";
    spec.bodyFilePath = originalPath;
    spec.bodyFileSize = 17;
    spec.precompressedBodyFilePath = compressedPath;
    spec.precompressedBodyFileSize = 14;

    EXPECT_CALL(m_performer, perform(_)).Times(2).WillRepeatedly(Return(response(TransportStatus::Ok, 415)));

    const auto result = compressing.send(spec, m_waiter, 4); // maxAttempts=4, but never a 3rd call.
    EXPECT_EQ(OutcomeClass::CompressionRejected, result.outcome);
}

TEST_F(RetrySenderTest, FileBackedSenderSkipsCompressionOnceTheSharedGateIsAlreadyDisabled)
{
    // The gate is shared across every stream regardless of body shape: an
    // in-memory sender's earlier 415 must stop a file-backed sender from ever
    // trying to compress, without it seeing a 415 itself.
    CompressionGate gate;
    gate.reportRejected();
    RetrySender compressing {m_performer, m_signer, m_clock, m_backoff, true, &gate};

    const std::string originalPath = writeTempFile("hc_rs_gate_original.bin", "the original body");

    HttpRequestSpec spec;
    spec.target = "/stateful";
    spec.bodyFilePath = originalPath;
    spec.bodyFileSize = 17;
    spec.precompressedBodyFilePath = writeTempFile("hc_rs_gate_precompressed.bin", "zstd-ish bytes");
    spec.precompressedBodyFileSize = 14;

    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & attempt)
    {
        EXPECT_THAT(attempt.headers, Not(Contains("Content-Encoding: zstd")));
        EXPECT_EQ(originalPath, attempt.bodyFilePath);
        return response(TransportStatus::Ok, 200);
    }));

    const auto result = compressing.send(spec, m_waiter, 1);
    EXPECT_EQ(OutcomeClass::Ok, result.outcome);
}

// #38492/#38491: the configured endpoint is folded into the wire target. The
// manager routes on the literal request-target (prefix included); the bearer
// token binds the agent's identity only, so the same token is valid for the
// bare and the prefixed target alike -- a prefix mismatch is a 404, never a 401.

TEST_F(RetrySenderTest, NoEndpointConfiguredLeavesTheTargetBare)
{
    // m_sender (the fixture default) is built with no serverEndpoint --
    // every other test in this file already relies on this being a no-op.
    HttpRequestSpec seenSpec;
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & attempt)
    {
        seenSpec = attempt;
        return response(TransportStatus::Ok, 200);
    }));

    const auto result = m_sender.send(makeSpec(), m_waiter, 1);

    EXPECT_EQ(OutcomeClass::Ok, result.outcome);
    EXPECT_EQ("/stateless", seenSpec.target);
}

TEST_F(RetrySenderTest, ConfiguredEndpointIsFoldedIntoTheWireTargetOnly)
{
    RetrySender withEndpoint {m_performer, m_signer, m_clock, m_backoff, false, nullptr, nullptr, "wazuh-manager"};

    HttpRequestSpec seenSpec;
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & attempt)
    {
        seenSpec = attempt;
        return response(TransportStatus::Ok, 200);
    }));

    const auto result = withEndpoint.send(makeSpec(), m_waiter, 1);

    EXPECT_EQ(OutcomeClass::Ok, result.outcome);
    // The wire target carries the prefix...
    ASSERT_EQ("/wazuh-manager/stateless", seenSpec.target);

    // ...and the Authorization header is a plain bearer for agent 001 that says
    // nothing about the target: verifiable with the key, no target inside it.
    const auto bearer = decodeBearer(seenSpec.headers.back(), testAgentKeyHex());
    ASSERT_TRUE(bearer.has_value());
    EXPECT_TRUE(bearer->signatureValid);
    EXPECT_EQ("001", bearer->claims.at("sub"));
    EXPECT_EQ(std::string::npos, seenSpec.headers.back().find("stateless"));
}

TEST_F(RetrySenderTest, ConfiguredEndpointComposesWithFileBackedTargets)
{
    RetrySender withEndpoint {m_performer, m_signer, m_clock, m_backoff, false, nullptr, nullptr, "wazuh-manager"};

    const std::string path = writeTempFile("hc_rs_endpoint_stateful.bin", "the body");

    HttpRequestSpec spec;
    spec.target = "/stateful";
    spec.bodyFilePath = path;
    spec.bodyFileSize = 8;

    HttpRequestSpec seenSpec;
    EXPECT_CALL(m_performer, perform(_))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & attempt)
    {
        seenSpec = attempt;
        return response(TransportStatus::Ok, 200);
    }));

    const auto result = withEndpoint.send(spec, m_waiter, 1);

    EXPECT_EQ(OutcomeClass::Ok, result.outcome);
    ASSERT_EQ("/wazuh-manager/stateful", seenSpec.target);

    EXPECT_TRUE(decodeBearer(seenSpec.headers.back(), testAgentKeyHex())->signatureValid);
}
