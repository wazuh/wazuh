/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * August 19, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "enrollClient.hpp"

#include "enrollSigner.hpp"
#include "fakeSysSeams.hpp"
#include "mockFsProbe.hpp"
#include "mockHttpPerformer.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>

using ::testing::_;
using ::testing::Invoke;
using ::testing::NiceMock;
using ::testing::Return;

namespace
{
    const LogFn TEST_LOG {"https-client-test"}; // Sink unset: LOGFN_* are no-ops.
    const std::string BODY = R"({"name":"agent01","version":"5.0.0"})";

    ModuleConfig openModeConfig()
    {
        ModuleConfig config;
        config.serverHost = "manager.example";
        config.serverPort = 1517;
        config.verifyMode = HC_VERIFY_NONE;
        config.requestTimeoutMs = 10000;
        // Explicit, not relying on ModuleConfig's own default (which is a
        // separate, independently-tunable production default that can change
        // -- e.g. it flipped to true after this test was written): tests that
        // want compression on set it themselves below.
        config.httpsCompressionEnabled = false;
        return config;
    }

    bool hasHeader(const std::vector<std::string>& headers, const std::string& prefix)
    {
        return std::any_of(headers.begin(), headers.end(),
                           [&](const std::string & header)
        {
            return header.rfind(prefix, 0) == 0;
        });
    }

    HttpResponse okResponse(long code = 200)
    {
        HttpResponse response;
        response.status = TransportStatus::Ok;
        response.httpCode = code;
        response.body = "{}";
        return response;
    }
} // namespace

TEST(EnrollClientTest, OpenModeSendsOnlyProtocolVersion)
{
    NiceMock<MockFsProbe> fsProbe;
    NiceMock<MockHttpPerformer> performer;
    FakeClock clock;
    EnrollClient client {openModeConfig(), performer, fsProbe, clock, TEST_LOG};

    EXPECT_CALL(performer, perform(_))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & spec)
    {
        EXPECT_EQ("/enroll", spec.target);
        EXPECT_EQ("application/json", spec.contentType);
        EXPECT_TRUE(hasHeader(spec.headers, "protocol-version: 1"));
        EXPECT_FALSE(hasHeader(spec.headers, "Authorization:"));
        EXPECT_FALSE(hasHeader(spec.headers, "Content-Encoding:"));
        EXPECT_EQ(BODY, std::string(reinterpret_cast<const char*>(spec.body), spec.bodyLength));
        return okResponse();
    }));

    const auto response = client.enroll(BODY, "");
    EXPECT_EQ(TransportStatus::Ok, response.status);
    EXPECT_EQ(200, response.httpCode);
}

TEST(EnrollClientTest, PasswordModeAddsAuthorizationHeaderMatchingEnrollSigner)
{
    NiceMock<MockFsProbe> fsProbe;
    NiceMock<MockHttpPerformer> performer;
    FakeClock clock;
    clock.setWall(1700000000);
    EnrollClient client {openModeConfig(), performer, fsProbe, clock, TEST_LOG};

    const auto expected = EnrollSigner::sign("s3cr3t", "POST", "/enroll",
                                             reinterpret_cast<const uint8_t*>(BODY.data()), BODY.size(),
                                             1700000000);
    ASSERT_TRUE(expected.has_value());

    EXPECT_CALL(performer, perform(_))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & spec)
    {
        EXPECT_TRUE(hasHeader(spec.headers, "protocol-version: 1"));
        EXPECT_TRUE(std::find(spec.headers.begin(), spec.headers.end(), expected->authorization)
                    != spec.headers.end());
        return okResponse();
    }));

    client.enroll(BODY, "s3cr3t");
}

// #38492/#38491: the manager's auth middleware CMACs the literal wire
// request-target (prefix included), so /enroll's password signature must
// cover the prefixed target too, exactly like every other endpoint
// (RetrySender::attemptOnce carries the equivalent test).
TEST(EnrollClientTest, ConfiguredEndpointIsFoldedIntoTheTargetAndTheSignature)
{
    NiceMock<MockFsProbe> fsProbe;
    NiceMock<MockHttpPerformer> performer;
    FakeClock clock;
    clock.setWall(1700000000);
    auto config = openModeConfig();
    config.serverEndpoint = "wazuh-manager";
    EnrollClient client {config, performer, fsProbe, clock, TEST_LOG};

    const auto expected = EnrollSigner::sign("s3cr3t", "POST", "/wazuh-manager/enroll",
                                             reinterpret_cast<const uint8_t*>(BODY.data()), BODY.size(),
                                             1700000000);
    ASSERT_TRUE(expected.has_value());

    EXPECT_CALL(performer, perform(_))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & spec)
    {
        EXPECT_EQ("/wazuh-manager/enroll", spec.target);
        EXPECT_TRUE(std::find(spec.headers.begin(), spec.headers.end(), expected->authorization)
                    != spec.headers.end());
        return okResponse();
    }));

    client.enroll(BODY, "s3cr3t");
}

TEST(EnrollClientTest, CertAndPasswordCoexistNoPrecedence)
{
    // #38465 Q3 (confirmed with the server team): a client cert and a
    // password can both be configured at once -- the cert authenticates the
    // connection (handled entirely by CurlPerformer/m_config, invisible
    // here), the password still signs the request. EnrollClient must not
    // suppress the Authorization header just because a cert is also present.
    NiceMock<MockFsProbe> fsProbe;
    ON_CALL(fsProbe, isReadableFile(_)).WillByDefault(Return(true));
    NiceMock<MockHttpPerformer> performer;
    FakeClock clock;

    auto config = openModeConfig();
    config.clientCert = "/etc/agent.pem";
    config.clientKey = "/etc/agent.key";
    EnrollClient client {config, performer, fsProbe, clock, TEST_LOG};

    EXPECT_CALL(performer, perform(_))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & spec)
    {
        EXPECT_TRUE(hasHeader(spec.headers, "Authorization: WazuhEnroll"));
        return okResponse();
    }));

    client.enroll(BODY, "s3cr3t");
}

TEST(EnrollClientTest, CompressesBodyWhenEnabledAndSignsTheCompressedBytes)
{
    NiceMock<MockFsProbe> fsProbe;
    NiceMock<MockHttpPerformer> performer;
    FakeClock clock;
    clock.setWall(1700000000);

    auto config = openModeConfig();
    config.httpsCompressionEnabled = true;
    EnrollClient client {config, performer, fsProbe, clock, TEST_LOG};

    EXPECT_CALL(performer, perform(_))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & spec)
    {
        EXPECT_TRUE(hasHeader(spec.headers, "Content-Encoding: zstd"));
        // The body actually on the wire must differ from the plain JSON...
        EXPECT_NE(BODY, std::string(reinterpret_cast<const char*>(spec.body), spec.bodyLength));

        // ...and the CMAC must cover exactly those compressed bytes, not the
        // original JSON (a signature over the wrong bytes would 401 forever).
        const auto expected = EnrollSigner::sign("s3cr3t", "POST", "/enroll", spec.body, spec.bodyLength,
                                                 1700000000);
        EXPECT_TRUE(expected.has_value());

        if (expected)
        {
            EXPECT_TRUE(std::find(spec.headers.begin(), spec.headers.end(), expected->authorization)
                        != spec.headers.end());
        }

        return okResponse();
    }));

    client.enroll(BODY, "s3cr3t");
}

TEST(EnrollClientTest, DoesNotCompressWhenDisabled)
{
    NiceMock<MockFsProbe> fsProbe;
    NiceMock<MockHttpPerformer> performer;
    FakeClock clock;
    EnrollClient client {openModeConfig(), performer, fsProbe, clock, TEST_LOG};

    EXPECT_CALL(performer, perform(_))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & spec)
    {
        EXPECT_FALSE(hasHeader(spec.headers, "Content-Encoding:"));
        EXPECT_EQ(BODY, std::string(reinterpret_cast<const char*>(spec.body), spec.bodyLength));
        return okResponse();
    }));

    client.enroll(BODY, "");
}

TEST(EnrollClientTest, RetriesOnceUncompressedOn415)
{
    NiceMock<MockFsProbe> fsProbe;
    NiceMock<MockHttpPerformer> performer;
    FakeClock clock;

    auto config = openModeConfig();
    config.httpsCompressionEnabled = true;
    EnrollClient client {config, performer, fsProbe, clock, TEST_LOG};

    ::testing::InSequence sequence;

    EXPECT_CALL(performer, perform(_))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & spec)
    {
        EXPECT_TRUE(hasHeader(spec.headers, "Content-Encoding: zstd"));
        return okResponse(415);
    }));

    EXPECT_CALL(performer, perform(_))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & spec)
    {
        EXPECT_FALSE(hasHeader(spec.headers, "Content-Encoding:"));
        EXPECT_EQ(BODY, std::string(reinterpret_cast<const char*>(spec.body), spec.bodyLength));
        return okResponse(200);
    }));

    const auto response = client.enroll(BODY, "");
    EXPECT_EQ(200, response.httpCode);
}

TEST(EnrollClientTest, DoesNotRetryOn415WhenCompressionWasAlreadyDisabled)
{
    NiceMock<MockFsProbe> fsProbe;
    NiceMock<MockHttpPerformer> performer;
    FakeClock clock;
    EnrollClient client {openModeConfig(), performer, fsProbe, clock, TEST_LOG};

    EXPECT_CALL(performer, perform(_)).Times(1).WillOnce(Return(okResponse(415)));

    const auto response = client.enroll(BODY, "");
    EXPECT_EQ(415, response.httpCode);
}

TEST(EnrollClientTest, CorrectsSkewedClockAndRetriesOnceOn401WithDate)
{
    NiceMock<MockFsProbe> fsProbe;
    NiceMock<MockHttpPerformer> performer;
    FakeClock clock;
    clock.setWall(1700000000);
    EnrollClient client {openModeConfig(), performer, fsProbe, clock, TEST_LOG};

    // The manager's clock is 1 hour ahead; its 401 carries that as Date.
    const std::time_t serverNow = 1700000000 + 3600;

    ::testing::InSequence sequence;

    EXPECT_CALL(performer, perform(_))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec&)
    {
        HttpResponse response;
        response.status = TransportStatus::Ok;
        response.httpCode = 401;
        response.serverDateSeconds = serverNow;
        return response;
    }));

    EXPECT_CALL(performer, perform(_))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & spec)
    {
        // Re-signed with the now-corrected clock: matches a signature
        // computed against the manager's time, not the original skewed one.
        const auto expected = EnrollSigner::sign("s3cr3t", "POST", "/enroll",
                                                 reinterpret_cast<const uint8_t*>(BODY.data()), BODY.size(),
                                                 serverNow);
        EXPECT_TRUE(expected.has_value());

        if (expected)
        {
            EXPECT_TRUE(std::find(spec.headers.begin(), spec.headers.end(), expected->authorization)
                        != spec.headers.end());
        }

        return okResponse(200);
    }));

    const auto response = client.enroll(BODY, "s3cr3t");
    EXPECT_EQ(200, response.httpCode);
    EXPECT_EQ(1, clock.offsetApplyCount());
    EXPECT_EQ(3600, clock.appliedOffsetSeconds());
}

TEST(EnrollClientTest, DoesNotRetryASecondConsecutive401)
{
    // A 401 that survives the grace-retry (still skew-corrected, or a
    // genuinely dead password either way) must reach the caller as-is, not
    // loop forever.
    NiceMock<MockFsProbe> fsProbe;
    NiceMock<MockHttpPerformer> performer;
    FakeClock clock;
    clock.setWall(1700000000);
    EnrollClient client {openModeConfig(), performer, fsProbe, clock, TEST_LOG};

    HttpResponse unauthorized;
    unauthorized.status = TransportStatus::Ok;
    unauthorized.httpCode = 401;
    unauthorized.serverDateSeconds = 1700000000 + 3600;

    EXPECT_CALL(performer, perform(_)).Times(2).WillRepeatedly(Return(unauthorized));

    const auto response = client.enroll(BODY, "s3cr3t");
    EXPECT_EQ(401, response.httpCode);
    EXPECT_EQ(1, clock.offsetApplyCount()); // Corrected once, not twice.
}

TEST(EnrollClientTest, RetriesOnceOn401WithoutADateHeaderButAppliesNoCorrection)
{
    // Same one-shot grace-retry as RetrySender's identical case (a 401 can
    // be a just-expired/edge timestamp even without measurable skew), but
    // with nothing to measure a delta against, no clock correction happens
    // -- the retry is just a fresh timestamp, signed again.
    NiceMock<MockFsProbe> fsProbe;
    NiceMock<MockHttpPerformer> performer;
    FakeClock clock;

    EnrollClient client {openModeConfig(), performer, fsProbe, clock, TEST_LOG};

    EXPECT_CALL(performer, perform(_)).Times(2).WillRepeatedly(Return(okResponse(401)));

    const auto response = client.enroll(BODY, "s3cr3t");
    EXPECT_EQ(401, response.httpCode);
    EXPECT_EQ(0, clock.offsetApplyCount());
}

TEST(EnrollClientTest, DoesNotRetryOn401InOpenModeEvenWithADate)
{
    // No password means no signature was ever sent -- a 401 here cannot be
    // a timestamp issue, so there is nothing to correct or retry.
    NiceMock<MockFsProbe> fsProbe;
    NiceMock<MockHttpPerformer> performer;
    FakeClock clock;
    clock.setWall(1700000000);

    EnrollClient client {openModeConfig(), performer, fsProbe, clock, TEST_LOG};

    HttpResponse unauthorized;
    unauthorized.status = TransportStatus::Ok;
    unauthorized.httpCode = 401;
    unauthorized.serverDateSeconds = 1700000000 + 3600;

    EXPECT_CALL(performer, perform(_)).Times(1).WillOnce(Return(unauthorized));

    const auto response = client.enroll(BODY, "");
    EXPECT_EQ(401, response.httpCode);
    EXPECT_EQ(0, clock.offsetApplyCount());
}

TEST(EnrollClientTest, RejectsWithoutSendingWhenTransportConfigIsInvalid)
{
    ::testing::StrictMock<MockFsProbe> fsProbe; // Must not even be asked.
    ::testing::StrictMock<MockHttpPerformer> performer; // Must never be called.
    FakeClock clock;

    auto config = openModeConfig();
    config.verifyMode = HC_VERIFY_FULL; // Fail-closed: no CA configured.
    EnrollClient client {config, performer, fsProbe, clock, TEST_LOG};

    const auto response = client.enroll(BODY, "");
    EXPECT_EQ(TransportStatus::TlsFail, response.status);
    EXPECT_EQ(0, response.httpCode);
}
