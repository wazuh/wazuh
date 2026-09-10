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
#include "jwt/base64Url.hpp"
#include "jwt/jwtEnrollTokenVerifier.hpp"
#include "jwt/jwtKeyDecoder.hpp"
#include "mockFsProbe.hpp"
#include "mockHttpPerformer.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <ctime>

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
        return std::any_of(
                   headers.begin(), headers.end(), [&](const std::string & header)
        {
            return header.rfind(prefix, 0) == 0;
        });
    }

    // Verifies the `Authorization: Bearer <wazuh-enroll+jwt>` header the client attached with the
    // manager's own shared verifier and the HKDF key of `password`, at wall time `at`.
    jwt_profile::v1::VerifyError
    verifyBearer(const std::vector<std::string>& headers, const std::string& password, std::time_t at)
    {
        const std::string prefix = "Authorization: Bearer ";
        const auto bearer =
            std::find_if(headers.begin(), headers.end(), [&](const std::string & h)
        {
            return h.rfind(prefix, 0) == 0;
        });
        const auto key = EnrollSigner::deriveKey(password);

        if (bearer == headers.end() || !key)
        {
            return jwt_profile::v1::VerifyError::InvalidToken;
        }

        return jwt_profile::v1::enroll::JwtEnrollTokenVerifier::verify(
                   bearer->substr(prefix.size()),
                   *key,
                   jwt_profile::v1::TimePolicy {},
                   std::chrono::system_clock::time_point {std::chrono::seconds {at}});
    }

    HttpResponse okResponse(long code = 200)
    {
        HttpResponse response;
        response.status = TransportStatus::Ok;
        response.httpCode = code;
        response.body = "{}";
        return response;
    }

    // A fixed token-kid credential: 16 bytes of id -> 22 canonical base64url chars, and a
    // 32-byte key as the 64-hex form hc_enroll_request_t::enroll_key_hex carries.
    const std::string TOKEN_KID = jwt_profile::v1::base64UrlEncode(std::string(16, '\x01'));
    const std::string TOKEN_KEY_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    // #39064: the other keyed credential. The `kid` is a canonical AGENT id, not a 22-character
    // token id, and the key is derived under WAZUH-REENROLL-KEY -- both frozen in
    // jwt/testVectors.hpp, which is what authd verifies against.
    const std::string REENROLL_KID = "001";
    const std::string REENROLL_KEY_HEX = "68b01ea65fc441951a17e3fd9b7e2dedc846d364f38596630ea3f69f60482ae9";

    // Verifies the `Authorization: Bearer <wazuh-enroll+jwt>` header against the given `kid` and
    // key, the way the manager's own JwtEnrollTokenVerifier::verifyWithKid() does.
    jwt_profile::v1::VerifyError verifyKeyedBearer(const std::vector<std::string>& headers,
                                                   const std::string& kid,
                                                   const std::string& keyHex,
                                                   std::time_t at)
    {
        const std::string prefix = "Authorization: Bearer ";
        const auto bearer =
            std::find_if(headers.begin(), headers.end(), [&](const std::string & h)
        {
            return h.rfind(prefix, 0) == 0;
        });
        const auto key = jwt_profile::v1::JwtKeyDecoder::decode(keyHex);

        if (bearer == headers.end() || !key)
        {
            return jwt_profile::v1::VerifyError::InvalidToken;
        }

        return jwt_profile::v1::enroll::JwtEnrollTokenVerifier::verifyWithKid(
                   bearer->substr(prefix.size()),
                   kid,
                   *key,
                   jwt_profile::v1::TimePolicy {},
                   std::chrono::system_clock::time_point {std::chrono::seconds {at}});
    }

    // Verifies the `Authorization: Bearer <wazuh-enroll+jwt>` header against the token-kid
    // shared verifier, the same way verifyBearer() above does for the password form.
    jwt_profile::v1::VerifyError verifyTokenBearer(const std::vector<std::string>& headers, std::time_t at)
    {
        const std::string prefix = "Authorization: Bearer ";
        const auto bearer =
            std::find_if(headers.begin(), headers.end(), [&](const std::string & h)
        {
            return h.rfind(prefix, 0) == 0;
        });
        const auto key = jwt_profile::v1::JwtKeyDecoder::decode(TOKEN_KEY_HEX);

        if (bearer == headers.end() || !key)
        {
            return jwt_profile::v1::VerifyError::InvalidToken;
        }

        return jwt_profile::v1::enroll::JwtEnrollTokenVerifier::verifyWithKid(
                   bearer->substr(prefix.size()),
                   TOKEN_KID,
                   *key,
                   jwt_profile::v1::TimePolicy {},
                   std::chrono::system_clock::time_point {std::chrono::seconds {at}});
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

TEST(EnrollClientTest, PasswordModeAddsABearerTheSharedVerifierAccepts)
{
    NiceMock<MockFsProbe> fsProbe;
    NiceMock<MockHttpPerformer> performer;
    FakeClock clock;
    clock.setWall(1700000000);
    EnrollClient client {openModeConfig(), performer, fsProbe, clock, TEST_LOG};

    EXPECT_CALL(performer, perform(_))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & spec)
    {
        EXPECT_TRUE(hasHeader(spec.headers, "protocol-version: 1"));
        EXPECT_EQ(jwt_profile::v1::VerifyError::None, verifyBearer(spec.headers, "s3cr3t", 1700000000));
        return okResponse();
    }));

    client.enroll(BODY, "s3cr3t");
}

// #38492/#38491: the manager routes on the literal wire request-target
// (prefix included), so /enroll must be sent under the prefixed target too,
// exactly like every other endpoint (RetrySender::attemptOnce carries the
// equivalent test); the bearer does not bind the target.
TEST(EnrollClientTest, ConfiguredEndpointIsFoldedIntoTheTarget)
{
    NiceMock<MockFsProbe> fsProbe;
    NiceMock<MockHttpPerformer> performer;
    FakeClock clock;
    clock.setWall(1700000000);
    auto config = openModeConfig();
    config.serverEndpoint = "wazuh-manager";
    EnrollClient client {config, performer, fsProbe, clock, TEST_LOG};

    EXPECT_CALL(performer, perform(_))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & spec)
    {
        EXPECT_EQ("/wazuh-manager/enroll", spec.target);
        EXPECT_EQ(jwt_profile::v1::VerifyError::None, verifyBearer(spec.headers, "s3cr3t", 1700000000));
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
        EXPECT_TRUE(hasHeader(spec.headers, "Authorization: Bearer "));
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

        // ...and a bearer minted from the password at the clock's time still accompanies
        // it: the token binds time and jti, never the body, so compression cannot break it.
        EXPECT_EQ(jwt_profile::v1::VerifyError::None, verifyBearer(spec.headers, "s3cr3t", 1700000000));

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
        // Re-minted with the now-corrected clock: valid at the manager's time, and NOT at the
        // original skewed local time (an hour behind -> "issued in the future" there).
        EXPECT_EQ(jwt_profile::v1::VerifyError::None, verifyBearer(spec.headers, "s3cr3t", serverNow));
        EXPECT_EQ(jwt_profile::v1::VerifyError::StaleToken, verifyBearer(spec.headers, "s3cr3t", 1700000000));

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

// Token-kid mode: the enrollment-token bootstrap's bearer.

TEST(EnrollClientTest, TokenKidModeAddsABearerTheSharedVerifierAccepts)
{
    NiceMock<MockFsProbe> fsProbe;
    NiceMock<MockHttpPerformer> performer;
    FakeClock clock;
    clock.setWall(1700000000);
    EnrollClient client {openModeConfig(), performer, fsProbe, clock, TEST_LOG};

    EXPECT_CALL(performer, perform(_))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & spec)
    {
        EXPECT_TRUE(hasHeader(spec.headers, "protocol-version: 1"));
        EXPECT_EQ(jwt_profile::v1::VerifyError::None, verifyTokenBearer(spec.headers, 1700000000));
        return okResponse();
    }));

    client.enroll(BODY, "", TOKEN_KID, TOKEN_KEY_HEX);
}

TEST(EnrollClientTest, TokenKidTakesPriorityOverAConfiguredPassword)
{
    // A token-based enrollment must not also sign with a possibly-unrelated authd.pass: when
    // both are supplied, only the token-kid bearer is minted.
    NiceMock<MockFsProbe> fsProbe;
    NiceMock<MockHttpPerformer> performer;
    FakeClock clock;
    clock.setWall(1700000000);
    EnrollClient client {openModeConfig(), performer, fsProbe, clock, TEST_LOG};

    EXPECT_CALL(performer, perform(_))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & spec)
    {
        EXPECT_EQ(jwt_profile::v1::VerifyError::None, verifyTokenBearer(spec.headers, 1700000000));
        // The password-derived shared-key verifier must reject it: this is not that token.
        EXPECT_EQ(jwt_profile::v1::VerifyError::InvalidToken, verifyBearer(spec.headers, "s3cr3t", 1700000000));
        return okResponse();
    }));

    client.enroll(BODY, "s3cr3t", TOKEN_KID, TOKEN_KEY_HEX);
}

// Re-enrollment (#39064): the same two fields carry an agent's own credential. The `kid` is a
// canonical agent id, so this proves the client is generic over the `kid`'s shape -- it neither
// validates it as a token id nor re-derives the key.

TEST(EnrollClientTest, AnAgentKidBearerIsAcceptedByTheSharedVerifier)
{
    NiceMock<MockFsProbe> fsProbe;
    NiceMock<MockHttpPerformer> performer;
    FakeClock clock;
    clock.setWall(1700000000);
    EnrollClient client {openModeConfig(), performer, fsProbe, clock, TEST_LOG};

    EXPECT_CALL(performer, perform(_))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & spec)
    {
        EXPECT_TRUE(hasHeader(spec.headers, "protocol-version: 1"));
        EXPECT_EQ(jwt_profile::v1::VerifyError::None,
                  verifyKeyedBearer(spec.headers, REENROLL_KID, REENROLL_KEY_HEX, 1700000000));
        return okResponse();
    }));

    client.enroll(BODY, "", REENROLL_KID, REENROLL_KEY_HEX);
}

TEST(EnrollClientTest, AnAgentKidTakesPriorityOverAConfiguredPassword)
{
    // Same rule as the token credential: an agent that holds its own secret must not also sign
    // with the fleet-wide authd.pass, or the audit trail would misreport what authenticated it.
    NiceMock<MockFsProbe> fsProbe;
    NiceMock<MockHttpPerformer> performer;
    FakeClock clock;
    clock.setWall(1700000000);
    EnrollClient client {openModeConfig(), performer, fsProbe, clock, TEST_LOG};

    EXPECT_CALL(performer, perform(_))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & spec)
    {
        EXPECT_EQ(jwt_profile::v1::VerifyError::None,
                  verifyKeyedBearer(spec.headers, REENROLL_KID, REENROLL_KEY_HEX, 1700000000));
        EXPECT_EQ(jwt_profile::v1::VerifyError::InvalidToken, verifyBearer(spec.headers, "s3cr3t", 1700000000));
        return okResponse();
    }));

    client.enroll(BODY, "s3cr3t", REENROLL_KID, REENROLL_KEY_HEX);
}

// The two keyed credentials are disjoint by construction: a bearer minted for one `kid` must not
// verify under the other's key. This is the property that lets one pair of ABI fields carry both.
TEST(EnrollClientTest, AnAgentKidBearerDoesNotVerifyAsATokenBearer)
{
    NiceMock<MockFsProbe> fsProbe;
    NiceMock<MockHttpPerformer> performer;
    FakeClock clock;
    clock.setWall(1700000000);
    EnrollClient client {openModeConfig(), performer, fsProbe, clock, TEST_LOG};

    EXPECT_CALL(performer, perform(_))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & spec)
    {
        EXPECT_NE(jwt_profile::v1::VerifyError::None, verifyTokenBearer(spec.headers, 1700000000));
        return okResponse();
    }));

    client.enroll(BODY, "", REENROLL_KID, REENROLL_KEY_HEX);
}

// Half a credential is no credential: the module must fall back to the password rather than mint
// a bearer it cannot sign, so the bridge's own "both or neither" rule has a counterpart here.
TEST(EnrollClientTest, AKidWithNoKeyFallsBackToThePassword)
{
    NiceMock<MockFsProbe> fsProbe;
    NiceMock<MockHttpPerformer> performer;
    FakeClock clock;
    clock.setWall(1700000000);
    EnrollClient client {openModeConfig(), performer, fsProbe, clock, TEST_LOG};

    EXPECT_CALL(performer, perform(_))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & spec)
    {
        EXPECT_EQ(jwt_profile::v1::VerifyError::None, verifyBearer(spec.headers, "s3cr3t", 1700000000));
        return okResponse();
    }));

    client.enroll(BODY, "s3cr3t", REENROLL_KID, "");
}

TEST(EnrollClientTest, RetriesOnceOn401InTokenKidModeAndCorrectsSkew)
{
    // Same one-shot grace-retry as password mode (#38440's self-correction): a 401 in
    // token-kid mode is not exempt just because it is not the password branch.
    NiceMock<MockFsProbe> fsProbe;
    NiceMock<MockHttpPerformer> performer;
    FakeClock clock;
    clock.setWall(1700000000);
    EnrollClient client {openModeConfig(), performer, fsProbe, clock, TEST_LOG};

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
        EXPECT_EQ(jwt_profile::v1::VerifyError::None, verifyTokenBearer(spec.headers, serverNow));
        return okResponse(200);
    }));

    const auto response = client.enroll(BODY, "", TOKEN_KID, TOKEN_KEY_HEX);
    EXPECT_EQ(200, response.httpCode);
    EXPECT_EQ(1, clock.offsetApplyCount());
}

// Non-regression check: the password-only behavior every test above already exercises via
// the 2-argument overload should match this 4-argument call with the token fields empty (same
// target/body/header set; not byte-for-byte, since EnrollSigner::sign() mints a fresh jti
// every call).
TEST(EnrollClientTest, PasswordOnlyBehaviorIsUnchangedWhenTokenFieldsAreExplicitlyEmpty)
{
    NiceMock<MockFsProbe> fsProbe;
    NiceMock<MockHttpPerformer> performer;
    FakeClock clock;
    clock.setWall(1700000000);

    std::string twoArgTarget, fourArgTarget;
    std::vector<std::string> twoArgHeaders, fourArgHeaders;
    std::string twoArgBody, fourArgBody;

    {
        EnrollClient client {openModeConfig(), performer, fsProbe, clock, TEST_LOG};
        EXPECT_CALL(performer, perform(_))
        .WillOnce(Invoke(
                      [&](const HttpRequestSpec & spec)
        {
            twoArgTarget = spec.target;
            twoArgHeaders = spec.headers;
            twoArgBody.assign(reinterpret_cast<const char*>(spec.body), spec.bodyLength);
            return okResponse();
        }));
        client.enroll(BODY, "s3cr3t");
    }
    {
        EnrollClient client {openModeConfig(), performer, fsProbe, clock, TEST_LOG};
        EXPECT_CALL(performer, perform(_))
        .WillOnce(Invoke(
                      [&](const HttpRequestSpec & spec)
        {
            fourArgTarget = spec.target;
            fourArgHeaders = spec.headers;
            fourArgBody.assign(reinterpret_cast<const char*>(spec.body), spec.bodyLength);
            return okResponse();
        }));
        client.enroll(BODY, "s3cr3t", "", "");
    }

    EXPECT_EQ(twoArgTarget, fourArgTarget);
    EXPECT_EQ(twoArgBody, fourArgBody);
    EXPECT_EQ(BODY, twoArgBody);
    EXPECT_EQ(twoArgHeaders.size(), fourArgHeaders.size());
    EXPECT_TRUE(hasHeader(twoArgHeaders, "protocol-version: 1"));
    EXPECT_TRUE(hasHeader(fourArgHeaders, "protocol-version: 1"));
    EXPECT_EQ(jwt_profile::v1::VerifyError::None, verifyBearer(twoArgHeaders, "s3cr3t", 1700000000));
    EXPECT_EQ(jwt_profile::v1::VerifyError::None, verifyBearer(fourArgHeaders, "s3cr3t", 1700000000));
}

TEST(EnrollClientTest, RejectsWithoutSendingWhenTransportConfigIsInvalid)
{
    ::testing::StrictMock<MockFsProbe> fsProbe;         // Must not even be asked.
    ::testing::StrictMock<MockHttpPerformer> performer; // Must never be called.
    FakeClock clock;

    auto config = openModeConfig();
    config.verifyMode = HC_VERIFY_FULL; // Fail-closed: no CA configured.
    EnrollClient client {config, performer, fsProbe, clock, TEST_LOG};

    const auto response = client.enroll(BODY, "");
    EXPECT_EQ(TransportStatus::TlsFail, response.status);
    EXPECT_EQ(0, response.httpCode);
}
