/*
 * Wazuh remoted module - POST /enroll end-to-end tests
 * Copyright (C) 2015, Wazuh Inc.
 * August 19, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Drives the FULL /enroll pipeline (EnrollmentAuthenticator + the endpoint's own validation/IP
 * resolution + a real AuthdClient talking to a FakeUdsServer standing in for authd) for the
 * scenarios the design's test plan calls out explicitly: a correctly signed Password-mode
 * request, Open mode, authd down, and a replayed signed request inside the freshness window
 * (D12: an accepted limitation, not something this code defends against -- authd's own
 * duplicate-name/IP rejection is what actually stops a meaningful replay from doing anything).
 * mTLS has nothing left to test here: EnrollmentAuthenticator has no notion of a client
 * certificate at all -- with requirePassword=false it always passes unconditionally (unit-tested
 * in enrollmentAuthenticator_test.cpp), so the interesting behavior for mTLS is the TLS listener's
 * own certificate verification -- transport-layer, not this code's (see enrollmentMtlsE2E_test.cpp).
 */

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <ctime>
#include <fstream>
#include <memory>
#include <mutex>
#include <string>
#include <unistd.h>

#include <gtest/gtest.h>

#include "auth/authTypes.hpp" // remoted::auth::kSupportedProtocolVersion
#include "auth/tokenKeySource.hpp"
#include "decoding/iBodyDecoder.hpp"
#include "enrollment/enrollmentEndpoint.hpp"
#include "fakeUdsServer.hpp"
#include "json.hpp"
#include "jwt/enrollKeyDerivation.hpp"
#include "jwt/jwtEnrollTokenSigner.hpp"
#include "jwt/testVectors.hpp"

#include <wazuh_metrics/manager.hpp>

using namespace remoted::enrollment;
using remoted::auth::PasswordKeySource;
using remoted::auth::TokenKeySource;
using remoted::decoding::ContentEncoding;
using remoted::decoding::IBodyDecoder;
using remoted::http::HttpRequest;
using remoted::http::HttpResponse;
using remoted::http::IHttpResponder;
using remoted::http::Method;
using remoted::test::FakeUdsServer;
using remoted::test::makeUniqueSocketPath;
using namespace std::chrono_literals;

namespace
{
    const std::string kBody = R"({"name":"agent1","version":"5.0.0"})";

    // Inert stand-in for the real BodyDecoder (see enrollmentEndpoint_test.cpp's identical stub):
    // these tests are about the auth/validation/authd pipeline, not Content-Encoding, so this
    // just passes every body through untouched.
    class PassthroughBodyDecoder final : public IBodyDecoder
    {
    public:
        remoted::auth::AuthError decode(ContentEncoding, remoted::auth::Payload&) const override
        {
            return remoted::auth::AuthError::None;
        }
    };

    std::shared_ptr<const IBodyDecoder> passthroughDecoder()
    {
        return std::make_shared<const PassthroughBodyDecoder>();
    }

    // These tests drive the REAL endpoint handler, which checks the signed timestamp against the
    // actual wall clock (std::time(nullptr) in enrollmentEndpoint.cpp) -- unlike
    // enrollmentAuthenticator_test.cpp's unit tests, which pass a fixed "now" straight into
    // authenticate() and so can use a fixed constant safely. A hardcoded timestamp here would
    // start failing the moment real time drifted more than 300s past it.
    std::int64_t nowTs()
    {
        return static_cast<std::int64_t>(std::time(nullptr));
    }

    class CapturingResponder : public IHttpResponder
    {
    public:
        void send(HttpResponse response) override
        {
            std::lock_guard<std::mutex> lock(m_mu);
            if (m_done)
            {
                return;
            }
            m_response = std::move(response);
            m_done = true;
            m_cv.notify_all();
        }

        HttpResponse wait(std::chrono::milliseconds timeout = 2s)
        {
            std::unique_lock<std::mutex> lock(m_mu);
            EXPECT_TRUE(m_cv.wait_for(lock, timeout, [&] { return m_done; })) << "responder never called";
            return m_response;
        }

    private:
        std::mutex m_mu;
        std::condition_variable m_cv;
        bool m_done {false};
        HttpResponse m_response;
    };

    std::string writePasswordFile(const std::string& password)
    {
        const std::string path = "/tmp/enrollmentE2E_test_" + std::to_string(::getpid()) + ".pass";
        std::ofstream file(path);
        file << password << "\n";
        return path;
    }

    // The `wazuh-enroll+jwt` bearer EnrollmentAuthenticator verifies (jwt/jwtEnrollTokenSigner.hpp),
    // minted with the manager's own HKDF key at `ts`.
    std::string bearerFor(const jwt_profile::v1::SecureBytes& key, std::int64_t ts)
    {
        const auto token = jwt_profile::v1::enroll::JwtEnrollTokenSigner::sign(
            key, std::chrono::system_clock::time_point {std::chrono::seconds {ts}});
        EXPECT_TRUE(token.has_value());
        return "Bearer " + token.value_or("");
    }

    Config baseConfig()
    {
        Config cfg;
        cfg.enrollmentEnabled = true;
        cfg.managerVersion = "5.0.0";
        cfg.authdResponseTimeoutMs = 500;
        return cfg;
    }

    HttpResponse dispatch(const remoted::http::RouteHandler& handler, const HttpRequest& request)
    {
        auto responder = std::make_shared<CapturingResponder>();
        handler(std::make_shared<const HttpRequest>(request), responder);
        return responder->wait();
    }
} // namespace

TEST(EnrollmentE2ETest, PasswordModeCorrectlySignedRequestEnrollsSuccessfully)
{
    const std::string passwordPath = writePasswordFile("MyEnrollmentSecret123");
    auto keySource = std::make_shared<PasswordKeySource>(passwordPath);
    EnrollmentAuthenticator authenticator {EnrollmentAuthConfig {true}, keySource};

    const std::string authdPath = makeUniqueSocketPath("enrollment_e2e_password");
    FakeUdsServer authd(authdPath,
                        [](const std::string&)
                        { return R"({"error":0,"data":{"id":"003","name":"agent1","ip":"any","key":"deadbeef"}})"; });

    AuthdClient authdClient(authdPath, /*isWorkerNode=*/false, 0, baseConfig().authdResponseTimeoutMs, 0);
    wazuh::metrics::Manager metricsManager;
    EnrollmentMetrics metrics = makeEnrollmentMetrics(metricsManager);
    auto handler = makeHandler(authenticator, authdClient, baseConfig(), metrics, passthroughDecoder());

    const auto key = keySource->currentKey();
    ASSERT_TRUE(key.has_value());

    HttpRequest request;
    request.method = Method::Post;
    request.target = "/enroll";
    request.headers.emplace("protocol-version", std::string {remoted::auth::kSupportedProtocolVersion});
    request.body = kBody;
    request.headers.emplace("authorization", bearerFor(*key, nowTs()));

    const auto response = dispatch(handler, request);
    EXPECT_EQ(response.status, 200);
    EXPECT_EQ(nlohmann::json::parse(response.body)["id"], "003");

    std::remove(passwordPath.c_str());
}

TEST(EnrollmentE2ETest, PasswordModeWrongSignatureIsRejected)
{
    const std::string passwordPath = writePasswordFile("MyEnrollmentSecret123");
    auto keySource = std::make_shared<PasswordKeySource>(passwordPath);
    EnrollmentAuthenticator authenticator {EnrollmentAuthConfig {true}, keySource};

    // authd must never be reached -- rejection happens at the auth layer.
    AuthdClient authdClient(makeUniqueSocketPath("enrollment_e2e_password_reject"));
    wazuh::metrics::Manager metricsManager;
    EnrollmentMetrics metrics = makeEnrollmentMetrics(metricsManager);
    auto handler = makeHandler(authenticator, authdClient, baseConfig(), metrics, passthroughDecoder());

    HttpRequest request;
    request.method = Method::Post;
    request.target = "/enroll";
    request.headers.emplace("protocol-version", std::string {remoted::auth::kSupportedProtocolVersion});
    request.body = kBody;
    request.headers.emplace("authorization",
                            "Bearer " + std::string {jwt_profile::v1::test_vectors::enroll::kWrongPasswordToken});

    const auto response = dispatch(handler, request);
    EXPECT_EQ(response.status, 401);
    // RFC 6750 §3: /enroll's 401 carries the same class-naming bearer challenge every other route's
    // does (regression: its own error envelope used to drop the header errorResponseFor() attaches),
    // and the body's `code` is that class (issue #38993).
    const auto challenge = std::find_if(response.headers.begin(),
                                        response.headers.end(),
                                        [](const auto& header) { return header.first == "WWW-Authenticate"; });
    ASSERT_NE(challenge, response.headers.end());
    EXPECT_EQ(challenge->second, R"(Bearer error="invalid_token", error_description="invalid_signature")");
    EXPECT_EQ(nlohmann::json::parse(response.body)["error"]["code"], "invalid_signature");

    std::remove(passwordPath.c_str());
}

TEST(EnrollmentE2ETest, OpenModeUnauthenticatedRequestEnrollsSuccessfully)
{
    EnrollmentAuthenticator authenticator {EnrollmentAuthConfig {false}, nullptr};

    const std::string authdPath = makeUniqueSocketPath("enrollment_e2e_open");
    FakeUdsServer authd(authdPath,
                        [](const std::string&)
                        { return R"({"error":0,"data":{"id":"004","name":"agent2","ip":"any","key":"cafef00d"}})"; });

    AuthdClient authdClient(authdPath, /*isWorkerNode=*/false, 0, baseConfig().authdResponseTimeoutMs, 0);
    wazuh::metrics::Manager metricsManager;
    EnrollmentMetrics metrics = makeEnrollmentMetrics(metricsManager);
    auto handler = makeHandler(authenticator, authdClient, baseConfig(), metrics, passthroughDecoder());

    HttpRequest request;
    request.method = Method::Post;
    request.target = "/enroll";
    request.headers.emplace("protocol-version", std::string {remoted::auth::kSupportedProtocolVersion});
    request.body = kBody;
    // No Authorization header at all -- Open mode requires none.

    const auto response = dispatch(handler, request);
    EXPECT_EQ(response.status, 200);
}

TEST(EnrollmentE2ETest, AuthdDownMapsTo503)
{
    EnrollmentAuthenticator authenticator {EnrollmentAuthConfig {false}, nullptr};

    Config config = baseConfig();
    config.authdResponseTimeoutMs = 300; // short: no FakeUdsServer is ever bound below

    AuthdClient authdClient(
        makeUniqueSocketPath("enrollment_e2e_authd_down"), /*isWorkerNode=*/false, 0, config.authdResponseTimeoutMs, 0);
    wazuh::metrics::Manager metricsManager;
    EnrollmentMetrics metrics = makeEnrollmentMetrics(metricsManager);
    auto handler = makeHandler(authenticator, authdClient, config, metrics, passthroughDecoder());

    HttpRequest request;
    request.method = Method::Post;
    request.target = "/enroll";
    request.headers.emplace("protocol-version", std::string {remoted::auth::kSupportedProtocolVersion});
    request.body = kBody;

    const auto response = dispatch(handler, request);
    EXPECT_EQ(response.status, 503);
}

TEST(EnrollmentE2ETest, ReplayedSignedRequestWithinWindowIsNotStoppedByRemotedItself)
{
    // D12 (accepted limitation): remoted keeps no jti replay store, so an identical, still-valid
    // bearer replayed inside the freshness window passes OUR authentication a second time
    // too -- exactly like the first. Whatever stops a meaningful replay is authd's own business
    // rule (typically duplicate-name/IP rejection), which this test's fake authd emulates by
    // answering the second identical call with 9008 (Duplicate name), not by remoted itself.
    const std::string passwordPath = writePasswordFile("MyEnrollmentSecret123");
    auto keySource = std::make_shared<PasswordKeySource>(passwordPath);
    EnrollmentAuthenticator authenticator {EnrollmentAuthConfig {true}, keySource};

    const std::string authdPath = makeUniqueSocketPath("enrollment_e2e_replay");
    int callCount = 0;
    std::mutex mu;
    FakeUdsServer authd(authdPath,
                        [&](const std::string&)
                        {
                            std::lock_guard<std::mutex> lock(mu);
                            ++callCount;
                            if (callCount == 1)
                            {
                                return std::string(
                                    R"({"error":0,"data":{"id":"003","name":"agent1","ip":"any","key":"deadbeef"}})");
                            }
                            return std::string(R"({"error":9008,"message":"ERROR: Duplicate name"})");
                        });

    AuthdClient authdClient(authdPath, /*isWorkerNode=*/false, 0, baseConfig().authdResponseTimeoutMs, 0);
    wazuh::metrics::Manager metricsManager;
    EnrollmentMetrics metrics = makeEnrollmentMetrics(metricsManager);
    auto handler = makeHandler(authenticator, authdClient, baseConfig(), metrics, passthroughDecoder());

    const auto key = keySource->currentKey();
    ASSERT_TRUE(key.has_value());

    HttpRequest request;
    request.method = Method::Post;
    request.target = "/enroll";
    request.headers.emplace("protocol-version", std::string {remoted::auth::kSupportedProtocolVersion});
    request.body = kBody;
    request.headers.emplace("authorization", bearerFor(*key, nowTs()));

    const auto first = dispatch(handler, request);
    EXPECT_EQ(first.status, 200);

    // Identical request, byte-for-byte, dispatched again -- our own auth accepts it again (no
    // nonce cache); authd's business rule is what actually rejects the replay.
    const auto second = dispatch(handler, request);
    EXPECT_EQ(second.status, 409);
    EXPECT_EQ(nlohmann::json::parse(second.body)["error"]["code"], 9008);

    std::remove(passwordPath.c_str());
}

// -----------------------------------------------------------------------------
// Enrollment tokens (issue #38993), end to end: Password mode stays configured (the password key
// is present and valid), the agent presents a token bearer instead, and the whole pipeline --
// TokenKeySource replica -> verifyWithKid -> token state -> AuthdClient with token_id -> authd's
// answer -- runs against the real handler.
// -----------------------------------------------------------------------------

namespace
{
    namespace tvt = jwt_profile::v1::test_vectors::enroll_token;

    std::string writeTokenStore(bool revoked)
    {
        const std::string path =
            "/tmp/enrollmentE2E_test_" + std::to_string(::getpid()) + (revoked ? "_revoked" : "_live") + ".tokens.json";
        std::ofstream file(path);
        file << R"({"version":1,"tokens":[{"id":")" << tvt::kIdB64Url << R"(","secret":")" << tvt::kSecretB64Url
             << R"(","adr":"siem.example.local","pin":")" << tvt::kPinB64Url
             << R"(","ca":null,"created":1700000000,"expires":4102444800,"max_uses":1,"uses":0,"revoked":)"
             << (revoked ? "true" : "false") << R"(,"description":null}]})";
        return path;
    }

    std::string tokenBearerFor(std::int64_t ts)
    {
        jwt_profile::v1::SecureBytes secret(jwt_profile::v1::enroll::kTokenSecretBytes);
        for (std::size_t i = 0; i < secret.size(); ++i)
        {
            secret.data()[i] = static_cast<std::uint8_t>(0x10 + i);
        }
        const auto key = jwt_profile::v1::enroll::deriveEnrollTokenKey(secret);
        EXPECT_TRUE(key.has_value());
        const auto token = jwt_profile::v1::enroll::JwtEnrollTokenSigner::signWithKid(
            *key, std::chrono::system_clock::time_point {std::chrono::seconds {ts}}, tvt::kIdB64Url);
        EXPECT_TRUE(token.has_value());
        return "Bearer " + token.value_or("");
    }
} // namespace

TEST(EnrollmentE2ETest, TokenModeSignedRequestEnrollsAndForwardsTheTokenId)
{
    const std::string passwordPath = writePasswordFile("MyEnrollmentSecret123");
    const std::string storePath = writeTokenStore(/*revoked=*/false);
    auto keySource = std::make_shared<PasswordKeySource>(passwordPath);
    auto tokenSource = std::make_shared<TokenKeySource>(storePath);
    EnrollmentAuthenticator authenticator {EnrollmentAuthConfig {true}, keySource, tokenSource};

    const std::string authdPath = makeUniqueSocketPath("enrollment_e2e_token");
    std::string captured;
    std::mutex mu;
    FakeUdsServer authd(authdPath,
                        [&](const std::string& request)
                        {
                            std::lock_guard<std::mutex> lock(mu);
                            captured = request;
                            return std::string(
                                R"({"error":0,"data":{"id":"005","name":"agent1","ip":"any","key":"c0ffee"}})");
                        });

    AuthdClient authdClient(authdPath, /*isWorkerNode=*/false, 0, baseConfig().authdResponseTimeoutMs, 0);
    wazuh::metrics::Manager metricsManager;
    EnrollmentMetrics metrics = makeEnrollmentMetrics(metricsManager);
    auto handler = makeHandler(authenticator, authdClient, baseConfig(), metrics, passthroughDecoder());

    HttpRequest request;
    request.method = Method::Post;
    request.target = "/enroll";
    request.headers.emplace("protocol-version", std::string {remoted::auth::kSupportedProtocolVersion});
    request.body = kBody;
    request.headers.emplace("authorization", tokenBearerFor(nowTs()));

    const auto response = dispatch(handler, request);
    EXPECT_EQ(response.status, 200);
    EXPECT_EQ(nlohmann::json::parse(response.body)["id"], "005");

    std::lock_guard<std::mutex> lock(mu);
    const auto wire = nlohmann::json::parse(captured);
    EXPECT_EQ(wire["arguments"]["token_id"], std::string {tvt::kIdB64Url});
    EXPECT_EQ(wire["arguments"]["name"], "agent1");
    EXPECT_EQ(static_cast<std::uint64_t>(metricsManager.get(METRIC_TOKEN_ACCEPTED)->value()), 1U);

    std::remove(passwordPath.c_str());
    std::remove(storePath.c_str());
}

TEST(EnrollmentE2ETest, RevokedTokenIsRejectedWith401)
{
    const std::string passwordPath = writePasswordFile("MyEnrollmentSecret123");
    const std::string storePath = writeTokenStore(/*revoked=*/true);
    auto keySource = std::make_shared<PasswordKeySource>(passwordPath);
    auto tokenSource = std::make_shared<TokenKeySource>(storePath);
    EnrollmentAuthenticator authenticator {EnrollmentAuthConfig {true}, keySource, tokenSource};

    // authd must never be reached -- rejection happens at the auth layer.
    AuthdClient authdClient(makeUniqueSocketPath("enrollment_e2e_token_revoked"));
    wazuh::metrics::Manager metricsManager;
    EnrollmentMetrics metrics = makeEnrollmentMetrics(metricsManager);
    auto handler = makeHandler(authenticator, authdClient, baseConfig(), metrics, passthroughDecoder());

    HttpRequest request;
    request.method = Method::Post;
    request.target = "/enroll";
    request.headers.emplace("protocol-version", std::string {remoted::auth::kSupportedProtocolVersion});
    request.body = kBody;
    request.headers.emplace("authorization", tokenBearerFor(nowTs()));

    const auto response = dispatch(handler, request);
    EXPECT_EQ(response.status, 401);
    // The generic message, and the class on the wire (issue #38993): the agent learns the token was
    // revoked (ask the operator for a new one), never anything finer...
    const auto body = nlohmann::json::parse(response.body);
    EXPECT_EQ(body["error"]["message"], "Invalid client authentication");
    EXPECT_EQ(body["error"]["code"], "token_revoked");
    const auto challenge = std::find_if(response.headers.begin(),
                                        response.headers.end(),
                                        [](const auto& header) { return header.first == "WWW-Authenticate"; });
    ASSERT_NE(challenge, response.headers.end());
    EXPECT_EQ(challenge->second, R"(Bearer error="invalid_token", error_description="token_revoked")");
    // ...and the operator keeps the cell.
    EXPECT_EQ(static_cast<std::uint64_t>(metricsManager.get(METRIC_TOKEN_REJECTED_REVOKED)->value()), 1U);

    std::remove(passwordPath.c_str());
    std::remove(storePath.c_str());
}

// -----------------------------------------------------------------------------
// Re-enrollment (issue #38993), end to end: Password mode configured, the agent presents the bearer
// signed with its re-enrollment key (the frozen vector: remoted never verifies it, so its 2023 iat is
// irrelevant here), and the whole pipeline -- authenticator -> AuthdClient with `reenroll` -> authd's
// rotated answer -- runs against the real handler.
// -----------------------------------------------------------------------------

TEST(EnrollmentE2ETest, ReenrollmentBearerReachesAuthdAndTheRotatedCredentialsComeBack)
{
    const std::string passwordPath = writePasswordFile("MyEnrollmentSecret123");
    auto keySource = std::make_shared<PasswordKeySource>(passwordPath);
    EnrollmentAuthenticator authenticator {EnrollmentAuthConfig {true}, keySource};

    const std::string authdPath = makeUniqueSocketPath("enrollment_e2e_reenroll");
    std::string captured;
    std::mutex mu;
    FakeUdsServer authd(
        authdPath,
        [&](const std::string& request)
        {
            std::lock_guard<std::mutex> lock(mu);
            captured = request;
            // The master's answer: same id, new key, new secret.
            return std::string(
                R"({"error":0,"data":{"id":"001","name":"agent1","ip":"any","key":"c0ffee02",)"
                R"("reenroll_secret":"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"}})");
        });

    AuthdClient authdClient(authdPath, /*isWorkerNode=*/false, 0, baseConfig().authdResponseTimeoutMs, 0);
    wazuh::metrics::Manager metricsManager;
    EnrollmentMetrics metrics = makeEnrollmentMetrics(metricsManager);
    auto handler = makeHandler(authenticator, authdClient, baseConfig(), metrics, passthroughDecoder());

    HttpRequest request;
    request.method = Method::Post;
    request.target = "/enroll";
    request.headers.emplace("protocol-version", std::string {remoted::auth::kSupportedProtocolVersion});
    request.body = kBody;
    request.headers.emplace("authorization",
                            "Bearer " + std::string {jwt_profile::v1::test_vectors::enroll_token::kAgentKidJwt});

    const auto response = dispatch(handler, request);
    EXPECT_EQ(response.status, 200);
    const auto body = nlohmann::json::parse(response.body);
    EXPECT_EQ(body["id"], "001");
    EXPECT_EQ(body["key"], "c0ffee02");
    EXPECT_EQ(body["reenroll_secret"], "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210");

    std::lock_guard<std::mutex> lock(mu);
    const auto wire = nlohmann::json::parse(captured);
    EXPECT_EQ(wire["arguments"]["reenroll"]["kid"], "001");
    EXPECT_EQ(wire["arguments"]["reenroll"]["bearer"],
              std::string {jwt_profile::v1::test_vectors::enroll_token::kAgentKidJwt});
    EXPECT_FALSE(wire["arguments"].contains("token_id"));
    EXPECT_EQ(wire["arguments"]["name"], "agent1");
    EXPECT_EQ(static_cast<std::uint64_t>(metricsManager.get(METRIC_REENROLL_ACCEPTED)->value()), 1U);
    EXPECT_EQ(static_cast<std::uint64_t>(metricsManager.get(METRIC_TOKEN_ACCEPTED)->value()), 0U);

    std::remove(passwordPath.c_str());
}

// Password mode with no etc/authd.pass at all (not yet synced to a worker, deleted, unreadable): the
// server cannot judge the credential, so the challenge is a bare `Bearer` -- RFC 6750 has no error
// code for "I could not check", and `invalid_token` would blame the agent -- while the body's `code`
// names the condition for the operator reading the agent's log (issue #38993).
TEST(EnrollmentE2ETest, MissingPasswordFileIsEnrollmentKeyUnavailableWithABareChallenge)
{
    auto keySource = std::make_shared<PasswordKeySource>("/nonexistent/enrollmentE2E_test/authd.pass");
    EnrollmentAuthenticator authenticator {EnrollmentAuthConfig {true}, keySource};
    AuthdClient authdClient(makeUniqueSocketPath("enrollment_e2e_no_password_file")); // never reached
    wazuh::metrics::Manager metricsManager;
    EnrollmentMetrics metrics = makeEnrollmentMetrics(metricsManager);
    auto handler = makeHandler(authenticator, authdClient, baseConfig(), metrics, passthroughDecoder());

    HttpRequest request;
    request.method = Method::Post;
    request.target = "/enroll";
    request.headers.emplace("protocol-version", std::string {remoted::auth::kSupportedProtocolVersion});
    request.body = kBody;
    request.headers.emplace("authorization",
                            "Bearer " + std::string {jwt_profile::v1::test_vectors::enroll::kWrongPasswordToken});

    const auto response = dispatch(handler, request);
    EXPECT_EQ(response.status, 401);
    const auto body = nlohmann::json::parse(response.body);
    EXPECT_EQ(body["error"]["code"], "enrollment_key_unavailable");
    EXPECT_EQ(body["error"]["message"], "Invalid client authentication");
    const auto challenge = std::find_if(response.headers.begin(),
                                        response.headers.end(),
                                        [](const auto& header) { return header.first == "WWW-Authenticate"; });
    ASSERT_NE(challenge, response.headers.end());
    EXPECT_EQ(challenge->second, "Bearer");
    EXPECT_EQ(static_cast<std::uint64_t>(metricsManager.get(METRIC_REJECTED_AUTH)->value()), 1U);
}
