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
#include "decoding/iBodyDecoder.hpp"
#include "enrollment/enrollmentEndpoint.hpp"
#include "fakeUdsServer.hpp"
#include "json.hpp"
#include "jwt/jwtEnrollTokenSigner.hpp"
#include "jwt/testVectors.hpp"

#include <wazuh_metrics/manager.hpp>

using namespace remoted::enrollment;
using remoted::auth::PasswordKeySource;
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
    // RFC 6750 §3: /enroll's 401 carries the same bearer challenge every other route's does
    // (regression: its own error envelope used to drop the header errorResponseFor() attaches).
    const auto challenge = std::find_if(response.headers.begin(),
                                        response.headers.end(),
                                        [](const auto& header) { return header.first == "WWW-Authenticate"; });
    ASSERT_NE(challenge, response.headers.end());
    EXPECT_EQ(challenge->second, "Bearer");

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
