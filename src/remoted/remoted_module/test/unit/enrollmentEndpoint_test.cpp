/*
 * Wazuh remoted module - POST /enroll endpoint unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * August 19, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Exercises the JSON/validation/IP-resolution/authd-error-mapping layer of `POST /enroll`, with a
 * real AuthdClient wired to FakeUdsServer instances standing in for authd. The auth-rejection
 * matrix itself (mode pass/deny, bearer negative scenarios) is covered by enrollmentAuthenticator_test.cpp;
 * these tests all use Open mode so the handler's OWN logic is what's under test.
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
#include "common/requestOutcomeMetrics.hpp"
#include "decoding/iBodyDecoder.hpp"
#include "enrollment/enrollmentEndpoint.hpp"
#include "fakeUdsServer.hpp"
#include "json.hpp"
#include "jwt/enrollKeyDerivation.hpp"
#include "jwt/jwtEnrollTokenSigner.hpp"
#include "jwt/testVectors.hpp"

#include <wazuh_metrics/manager.hpp>

using namespace remoted::enrollment;
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

    HttpRequest makeRequest(const std::string& body, const std::string& remoteIp = "")
    {
        HttpRequest req;
        req.method = Method::Post;
        req.target = "/enroll";
        req.body = body;
        req.remoteIp = remoteIp;
        // Required on /enroll like on every other authenticated route: without it the endpoint
        // answers 400 before it looks at anything else. Set here so each test exercises what it is
        // actually about, rather than re-failing this one check.
        req.headers.emplace("protocol-version", std::string {remoted::auth::kSupportedProtocolVersion});
        return req;
    }

    HttpRequest makeRequestWithContentEncoding(const std::string& body, const std::string& encoding)
    {
        auto req = makeRequest(body);
        req.headers.emplace("content-encoding", encoding);
        return req;
    }

    Config openModeConfig()
    {
        Config cfg;
        cfg.enrollmentEnabled = true;
        cfg.usePassword = false;
        cfg.useSourceIp = false;
        cfg.allowHigherVersions = false;
        cfg.managerVersion = "5.0.0";
        cfg.authdResponseTimeoutMs = 500; // short: tests exercising "authd absent" resolve via this timeout
        return cfg;
    }

    const std::string kValidBody = R"({"name":"agent1","version":"5.0.0"})";

    // IBodyDecoder stub backed by a lambda, mirroring authGateway_test.cpp's StubBodyDecoder: each
    // test states just the decode behavior it cares about. The REAL zstd decoder is exercised in
    // bodyDecoder_test.cpp -- these tests are only about how the endpoint WIRES the step in (order
    // relative to auth, and how a decode failure maps to an HTTP status), not about zstd itself.
    class StubBodyDecoder final : public IBodyDecoder
    {
    public:
        using Fn = std::function<remoted::auth::AuthError(ContentEncoding, remoted::auth::Payload&)>;

        explicit StubBodyDecoder(Fn fn)
            : m_fn {std::move(fn)}
        {
        }

        remoted::auth::AuthError decode(ContentEncoding encoding, remoted::auth::Payload& payload) const override
        {
            return m_fn(encoding, payload);
        }

    private:
        Fn m_fn;
    };

    std::shared_ptr<const IBodyDecoder> stubDecoder(StubBodyDecoder::Fn fn)
    {
        return std::make_shared<const StubBodyDecoder>(std::move(fn));
    }

    // Default for tests that aren't about Content-Encoding at all: present (a required dependency)
    // but inert.
    std::shared_ptr<const IBodyDecoder> passthroughDecoder()
    {
        return stubDecoder([](ContentEncoding, remoted::auth::Payload&) { return remoted::auth::AuthError::None; });
    }

    // Runs one dispatch through a freshly built handler (fresh authenticator/AuthdClient every
    // call -- AuthdClient's worker thread must not be shared across tests). authdPath need not
    // have a FakeUdsServer bound at all -- that's how the "authd unreachable" tests are expressed.
    HttpResponse run(const Config& config,
                     const std::string& body,
                     const std::string& authdPath,
                     const std::string& remoteIp = "",
                     std::shared_ptr<const IBodyDecoder> bodyDecoder = nullptr)
    {
        EnrollmentAuthenticator authenticator {EnrollmentAuthConfig {false}, nullptr};
        wazuh::metrics::Manager metricsManager;
        EnrollmentMetrics metrics = makeEnrollmentMetrics(metricsManager);

        AuthdClient authdClient(authdPath,
                                /*isWorkerNode=*/false,
                                /*connectTimeoutMs=*/0,
                                config.authdResponseTimeoutMs,
                                /*maxQueueSize=*/0);

        auto handler =
            makeHandler(authenticator, authdClient, config, metrics, bodyDecoder ? bodyDecoder : passthroughDecoder());

        auto request = std::make_shared<const HttpRequest>(makeRequest(body, remoteIp));
        auto responder = std::make_shared<CapturingResponder>();
        handler(request, responder);
        return responder->wait();
    }

    nlohmann::json parseBody(const HttpResponse& response)
    {
        return nlohmann::json::parse(response.body, nullptr, false);
    }

    // An authd stand-in that echoes a fixed response regardless of the request, plus the path it
    // was bound to (FakeUdsServer itself exposes no accessor for its own path).
    struct AuthdStub
    {
        std::string path;
        std::unique_ptr<FakeUdsServer> server;
    };

    AuthdStub fixedAuthdServer(const std::string& response)
    {
        AuthdStub stub;
        stub.path = makeUniqueSocketPath("enrollment_endpoint");
        stub.server = std::make_unique<FakeUdsServer>(stub.path, [response](const std::string&) { return response; });
        return stub;
    }
} // namespace

// -----------------------------------------------------------------------------
// Administrative disable -- checked before authentication or the authd bridge.
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// remoted.http.enroll.* -- the status/latency view of the same requests the
// remoted.enroll.* counters describe by outcome.
// -----------------------------------------------------------------------------

// /enroll is registered straight on IHttpServer, not through AuthGateway, so nothing stamps a
// receipt time for it and nothing counted its status codes. The handler wraps its responder in a
// MeteredResponder instead, which is why this holds for BOTH the answers it sends inline and the
// one authd's callback delivers on a worker thread -- the case a per-send-site instrumentation
// is most likely to miss.
TEST(EnrollmentEndpointTest, HttpMetricsCountEveryStatusAndTimeEveryAnswer)
{
    wazuh::metrics::Manager manager;
    const auto http = remoted::metrics::makeEndpointHttpMetrics(manager, "enroll", /*withLatency=*/true);

    const auto valueOf = [&manager](const std::string& name)
    {
        return static_cast<uint64_t>(manager.get(name)->value());
    };
    const auto latencyCount = [&http]
    {
        return http.latency->snapshot().count;
    };

    // Runs one request through a handler wired with the shared family above.
    const auto dispatch = [&http](const Config& config, const std::string& body, const std::string& authdPath)
    {
        EnrollmentAuthenticator authenticator {EnrollmentAuthConfig {false}, nullptr};
        wazuh::metrics::Manager outcomeManager;
        EnrollmentMetrics outcomes = makeEnrollmentMetrics(outcomeManager);
        AuthdClient authdClient(authdPath, /*isWorkerNode=*/false, /*connectTimeoutMs=*/0, 300, /*maxQueueSize=*/0);

        auto handler = makeHandler(authenticator, authdClient, config, outcomes, passthroughDecoder(), http);
        auto request = std::make_shared<const HttpRequest>(makeRequest(body, ""));
        auto responder = std::make_shared<CapturingResponder>();
        handler(request, responder);
        return responder->wait();
    };

    // 1. Inline 403: administratively disabled, answered before auth or the bridge.
    Config disabled = openModeConfig();
    disabled.enrollmentEnabled = false;
    EXPECT_EQ(dispatch(disabled, R"({"name":"agent1","version":"5.0.0"})", "/nonexistent").status, 403);
    EXPECT_EQ(valueOf("remoted.http.enroll.responses.403"), 1U);
    EXPECT_EQ(latencyCount(), 1U);

    // 2. Inline 400: local validation, still without reaching authd.
    EXPECT_EQ(dispatch(openModeConfig(), R"({"version":"5.0.0"})", "/nonexistent").status, 400);
    EXPECT_EQ(valueOf("remoted.http.enroll.responses.400"), 1U);
    EXPECT_EQ(latencyCount(), 2U);

    // 3. The asynchronous 200: delivered from authd's callback, on another thread.
    auto stub = fixedAuthdServer(R"({"error":0,"data":{"id":"1","name":"agent1","ip":"any","key":"k"}})");
    EXPECT_EQ(dispatch(openModeConfig(), R"({"name":"agent1","version":"5.0.0"})", stub.path).status, 200);
    EXPECT_EQ(valueOf("remoted.http.enroll.responses.2xx"), 1U);
    EXPECT_EQ(latencyCount(), 3U); // every answer is timed, whichever thread sends it

    // Exactly one cell per request, and no cross-talk into another endpoint's family.
    EXPECT_EQ(valueOf("remoted.http.enroll.responses.500"), 0U);
    EXPECT_EQ(valueOf("remoted.http.enroll.responses.503"), 0U);
    EXPECT_EQ(valueOf("remoted.http.enroll.responses.other"), 0U);
}

TEST(EnrollmentEndpointTest, DisabledEnrollmentReturns403WithoutTouchingAuthOrAuthd)
{
    Config config = openModeConfig();
    config.enrollmentEnabled = false;

    // Password mode with a null key source would reject with 401 if authentication ever ran --
    // getting 403 instead proves the disabled check short-circuits before that.
    EnrollmentAuthenticator authenticator {EnrollmentAuthConfig {true}, nullptr};
    wazuh::metrics::Manager metricsManager;
    EnrollmentMetrics metrics = makeEnrollmentMetrics(metricsManager);
    AuthdClient authdClient(makeUniqueSocketPath("enrollment_endpoint_disabled"));

    auto handler = makeHandler(authenticator, authdClient, config, metrics, passthroughDecoder());
    auto request = std::make_shared<const HttpRequest>(makeRequest(kValidBody));
    auto responder = std::make_shared<CapturingResponder>();
    handler(request, responder);
    const auto response = responder->wait();

    EXPECT_EQ(response.status, 403);
    EXPECT_EQ(parseBody(response)["error"]["message"], "Enrollment is disabled on this manager");
}

// -----------------------------------------------------------------------------
// Local validation -- never reaches authd.
// -----------------------------------------------------------------------------

TEST(EnrollmentEndpointTest, EmptyBodyIsRejectedWith400)
{
    const auto response = run(openModeConfig(), "", makeUniqueSocketPath("enrollment_endpoint_v1"));
    EXPECT_EQ(response.status, 400);
}

TEST(EnrollmentEndpointTest, MalformedJsonIsRejectedWith400)
{
    const auto response = run(openModeConfig(), "not json{{{", makeUniqueSocketPath("enrollment_endpoint_v2"));
    EXPECT_EQ(response.status, 400);
}

TEST(EnrollmentEndpointTest, MissingNameIsRejectedWith400)
{
    const auto response =
        run(openModeConfig(), R"({"version":"5.0.0"})", makeUniqueSocketPath("enrollment_endpoint_v3"));
    EXPECT_EQ(response.status, 400);
    EXPECT_NE(parseBody(response)["error"]["message"].get<std::string>().find("name"), std::string::npos);
}

// Mirrors OS_IsValidName() (shared/src/agent_validate_op.c): a name outside this charset must
// never reach authd, since a space would split into extra client.keys fields on write (name/IP/key
// all shift) and a leading '#'/'!' would collide with the removed-entry marker convention -- both
// silently corrupt the agent record rather than producing a visible error.
class EnrollmentEndpointNameValidationTest : public ::testing::TestWithParam<std::string>
{
};

TEST_P(EnrollmentEndpointNameValidationTest, InvalidNameIsRejectedWith400)
{
    nlohmann::json body;
    body["name"] = GetParam();
    body["version"] = "5.0.0";
    const auto response = run(openModeConfig(), body.dump(), makeUniqueSocketPath("enrollment_endpoint_invalid_name"));
    EXPECT_EQ(response.status, 400);
}

INSTANTIATE_TEST_SUITE_P(InvalidNames,
                         EnrollmentEndpointNameValidationTest,
                         ::testing::Values("web 01",                // space -- would split client.keys fields
                                           "#web01",                // leading '#' -- removed-entry marker
                                           "!web01",                // leading '!' -- removed-entry marker
                                           ".web01",                // leading '.' -- OS_IsValidName() rejects
                                           "a",                     // length 1 -- below OS_IsValidName()'s minimum
                                           "",                      // empty
                                           std::string(129, 'a'))); // over the 128-char cap

TEST(EnrollmentEndpointTest, NameWithAllowedPunctuationIsAccepted)
{
    auto stub = fixedAuthdServer(R"({"error":0,"data":{"id":"1","name":"web-01.prod_a","ip":"any","key":"k"}})");
    const auto response = run(openModeConfig(), R"({"name":"web-01.prod_a","version":"5.0.0"})", stub.path);
    EXPECT_EQ(response.status, 200);
}

TEST(EnrollmentEndpointTest, MissingVersionIsRejectedWith400)
{
    const auto response = run(openModeConfig(), R"({"name":"agent1"})", makeUniqueSocketPath("enrollment_endpoint_v4"));
    EXPECT_EQ(response.status, 400);
}

TEST(EnrollmentEndpointTest, InvalidIpIsRejectedWith400)
{
    const auto response = run(openModeConfig(),
                              R"({"name":"agent1","version":"5.0.0","ip":"not-an-ip"})",
                              makeUniqueSocketPath("enrollment_endpoint_v5"));
    EXPECT_EQ(response.status, 400);
}

TEST(EnrollmentEndpointTest, ValidCidrIpIsAccepted)
{
    auto stub = fixedAuthdServer(R"({"error":0,"data":{"id":"1","name":"agent1","ip":"i","key":"k"}})");
    const auto response = run(openModeConfig(), R"({"name":"agent1","version":"5.0.0","ip":"10.0.0.0/24"})", stub.path);
    EXPECT_EQ(response.status, 200);
}

TEST(EnrollmentEndpointTest, OverlongCidrPrefixIsRejectedWith400NotAnUncaughtException)
{
    // All-digit but too many digits to fit in an int -- isValidIpOrCidr()'s std::stoi() call used
    // to let std::out_of_range escape uncaught for input like this; it must be rejected as an
    // ordinary invalid request, not crash or bubble up as an unhandled exception.
    const auto response = run(openModeConfig(),
                              R"({"name":"agent1","version":"5.0.0","ip":"10.0.0.0/99999999999999999999"})",
                              makeUniqueSocketPath("enrollment_endpoint_overlong_prefix"));
    EXPECT_EQ(response.status, 400);
}

TEST(EnrollmentEndpointTest, VersionTooNewIsRejectedWhenNotAllowed)
{
    Config config = openModeConfig();
    config.managerVersion = "4.9.0";
    config.allowHigherVersions = false;

    const auto response =
        run(config, R"({"name":"agent1","version":"5.0.0"})", makeUniqueSocketPath("enrollment_endpoint_v6"));
    EXPECT_EQ(response.status, 400);
}

TEST(EnrollmentEndpointTest, VersionTooNewIsAcceptedWhenAllowed)
{
    Config config = openModeConfig();
    config.managerVersion = "4.9.0";
    config.allowHigherVersions = true;

    auto stub = fixedAuthdServer(R"({"error":0,"data":{"id":"1","name":"agent1","ip":"any","key":"k"}})");
    const auto response = run(config, R"({"name":"agent1","version":"5.0.0"})", stub.path);
    EXPECT_EQ(response.status, 200);
}

// -----------------------------------------------------------------------------
// Content-Encoding wiring -- how the endpoint composes IBodyDecoder, not zstd itself (see
// bodyDecoder_test.cpp for the real codec). These prove the decoded bytes are what actually
// reaches JSON parsing/authd, and that a decode failure maps to the same status codes AuthGateway
// uses for every other endpoint (415/400/413).
// -----------------------------------------------------------------------------

TEST(EnrollmentEndpointTest, ContentEncodingHeaderIsParsedAndPassedToTheDecoder)
{
    ContentEncoding observed = ContentEncoding::None;
    auto decoder = stubDecoder(
        [&](ContentEncoding encoding, remoted::auth::Payload&)
        {
            observed = encoding;
            return remoted::auth::AuthError::None;
        });

    EnrollmentAuthenticator authenticator {EnrollmentAuthConfig {false}, nullptr};
    wazuh::metrics::Manager metricsManager;
    EnrollmentMetrics metrics = makeEnrollmentMetrics(metricsManager);
    AuthdClient authdClient(makeUniqueSocketPath("enrollment_endpoint_content_encoding_header"));

    auto handler = makeHandler(authenticator, authdClient, openModeConfig(), metrics, decoder);
    auto request = std::make_shared<const HttpRequest>(makeRequestWithContentEncoding(kValidBody, "zstd"));
    auto responder = std::make_shared<CapturingResponder>();
    handler(request, responder);
    responder->wait(); // authd is unreachable here; only the decoder's observed value matters

    EXPECT_EQ(observed, ContentEncoding::Zstd);
}

TEST(EnrollmentEndpointTest, DecodedBodyIsWhatGetsParsedAndForwardedToAuthd)
{
    // The wire body is deliberately NOT valid JSON on its own -- if the endpoint ever parsed
    // request->body directly instead of the decoder's output, this would fail with 400 and authd
    // would never be reached.
    std::string capturedRequest;
    std::mutex captureMutex;
    const std::string path = makeUniqueSocketPath("enrollment_endpoint_decode_success");
    FakeUdsServer server(path,
                         [&](const std::string& request)
                         {
                             std::lock_guard<std::mutex> lock(captureMutex);
                             capturedRequest = request;
                             return R"({"error":0,"data":{"id":"1","name":"decoded-agent","ip":"any","key":"k"}})";
                         });

    auto decoder = stubDecoder(
        [](ContentEncoding, remoted::auth::Payload& payload)
        {
            auto replacement = std::make_shared<const std::string>(R"({"name":"decoded-agent","version":"5.0.0"})");
            payload = remoted::auth::Payload {std::string_view {*replacement}, replacement};
            return remoted::auth::AuthError::None;
        });

    const auto response = run(openModeConfig(), "this is not json", path, "", decoder);
    EXPECT_EQ(response.status, 200);

    std::string captured;
    {
        std::lock_guard<std::mutex> lock(captureMutex);
        captured = capturedRequest;
    }
    const auto json = nlohmann::json::parse(captured);
    EXPECT_EQ(json.at("arguments").at("name"), "decoded-agent");
}

TEST(EnrollmentEndpointTest, UnsupportedContentEncodingIsRejectedWith415)
{
    auto decoder = stubDecoder([](ContentEncoding, remoted::auth::Payload&)
                               { return remoted::auth::AuthError::UnsupportedContentEncoding; });

    const auto response = run(openModeConfig(),
                              kValidBody,
                              makeUniqueSocketPath("enrollment_endpoint_415"), // never actually reached
                              "",
                              decoder);
    EXPECT_EQ(response.status, 415);
}

TEST(EnrollmentEndpointTest, MalformedContentEncodingIsRejectedWith400)
{
    auto decoder = stubDecoder([](ContentEncoding, remoted::auth::Payload&)
                               { return remoted::auth::AuthError::MalformedContentEncoding; });

    const auto response =
        run(openModeConfig(), kValidBody, makeUniqueSocketPath("enrollment_endpoint_decode_400"), "", decoder);
    EXPECT_EQ(response.status, 400);
}

TEST(EnrollmentEndpointTest, BodyTooLargeDuringDecodeIsRejectedWith413)
{
    auto decoder =
        stubDecoder([](ContentEncoding, remoted::auth::Payload&) { return remoted::auth::AuthError::BodyTooLarge; });

    const auto response =
        run(openModeConfig(), kValidBody, makeUniqueSocketPath("enrollment_endpoint_413"), "", decoder);
    EXPECT_EQ(response.status, 413);
}

// -----------------------------------------------------------------------------
// IP resolution matrix
// -----------------------------------------------------------------------------

TEST(EnrollmentEndpointTest, UseSourceIpOverridesBodyIp)
{
    std::string captured;
    std::mutex mu;
    const std::string path = makeUniqueSocketPath("enrollment_endpoint_ip1");
    FakeUdsServer server(path,
                         [&](const std::string& req)
                         {
                             std::lock_guard<std::mutex> lock(mu);
                             captured = req;
                             return R"({"error":0,"data":{"id":"1","name":"n","ip":"i","key":"k"}})";
                         });

    Config config = openModeConfig();
    config.useSourceIp = true;
    run(config, R"({"name":"agent1","version":"5.0.0","ip":"10.0.0.1"})", path, "203.0.113.7");

    std::lock_guard<std::mutex> lock(mu);
    const auto j = nlohmann::json::parse(captured);
    EXPECT_EQ(j["arguments"]["ip"], "203.0.113.7");
}

TEST(EnrollmentEndpointTest, BodyIpUsedWhenSourceIpDisabledAndPresent)
{
    std::string captured;
    std::mutex mu;
    const std::string path = makeUniqueSocketPath("enrollment_endpoint_ip2");
    FakeUdsServer server(path,
                         [&](const std::string& req)
                         {
                             std::lock_guard<std::mutex> lock(mu);
                             captured = req;
                             return R"({"error":0,"data":{"id":"1","name":"n","ip":"i","key":"k"}})";
                         });

    Config config = openModeConfig();
    config.useSourceIp = false;
    run(config, R"({"name":"agent1","version":"5.0.0","ip":"10.0.0.1"})", path, "203.0.113.7");

    std::lock_guard<std::mutex> lock(mu);
    const auto j = nlohmann::json::parse(captured);
    EXPECT_EQ(j["arguments"]["ip"], "10.0.0.1");
}

TEST(EnrollmentEndpointTest, AnyUsedWhenNeitherSourceIpNorBodyIpPresent)
{
    std::string captured;
    std::mutex mu;
    const std::string path = makeUniqueSocketPath("enrollment_endpoint_ip3");
    FakeUdsServer server(path,
                         [&](const std::string& req)
                         {
                             std::lock_guard<std::mutex> lock(mu);
                             captured = req;
                             return R"({"error":0,"data":{"id":"1","name":"n","ip":"i","key":"k"}})";
                         });

    Config config = openModeConfig();
    config.useSourceIp = false;
    run(config, kValidBody, path, "203.0.113.7");

    std::lock_guard<std::mutex> lock(mu);
    const auto j = nlohmann::json::parse(captured);
    EXPECT_EQ(j["arguments"]["ip"], "any");
}

TEST(EnrollmentEndpointTest, SrcSentinelResolvesToThePeerAddressNotForwardedLiterally)
{
    // "src" mirrors legacy port 1515's own wire sentinel (os_auth/src/auth.c's `IP:'src'`, sent by
    // an agent configured with its own client-side <use_source_ip>) -- it must resolve to the
    // HTTPS connection's actual peer address, never reach authd as the literal string "src" (which
    // local_add() has no notion of and would reject as an invalid IP).
    std::string captured;
    std::mutex mu;
    const std::string path = makeUniqueSocketPath("enrollment_endpoint_ip_src");
    FakeUdsServer server(path,
                         [&](const std::string& req)
                         {
                             std::lock_guard<std::mutex> lock(mu);
                             captured = req;
                             return R"({"error":0,"data":{"id":"1","name":"n","ip":"i","key":"k"}})";
                         });

    Config config = openModeConfig();
    config.useSourceIp = false; // manager-side flag off: the body's "src" is what must be honored
    const auto response = run(config, R"({"name":"agent1","version":"5.0.0","ip":"src"})", path, "203.0.113.7");
    EXPECT_EQ(response.status, 200);

    std::lock_guard<std::mutex> lock(mu);
    const auto j = nlohmann::json::parse(captured);
    EXPECT_EQ(j["arguments"]["ip"], "203.0.113.7");
}

// -----------------------------------------------------------------------------
// Wire shape: force/id/key never sent (mirrors AuthdClient's own coverage of this, exercised here
// end-to-end through the endpoint instead of a hand-built AuthdAddRequest).
// -----------------------------------------------------------------------------

TEST(EnrollmentEndpointTest, RequestNeverIncludesForceIdOrKey)
{
    std::string captured;
    std::mutex mu;
    const std::string path = makeUniqueSocketPath("enrollment_endpoint_wireshape");
    FakeUdsServer server(path,
                         [&](const std::string& req)
                         {
                             std::lock_guard<std::mutex> lock(mu);
                             captured = req;
                             return R"({"error":0,"data":{"id":"1","name":"n","ip":"i","key":"k"}})";
                         });

    run(openModeConfig(), kValidBody, path);

    std::lock_guard<std::mutex> lock(mu);
    const auto j = nlohmann::json::parse(captured);
    EXPECT_EQ(j["function"], "add");
    EXPECT_FALSE(j["arguments"].contains("force"));
    EXPECT_FALSE(j["arguments"].contains("id"));
    EXPECT_FALSE(j["arguments"].contains("key"));
    // And no enrollment token was used, so no token_id either: the Open/password request stays
    // byte-identical to what authd received before tokens existed (issue #38993).
    EXPECT_FALSE(j["arguments"].contains("token_id"));
}

// -----------------------------------------------------------------------------
// Success + authd error-code -> HTTP status mapping
// -----------------------------------------------------------------------------

TEST(EnrollmentEndpointTest, SuccessReturns200WithAgentData)
{
    auto stub = fixedAuthdServer(
        R"({"error":0,"data":{"id":"003","name":"agent1","ip":"any","key":"675aaf366e6827ee7a77b2f7b4d89e603a21333c09afbb02c40191f199d7c915"}})");
    const auto response = run(openModeConfig(), kValidBody, stub.path);

    EXPECT_EQ(response.status, 200);
    const auto j = parseBody(response);
    EXPECT_EQ(j["id"], "003");
    EXPECT_EQ(j["name"], "agent1");
    EXPECT_EQ(j["key"], "675aaf366e6827ee7a77b2f7b4d89e603a21333c09afbb02c40191f199d7c915");
    // authd sent no re-enrollment secret: the 200 has no such field (omitted, never empty).
    EXPECT_FALSE(j.contains("reenroll_secret"));
}

TEST(EnrollmentEndpointTest, SuccessCarriesTheReenrollSecretWhenAuthdSendsIt)
{
    // The fifth field of a 200 (issue #38993): authd's re-enrollment secret, verbatim like the other
    // four -- the agent stores it and re-enrolls with it later.
    auto stub = fixedAuthdServer(
        R"({"error":0,"data":{"id":"003","name":"agent1","ip":"any","key":"675aaf366e6827ee7a77b2f7b4d89e603a21333c09afbb02c40191f199d7c915",)"
        R"("reenroll_secret":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}})");
    const auto response = run(openModeConfig(), kValidBody, stub.path);

    EXPECT_EQ(response.status, 200);
    const auto j = parseBody(response);
    EXPECT_EQ(j["id"], "003");
    EXPECT_EQ(j["key"], "675aaf366e6827ee7a77b2f7b4d89e603a21333c09afbb02c40191f199d7c915");
    EXPECT_EQ(j["reenroll_secret"], "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
}

struct AuthdErrorCase
{
    int authdCode;
    int expectedStatus;
};

class EnrollmentEndpointAuthdErrorTest : public ::testing::TestWithParam<AuthdErrorCase>
{
};

TEST_P(EnrollmentEndpointAuthdErrorTest, MapsToExpectedHttpStatus)
{
    const auto param = GetParam();
    nlohmann::json body;
    body["error"] = param.authdCode;
    body["message"] = "ERROR: some authd message";
    auto stub = fixedAuthdServer(body.dump());

    const auto response = run(openModeConfig(), kValidBody, stub.path);

    EXPECT_EQ(response.status, param.expectedStatus) << "authd code " << param.authdCode;
    const auto j = parseBody(response);
    EXPECT_EQ(j["error"]["code"], param.authdCode);
    EXPECT_EQ(j["error"]["message"], "some authd message"); // "ERROR: " prefix stripped by AuthdClient
}

INSTANTIATE_TEST_SUITE_P(AuthdCodes,
                         EnrollmentEndpointAuthdErrorTest,
                         ::testing::Values(AuthdErrorCase {9001, 500},
                                           AuthdErrorCase {9002, 500},
                                           AuthdErrorCase {9009, 500},
                                           AuthdErrorCase {9003, 400},
                                           AuthdErrorCase {9004, 400},
                                           AuthdErrorCase {9005, 400},
                                           AuthdErrorCase {9006, 400},
                                           AuthdErrorCase {9014, 400},
                                           AuthdErrorCase {9017, 400}, // invalid agent name (new)
                                           AuthdErrorCase {9019, 400}, // invalid caller-supplied key
                                           AuthdErrorCase {9020, 400}, // invalid caller-supplied id
                                           AuthdErrorCase {9007, 409},
                                           AuthdErrorCase {9008, 409},
                                           AuthdErrorCase {9012, 409},
                                           AuthdErrorCase {9013, 503},
                                           AuthdErrorCase {9015, 503},
                                           AuthdErrorCase {9016, 503},
                                           AuthdErrorCase {9022, 403},   // enrollment token unknown/revoked (#38993)
                                           AuthdErrorCase {9023, 403},   // enrollment token expired
                                           AuthdErrorCase {9024, 403},   // enrollment token exhausted
                                           AuthdErrorCase {9999, 500})); // unknown code -> safe default

TEST(EnrollmentEndpointTest, AuthdUnreachableMapsTo503)
{
    // No FakeUdsServer bound at all -- resolves via the (short, test-configured)
    // authdResponseTimeoutMs, same reasoning as AuthdClientTest.ServerAbsentIsATransportFailure.
    const auto response = run(openModeConfig(), kValidBody, makeUniqueSocketPath("enrollment_endpoint_absent"));

    EXPECT_EQ(response.status, 503);
    const auto j = parseBody(response);
    EXPECT_EQ(j["error"]["code"], -1);
}

// -----------------------------------------------------------------------------
// Enrollment tokens (issue #38993): the id of a verified token travels to authd as `token_id`,
// authd's refusals of it are 403, and both outcomes count in remoted.enroll.token.*.
// -----------------------------------------------------------------------------

namespace
{
    namespace tvt = jwt_profile::v1::test_vectors::enroll_token;

    // A store holding the frozen vector token (id 00..0f, secret 10..1f), as authd writes it.
    std::string writeTokenStore(const char* tag, bool revoked = false)
    {
        const std::string path = "/tmp/enrollmentEndpoint_test_" + std::to_string(::getpid()) + tag + ".tokens.json";
        std::ofstream file(path);
        file << R"({"version":1,"tokens":[{"id":")" << tvt::kIdB64Url << R"(","secret":")" << tvt::kSecretB64Url
             << R"(","adr":"siem.example.local","pin":")" << tvt::kPinB64Url
             << R"(","ca":null,"created":1700000000,"expires":4102444800,"max_uses":1,"uses":0,"revoked":)"
             << (revoked ? "true" : "false") << R"(,"description":null}]})";
        return path;
    }

    // The bearer an agent holding the pasted token mints: kid = token id, key = HKDF(secret), now.
    std::string vectorTokenBearer(std::int64_t now)
    {
        jwt_profile::v1::SecureBytes secret(jwt_profile::v1::enroll::kTokenSecretBytes);
        for (std::size_t i = 0; i < secret.size(); ++i)
        {
            secret.data()[i] = static_cast<std::uint8_t>(0x10 + i);
        }
        const auto key = jwt_profile::v1::enroll::deriveEnrollTokenKey(secret);
        EXPECT_TRUE(key.has_value());
        const auto token = jwt_profile::v1::enroll::JwtEnrollTokenSigner::signWithKid(
            *key, std::chrono::system_clock::time_point {std::chrono::seconds {now}}, tvt::kIdB64Url);
        EXPECT_TRUE(token.has_value());
        return "Bearer " + token.value_or("");
    }

    struct TokenRun
    {
        HttpResponse response;
        std::string authdRequest; // what the fake authd received ("" when it was never reached)
        std::uint64_t enrollValue(const std::string& name) const
        {
            const auto metric = manager->get(name);
            return metric ? static_cast<std::uint64_t>(metric->value()) : 0U;
        }
        std::shared_ptr<wazuh::metrics::Manager> manager;
    };

    // One /enroll with the vector token bearer against a fake authd answering @p authdResponse
    // (empty: no authd at all). Open mode + the token replica: the token path is what is under test.
    TokenRun runWithToken(const std::string& storePath, const std::string& authdResponse, const std::string& tag)
    {
        TokenRun out;
        out.manager = std::make_shared<wazuh::metrics::Manager>();
        EnrollmentMetrics metrics = makeEnrollmentMetrics(*out.manager);

        auto tokenSource = std::make_shared<remoted::auth::TokenKeySource>(storePath);
        EnrollmentAuthenticator authenticator {EnrollmentAuthConfig {false}, nullptr, tokenSource};

        const std::string path = makeUniqueSocketPath("enrollment_endpoint_token_" + tag);
        std::mutex mu;
        std::unique_ptr<FakeUdsServer> authd;
        if (!authdResponse.empty())
        {
            authd = std::make_unique<FakeUdsServer>(path,
                                                    [&](const std::string& req)
                                                    {
                                                        std::lock_guard<std::mutex> lock(mu);
                                                        out.authdRequest = req;
                                                        return authdResponse;
                                                    });
        }
        Config config = openModeConfig();
        AuthdClient authdClient(path, false, 0, config.authdResponseTimeoutMs, 0);
        auto handler = makeHandler(authenticator, authdClient, config, metrics, passthroughDecoder());

        auto request = makeRequest(kValidBody);
        request.headers.emplace("authorization", vectorTokenBearer(static_cast<std::int64_t>(std::time(nullptr))));
        auto responder = std::make_shared<CapturingResponder>();
        handler(std::make_shared<const HttpRequest>(request), responder);
        out.response = responder->wait();
        std::lock_guard<std::mutex> lock(mu);
        return out;
    }
} // namespace

TEST(EnrollmentEndpointTest, TokenIdIsForwardedToAuthdAndCountedAsAccepted)
{
    const std::string store = writeTokenStore("_forward");
    const auto run =
        runWithToken(store, R"({"error":0,"data":{"id":"007","name":"agent1","ip":"any","key":"k"}})", "forward");

    EXPECT_EQ(run.response.status, 200);
    const auto j = nlohmann::json::parse(run.authdRequest);
    EXPECT_EQ(j["function"], "add");
    EXPECT_EQ(j["arguments"]["token_id"], std::string {tvt::kIdB64Url}); // the verified kid, verbatim
    EXPECT_EQ(run.enrollValue(METRIC_TOKEN_ACCEPTED), 1U);
    EXPECT_EQ(run.enrollValue(METRIC_ACCEPTED), 1U);
    EXPECT_EQ(run.enrollValue(METRIC_TOKEN_REJECTED_EXHAUSTED), 0U);

    std::remove(store.c_str());
}

TEST(EnrollmentEndpointTest, TokenExhaustedByAuthdIs403AndCountsRejectedExhausted)
{
    // remoted's replica knows nothing about uses: only authd can refuse an exhausted token, and it
    // does so AFTER the bearer verified -- so 403 (a valid credential authd would not honour), not 401.
    const std::string store = writeTokenStore("_exhausted");
    const auto run =
        runWithToken(store, R"({"error":9024,"message":"ERROR: Enrollment token exhausted"})", "exhausted");

    EXPECT_EQ(run.response.status, 403);
    const auto body = parseBody(run.response);
    EXPECT_EQ(body["error"]["code"], 9024);
    EXPECT_EQ(run.enrollValue(METRIC_TOKEN_REJECTED_EXHAUSTED), 1U);
    EXPECT_EQ(run.enrollValue(METRIC_AUTHD_ERROR), 1U);
    EXPECT_EQ(run.enrollValue(METRIC_TOKEN_ACCEPTED), 0U);

    std::remove(store.c_str());
}

TEST(EnrollmentEndpointTest, RevokedTokenIs401AndCountsItsClassWithoutReachingAuthd)
{
    const std::string store = writeTokenStore("_revoked", /*revoked=*/true);
    const auto run = runWithToken(store, "", "revoked"); // no authd bound: it must never be needed

    EXPECT_EQ(run.response.status, 401);
    EXPECT_TRUE(run.authdRequest.empty());
    EXPECT_EQ(run.enrollValue(METRIC_REJECTED_AUTH), 1U);
    EXPECT_EQ(run.enrollValue(METRIC_TOKEN_REJECTED_REVOKED), 1U);
    EXPECT_EQ(run.enrollValue(METRIC_TOKEN_REJECTED_UNKNOWN), 0U);
    // The generic bearer challenge, like every credential 401 on this server.
    const auto challenge = std::find_if(run.response.headers.begin(),
                                        run.response.headers.end(),
                                        [](const auto& header) { return header.first == "WWW-Authenticate"; });
    ASSERT_NE(challenge, run.response.headers.end());
    EXPECT_EQ(challenge->second, "Bearer");

    std::remove(store.c_str());
}

TEST(EnrollmentEndpointTest, UnknownTokenIs401AndCountsRejectedUnknown)
{
    // An empty store: the vector token was never minted here.
    const std::string store = "/tmp/enrollmentEndpoint_test_" + std::to_string(::getpid()) + "_empty.tokens.json";
    {
        std::ofstream file(store);
        file << R"({"version":1,"tokens":[]})";
    }
    const auto run = runWithToken(store, "", "unknown");

    EXPECT_EQ(run.response.status, 401);
    EXPECT_TRUE(run.authdRequest.empty());
    EXPECT_EQ(run.enrollValue(METRIC_TOKEN_REJECTED_UNKNOWN), 1U);
    EXPECT_EQ(run.enrollValue(METRIC_REJECTED_AUTH), 1U);

    std::remove(store.c_str());
}
