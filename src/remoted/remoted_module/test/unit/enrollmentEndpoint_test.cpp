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
 * matrix itself (mode pass/deny, CMAC tamper scenarios) is covered by enrollmentAuthenticator_test.cpp;
 * these tests all use Open mode so the handler's OWN logic is what's under test.
 */

#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>

#include <gtest/gtest.h>

#include "enrollment/enrollmentEndpoint.hpp"
#include "fakeUdsServer.hpp"
#include "json.hpp"

#include <wazuh_metrics/manager.hpp>

using namespace remoted::enrollment;
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

    // Runs one dispatch through a freshly built handler (fresh authenticator/AuthdClient every
    // call -- AuthdClient's worker thread must not be shared across tests). authdPath need not
    // have a FakeUdsServer bound at all -- that's how the "authd unreachable" tests are expressed.
    HttpResponse
    run(const Config& config, const std::string& body, const std::string& authdPath, const std::string& remoteIp = "")
    {
        EnrollmentAuthenticator authenticator {EnrollmentAuthConfig {false}, nullptr};
        wazuh::metrics::Manager metricsManager;
        EnrollmentMetrics metrics = makeEnrollmentMetrics(metricsManager);

        AuthdClient authdClient(authdPath,
                                /*isWorkerNode=*/false,
                                /*connectTimeoutMs=*/0,
                                config.authdResponseTimeoutMs,
                                /*maxQueueSize=*/0);

        auto handler = makeHandler(authenticator, authdClient, config, metrics);

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

    auto handler = makeHandler(authenticator, authdClient, config, metrics);
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
                                           AuthdErrorCase {9007, 409},
                                           AuthdErrorCase {9008, 409},
                                           AuthdErrorCase {9012, 409},
                                           AuthdErrorCase {9013, 503},
                                           AuthdErrorCase {9015, 503},
                                           AuthdErrorCase {9016, 503},
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
