/*
 * Wazuh remoted module - controlEndpoint unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 31, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Tests the JSON dispatch layer of `POST /control`. The four rejection paths
 * (invalid body, invalid JSON, invalid agent id, unknown type) are covered
 * synchronously with only a capturing responder. The three happy paths
 * (startup / notify / shutdown) also plug in a real ControlHandler wired to
 * FakeUdsServer instances so the round-trip response body is asserted end-to-end.
 */

#include "auth/authTypes.hpp"
#include "common/vdClient.hpp"
#include "control/agentRegistry.hpp"
#include "control/controlConfig.hpp"
#include "control/controlHandler.hpp"
#include "control/hashCache.hpp"
#include "control/metrics.hpp"
#include "control/taskClient.hpp"
#include "control/wazuhDBClient.hpp"
#include "endpoints/controlEndpoint.hpp"
#include "fakeUdsServer.hpp"
#include "http_server/IHttpServer.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <json.hpp>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unistd.h>

using namespace remoted::control;
using remoted::auth::AuthenticatedRequest;
using remoted::auth::Payload;
using remoted::http::IHttpResponder;
using remoted::test::FakeUdsServer;
namespace fs = std::filesystem;
using namespace std::chrono_literals;

namespace
{
    // Minimal test responder that captures whatever `send()` receives.
    class CapturingResponder : public IHttpResponder
    {
    public:
        void send(remoted::http::HttpResponse response) override
        {
            std::lock_guard<std::mutex> lock(m_mu);
            if (m_done) // duplicate send would be a bug we want the tests to see
                return;
            m_response = std::move(response);
            m_done = true;
            m_cv.notify_all();
        }

        bool wait(std::chrono::milliseconds timeout)
        {
            std::unique_lock<std::mutex> lock(m_mu);
            return m_cv.wait_for(lock, timeout, [&] { return m_done; });
        }

        remoted::http::HttpResponse captured()
        {
            std::lock_guard<std::mutex> lock(m_mu);
            return m_response;
        }

    private:
        std::mutex m_mu;
        std::condition_variable m_cv;
        bool m_done {false};
        remoted::http::HttpResponse m_response;
    };

    // Build an AuthenticatedRequest with an in-memory payload. The keepAlive
    // pointer is a dummy: it only has to be non-null so Payload::bytes() returns
    // the view instead of an empty one.
    std::shared_ptr<AuthenticatedRequest> makeRequest(const std::string& agentId, const std::string& body)
    {
        // Return by shared_ptr so the string backing the payload outlives the request.
        struct Holder
        {
            std::shared_ptr<AuthenticatedRequest> req;
            std::shared_ptr<std::string> body;
        };
        auto req = std::make_shared<AuthenticatedRequest>();
        req->agentId = agentId;
        req->method = "POST";
        req->requestTarget = "/control";
        auto bodyBuf = std::make_shared<std::string>(body);
        req->payload = Payload(std::string_view(*bodyBuf), std::shared_ptr<const void>(bodyBuf, bodyBuf.get()));
        return req;
    }

    // Fixture that wires a full ControlHandler with fake wdb/task backends.
    // We reuse this for the dispatch tests so we can assert the ControlHandler
    // was actually invoked (response body has cluster envelope for startup, etc).
    struct DispatchFixture
    {
        fs::path base;
        std::string wdbPath;
        std::string taskPath;
        Config cfg;
        ControlMetrics metrics;
        std::unique_ptr<FakeUdsServer> wdbServer;
        std::unique_ptr<FakeUdsServer> taskServer;
        std::shared_ptr<AgentRegistry> registry;
        std::shared_ptr<WazuhDBClient> wdbClient;
        std::shared_ptr<TaskClient> taskClient;
        std::shared_ptr<HashCache> hashCache;
        std::shared_ptr<remoted::common::VdClient> vdClient;
        std::unique_ptr<ControlHandler> handler;
        remoted::endpoints::AuthenticatedHandler endpointHandler;

        DispatchFixture()
        {
            base = fs::temp_directory_path() / ("wazuh_ctrl_ep_test_" + std::to_string(::getpid()) + "_" +
                                                std::to_string(reinterpret_cast<uintptr_t>(this)));
            fs::create_directories(base / "shared");
            fs::create_directories(base / "multi");
            wdbPath = remoted::test::makeUniqueSocketPath("ep_wdb");
            taskPath = remoted::test::makeUniqueSocketPath("ep_task");

            cfg.sharedGroupsRoot = (base / "shared").string();
            cfg.multiGroupsRoot = (base / "multi").string();
            cfg.wdbSocketPath = wdbPath;
            cfg.taskSocketPath = taskPath;
            cfg.clusterName = "wazuh";
            cfg.managerVersion = "5.0.0";
            cfg.limits = nlohmann::json::object();
            cfg.wdbRequestConnections = 1;
            cfg.wdbRoundtripDeadlineMs = 2000;
            cfg.wdbMaxQueueSize = 100;
            cfg.tmConcurrency = 1;
            cfg.tmDeadlineMs = 2000;
            cfg.tmMaxQueueSize = 100;

            wdbServer = std::make_unique<FakeUdsServer>(wdbPath,
                                                        [](const std::string& req) -> std::string
                                                        {
                                                            if (req.find("global select-agent-group") == 0)
                                                                return "ok {\"group\":\"default\"}";
                                                            return "ok";
                                                        });
            taskServer = std::make_unique<FakeUdsServer>(
                taskPath, [](const std::string&) -> std::string { return "{\"status\":\"ok\",\"tasks\":[]}"; });

            registry = std::make_shared<AgentRegistry>();
            wdbClient = std::make_shared<WazuhDBClient>(
                cfg.wdbSocketPath, cfg.wdbRequestConnections, cfg.wdbRoundtripDeadlineMs, cfg.wdbMaxQueueSize, metrics);
            taskClient = std::make_shared<TaskClient>(
                cfg.taskSocketPath, cfg.tmConcurrency, cfg.tmDeadlineMs, cfg.tmMaxQueueSize, metrics);
            hashCache = std::make_shared<HashCache>(cfg);
            vdClient = std::make_shared<remoted::common::VdClient>();
            handler =
                std::make_unique<ControlHandler>(registry, wdbClient, taskClient, hashCache, vdClient, metrics, cfg);
            endpointHandler = remoted::endpoints::control::makeHandler(*handler);
        }
        ~DispatchFixture()
        {
            std::error_code ec;
            fs::remove_all(base, ec);
        }
    };
} // namespace

// =============================================================================
// Rejection paths -- no ControlHandler needed; a no-op handler suffices because
// the endpoint short-circuits before calling it.
// =============================================================================

namespace
{
    // A ControlHandler-less dispatcher: for rejection tests we still need to
    // construct an AuthenticatedHandler, so we spin up a minimal handler with
    // no backing sockets. Its methods are never reached in these tests.
    struct RejectionFixture : DispatchFixture
    {
        // Nothing special: DispatchFixture already provides the wiring; we just
        // rely on the fact that a rejected request never touches the sockets.
    };
} // namespace

TEST(ControlEndpointTest, EmptyBodyReturns400InvalidBody)
{
    RejectionFixture f;
    auto req = makeRequest("1", "");
    auto resp = std::make_shared<CapturingResponder>();
    f.endpointHandler(req, resp);

    ASSERT_TRUE(resp->wait(500ms));
    EXPECT_EQ(resp->captured().status, 400);
    EXPECT_NE(resp->captured().body.find("invalid_body"), std::string::npos);
}

TEST(ControlEndpointTest, OversizedBodyReturns400InvalidBody)
{
    RejectionFixture f;
    // 64 KiB + 1: just above the endpoint-local kMaxControlBodySize.
    std::string big(64U * 1024U + 1U, 'a');
    auto req = makeRequest("1", big);
    auto resp = std::make_shared<CapturingResponder>();
    f.endpointHandler(req, resp);

    ASSERT_TRUE(resp->wait(500ms));
    EXPECT_EQ(resp->captured().status, 400);
    EXPECT_NE(resp->captured().body.find("invalid_body"), std::string::npos);
}

TEST(ControlEndpointTest, MalformedJsonReturns400InvalidJson)
{
    RejectionFixture f;
    auto req = makeRequest("1", "{not json");
    auto resp = std::make_shared<CapturingResponder>();
    f.endpointHandler(req, resp);

    ASSERT_TRUE(resp->wait(500ms));
    EXPECT_EQ(resp->captured().status, 400);
    EXPECT_NE(resp->captured().body.find("invalid_json"), std::string::npos);
}

TEST(ControlEndpointTest, NonObjectJsonReturns400InvalidJson)
{
    RejectionFixture f;
    // Valid JSON, but not a top-level object -- endpoint requires an object.
    auto req = makeRequest("1", "[\"list\"]");
    auto resp = std::make_shared<CapturingResponder>();
    f.endpointHandler(req, resp);

    ASSERT_TRUE(resp->wait(500ms));
    EXPECT_EQ(resp->captured().status, 400);
    EXPECT_NE(resp->captured().body.find("invalid_json"), std::string::npos);
}

TEST(ControlEndpointTest, NonNumericAgentIdReturns400InvalidAgentId)
{
    RejectionFixture f;
    auto req = makeRequest("abc", R"({"type":"startup","version":"5.0.0"})");
    auto resp = std::make_shared<CapturingResponder>();
    f.endpointHandler(req, resp);

    ASSERT_TRUE(resp->wait(500ms));
    EXPECT_EQ(resp->captured().status, 400);
    EXPECT_NE(resp->captured().body.find("invalid_agent_id"), std::string::npos);
}

TEST(ControlEndpointTest, NegativeAgentIdReturns400InvalidAgentId)
{
    RejectionFixture f;
    // uint32_t from_chars must reject a leading '-'.
    auto req = makeRequest("-1", R"({"type":"startup","version":"5.0.0"})");
    auto resp = std::make_shared<CapturingResponder>();
    f.endpointHandler(req, resp);

    ASSERT_TRUE(resp->wait(500ms));
    EXPECT_EQ(resp->captured().status, 400);
    EXPECT_NE(resp->captured().body.find("invalid_agent_id"), std::string::npos);
}

TEST(ControlEndpointTest, AgentIdWithTrailingGarbageReturns400)
{
    RejectionFixture f;
    // from_chars must fully consume the string.
    auto req = makeRequest("42abc", R"({"type":"startup","version":"5.0.0"})");
    auto resp = std::make_shared<CapturingResponder>();
    f.endpointHandler(req, resp);

    ASSERT_TRUE(resp->wait(500ms));
    EXPECT_EQ(resp->captured().status, 400);
    EXPECT_NE(resp->captured().body.find("invalid_agent_id"), std::string::npos);
}

TEST(ControlEndpointTest, MissingTypeReturns400UnknownMessageType)
{
    RejectionFixture f;
    auto req = makeRequest("1", R"({"version":"5.0.0"})");
    auto resp = std::make_shared<CapturingResponder>();
    f.endpointHandler(req, resp);

    ASSERT_TRUE(resp->wait(500ms));
    EXPECT_EQ(resp->captured().status, 400);
    EXPECT_NE(resp->captured().body.find("unknown_message_type"), std::string::npos);
}

TEST(ControlEndpointTest, UnknownTypeReturns400)
{
    RejectionFixture f;
    auto req = makeRequest("1", R"({"type":"handshake"})");
    auto resp = std::make_shared<CapturingResponder>();
    f.endpointHandler(req, resp);

    ASSERT_TRUE(resp->wait(500ms));
    EXPECT_EQ(resp->captured().status, 400);
    EXPECT_NE(resp->captured().body.find("unknown_message_type"), std::string::npos);
}

TEST(ControlEndpointTest, ErrorResponsesAreApplicationJson)
{
    RejectionFixture f;
    auto req = makeRequest("1", "");
    auto resp = std::make_shared<CapturingResponder>();
    f.endpointHandler(req, resp);

    ASSERT_TRUE(resp->wait(500ms));
    // All /control errors go out with Content-Type: application/json so clients
    // can parse the {"error":"..."} body uniformly.
    bool sawJson = false;
    for (const auto& [name, value] : resp->captured().headers)
    {
        if (name == "Content-Type" && value == "application/json")
            sawJson = true;
    }
    EXPECT_TRUE(sawJson);
}

// =============================================================================
// Happy paths -- full dispatch to the underlying ControlHandler.
// =============================================================================

TEST(ControlEndpointTest, StartupDispatchesToHandlerAndReturnsClusterEnvelope)
{
    DispatchFixture f;
    auto req = makeRequest("42", R"({"type":"startup","version":"5.0.0"})");
    auto resp = std::make_shared<CapturingResponder>();
    f.endpointHandler(req, resp);

    ASSERT_TRUE(resp->wait(3000ms));
    EXPECT_EQ(resp->captured().status, 200);
    auto j = nlohmann::json::parse(resp->captured().body);
    EXPECT_EQ(j["cluster"]["name"], "wazuh");
    ASSERT_TRUE(j["agent"]["groups"].is_array());
    EXPECT_EQ(j["agent"]["groups"][0], "default");
    EXPECT_GE(f.metrics.startupCount.load(), 1U);
}

TEST(ControlEndpointTest, NotifyDispatchesToHandlerAndReturnsConfigAndSettingsHash)
{
    DispatchFixture f;
    auto req = makeRequest(
        "42",
        R"({"type":"notify","agent":{"version":"5.0.0"},"host":{"hostname":"h1","ip":"127.0.0.1","architecture":"x86_64","os":{"name":"Ubuntu","version":"24.04","platform":"ubuntu","type":"Linux"}}})");
    auto resp = std::make_shared<CapturingResponder>();
    f.endpointHandler(req, resp);

    ASSERT_TRUE(resp->wait(3000ms));
    EXPECT_EQ(resp->captured().status, 200);
    auto j = nlohmann::json::parse(resp->captured().body);
    EXPECT_TRUE(j.contains("agent"));
    EXPECT_TRUE(j["agent"].contains("groups"));
    EXPECT_TRUE(j["agent"].contains("config_hash"));
    EXPECT_TRUE(j.contains("settings_hash"));
    EXPECT_EQ(j["settings_hash"].get<std::string>().size(), 64U);
    EXPECT_GE(f.metrics.notifyCount.load(), 1U);
}

TEST(ControlEndpointTest, ShutdownDispatchesToHandlerAndReturnsEmptyJsonObject)
{
    DispatchFixture f;
    auto req = makeRequest("42", R"({"type":"shutdown"})");
    auto resp = std::make_shared<CapturingResponder>();
    f.endpointHandler(req, resp);

    ASSERT_TRUE(resp->wait(500ms));
    EXPECT_EQ(resp->captured().status, 200);
    EXPECT_EQ(resp->captured().body, "{}");
    EXPECT_GE(f.metrics.shutdownCount.load(), 1U);
}

TEST(ControlEndpointTest, SuccessResponsesAreApplicationJson)
{
    DispatchFixture f;
    auto req = makeRequest("42", R"({"type":"shutdown"})");
    auto resp = std::make_shared<CapturingResponder>();
    f.endpointHandler(req, resp);

    ASSERT_TRUE(resp->wait(500ms));
    bool sawJson = false;
    for (const auto& [name, value] : resp->captured().headers)
    {
        if (name == "Content-Type" && value == "application/json")
            sawJson = true;
    }
    EXPECT_TRUE(sawJson);
}
