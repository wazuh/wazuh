/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * August 5, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// Unit-tests the /stateful endpoint policy: the downstream target it builds (inventory sync
// server + X-Wazuh-Agent-Id + dedicated response deadline), the passthrough of the sync
// contract's statuses/bodies/Retry-After, and the makeHandler() glue (empty-body short-circuit,
// opaque forward). Pure functions except the handler tests, which use a fake downstream client +
// a real DeferredForwarder -- the same pattern as statsEndpoint_test.cpp.
#include "endpoints/statefulEndpoint.hpp"

#include "auth/cmac.hpp"
#include "decoding/iBodyDecoder.hpp"
#include "downstream/IDownstreamClient.hpp"
#include "downstream/deferredWorkLimiter.hpp"
#include "endpoints/authGateway.hpp"
#include "fakeHttpServer.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using remoted::auth::AuthenticatedRequest;
using remoted::auth::Payload;
using remoted::downstream::DeferredForwarder;
using remoted::downstream::DeferredWorkLimiter;
using remoted::downstream::DownstreamError;
using remoted::downstream::DownstreamResponse;
using remoted::http::HttpResponse;
using remoted::http::Method;
// The shared transport fake, rather than a local copy: it already satisfies every IHttpServer
// virtual (including the in-flight byte reservation) so a new one does not break this test.
using remoted::testutil::FakeHttpServer;
namespace stateful = remoted::endpoints::stateful;

namespace
{
    struct AuthReqFixture
    {
        std::shared_ptr<const AuthenticatedRequest> req;
        std::shared_ptr<std::string> buffer; // owns the payload bytes
    };

    AuthReqFixture makeAuthReq(const std::string& body, const std::string& agentId)
    {
        auto buffer = std::make_shared<std::string>(body);
        AuthenticatedRequest ar;
        ar.agentId = agentId;
        ar.method = "POST";
        ar.requestTarget = "/stateful";
        ar.payload = Payload {std::string_view {*buffer}, buffer};
        return {std::make_shared<const AuthenticatedRequest>(std::move(ar)), std::move(buffer)};
    }

    std::optional<std::string> headerValue(const HttpResponse& response, const std::string& name)
    {
        for (const auto& [headerName, value] : response.headers)
        {
            if (headerName == name)
            {
                return value;
            }
        }
        return std::nullopt;
    }
} // namespace

TEST(StatefulEndpoint, TargetPointsAtTheInventorySyncServer)
{
    const auto target = stateful::target("queue/sockets/inventory-sync.sock", "1001", 20000);
    EXPECT_EQ(target.socketPath, "queue/sockets/inventory-sync.sock");
    EXPECT_EQ(target.method, Method::Post);
    EXPECT_EQ(target.path, "/stateful");
    EXPECT_EQ(target.contentType, "application/octet-stream");
    EXPECT_STREQ(target.serviceName, "inventory sync server");
    // The dedicated route deadline (remoted.downstream_stateful_response_timeout): sessions index
    // within the request, so /stateful must NOT ride the global 5 s default the way /stats does.
    EXPECT_EQ(target.responseTimeoutMs, 20000);
}

TEST(StatefulEndpoint, TargetCarriesTheAuthenticatedAgentIdAsAHeader)
{
    const auto target = stateful::target("queue/sockets/inventory-sync.sock", "1001", 20000);
    ASSERT_EQ(target.headers.size(), 1U);
    EXPECT_EQ(target.headers[0].first, "X-Wazuh-Agent-Id");
    EXPECT_EQ(target.headers[0].second, "1001");
}

TEST(StatefulEndpoint, PostProcessPassesTheContractStatusesAndBodiesThrough)
{
    // The downstream result IS the session result (D2): each contract status must reach the agent
    // with the server's own body, not a neutral rewrite -- e.g. the 409 body is what triggers the
    // agent's full resync.
    struct Case
    {
        int status;
        const char* body;
    };
    const Case cases[] = {
        {200, R"({"status":"ok"})"},
        {200, R"({"status":"ok","noop":true})"},
        {400, R"({"error":"values must not be empty","code":400})"},
        {403, R"({"error":"identity mismatch","code":403})"},
        {409, R"({"status":"checksum_mismatch"})"},
        {413, R"({"error":"session exceeds the total budget","code":413})"},
        {500, R"({"error":"vulnerability scan failed","code":500})"},
        {503, R"({"error":"indexer unavailable","code":503})"},
    };

    for (const auto& c : cases)
    {
        const auto response = stateful::postProcess(DownstreamError::None, DownstreamResponse {c.status, c.body, {}});
        EXPECT_EQ(response.status, c.status);
        EXPECT_EQ(response.body, c.body);
        EXPECT_EQ(headerValue(response, "Content-Type"), std::optional<std::string> {"application/json"});
    }
}

TEST(StatefulEndpoint, PostProcessMapsEveryTransportFailureToANeutral503)
{
    const DownstreamError errors[] = {
        DownstreamError::Connect,
        DownstreamError::ConnectTimeout,
        DownstreamError::WriteTimeout,
        DownstreamError::ResponseTimeout,
        DownstreamError::Transport,
        DownstreamError::Protocol,
        DownstreamError::ResponseTooLarge,
    };

    for (const auto error : errors)
    {
        const auto response = stateful::postProcess(error, DownstreamResponse {});
        EXPECT_EQ(response.status, 503) << "error=" << static_cast<int>(error);
        EXPECT_EQ(response.body, R"({"error":"Service unavailable","code":503})");
    }
}

TEST(StatefulEndpoint, PostProcessCollapsesNonContractStatusesToANeutral503)
{
    // 404/405: route contract mismatch (mismatched versions). 202/302: nothing the sync server
    // produces. None of them is a session result the agent could act on.
    for (const int status : {202, 302, 404, 405, 418})
    {
        const auto response =
            stateful::postProcess(DownstreamError::None, DownstreamResponse {status, "downstream internals", {}});
        EXPECT_EQ(response.status, 503) << "status=" << status;
        EXPECT_EQ(response.body, R"({"error":"Service unavailable","code":503})"); // never the downstream body
    }
}

TEST(StatefulEndpoint, RetryAfterIsForwardedOnA503)
{
    DownstreamResponse downstream {503, R"({"error":"vulnerability feed not ready","code":503})", {}};
    downstream.headers.emplace_back("content-type", "application/json"); // client lower-cases names
    downstream.headers.emplace_back("retry-after", "60");

    const auto response = stateful::postProcess(DownstreamError::None, downstream);
    EXPECT_EQ(response.status, 503);
    EXPECT_EQ(response.body, downstream.body);
    EXPECT_EQ(headerValue(response, "Retry-After"), std::optional<std::string> {"60"});
}

TEST(StatefulEndpoint, RetryAfterIsOnlyForwardedOnA503)
{
    // Present on any other status it would be meaningless contract-wise -- not reflected.
    DownstreamResponse downstream {200, R"({"status":"ok"})", {}};
    downstream.headers.emplace_back("retry-after", "60");

    const auto response = stateful::postProcess(DownstreamError::None, downstream);
    EXPECT_EQ(response.status, 200);
    EXPECT_EQ(headerValue(response, "Retry-After"), std::nullopt);
}

TEST(StatefulEndpoint, MalformedRetryAfterIsDroppedNotReflected)
{
    // Our own server only ever produces a small digits-only delay; anything else is dropped so a
    // misbehaving downstream can never place an arbitrary string in an agent-visible header.
    for (const char* bad : {"", "60; drop", "Tue, 03 Jun 2027 11:00:00 GMT", "1234567", "-5"})
    {
        DownstreamResponse downstream {503, "{}", {}};
        downstream.headers.emplace_back("retry-after", bad);

        const auto response = stateful::postProcess(DownstreamError::None, downstream);
        EXPECT_EQ(response.status, 503);
        EXPECT_EQ(headerValue(response, "Retry-After"), std::nullopt) << "value='" << bad << "'";
    }
}

// --- makeHandler() ----------------------------------------------------------------------------

namespace
{
    // Records whether sendAsync() was called; fires the callback on demand (same shape as the
    // stateless/stats endpoint tests).
    class FakeDownstreamClient final : public remoted::downstream::IDownstreamClient
    {
    public:
        void sendAsync(remoted::downstream::DownstreamRequest req,
                       std::shared_ptr<const void> /*keepAlive*/,
                       remoted::downstream::DownstreamCallback cb) override
        {
            std::lock_guard<std::mutex> lock {m_mutex};
            m_request = std::move(req);
            m_callback = std::move(cb);
            m_called = true;
        }

        bool called() const
        {
            std::lock_guard<std::mutex> lock {m_mutex};
            return m_called;
        }

        remoted::downstream::DownstreamRequest request() const
        {
            std::lock_guard<std::mutex> lock {m_mutex};
            return m_request;
        }

        void fire(DownstreamError error, DownstreamResponse response)
        {
            remoted::downstream::DownstreamCallback cb;
            {
                std::lock_guard<std::mutex> lock {m_mutex};
                cb = std::move(m_callback);
            }
            ASSERT_TRUE(static_cast<bool>(cb));
            cb(error, std::move(response));
        }

    private:
        mutable std::mutex m_mutex;
        remoted::downstream::DownstreamRequest m_request;
        remoted::downstream::DownstreamCallback m_callback;
        bool m_called {false};
    };

    class CapturingResponder final : public remoted::http::IHttpResponder
    {
    public:
        void send(HttpResponse response) override
        {
            if (!m_answered.exchange(true))
            {
                m_promise.set_value(std::move(response));
            }
        }
        std::future<HttpResponse> future()
        {
            return m_promise.get_future();
        }

    private:
        std::promise<HttpResponse> m_promise;
        std::atomic<bool> m_answered {false};
    };
} // namespace

TEST(StatefulMakeHandler, EmptyBodyShortCircuitsBeforeForward)
{
    auto client = std::make_shared<FakeDownstreamClient>();
    auto limiter = std::make_shared<DeferredWorkLimiter>(4);
    DeferredForwarder forwarder {client, limiter, 1};

    auto handler = stateful::makeHandler(forwarder, "queue/sockets/inventory-sync.sock", 20000);
    auto fixture = makeAuthReq("", "1001");
    auto responder = std::make_shared<CapturingResponder>();
    auto fut = responder->future();

    handler(fixture.req, responder);

    ASSERT_EQ(fut.wait_for(std::chrono::seconds {2}), std::future_status::ready);
    const auto response = fut.get();
    EXPECT_EQ(response.status, 400);
    EXPECT_EQ(response.body, R"({"error":"Empty request body","code":400})");
    EXPECT_FALSE(client->called()); // forward() must never run for an empty body
}

TEST(StatefulMakeHandler, ForwardsTheOpaqueSessionWithAgentIdAndDedicatedTimeoutThenPassesThrough)
{
    auto client = std::make_shared<FakeDownstreamClient>();
    auto limiter = std::make_shared<DeferredWorkLimiter>(4);
    DeferredForwarder forwarder {client, limiter, 1};

    auto handler = stateful::makeHandler(forwarder, "queue/sockets/inventory-sync.sock", 20000);
    // Deliberately NOT a valid FlatBuffer: remoted must forward it opaquely, without parsing.
    auto fixture = makeAuthReq("\x01\x02binary-fullsession-bytes", "1001");
    auto responder = std::make_shared<CapturingResponder>();
    auto fut = responder->future();

    handler(fixture.req, responder);

    ASSERT_TRUE(client->called());
    const auto req = client->request();
    EXPECT_EQ(req.socketPath, "queue/sockets/inventory-sync.sock");
    EXPECT_EQ(req.path, "/stateful");
    EXPECT_EQ(req.contentType, "application/octet-stream");
    EXPECT_EQ(req.responseTimeoutMs, 20000); // the dedicated deadline reaches the wire request
    ASSERT_EQ(req.headers.size(), 1U);
    EXPECT_EQ(req.headers[0].first, "X-Wazuh-Agent-Id");
    EXPECT_EQ(req.headers[0].second, "1001");

    client->fire(DownstreamError::None, DownstreamResponse {409, R"({"status":"checksum_mismatch"})", {}});

    ASSERT_EQ(fut.wait_for(std::chrono::seconds {2}), std::future_status::ready);
    const auto response = fut.get();
    EXPECT_EQ(response.status, 409); // the session result reaches the agent untouched
    EXPECT_EQ(response.body, R"({"status":"checksum_mismatch"})");
}

// --- gateway + endpoint composition (doc 10 §3) ------------------------------------------------

namespace
{
    // Minimal fakes for the composition test, same shapes as authGateway_test.cpp's.
    // The transport fake itself comes from fakeHttpServer.hpp (see the using above).

    // AuthGateway requires a body-decoding step. This test is about the authenticated id reaching
    // the downstream header, not about content encodings, so it passes bodies through untouched --
    // the same stub shape authGateway_test.cpp uses.
    class StubBodyDecoder final : public remoted::decoding::IBodyDecoder
    {
    public:
        remoted::auth::AuthError decode(remoted::decoding::ContentEncoding /*encoding*/,
                                        Payload& /*payload*/) const override
        {
            return remoted::auth::AuthError::None;
        }
    };

    std::shared_ptr<const remoted::decoding::IBodyDecoder> passthroughDecoder()
    {
        return std::make_shared<const StubBodyDecoder>();
    }

    class FakeKeystore final : public remoted::auth::IAgentKeystore
    {
    public:
        std::optional<std::vector<std::uint8_t>> keyFor(remoted::auth::AgentId agentId) const override
        {
            if (agentId == 1)
            {
                return std::vector<std::uint8_t>(16, 0x0A);
            }
            return std::nullopt;
        }
    };
} // namespace

// The doc-10 §3 component chain in one piece: a CMAC-signed agent request to /stateful runs
// through the real AuthGateway into the real handler, and the id that reaches the downstream
// X-Wazuh-Agent-Id header is the AUTHENTICATED one -- written by the manager from the verified
// Authorization header, never taken from anything the agent controls independently of the MAC.
TEST(StatefulMakeHandler, AuthenticatedRequestFlowsThroughTheGatewayIntoTheForward)
{
    auto client = std::make_shared<FakeDownstreamClient>();
    auto limiter = std::make_shared<DeferredWorkLimiter>(4);
    DeferredForwarder forwarder {client, limiter, 1};

    FakeHttpServer server;
    remoted::endpoints::AuthGateway gateway {
        remoted::auth::AuthConfig {}, std::make_shared<FakeKeystore>(), passthroughDecoder()};
    gateway.addAuthenticatedRoute(server,
                                  Method::Post,
                                  "/stateful",
                                  stateful::makeHandler(forwarder, "queue/sockets/inventory-sync.sock", 20000));

    // Sign the canonical byte sequence AuthMiddleware verifies, with FakeKeystore's key for 001.
    const std::string body = "\x01\x02opaque-fullsession";
    const auto ts = static_cast<std::int64_t>(std::time(nullptr));
    const std::vector<std::uint8_t> key(16, 0x0A);
    remoted::auth::Cmac cmac(key);
    cmac.update("WAZUH-REQUEST\n");
    cmac.update("1\n"); // protocol-version
    cmac.update("POST\n");
    cmac.update("/stateful\n");
    cmac.update("001\n");
    cmac.update(std::to_string(ts));
    cmac.update("\n");
    cmac.update(body);
    const auto mac = cmac.finalize();

    remoted::http::HttpRequest request;
    request.method = Method::Post;
    request.target = "/stateful";
    request.body = body;
    request.headers.emplace("protocol-version", "1");
    request.headers.emplace(
        "authorization", "Wazuh 001:" + std::to_string(ts) + ":" + remoted::auth::toLowerHex(mac.data(), mac.size()));

    auto responder = std::make_shared<CapturingResponder>();
    auto fut = responder->future();
    server.dispatch(Method::Post, "/stateful", request, responder);

    ASSERT_TRUE(client->called());
    const auto req = client->request();
    ASSERT_EQ(req.headers.size(), 1U);
    EXPECT_EQ(req.headers[0].first, "X-Wazuh-Agent-Id");
    EXPECT_EQ(req.headers[0].second, "001"); // the id the CMAC authenticated, wire form

    client->fire(DownstreamError::None, DownstreamResponse {200, R"({"status":"ok"})", {}});
    ASSERT_EQ(fut.wait_for(std::chrono::seconds {2}), std::future_status::ready);
    const auto response = fut.get();
    EXPECT_EQ(response.status, 200);
    EXPECT_EQ(response.body, R"({"status":"ok"})");
}
