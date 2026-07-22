/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * July 21, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "auth/cmac.hpp"
#include "endpoints/authGateway.hpp"
#include "http_server/IHttpServer.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <ctime>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using namespace remoted::http;
using namespace remoted::endpoints;

namespace
{
    // Fake transport: stores registered routes so a test can dispatch them directly
    // (synchronously, no sockets), exactly as the gateway's wrapper would run on a
    // worker thread.
    class FakeHttpServer final : public IHttpServer
    {
    public:
        void addRoute(Method method, const std::string& path, RouteHandler handler) override
        {
            m_routes[{method, path}] = std::move(handler);
        }
        void start(const HttpServerConfig&) override {}
        void stop() noexcept override {}

        void dispatch(Method method,
                      const std::string& path,
                      const HttpRequest& request,
                      std::shared_ptr<IHttpResponder> responder)
        {
            m_routes.at({method, path})(request, std::move(responder));
        }

        bool hasRoute(Method method, const std::string& path) const
        {
            return m_routes.count({method, path}) != 0;
        }

    private:
        std::map<std::pair<Method, std::string>, RouteHandler> m_routes;
    };

    // Keystore stub: knows one agent; anything else is unknown.
    class FakeKeystore final : public remoted::auth::IAgentKeystore
    {
    public:
        std::optional<std::vector<std::uint8_t>> keyFor(const std::string& agentId) const override
        {
            if (agentId == "001")
            {
                return std::vector<std::uint8_t>(16, 0x0A); // 16-byte AES-128 key
            }
            return std::nullopt;
        }
    };

    class CapturingResponder final : public IHttpResponder
    {
    public:
        void send(HttpResponse response) override
        {
            if (!captured.has_value())
            {
                captured = std::move(response);
            }
        }
        std::optional<HttpResponse> captured;
    };

    AuthGateway makeGateway()
    {
        return AuthGateway {remoted::auth::AuthConfig {}, std::make_shared<FakeKeystore>()};
    }

    // Build a valid "Wazuh <id>:<ts>:<mac>" Authorization for agent 001, signing the same
    // canonical byte sequence AuthMiddleware verifies, with the key FakeKeystore returns.
    std::string
    buildAuthorization(const std::string& method, const std::string& target, const std::string& body, std::int64_t ts)
    {
        const std::vector<std::uint8_t> key(16, 0x0A); // matches FakeKeystore::keyFor("001")
        remoted::auth::Cmac cmac(key);
        cmac.update("WAZUH-REQUEST\n");
        cmac.update("1\n"); // protocol-version
        cmac.update(method);
        cmac.update("\n");
        cmac.update(target);
        cmac.update("\n");
        cmac.update("001\n"); // agent id
        cmac.update(std::to_string(ts));
        cmac.update("\n");
        cmac.update(body);
        const auto mac = cmac.finalize();
        return "Wazuh 001:" + std::to_string(ts) + ":" + remoted::auth::toLowerHex(mac.data(), mac.size());
    }

    // A request that authenticates cleanly for agent 001 against makeGateway().
    HttpRequest signedRequest(const std::string& body)
    {
        const auto ts = static_cast<std::int64_t>(std::time(nullptr));
        HttpRequest request;
        request.method = Method::Post;
        request.target = "/stateless";
        request.body = body;
        request.headers.emplace("protocol-version", "1");
        request.headers.emplace("authorization", buildAuthorization("POST", "/stateless", body, ts));
        return request;
    }
} // namespace

TEST(AuthGatewayTest, RegistersRouteOnTheServer)
{
    FakeHttpServer server;
    auto gateway = makeGateway();

    gateway.addAuthenticatedRoute(
        server,
        Method::Post,
        "/stateless",
        [](const remoted::auth::AuthenticatedRequest&, std::shared_ptr<IHttpResponder> responder)
        { responder->send(HttpResponse {200, "", {}}); });

    EXPECT_TRUE(server.hasRoute(Method::Post, "/stateless"));
}

TEST(AuthGatewayTest, MissingProtocolVersionYields400AndSkipsHandler)
{
    FakeHttpServer server;
    auto gateway = makeGateway();

    bool handlerCalled = false;
    gateway.addAuthenticatedRoute(
        server,
        Method::Post,
        "/stateless",
        [&handlerCalled](const remoted::auth::AuthenticatedRequest&, std::shared_ptr<IHttpResponder> responder)
        {
            handlerCalled = true;
            responder->send(HttpResponse {200, "", {}});
        });

    HttpRequest request;
    request.method = Method::Post;
    request.target = "/stateless";
    // No protocol-version, no authorization.

    auto responder = std::make_shared<CapturingResponder>();
    server.dispatch(Method::Post, "/stateless", request, responder);

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(responder->captured->status, 400);
    EXPECT_FALSE(handlerCalled);
}

TEST(AuthGatewayTest, MissingAuthorizationYields401AndSkipsHandler)
{
    FakeHttpServer server;
    auto gateway = makeGateway();

    bool handlerCalled = false;
    gateway.addAuthenticatedRoute(
        server,
        Method::Post,
        "/stateless",
        [&handlerCalled](const remoted::auth::AuthenticatedRequest&, std::shared_ptr<IHttpResponder> responder)
        {
            handlerCalled = true;
            responder->send(HttpResponse {200, "", {}});
        });

    HttpRequest request;
    request.method = Method::Post;
    request.target = "/stateless";
    request.headers.emplace("protocol-version", "1"); // present, but no Authorization

    auto responder = std::make_shared<CapturingResponder>();
    server.dispatch(Method::Post, "/stateless", request, responder);

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(responder->captured->status, 401);
    EXPECT_FALSE(handlerCalled);
}

TEST(AuthGatewayTest, HeaderLookupIsCaseInsensitive)
{
    FakeHttpServer server;
    auto gateway = makeGateway();

    gateway.addAuthenticatedRoute(
        server,
        Method::Post,
        "/stateless",
        [](const remoted::auth::AuthenticatedRequest&, std::shared_ptr<IHttpResponder> responder)
        { responder->send(HttpResponse {200, "", {}}); });

    HttpRequest request;
    request.method = Method::Post;
    request.target = "/stateless";
    // Mixed-case header name must still be found (so we reach the 401 auth path, not 400).
    request.headers.emplace("Protocol-Version", "1");

    auto responder = std::make_shared<CapturingResponder>();
    server.dispatch(Method::Post, "/stateless", request, responder);

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(responder->captured->status, 401); // missing Authorization, not missing protocol-version
}

TEST(AuthGatewayTest, ValidAuthReachesHandlerWithVerifiedRequest)
{
    FakeHttpServer server;
    auto gateway = makeGateway();

    std::string seenAgentId;
    gateway.addAuthenticatedRoute(
        server,
        Method::Post,
        "/stateless",
        [&seenAgentId](const remoted::auth::AuthenticatedRequest& authReq, std::shared_ptr<IHttpResponder> responder)
        {
            seenAgentId = authReq.agentId;
            responder->send(HttpResponse::json(200, R"({"ok":true})"));
        });

    const auto request = signedRequest("some-body");
    auto responder = std::make_shared<CapturingResponder>();
    server.dispatch(Method::Post, "/stateless", request, responder);

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(responder->captured->status, 200);
    EXPECT_EQ(seenAgentId, "001"); // the handler received the authenticated identity
}

TEST(AuthGatewayTest, HandlerExceptionYields500)
{
    FakeHttpServer server;
    auto gateway = makeGateway();

    bool handlerCalled = false;
    gateway.addAuthenticatedRoute(
        server,
        Method::Post,
        "/stateless",
        [&handlerCalled](const remoted::auth::AuthenticatedRequest&, std::shared_ptr<IHttpResponder>)
        {
            handlerCalled = true;
            throw std::runtime_error("boom"); // handler fails after auth succeeded
        });

    const auto request = signedRequest("some-body");
    auto responder = std::make_shared<CapturingResponder>();
    server.dispatch(Method::Post, "/stateless", request, responder);

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_TRUE(handlerCalled);                  // auth passed, the handler ran
    EXPECT_EQ(responder->captured->status, 500); // ... then the gateway caught the throw
}
