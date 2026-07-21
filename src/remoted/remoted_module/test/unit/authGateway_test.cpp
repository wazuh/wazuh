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

#include "http_server/IHttpServer.hpp"
#include "http_server/authGateway.hpp"

#include <gtest/gtest.h>

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

using namespace remoted::http;

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

    void dispatch(Method method, const std::string& path, const HttpRequest& request,
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

// Resolver stub: knows one agent; anything else is unknown.
class FakeResolver final : public wazuh_auth::IAgentKeyResolver
{
public:
    std::optional<std::vector<std::uint8_t>> resolve(const std::string& agentId) const override
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
    return AuthGateway {wazuh_auth::AuthConfig {}, std::make_shared<FakeResolver>()};
}
} // namespace

TEST(AuthGatewayTest, RegistersRouteOnTheServer)
{
    FakeHttpServer server;
    auto gateway = makeGateway();

    gateway.addAuthenticatedRoute(server, Method::Post, "/stateless",
                                  [](const wazuh_auth::AuthenticatedRequest&) { return HttpResponse{200, "", {}}; });

    EXPECT_TRUE(server.hasRoute(Method::Post, "/stateless"));
}

TEST(AuthGatewayTest, MissingProtocolVersionYields400AndSkipsHandler)
{
    FakeHttpServer server;
    auto gateway = makeGateway();

    bool handlerCalled = false;
    gateway.addAuthenticatedRoute(server, Method::Post, "/stateless",
                                  [&handlerCalled](const wazuh_auth::AuthenticatedRequest&)
                                  {
                                      handlerCalled = true;
                                      return HttpResponse{200, "", {}};
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
    gateway.addAuthenticatedRoute(server, Method::Post, "/stateless",
                                  [&handlerCalled](const wazuh_auth::AuthenticatedRequest&)
                                  {
                                      handlerCalled = true;
                                      return HttpResponse{200, "", {}};
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

    gateway.addAuthenticatedRoute(server, Method::Post, "/stateless",
                                  [](const wazuh_auth::AuthenticatedRequest&) { return HttpResponse{200, "", {}}; });

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
