/*
 * Wazuh remoted module - global endpoint prefix end-to-end test (issue #38491)
 * Copyright (C) 2015, Wazuh Inc.
 * August 22, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Drives a REAL TLS RestinioHttpServer + real AuthGateway with a global prefix configured, to
 * pin the feature's routing contract: routes live at the prefixed path, an unprefixed request is
 * a 404 (auth never runs), and -- since the bearer profile authenticates identity only -- the same
 * token is valid for any target the router accepts (the token does not bind the target, by design).
 * (the legacy-tooling failure mode); an unprefixed request never reaches auth at all (404).
 * GlobalPrefixTransportTest (httpServer_test.cpp) covers the routing-only side without auth.
 */

#include "auth/authTypes.hpp"
#include "decoding/bodyDecoder.hpp"
#include "endpoints/authGateway.hpp"
#include "http_server/IHttpServer.hpp"
#include "http_server/httpServerFactory.hpp"

#include "testTlsServer.hpp"

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdint>
#include <cstdlib>
#include <memory>
#include <optional>
#include <string>
#include <vector>

using namespace remoted::http;
using remoted::endpoints::AuthGateway;

namespace
{
    std::uint16_t findFreePort()
    {
        const int probe = ::socket(AF_INET, SOCK_STREAM, 0);
        if (probe < 0)
        {
            return 0;
        }

        sockaddr_in address {};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = 0;

        std::uint16_t port = 0;
        if (::bind(probe, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0)
        {
            socklen_t length = sizeof(address);
            if (::getsockname(probe, reinterpret_cast<sockaddr*>(&address), &length) == 0)
            {
                port = ntohs(address.sin_port);
            }
        }

        ::close(probe);
        return port;
    }

    int statusOf(const std::string& rawResponse)
    {
        const auto space = rawResponse.find(' ');
        if (space == std::string::npos || space + 4 > rawResponse.size())
        {
            return 0;
        }
        return std::atoi(rawResponse.c_str() + space + 1);
    }

    // The RemotedModuleFacade wiring slice that matters here: a real server, a real gateway
    // (real AuthMiddleware + bearer verification against FakeKeystore's one agent), and a trivial
    // always-200 authenticated handler on the LOGICAL path "/stateless".
    class GlobalPrefixE2ETest : public ::testing::Test
    {
    protected:
        void SetUp() override
        {
            if (std::system("openssl version >/dev/null 2>&1") != 0)
            {
                GTEST_SKIP() << "openssl not available to generate the test certificate";
            }
            m_cert = remoted::test::generateTestCertificate("global_prefix_e2e");
            if (!m_cert)
            {
                GTEST_SKIP() << "could not generate a throwaway TLS certificate";
            }
            m_cleanup = std::make_unique<remoted::test::ScratchFileCleanup>(
                std::vector<std::string> {m_cert->certPath, m_cert->keyPath});
        }

        void startServer(const std::string& rawPrefix)
        {
            m_port = findFreePort();
            ASSERT_NE(m_port, 0);

            m_server = makeHttpServer();
            m_gateway = std::make_unique<AuthGateway>(
                remoted::auth::AuthConfig {},
                std::make_shared<remoted::test::FakeKeystore>(),
                std::make_shared<const remoted::decoding::BodyDecoder>(*m_server, /*enabled=*/true));

            m_gateway->addAuthenticatedRoute(*m_server,
                                             Method::Post,
                                             "/stateless",
                                             [](std::shared_ptr<const remoted::auth::AuthenticatedRequest>,
                                                std::shared_ptr<IHttpResponder> responder)
                                             { responder->send(HttpResponse::json(200, R"({"handled":true})")); });

            HttpServerConfig config;
            config.port = m_port;
            config.certificatePath = m_cert->certPath;
            config.privateKeyPath = m_cert->keyPath;
            config.globalPrefix = rawPrefix;
            ASSERT_NO_THROW(m_server->start(config));
        }

        void TearDown() override
        {
            if (m_server)
            {
                m_server->stop();
            }
        }

        std::uint16_t m_port {0};
        std::shared_ptr<IHttpServer> m_server;
        std::unique_ptr<AuthGateway> m_gateway;
        std::optional<remoted::test::TestCertificate> m_cert;
        std::unique_ptr<remoted::test::ScratchFileCleanup> m_cleanup;
    };
} // namespace

TEST_F(GlobalPrefixE2ETest, AuthenticatedRequestToThePrefixedTargetSucceeds)
{
    startServer("/wazuh-manager/");

    // The feature's load-bearing contract: the agent sends the full prefixed target, which is what
    // the router matches -- and authentication passes on the bearer alone.
    const auto key = remoted::test::testAgentKey();
    const auto response = remoted::test::sendSignedRequest(m_port, key, "/wazuh-manager/stateless", R"({"events":[]})");
    EXPECT_EQ(statusOf(response), 200) << response;
}

TEST_F(GlobalPrefixE2ETest, TheBearerDoesNotBindTheTargetOrTheQueryString)
{
    startServer("/wazuh-manager/");

    // A documented, deliberate property of the profile: the token authenticates identity only, so one
    // token is valid for any target the router accepts -- prefix and query string included. The
    // target is purely a routing matter (an unprefixed target is a 404, see below).
    const auto key = remoted::test::testAgentKey();
    const auto plain = remoted::test::sendSignedRequest(m_port, key, "/wazuh-manager/stateless", R"({"events":[]})");
    EXPECT_EQ(statusOf(plain), 200) << plain;
    const auto withQuery =
        remoted::test::sendSignedRequest(m_port, key, "/wazuh-manager/stateless?x=1", R"({"events":[]})");
    EXPECT_EQ(statusOf(withQuery), 200) << withQuery;
}

TEST_F(GlobalPrefixE2ETest, UnprefixedRequestNeverReachesAuth)
{
    startServer("/wazuh-manager/");

    // A valid bearer, but the unprefixed route does not exist: 404 from the router's non-matched
    // handler, not a 401 -- auth never ran. Also the symptom of an agent/manager prefix mismatch.
    const auto key = remoted::test::testAgentKey();
    const auto response = remoted::test::sendSignedRequest(m_port, key, "/stateless", R"({"events":[]})");
    EXPECT_EQ(statusOf(response), 404) << response;
}

TEST_F(GlobalPrefixE2ETest, ADifferentPrefixCarriesTheSameContract)
{
    startServer("/edge/wazuh-5");

    const auto key = remoted::test::testAgentKey();
    const auto good = remoted::test::sendSignedRequest(m_port, key, "/edge/wazuh-5/stateless", R"({"events":[]})");
    EXPECT_EQ(statusOf(good), 200) << good;

    // The default prefix is not routed on this server: 404 from the router, auth never runs.
    const auto other = remoted::test::sendSignedRequest(m_port, key, "/wazuh-manager/stateless", R"({"events":[]})");
    EXPECT_EQ(statusOf(other), 404) << other;
}

TEST_F(GlobalPrefixE2ETest, IdentityPrefixKeepsTodaysContract)
{
    startServer("/");

    const auto key = remoted::test::testAgentKey();
    const auto response = remoted::test::sendSignedRequest(m_port, key, "/stateless", R"({"events":[]})");
    EXPECT_EQ(statusOf(response), 200) << response;
}
