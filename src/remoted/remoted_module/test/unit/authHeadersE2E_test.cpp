/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * August 26, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// The bearer-token auth contract as seen ON THE WIRE, through a real RestinioHttpServer over TLS
// (issue #38582): a request that carries `Authorization` or `protocol-version` twice -- identical or
// case-variant spellings -- is rejected instead of "first wins" (the transport collapses the
// duplicate to an empty value, RestinioHttpServer::makeHttpRequest), every 401 carries
// `WWW-Authenticate: Bearer`, and the raw header text an agent puts on the wire authenticates.
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
#include <string>
#include <vector>

using namespace remoted::http;
using namespace remoted::endpoints;

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

    /// Raw POST /stateless with caller-chosen header lines (each already "Name: value").
    std::string rawRequest(const std::vector<std::string>& headerLines, const std::string& body = "{}")
    {
        std::string request = "POST /stateless HTTP/1.1\r\n";
        request += "Host: 127.0.0.1\r\n";
        for (const auto& line : headerLines)
        {
            request += line + "\r\n";
        }
        request += "Content-Length: " + std::to_string(body.size()) + "\r\n";
        request += "Connection: close\r\n\r\n";
        request += body;
        return request;
    }

    class AuthHeadersE2ETest : public ::testing::Test
    {
    protected:
        void SetUp() override
        {
            if (std::system("openssl version >/dev/null 2>&1") != 0)
            {
                GTEST_SKIP() << "openssl not available to generate the test certificate";
            }
            m_cert = remoted::test::generateTestCertificate("auth_headers_e2e");
            if (!m_cert)
            {
                GTEST_SKIP() << "could not generate a throwaway TLS certificate";
            }
            m_cleanup = std::make_unique<remoted::test::ScratchFileCleanup>(
                std::vector<std::string> {m_cert->certPath, m_cert->keyPath});

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
            ASSERT_NO_THROW(m_server->start(config));
        }

        void TearDown() override
        {
            if (m_server)
            {
                m_server->stop();
            }
        }

        std::string bearerLine() const
        {
            return "Authorization: Bearer " + remoted::test::bearerToken(remoted::test::testAgentKey());
        }

        std::uint16_t m_port {0};
        std::shared_ptr<IHttpServer> m_server;
        std::unique_ptr<AuthGateway> m_gateway;
        std::optional<remoted::test::TestCertificate> m_cert;
        std::unique_ptr<remoted::test::ScratchFileCleanup> m_cleanup;
    };
} // namespace

TEST_F(AuthHeadersE2ETest, OneBearerAndOneProtocolVersionAuthenticate)
{
    const auto response = remoted::test::sendRawOverTls(m_port, rawRequest({"protocol-version: 1", bearerLine()}));
    EXPECT_EQ(statusOf(response), 200) << response;
    EXPECT_EQ(response.find("WWW-Authenticate"), std::string::npos) << response;
}

TEST_F(AuthHeadersE2ETest, HeaderNamesAreCaseInsensitiveOnTheWire)
{
    const auto response = remoted::test::sendRawOverTls(
        m_port, rawRequest({"Protocol-Version: 1", "AUTHORIZATION" + bearerLine().substr(13)}));
    EXPECT_EQ(statusOf(response), 200) << response;
}

TEST_F(AuthHeadersE2ETest, DuplicatedAuthorizationIsRejectedEvenWhenBothAreValid)
{
    const auto first = bearerLine();
    const auto second = bearerLine(); // a different, equally valid token
    const auto response = remoted::test::sendRawOverTls(m_port, rawRequest({"protocol-version: 1", first, second}));
    EXPECT_EQ(statusOf(response), 401) << response;
    EXPECT_NE(response.find("WWW-Authenticate: Bearer"), std::string::npos) << response;
}

TEST_F(AuthHeadersE2ETest, CaseVariantDuplicateAuthorizationIsRejected)
{
    // The smuggling shape: a valid credential under one spelling, garbage under another. Neither
    // "first wins" nor "last wins" -- the request is refused.
    const auto response = remoted::test::sendRawOverTls(
        m_port, rawRequest({"protocol-version: 1", bearerLine(), "authorization: Bearer garbage"}));
    EXPECT_EQ(statusOf(response), 401) << response;
    const auto reversed = remoted::test::sendRawOverTls(
        m_port, rawRequest({"protocol-version: 1", "authorization: Bearer garbage", bearerLine()}));
    EXPECT_EQ(statusOf(reversed), 401) << reversed;
}

TEST_F(AuthHeadersE2ETest, DuplicatedProtocolVersionIsRejected)
{
    const auto response =
        remoted::test::sendRawOverTls(m_port, rawRequest({"protocol-version: 1", "Protocol-Version: 1", bearerLine()}));
    EXPECT_EQ(statusOf(response), 400) << response; // read as absent -> missing protocol-version
    EXPECT_EQ(response.find("WWW-Authenticate"), std::string::npos) << response;
}

TEST_F(AuthHeadersE2ETest, DuplicatedOrdinaryHeadersStillPass)
{
    // Only the two credential headers are guarded; other repeated headers keep first-wins.
    const auto response = remoted::test::sendRawOverTls(
        m_port, rawRequest({"protocol-version: 1", bearerLine(), "X-Trace: a", "X-Trace: b"}));
    EXPECT_EQ(statusOf(response), 200) << response;
}

TEST_F(AuthHeadersE2ETest, Every401OnTheWireCarriesTheBearerChallenge)
{
    for (const auto& authorization : std::vector<std::string> {
             "Authorization: Bearer not.a.token",
             "Authorization: Wazuh 7:1784238000:00112233445566778899aabbccddeeff",
             "Authorization: Bearer " + remoted::test::bearerToken(std::vector<std::uint8_t>(32, 0x0C)) // wrong key
         })
    {
        const auto response = remoted::test::sendRawOverTls(m_port, rawRequest({"protocol-version: 1", authorization}));
        EXPECT_EQ(statusOf(response), 401) << response;
        EXPECT_NE(response.find("WWW-Authenticate: Bearer"), std::string::npos) << response;
        // The body never says why.
        EXPECT_NE(response.find(R"({"error":"Invalid client authentication","code":401})"), std::string::npos)
            << response;
    }
    const auto missing = remoted::test::sendRawOverTls(m_port, rawRequest({"protocol-version: 1"}));
    EXPECT_EQ(statusOf(missing), 401) << missing;
    EXPECT_NE(missing.find("WWW-Authenticate: Bearer"), std::string::npos) << missing;
}
