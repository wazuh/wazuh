/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * August 21, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// SPIKE (issue #38491, global endpoint prefix -- plan E0): pins the matching semantics of
// RESTinio's express_router_t for PREFIXED literal routes, which the repo cannot establish by
// reading (RESTinio is fetched by `make deps`, not vendored). No product code is exercised
// beyond the current addRoute/start API: routes are registered at literally-prefixed paths.
//
// The assertions below record OBSERVED router behavior, not a feature contract: the global
// prefix feature (plan E1) only concatenates `prefix + path` at registration time, so whatever
// this suite pins is exactly what the feature inherits. Cases marked [hypothesis] started as
// path2regex-default guesses (sensitive=false, strict=false, no percent-decoding before match)
// and were corrected to the observed result if the run disagreed.

#include "http_server/IHttpServer.hpp"
#include "http_server/httpServerFactory.hpp"

#include "testTlsServer.hpp"

#include <gtest/gtest.h>

#include <asio/connect.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/ssl.hpp>
#include <asio/write.hpp>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

using namespace remoted::http;

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

    // Raw TLS exchange: writes an unauthenticated request verbatim (the spike routes bypass the
    // auth gateway on purpose -- routing is what is being measured) and reads until the server
    // closes. Returns the whole response; empty when the exchange failed.
    std::string sendRaw(std::uint16_t port, const std::string& method, const std::string& target)
    {
        std::string received;
        try
        {
            asio::io_context ioc;
            asio::ssl::context sslContext {asio::ssl::context::tls_client};
            sslContext.set_verify_mode(asio::ssl::verify_none);

            asio::ssl::stream<asio::ip::tcp::socket> stream {ioc, sslContext};
            asio::ip::tcp::resolver resolver {ioc};
            asio::connect(stream.next_layer(), resolver.resolve("127.0.0.1", std::to_string(port)));
            stream.handshake(asio::ssl::stream_base::client);

            std::string request = method + " " + target + " HTTP/1.1\r\n";
            request += "Host: 127.0.0.1\r\n";
            request += "Content-Length: 0\r\n";
            request += "Connection: close\r\n\r\n";
            asio::write(stream, asio::buffer(request));

            std::vector<char> buffer(16 * 1024);
            while (true)
            {
                asio::error_code ec;
                const auto n = stream.read_some(asio::buffer(buffer), ec);
                if (ec)
                {
                    break;
                }
                received.append(buffer.data(), n);
            }
        }
        catch (const std::exception&)
        {
        }
        return received;
    }

    int statusOf(const std::string& rawResponse)
    {
        // "HTTP/1.1 NNN ..."
        const auto space = rawResponse.find(' ');
        if (space == std::string::npos || space + 4 > rawResponse.size())
        {
            return 0;
        }
        return std::atoi(rawResponse.c_str() + space + 1);
    }

    // One server, routes registered at LITERALLY prefixed paths via the current API.
    class RouterSemanticsSpike : public ::testing::Test
    {
    protected:
        void SetUp() override
        {
            if (std::system("openssl version >/dev/null 2>&1") != 0)
            {
                GTEST_SKIP() << "openssl not available to generate the test certificate";
            }
            auto cert = remoted::test::generateTestCertificate("router_spike");
            if (!cert)
            {
                GTEST_SKIP() << "could not generate a throwaway TLS certificate";
            }
            m_cleanup = std::make_unique<remoted::test::ScratchFileCleanup>(
                std::vector<std::string> {cert->certPath, cert->keyPath});

            m_port = findFreePort();
            ASSERT_NE(m_port, 0);

            m_server = makeHttpServer();
            // The health-probe shape: prefix + "/".
            m_server->addRoute(Method::Get,
                               "/p/",
                               [](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> r)
                               { r->send(HttpResponse::json(200, R"({"probe":"root"})")); });
            // The alternative health-probe registration: bare prefix, NO trailing slash. S9
            // measures whether this single pattern answers both "/q" and "/q/".
            m_server->addRoute(Method::Get,
                               "/q",
                               [](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> r)
                               { r->send(HttpResponse::json(200, R"({"probe":"bare"})")); });
            // Echoes the raw target the handler observed, so assertions can see exactly what the
            // transport delivered.
            m_server->addRoute(Method::Post,
                               "/p/stateless",
                               [](std::shared_ptr<const HttpRequest> request, std::shared_ptr<IHttpResponder> r)
                               { r->send(HttpResponse::json(200, request->target)); });

            HttpServerConfig config;
            config.port = m_port;
            config.certificatePath = cert->certPath;
            config.privateKeyPath = cert->keyPath;
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
        std::unique_ptr<remoted::test::ScratchFileCleanup> m_cleanup;
    };
} // namespace

TEST_F(RouterSemanticsSpike, S1_ExactRegisteredPathMatches)
{
    EXPECT_EQ(statusOf(sendRaw(m_port, "GET", "/p/")), 200);
}

TEST_F(RouterSemanticsSpike, S2_PatternWithTrailingSlashDoesNotMatchBarePath)
{
    // OBSERVED 2026-08-21 (hypothesis "strict=false makes /p match /p/" REFUTED): a pattern
    // registered WITH a trailing slash ("/p/") does NOT match the bare "/p". The trailing-slash
    // tolerance is one-directional: see S8 (pattern without slash DOES match path+slash) and S9.
    const auto raw = sendRaw(m_port, "GET", "/p");
    EXPECT_EQ(statusOf(raw), 404) << "observed: " << raw.substr(0, raw.find("\r\n"));
}

TEST_F(RouterSemanticsSpike, S2b_QueryAfterBarePrefix)
{
    // Same boundary through a query string: "GET /p?x=1" -- same one-directional rule as S2.
    const auto raw = sendRaw(m_port, "GET", "/p?x=1");
    EXPECT_EQ(statusOf(raw), 404) << "observed: " << raw.substr(0, raw.find("\r\n"));
}

TEST_F(RouterSemanticsSpike, S9_BarePatternMatchesBothSpellings)
{
    // The registration shape plan E1 should use for the "/" health route under a prefix:
    // registering the BARE pattern ("/q", no trailing slash) answers both spellings.
    EXPECT_EQ(statusOf(sendRaw(m_port, "GET", "/q")), 200);
    EXPECT_EQ(statusOf(sendRaw(m_port, "GET", "/q/")), 200);
    EXPECT_EQ(statusOf(sendRaw(m_port, "GET", "/q?x=1")), 200);
}

TEST_F(RouterSemanticsSpike, S3_CaseInsensitiveMatch)
{
    // [hypothesis: sensitive=false] "/P/" should match "/p/".
    const auto raw = sendRaw(m_port, "GET", "/P/");
    EXPECT_EQ(statusOf(raw), 200) << "observed: " << raw.substr(0, raw.find("\r\n"));
}

TEST_F(RouterSemanticsSpike, S4_EmptySegmentDoesNotMatch)
{
    EXPECT_EQ(statusOf(sendRaw(m_port, "POST", "/p//stateless")), 404);
}

TEST_F(RouterSemanticsSpike, S5_PercentEncodedSlashDoesNotMatch)
{
    // [hypothesis: no percent-decoding before matching]
    const auto raw = sendRaw(m_port, "POST", "/p%2Fstateless");
    EXPECT_EQ(statusOf(raw), 404) << "observed: " << raw.substr(0, raw.find("\r\n"));
}

TEST_F(RouterSemanticsSpike, S10_PercentDecodedOrdinaryByteMatches)
{
    // OBSERVED 2026-08-22 (discovered by GlobalPrefixTransportTest, not part of the original
    // matrix): the router percent-DECODES ordinary bytes before matching ("%6C" == 'l'), unlike
    // the encoded slash of S5. The raw (encoded) target is what handlers/auth observe.
    const auto raw = sendRaw(m_port, "POST", "/p/state%6Cess");
    EXPECT_EQ(statusOf(raw), 200) << "observed: " << raw.substr(0, raw.find("\r\n"));
    EXPECT_NE(raw.find("/p/state%6Cess"), std::string::npos) << raw;
}

TEST_F(RouterSemanticsSpike, S6_UnprefixedPathIs404)
{
    EXPECT_EQ(statusOf(sendRaw(m_port, "POST", "/stateless")), 404);
}

TEST_F(RouterSemanticsSpike, S7_QueryExcludedFromMatchButPresentInTarget)
{
    const auto raw = sendRaw(m_port, "POST", "/p/stateless?x=1");
    EXPECT_EQ(statusOf(raw), 200);
    // The handler echoed request->target: the raw target, query included.
    EXPECT_NE(raw.find("/p/stateless?x=1"), std::string::npos) << raw;
}

TEST_F(RouterSemanticsSpike, S8_TrailingSlashOnNonSlashRoute)
{
    // [hypothesis: strict=false] "/p/stateless/" should match "/p/stateless", raw target kept.
    const auto raw = sendRaw(m_port, "POST", "/p/stateless/");
    EXPECT_EQ(statusOf(raw), 200) << "observed: " << raw.substr(0, raw.find("\r\n"));
    if (statusOf(raw) == 200)
    {
        EXPECT_NE(raw.find("/p/stateless/"), std::string::npos) << raw;
    }
}
