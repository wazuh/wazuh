/*
 * Wazuh remoted module - GET /cacerts end-to-end test
 * Copyright (C) 2015, Wazuh Inc.
 * September 7, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Drives a REAL TLS RestinioHttpServer with /cacerts registered exactly as RemotedModuleFacade
 * wires it (no gateway, budget-exempt, the status read through the server) and a leaf signed by a
 * throwaway CA, to pin the property the route exists for: the PEM it hands out is the CA the
 * listener chains to -- a client that trusts ONLY that PEM completes a verifying handshake against
 * the same listener. Plus the two negatives the handler alone cannot prove: the global prefix is
 * applied like on every other route, and a CA that does not sign the served leaf is refused (503)
 * by the real start-time evaluation, not a faked status.
 */

#include "endpoints/cacertsEndpoint.hpp"
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
#include <fstream>
#include <iterator>
#include <memory>
#include <optional>
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
            sockaddr_in bound {};
            socklen_t length = sizeof(bound);
            if (::getsockname(probe, reinterpret_cast<sockaddr*>(&bound), &length) == 0)
            {
                port = ntohs(bound.sin_port);
            }
        }
        ::close(probe);
        return port;
    }

    int statusOf(const std::string& rawResponse)
    {
        const auto space = rawResponse.find(' ');
        if (space == std::string::npos)
        {
            return -1;
        }
        return std::atoi(rawResponse.c_str() + space + 1);
    }

    std::string readFile(const std::string& path)
    {
        std::ifstream file {path, std::ios::binary};
        return std::string {std::istreambuf_iterator<char> {file}, std::istreambuf_iterator<char> {}};
    }

    class CacertsE2ETest : public ::testing::Test
    {
    protected:
        void SetUp() override
        {
            if (std::system("openssl version >/dev/null 2>&1") != 0)
            {
                GTEST_SKIP() << "openssl not available to generate the test certificates";
            }
            m_pki = remoted::test::generateCaSignedCertificate("cacerts_e2e");
            m_foreignCa = remoted::test::generateTestCertificate("cacerts_e2e_foreign");
            if (!m_pki || !m_foreignCa)
            {
                GTEST_SKIP() << "could not generate the throwaway CA-signed certificate";
            }
            auto files = m_pki->files();
            files.push_back(m_foreignCa->certPath);
            files.push_back(m_foreignCa->keyPath);
            m_cleanup = std::make_unique<remoted::test::ScratchFileCleanup>(std::move(files));
        }

        // The facade's wiring slice: GET / and GET /cacerts, both raw routes, both budget-exempt,
        // the status read through the server the route belongs to.
        void startServer(const std::string& rawPrefix, const std::string& caCertificatePath)
        {
            m_port = findFreePort();
            ASSERT_NE(m_port, 0);

            m_server = makeHttpServer();
            m_server->addRoute(
                Method::Get,
                "/",
                [](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> responder)
                { responder->send(HttpResponse::json(200, R"({"status":"ok","module":"remoted"})")); },
                /*countAgainstBudget=*/false);
            // Same slice as the facade: the CA the transport publishes comes from the transport
            // itself, so the bytes and the verdict cannot disagree (issue #39078).
            m_server->addRoute(Method::Get,
                               "/cacerts",
                               remoted::endpoints::cacerts::makeHandler(
                                   [weak = std::weak_ptr<IHttpServer>(m_server)]() -> CaCertificateSnapshot
                                   {
                                       if (const auto server = weak.lock())
                                       {
                                           return server->caCertificateSnapshot();
                                       }
                                       return {};
                                   },
                                   remoted::endpoints::cacerts::CacertsMetrics {},
                                   nullptr),
                               /*countAgainstBudget=*/false);

            HttpServerConfig config;
            config.port = m_port;
            config.certificatePath = m_pki->certPath;
            config.privateKeyPath = m_pki->keyPath;
            config.caCertificatePath = caCertificatePath;
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
        std::optional<remoted::test::TestCaSignedCertificate> m_pki;
        std::optional<remoted::test::TestCertificate> m_foreignCa;
        std::unique_ptr<remoted::test::ScratchFileCleanup> m_cleanup;
    };
} // namespace

TEST_F(CacertsE2ETest, ServesTheCaTheListenerChainsTo)
{
    startServer("", m_pki->caCertPath);

    const auto response = remoted::test::sendGetRequest(m_port, "/cacerts");
    ASSERT_EQ(statusOf(response), 200) << response;
    const auto [head, body] = remoted::test::splitResponse(response);
    EXPECT_NE(head.find("Content-Type: application/x-pem-file"), std::string::npos) << head;
    EXPECT_EQ(body, readFile(m_pki->caCertPath)); // the file, byte for byte

    // The property (design §2.3): a client that trusts ONLY what /cacerts handed out verifies this
    // very listener's certificate -- the served CA really is the one the leaf chains to.
    const auto verified = remoted::test::sendGetRequestVerifying(m_port, "/", body);
    EXPECT_EQ(statusOf(verified), 200) << "verifying handshake failed against the served CA: " << verified;

    // Control: trusting an unrelated CA instead fails the handshake (empty response).
    const auto rejected = remoted::test::sendGetRequestVerifying(m_port, "/", readFile(m_foreignCa->certPath));
    EXPECT_TRUE(rejected.empty()) << rejected;

    const auto status = m_server->certificateStatus();
    EXPECT_EQ(status.caMatchesLeaf, true);
    EXPECT_EQ(status.evaluations, 1U);
}

TEST_F(CacertsE2ETest, UnderTheGlobalPrefixOnlyThePrefixedTargetAnswers)
{
    startServer("/wazuh-manager", m_pki->caCertPath);

    const auto prefixed = remoted::test::sendGetRequest(m_port, "/wazuh-manager/cacerts");
    EXPECT_EQ(statusOf(prefixed), 200) << prefixed;
    EXPECT_EQ(remoted::test::splitResponse(prefixed).second, readFile(m_pki->caCertPath));

    // The transport's routing, same as every other route: the bare path is a 404 from the router's
    // non-matched handler -- the same body the handler itself uses for a missing file, so an agent
    // cannot tell the two apart (and does not need to: neither is a CA it can use).
    const auto bare = remoted::test::sendGetRequest(m_port, "/cacerts");
    EXPECT_EQ(statusOf(bare), 404) << bare;
    EXPECT_EQ(remoted::test::splitResponse(bare).second, R"({"error":"not_found"})");
}

TEST_F(CacertsE2ETest, ForeignCaAnswers503)
{
    // The configured CA is readable and a perfectly good CA -- just not the one that signed the
    // leaf this listener serves. The REAL start-time evaluation must catch it.
    startServer("", m_foreignCa->certPath);

    const auto status = m_server->certificateStatus();
    EXPECT_EQ(status.caMatchesLeaf, false);
    EXPECT_EQ(status.evaluations, 1U);

    const auto response = remoted::test::sendGetRequest(m_port, "/cacerts");
    EXPECT_EQ(statusOf(response), 503) << response;
    const auto [head, body] = remoted::test::splitResponse(response);
    EXPECT_EQ(body, R"({"error":"ca_mismatch"})");
    EXPECT_NE(head.find("Content-Type: application/json"), std::string::npos) << head;

    // Everything else on the listener is unaffected: the leaf is still served over TLS.
    EXPECT_EQ(statusOf(remoted::test::sendGetRequest(m_port, "/")), 200);
}

TEST_F(CacertsE2ETest, MissingCaAnswers404WithoutARestart)
{
    startServer("", m_pki->caCertPath);
    ASSERT_EQ(statusOf(remoted::test::sendGetRequest(m_port, "/cacerts")), 200);

    // The file is read per request: moving the CA away is a 404 immediately, no tick or restart
    // needed (the sandbox matrix's "CA moved away" row); putting it back serves again.
    const auto moved = m_pki->caCertPath + ".off";
    ASSERT_EQ(std::rename(m_pki->caCertPath.c_str(), moved.c_str()), 0);
    const auto gone = remoted::test::sendGetRequest(m_port, "/cacerts");
    EXPECT_EQ(statusOf(gone), 404) << gone;
    EXPECT_EQ(remoted::test::splitResponse(gone).second, R"({"error":"not_found"})");

    ASSERT_EQ(std::rename(moved.c_str(), m_pki->caCertPath.c_str()), 0);
    EXPECT_EQ(statusOf(remoted::test::sendGetRequest(m_port, "/cacerts")), 200);
}
