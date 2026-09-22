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
 *
 * The CA file the fixture installs is a STAMPED bundle (issue #39319, D9): the `##` publication
 * block `wazuh-manager-certs` writes, in front of the certificate. That is the shape a rotated
 * manager has on disk, so it is the shape these end-to-end tests run against -- and what the route
 * answers with is still the certificate alone, re-serialised by the process, never the file.
 */

#include "endpoints/cacertsEndpoint.hpp"
#include "http_server/IHttpServer.hpp"
#include "http_server/httpServerFactory.hpp"

#include "ca_bundle/ca_bundle.hpp"

#include "testCertificates.hpp"
#include "testTlsServer.hpp"

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <memory>
#include <optional>
#include <string>
#include <thread>
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

    void writeFile(const std::string& path, const std::string& contents)
    {
        std::ofstream file {path, std::ios::binary | std::ios::trunc};
        file << contents;
    }

    /// The document `wazuh-manager-certs` leaves behind for @p pem's certificates: its block, then
    /// the certificates re-serialised.
    std::string stampedDocument(const std::string& pem, std::int64_t publication)
    {
        const auto certificates = ca_bundle::parseBundle(pem).certificates;
        ca_bundle::PublicationBlock block;
        block.publication = publication;
        block.contentSha256 = ca_bundle::contentSha256(certificates);
        block.updated = "2026-09-18T00:00:00Z";
        block.writtenBy = "cacertsE2E_test";
        return ca_bundle::renderBlock(block) + ca_bundle::serializeCertificates(certificates);
    }

    /// A CA-signed listener PKI built in memory, with the CA's validity window chosen by the test:
    /// what the CLI recipes cannot produce with second granularity.
    struct ShortLivedPki
    {
        std::string caPath;
        std::string certPath;
        std::string keyPath;
        std::string servedCa; ///< The CA alone, re-serialised: what /cacerts must answer.

        std::vector<std::string> files() const
        {
            return {caPath, certPath, keyPath};
        }
    };

    ShortLivedPki makeShortLivedPki(const std::string& prefix, long caNotBeforeSeconds, long caNotAfterSeconds)
    {
        const auto caKey = remoted::test::makeTestKey();
        const auto leafKey = remoted::test::makeTestKey();
        const auto ca = remoted::test::makeCertificate((prefix + "-ca").c_str(),
                                                       caNotBeforeSeconds,
                                                       caNotAfterSeconds,
                                                       caKey.get(),
                                                       caKey.get(),
                                                       nullptr,
                                                       nullptr,
                                                       true);
        const auto leaf = remoted::test::makeCertificate(
            (prefix + "-leaf").c_str(), -60, 3600, leafKey.get(), caKey.get(), ca.get(), "IP:127.0.0.1");

        ShortLivedPki pki;
        const auto base = "/tmp/" + prefix + "_" + std::to_string(::getpid());
        pki.caPath = base + "-ca.pem";
        pki.certPath = base + "-leaf.pem";
        pki.keyPath = base + "-key.pem";
        remoted::test::writePemFile(pki.certPath, {leaf.get()});
        EXPECT_TRUE(remoted::test::writePemKey(pki.keyPath, leafKey.get()));
        remoted::test::writePemFile(pki.caPath, {ca.get()});
        pki.servedCa = ca_bundle::serializeCertificates(ca_bundle::parseBundle(readFile(pki.caPath)).certificates);
        return pki;
    }

    /// Polls `GET /cacerts` until it answers @p wanted or @p maxWait elapses; the last response.
    std::string waitForCacertsStatus(std::uint16_t port, int wanted, std::chrono::seconds maxWait)
    {
        const auto deadline = std::chrono::steady_clock::now() + maxWait;
        std::string response;
        do
        {
            response = remoted::test::sendGetRequest(port, "/cacerts");
            if (statusOf(response) == wanted)
            {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds {200});
        } while (std::chrono::steady_clock::now() < deadline);
        return response;
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

            // Stamp the CA file the way the tool does (D9): the block, then the certificate it
            // describes. `##` lines are comments to every PEM reader, so nothing downstream --
            // OpenSSL's trust store, the source, the route -- changes shape because of them.
            const std::string caPath = m_pki->caCertPath;
            const auto certificates = ca_bundle::parseBundle(readFile(caPath)).certificates;
            if (certificates.size() != 1)
            {
                GTEST_SKIP() << "the throwaway CA file did not yield exactly one certificate";
            }

            m_servedCa = ca_bundle::serializeCertificates(certificates);
            ca_bundle::PublicationBlock block;
            m_publication = 1789000000;
            block.publication = m_publication;
            block.contentSha256 = ca_bundle::contentSha256(certificates);
            block.updated = "2026-09-18T00:00:00Z";
            block.writtenBy = "cacertsE2E_test";
            m_caFileContents = ca_bundle::renderBlock(block) + m_servedCa;

            std::ofstream stamped {caPath, std::ios::binary | std::ios::trunc};
            stamped << m_caFileContents;
            stamped.close();
            ASSERT_FALSE(stamped.fail()) << "cannot stamp " << caPath;
        }

        // The facade's wiring slice: GET / and GET /cacerts, both raw routes, both budget-exempt,
        // the status read through the server the route belongs to.
        void startServer(const std::string& rawPrefix, const std::string& caCertificatePath)
        {
            startServerWith(rawPrefix, m_pki->certPath, m_pki->keyPath, caCertificatePath);
        }

        void startServerWith(const std::string& rawPrefix,
                             const std::string& certificatePath,
                             const std::string& privateKeyPath,
                             const std::string& caCertificatePath)
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
            config.certificatePath = certificatePath;
            config.privateKeyPath = privateKeyPath;
            config.caCertificatePath = caCertificatePath;
            config.globalPrefix = rawPrefix;
            // The publication record is not under test here: the default path would point at a
            // var/run directory that does not exist in the build's cwd and warn once per server
            // (paso 7, addendum). CaCertificateSourceRecord covers the record itself.
            config.caPublicationRecordPath = "";
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
        std::string m_servedCa;         ///< The certificate alone, re-serialised: what /cacerts must answer.
        std::string m_caFileContents;   ///< The stamped file on disk: the block plus that certificate.
        std::int64_t m_publication {0}; ///< The block's publication SetUp() stamped the file with.
    };
} // namespace

TEST_F(CacertsE2ETest, ServesTheCaTheListenerChainsTo)
{
    startServer("", m_pki->caCertPath);

    const auto response = remoted::test::sendGetRequest(m_port, "/cacerts");
    ASSERT_EQ(statusOf(response), 200) << response;
    const auto [head, body] = remoted::test::splitResponse(response);
    EXPECT_NE(head.find("Content-Type: application/x-pem-file"), std::string::npos) << head;

    // The real transport puts the generation the fixture stamped the file with on the wire (issue
    // #39319, RF-4), the same value the block above carries -- not a hash of anything.
    EXPECT_NE(head.find("Wazuh-CA-Generation: " + std::to_string(m_publication)), std::string::npos) << head;

    // The file carries the publication block; what the route hands out is the certificate this
    // process re-serialised out of it, with no `##` line in sight (D9).
    ASSERT_NE(m_caFileContents.find("## Wazuh CA bundle"), std::string::npos);
    EXPECT_EQ(body, m_servedCa);
    EXPECT_EQ(body.find("##"), std::string::npos);

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
    EXPECT_EQ(remoted::test::splitResponse(prefixed).second, m_servedCa);

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

TEST_F(CacertsE2ETest, MissingCaKeepsServingThePreviousSnapshot)
{
    startServer("", m_pki->caCertPath);
    const auto first = remoted::test::sendGetRequest(m_port, "/cacerts");
    ASSERT_EQ(statusOf(first), 200) << first;
    const auto firstBody = remoted::test::splitResponse(first).second;

    // The file is read per request, but a failed read is a window, not a decision (issue
    // #39318): moving the CA away keeps the last good snapshot being served, no tick or restart
    // needed -- not a 404, which is what would strand every agent until the file came back.
    const auto moved = m_pki->caCertPath + ".off";
    ASSERT_EQ(std::rename(m_pki->caCertPath.c_str(), moved.c_str()), 0);
    const auto stillServed = remoted::test::sendGetRequest(m_port, "/cacerts");
    ASSERT_EQ(statusOf(stillServed), 200) << stillServed;
    EXPECT_EQ(remoted::test::splitResponse(stillServed).second, firstBody);

    ASSERT_EQ(std::rename(moved.c_str(), m_pki->caCertPath.c_str()), 0);
    EXPECT_EQ(statusOf(remoted::test::sendGetRequest(m_port, "/cacerts")), 200);
}

TEST_F(CacertsE2ETest, AnEmptiedCaAnswers404WithoutARestart)
{
    startServer("", m_pki->caCertPath);
    ASSERT_EQ(statusOf(remoted::test::sendGetRequest(m_port, "/cacerts")), 200);

    // Unlike a failed read, a readable file with nothing in it is the operator's way of saying
    // "stop serving" -- it takes effect at once, no restart needed.
    {
        std::ofstream truncate {m_pki->caCertPath, std::ios::binary | std::ios::trunc};
    }
    const auto emptied = remoted::test::sendGetRequest(m_port, "/cacerts");
    EXPECT_EQ(statusOf(emptied), 404) << emptied;
    EXPECT_EQ(remoted::test::splitResponse(emptied).second, R"({"error":"not_found"})");

    // Restored to the stamped bytes SetUp() wrote, block included.
    std::ofstream restore {m_pki->caCertPath, std::ios::binary | std::ios::trunc};
    restore << m_caFileContents;
    restore.close();
    EXPECT_EQ(statusOf(remoted::test::sendGetRequest(m_port, "/cacerts")), 200);
}

TEST_F(CacertsE2ETest, ACaThatExpiresInPlaceStopsBeingServedWithoutATouch)
{
    // A stamped CA with eight seconds left signs the leaf this listener serves, and the file is
    // never written again: the 200 has to become the 503 on the clock alone. Eight, not three: the
    // first request has to land inside the window under valgrind as well.
    const auto pki = makeShortLivedPki("cacerts_e2e_expiring", -60, 8);
    remoted::test::ScratchFileCleanup cleanup {pki.files()};
    const auto stamped = stampedDocument(readFile(pki.caPath), 1789000000);
    writeFile(pki.caPath, stamped);
    struct stat before {};
    ASSERT_EQ(::stat(pki.caPath.c_str(), &before), 0);

    startServerWith("", pki.certPath, pki.keyPath, pki.caPath);

    const auto first = remoted::test::sendGetRequest(m_port, "/cacerts");
    ASSERT_EQ(statusOf(first), 200) << first;
    const auto [firstHead, firstBody] = remoted::test::splitResponse(first);
    EXPECT_NE(firstHead.find("Wazuh-CA-Generation: 1789000000"), std::string::npos) << firstHead;
    EXPECT_EQ(firstBody, pki.servedCa);
    EXPECT_EQ(m_server->certificateStatus().caMatchesLeaf, true);

    const auto refused = waitForCacertsStatus(m_port, 503, std::chrono::seconds {20});
    ASSERT_EQ(statusOf(refused), 503) << refused;
    EXPECT_EQ(remoted::test::splitResponse(refused).second, R"({"error":"ca_mismatch"})");
    EXPECT_EQ(m_server->certificateStatus().caMatchesLeaf, false);

    // The file is exactly what it was: same bytes, same mtime. Only the clock moved.
    struct stat after {};
    ASSERT_EQ(::stat(pki.caPath.c_str(), &after), 0);
    EXPECT_EQ(before.st_mtime, after.st_mtime);
    EXPECT_EQ(readFile(pki.caPath), stamped);

    // Everything else on the listener is unaffected: the leaf is still served over TLS.
    EXPECT_EQ(statusOf(remoted::test::sendGetRequest(m_port, "/")), 200);
}

TEST_F(CacertsE2ETest, APreStagedCaStartsBeingServedAtItsNotBefore)
{
    // The rotation's step 1 with a CA whose window has not opened yet: refused and announced as 0
    // until its notBefore, served and published from then on -- with nobody touching the file.
    const auto pki = makeShortLivedPki("cacerts_e2e_prestaged", 8, 3600);
    remoted::test::ScratchFileCleanup cleanup {pki.files()};
    const auto stamped = stampedDocument(readFile(pki.caPath), 1789000000);
    writeFile(pki.caPath, stamped);
    struct stat before {};
    ASSERT_EQ(::stat(pki.caPath.c_str(), &before), 0);

    startServerWith("", pki.certPath, pki.keyPath, pki.caPath);

    const auto first = remoted::test::sendGetRequest(m_port, "/cacerts");
    ASSERT_EQ(statusOf(first), 503) << first;
    EXPECT_EQ(remoted::test::splitResponse(first).second, R"({"error":"ca_mismatch"})");
    EXPECT_EQ(m_server->certificateStatus().caMatchesLeaf, false);

    const auto served = waitForCacertsStatus(m_port, 200, std::chrono::seconds {20});
    ASSERT_EQ(statusOf(served), 200) << served;
    const auto [head, body] = remoted::test::splitResponse(served);
    EXPECT_NE(head.find("Wazuh-CA-Generation: 1789000000"), std::string::npos) << head;
    EXPECT_EQ(body, pki.servedCa);
    EXPECT_EQ(m_server->certificateStatus().caMatchesLeaf, true);

    struct stat after {};
    ASSERT_EQ(::stat(pki.caPath.c_str(), &after), 0);
    EXPECT_EQ(before.st_mtime, after.st_mtime);
    EXPECT_EQ(readFile(pki.caPath), stamped);
}
