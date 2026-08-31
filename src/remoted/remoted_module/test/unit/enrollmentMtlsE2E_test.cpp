/*
 * Wazuh remoted module - POST /enroll mTLS end-to-end test
 * Copyright (C) 2015, Wazuh Inc.
 * August 19, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Drives a REAL RestinioHttpServer (via makeHttpServer()) with /enroll registered exactly as
 * RemotedModuleFacade::startHttpServer() wires it. EnrollmentAuthenticator has no notion of a
 * client certificate at all -- that's enforced entirely by the TLS listener's own verificationMode,
 * independently of whatever EnrollmentAuthConfig::requirePassword says (see the class comment in
 * enrollmentAuthenticator.hpp for why these two are deliberately independent, not a mutually
 * exclusive "mode"). What this test proves is the piece nothing else covers: that a real TLS
 * listener configured the way the facade configures it actually gates /enroll on a client
 * certificate before the handler ever runs -- plus, in the last test below, that a listener
 * configured to require BOTH a client certificate AND a password enforces both simultaneously.
 */

#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <optional>
#include <string>
#include <unistd.h>

#include <asio/connect.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/ssl.hpp>
#include <asio/write.hpp>

#include <gtest/gtest.h>

#include <chrono>

#include "auth/authTypes.hpp" // remoted::auth::kSupportedProtocolVersion
#include "decoding/iBodyDecoder.hpp"
#include "enrollment/enrollmentEndpoint.hpp"
#include "fakeUdsServer.hpp"
#include "http_server/httpServerFactory.hpp"
#include "jwt/jwtEnrollTokenSigner.hpp"

#include <wazuh_metrics/manager.hpp>

using namespace remoted::enrollment;
using remoted::auth::PasswordKeySource;
using remoted::decoding::ContentEncoding;
using remoted::decoding::IBodyDecoder;
using remoted::http::ClientVerificationMode;
using remoted::http::HttpServerConfig;
using remoted::http::Method;
using remoted::test::FakeUdsServer;
using remoted::test::makeUniqueSocketPath;

namespace
{
    // Inert stand-in for the real BodyDecoder (see enrollmentEndpoint_test.cpp's identical stub):
    // this test is about the TLS listener's own client-certificate gate, not Content-Encoding.
    class PassthroughBodyDecoder final : public IBodyDecoder
    {
    public:
        remoted::auth::AuthError decode(ContentEncoding, remoted::auth::Payload&) const override
        {
            return remoted::auth::AuthError::None;
        }
    };

    std::shared_ptr<const IBodyDecoder> passthroughDecoder()
    {
        return std::make_shared<const PassthroughBodyDecoder>();
    }

    struct MtlsPki
    {
        std::string dir;
        std::string caCert, caKey;
        std::string serverCert, serverKey;
        std::string clientCert, clientKey;
    };

    bool runQuiet(const std::string& command)
    {
        return std::system((command + " >/dev/null 2>&1").c_str()) == 0;
    }

    // Minimal CA + one server cert + one client cert, all signed by the same throwaway CA. No SAN
    // extension is needed for either: ClientVerificationMode::Certificate (unlike ::Full) never
    // checks a SAN against the peer address, and the test client never verifies the server's cert
    // at all (set_verify_mode(verify_none) below), matching this file's siblings' convention.
    std::optional<MtlsPki> generateMtlsPki()
    {
        char dirTemplate[] = "/tmp/enrollmentMtlsE2EXXXXXX";
        const char* dir = ::mkdtemp(dirTemplate);
        if (!dir)
        {
            return std::nullopt;
        }

        MtlsPki pki;
        pki.dir = dir;
        pki.caCert = pki.dir + "/ca.crt";
        pki.caKey = pki.dir + "/ca.key";
        pki.serverCert = pki.dir + "/server.crt";
        pki.serverKey = pki.dir + "/server.key";
        pki.clientCert = pki.dir + "/client.crt";
        pki.clientKey = pki.dir + "/client.key";

        if (!runQuiet("openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=test-ca -keyout " + pki.caKey +
                      " -out " + pki.caCert))
        {
            return std::nullopt;
        }

        auto issue = [&](const std::string& commonName, const std::string& keyOut, const std::string& certOut) -> bool
        {
            const std::string csr = pki.dir + "/" + commonName + ".csr";
            if (!runQuiet("openssl req -newkey rsa:2048 -nodes -subj /CN=" + commonName + " -keyout " + keyOut +
                          " -out " + csr))
            {
                return false;
            }
            const bool ok = runQuiet("openssl x509 -req -in " + csr + " -days 1 -CA " + pki.caCert + " -CAkey " +
                                     pki.caKey + " -CAcreateserial -out " + certOut);
            std::remove(csr.c_str());
            return ok;
        };

        if (!issue("test-server", pki.serverKey, pki.serverCert) ||
            !issue("test-client", pki.clientKey, pki.clientCert))
        {
            return std::nullopt;
        }

        return pki;
    }

    void cleanupMtlsPki(const MtlsPki& pki)
    {
        for (const auto& path : {pki.caCert, pki.caKey, pki.serverCert, pki.serverKey, pki.clientCert, pki.clientKey})
        {
            std::remove(path.c_str());
        }
        std::remove((pki.dir + "/ca.srl").c_str());
        ::rmdir(pki.dir.c_str());
    }

    // Sends one POST /enroll, optionally carrying the wazuh-enroll+jwt bearer when requirePassword is
    // set (authorizationHeader empty otherwise), and reads the response until the server closes.
    // clientCert/clientKey null means "present no client certificate at all", to exercise the
    // listener's own rejection.
    std::string sendEnrollRequest(std::uint16_t port,
                                  const std::string& body,
                                  const std::string* clientCert,
                                  const std::string* clientKey,
                                  const std::string& authorizationHeader = {})
    {
        std::string received;
        try
        {
            asio::io_context ioc;
            asio::ssl::context sslContext {asio::ssl::context::tls_client};
            sslContext.set_verify_mode(asio::ssl::verify_none); // this test doesn't care about server identity
            if (clientCert && clientKey)
            {
                sslContext.use_certificate_file(*clientCert, asio::ssl::context::pem);
                sslContext.use_private_key_file(*clientKey, asio::ssl::context::pem);
            }

            asio::ssl::stream<asio::ip::tcp::socket> stream {ioc, sslContext};
            asio::ip::tcp::resolver resolver {ioc};
            const auto endpoints = resolver.resolve("127.0.0.1", std::to_string(port));
            asio::connect(stream.next_layer(), endpoints);
            stream.handshake(asio::ssl::stream_base::client); // throws if the server rejects us

            std::string request = "POST /enroll HTTP/1.1\r\n";
            request += "Host: 127.0.0.1\r\n";
            request += "Content-Type: application/json\r\n";
            // Required on /enroll like on every other authenticated route; without it the endpoint
            // answers 400 before reaching the mTLS behavior these tests are about.
            request += "protocol-version: " + std::string {remoted::auth::kSupportedProtocolVersion} + "\r\n";
            if (!authorizationHeader.empty())
            {
                request += "Authorization: " + authorizationHeader + "\r\n";
            }
            request += "Content-Length: " + std::to_string(body.size()) + "\r\n";
            request += "Connection: close\r\n\r\n";
            request += body;
            asio::write(stream, asio::buffer(request));

            std::vector<char> buffer(64 * 1024);
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
            // Best-effort: an empty result IS the expected outcome for the no-cert test below.
        }
        return received;
    }

    // Builds the /enroll route exactly as RemotedModuleFacade wires it: an AuthdClient bridging
    // to a real FakeUdsServer standing in for authd, plus whatever authenticator the caller built
    // (with or without requirePassword, independently of the listener's own cert requirement).
    std::unique_ptr<remoted::http::IHttpServer> buildMtlsEnrollServer(EnrollmentAuthenticator& authenticator,
                                                                      AuthdClient& authdClient,
                                                                      const Config& config,
                                                                      EnrollmentMetrics& metrics)
    {
        auto server = remoted::http::makeHttpServer();
        server->addRoute(
            Method::Post, "/enroll", makeHandler(authenticator, authdClient, config, metrics, passthroughDecoder()));
        return server;
    }

    std::string writePasswordFile(const std::string& password)
    {
        const std::string path = "/tmp/enrollmentMtlsE2E_test_" + std::to_string(::getpid()) + ".pass";
        std::ofstream file(path);
        file << password << "\n";
        return path;
    }

    // The `wazuh-enroll+jwt` bearer EnrollmentAuthenticator verifies (jwt/jwtEnrollTokenSigner.hpp),
    // minted with the manager's own HKDF key at `ts`.
    std::string bearerFor(const jwt_profile::v1::SecureBytes& key, std::int64_t ts)
    {
        const auto token = jwt_profile::v1::enroll::JwtEnrollTokenSigner::sign(
            key, std::chrono::system_clock::time_point {std::chrono::seconds {ts}});
        EXPECT_TRUE(token.has_value());
        return "Bearer " + token.value_or("");
    }
} // namespace

TEST(EnrollmentMtlsE2ETest, ValidClientCertificateEnrollsSuccessfully)
{
    if (!runQuiet("openssl version"))
    {
        GTEST_SKIP() << "openssl not available to generate the test PKI";
    }
    const auto pki = generateMtlsPki();
    ASSERT_TRUE(pki.has_value());

    const std::string authdPath = makeUniqueSocketPath("enrollment_mtls_e2e_ok");
    FakeUdsServer authd(authdPath,
                        [](const std::string&)
                        { return R"({"error":0,"data":{"id":"005","name":"agent1","ip":"any","key":"deadbeef"}})"; });

    EnrollmentAuthenticator authenticator {EnrollmentAuthConfig {false}, nullptr};
    AuthdClient authdClient(authdPath, /*isWorkerNode=*/false, 0, 2000, 0);
    wazuh::metrics::Manager metricsManager;
    EnrollmentMetrics metrics = makeEnrollmentMetrics(metricsManager);
    Config config;
    config.enrollmentEnabled = true;
    config.managerVersion = "5.0.0";

    auto server = buildMtlsEnrollServer(authenticator, authdClient, config, metrics);

    HttpServerConfig serverConfig;
    serverConfig.bindAddress = "127.0.0.1";
    serverConfig.port = static_cast<std::uint16_t>(40000 + (::getpid() % 5000));
    serverConfig.certificatePath = pki->serverCert;
    serverConfig.privateKeyPath = pki->serverKey;
    serverConfig.caPath = pki->caCert;
    serverConfig.verificationMode = ClientVerificationMode::Certificate;

    ASSERT_NO_THROW(server->start(serverConfig));

    const std::string body = R"({"name":"agent1","version":"5.0.0"})";
    const std::string raw = sendEnrollRequest(serverConfig.port, body, &pki->clientCert, &pki->clientKey);

    EXPECT_NE(raw.find("200"), std::string::npos) << "response was: " << raw;
    EXPECT_NE(raw.find(R"("id":"005")"), std::string::npos) << "response was: " << raw;

    server->stopAccepting();
    server->stop();
    cleanupMtlsPki(*pki);
}

TEST(EnrollmentMtlsE2ETest, MissingClientCertificateIsRejectedByTheListenerBeforeTheHandlerRuns)
{
    if (!runQuiet("openssl version"))
    {
        GTEST_SKIP() << "openssl not available to generate the test PKI";
    }
    const auto pki = generateMtlsPki();
    ASSERT_TRUE(pki.has_value());

    // authd must never be reached: the TLS handshake itself is expected to fail.
    const std::string authdPath = makeUniqueSocketPath("enrollment_mtls_e2e_reject");

    EnrollmentAuthenticator authenticator {EnrollmentAuthConfig {false}, nullptr};
    AuthdClient authdClient(authdPath, /*isWorkerNode=*/false, 0, 2000, 0);
    wazuh::metrics::Manager metricsManager;
    EnrollmentMetrics metrics = makeEnrollmentMetrics(metricsManager);
    Config config;
    config.enrollmentEnabled = true;
    config.managerVersion = "5.0.0";

    auto server = buildMtlsEnrollServer(authenticator, authdClient, config, metrics);

    HttpServerConfig serverConfig;
    serverConfig.bindAddress = "127.0.0.1";
    serverConfig.port = static_cast<std::uint16_t>(45000 + (::getpid() % 5000));
    serverConfig.certificatePath = pki->serverCert;
    serverConfig.privateKeyPath = pki->serverKey;
    serverConfig.caPath = pki->caCert;
    serverConfig.verificationMode = ClientVerificationMode::Certificate;

    ASSERT_NO_THROW(server->start(serverConfig));

    const std::string body = R"({"name":"agent1","version":"5.0.0"})";
    const std::string raw = sendEnrollRequest(serverConfig.port, body, nullptr, nullptr);

    EXPECT_TRUE(raw.empty()) << "expected the handshake to fail with no client certificate, got: " << raw;

    server->stopAccepting();
    server->stop();
    cleanupMtlsPki(*pki);
}

// -----------------------------------------------------------------------------
// Combined requirement: a listener configured to require BOTH a client certificate AND a
// password must enforce both -- this is the scenario the mode-vs-independent-flags fix exists
// for (see this file's header comment and EnrollmentAuthConfig's doc comment).
// -----------------------------------------------------------------------------

TEST(EnrollmentMtlsE2ETest, ValidCertificateWithCorrectPasswordEnrollsSuccessfully)
{
    if (!runQuiet("openssl version"))
    {
        GTEST_SKIP() << "openssl not available to generate the test PKI";
    }
    const auto pki = generateMtlsPki();
    ASSERT_TRUE(pki.has_value());

    const std::string passwordPath = writePasswordFile("MyEnrollmentSecret123");
    auto keySource = std::make_shared<PasswordKeySource>(passwordPath);
    const auto key = keySource->currentKey();
    ASSERT_TRUE(key.has_value());

    const std::string authdPath = makeUniqueSocketPath("enrollment_mtls_e2e_both_ok");
    FakeUdsServer authd(authdPath,
                        [](const std::string&)
                        { return R"({"error":0,"data":{"id":"006","name":"agent1","ip":"any","key":"deadbeef"}})"; });

    EnrollmentAuthenticator authenticator {EnrollmentAuthConfig {true}, keySource};
    AuthdClient authdClient(authdPath, /*isWorkerNode=*/false, 0, 2000, 0);
    wazuh::metrics::Manager metricsManager;
    EnrollmentMetrics metrics = makeEnrollmentMetrics(metricsManager);
    Config config;
    config.enrollmentEnabled = true;
    config.managerVersion = "5.0.0";

    auto server = buildMtlsEnrollServer(authenticator, authdClient, config, metrics);

    HttpServerConfig serverConfig;
    serverConfig.bindAddress = "127.0.0.1";
    serverConfig.port = static_cast<std::uint16_t>(50000 + (::getpid() % 5000));
    serverConfig.certificatePath = pki->serverCert;
    serverConfig.privateKeyPath = pki->serverKey;
    serverConfig.caPath = pki->caCert;
    serverConfig.verificationMode = ClientVerificationMode::Certificate;

    ASSERT_NO_THROW(server->start(serverConfig));

    const std::string body = R"({"name":"agent1","version":"5.0.0"})";
    // Must be the real wall clock: the request goes through the actual handler, which checks the
    // timestamp against std::time(nullptr), not a fixed value (see enrollmentE2E_test.cpp's nowTs()
    // comment for why a hardcoded constant here would start failing as soon as real time moved on).
    const std::int64_t ts = static_cast<std::int64_t>(std::time(nullptr));
    const std::string raw =
        sendEnrollRequest(serverConfig.port, body, &pki->clientCert, &pki->clientKey, bearerFor(*key, ts));

    EXPECT_NE(raw.find("200"), std::string::npos) << "response was: " << raw;
    EXPECT_NE(raw.find(R"("id":"006")"), std::string::npos) << "response was: " << raw;

    server->stopAccepting();
    server->stop();
    cleanupMtlsPki(*pki);
    std::remove(passwordPath.c_str());
}

TEST(EnrollmentMtlsE2ETest, ValidCertificateButWrongPasswordSignatureIsRejected)
{
    if (!runQuiet("openssl version"))
    {
        GTEST_SKIP() << "openssl not available to generate the test PKI";
    }
    const auto pki = generateMtlsPki();
    ASSERT_TRUE(pki.has_value());

    const std::string passwordPath = writePasswordFile("MyEnrollmentSecret123");
    auto keySource = std::make_shared<PasswordKeySource>(passwordPath);

    // authd must never be reached: a valid client certificate alone must not be enough once
    // requirePassword is also set.
    const std::string authdPath = makeUniqueSocketPath("enrollment_mtls_e2e_both_reject");

    EnrollmentAuthenticator authenticator {EnrollmentAuthConfig {true}, keySource};
    AuthdClient authdClient(authdPath, /*isWorkerNode=*/false, 0, 2000, 0);
    wazuh::metrics::Manager metricsManager;
    EnrollmentMetrics metrics = makeEnrollmentMetrics(metricsManager);
    Config config;
    config.enrollmentEnabled = true;
    config.managerVersion = "5.0.0";

    auto server = buildMtlsEnrollServer(authenticator, authdClient, config, metrics);

    HttpServerConfig serverConfig;
    serverConfig.bindAddress = "127.0.0.1";
    serverConfig.port = static_cast<std::uint16_t>(55000 + (::getpid() % 5000));
    serverConfig.certificatePath = pki->serverCert;
    serverConfig.privateKeyPath = pki->serverKey;
    serverConfig.caPath = pki->caCert;
    serverConfig.verificationMode = ClientVerificationMode::Certificate;

    ASSERT_NO_THROW(server->start(serverConfig));

    const std::string body = R"({"name":"agent1","version":"5.0.0"})";
    // Valid client certificate, but no Authorization header at all -- the TLS handshake succeeds,
    // and the request must still be rejected by EnrollmentAuthenticator's password check.
    const std::string raw = sendEnrollRequest(serverConfig.port, body, &pki->clientCert, &pki->clientKey);

    EXPECT_NE(raw.find("401"), std::string::npos) << "response was: " << raw;

    server->stopAccepting();
    server->stop();
    cleanupMtlsPki(*pki);
    std::remove(passwordPath.c_str());
}
