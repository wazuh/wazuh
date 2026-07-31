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
#include "http_server/RestinioHttpServer.hpp"
#include "http_server/httpServerConfig.hpp"
#include "http_server/httpServerFactory.hpp"
#include "proc.hpp"

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "testTlsServer.hpp"

#include <gtest/gtest.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>

using namespace remoted::http;

namespace
{
    // Responder stub that captures whatever a handler sends (once).
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

    // Zero-initialized C-ABI config, like remoted's `= {0}`. verification_mode is set to
    // UNSET (not left at the memset 0) because that's what remoted actually sends when
    // <https><verification_mode> was never configured -- RemotedConfig() pre-initializes
    // it to REMOTED_HTTPS_VERIFY_UNSET before parsing, and secure.c copies it through
    // unconditionally. 0 is reserved for an explicit <verification_mode>none</verification_mode>.
    remoted_module_config_t zeroedConfig()
    {
        remoted_module_config_t config;
        std::memset(&config, 0, sizeof(config));
        config.verification_mode = REMOTED_MODULE_HTTPS_VERIFY_UNSET;
        return config;
    }

    using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
    using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;

    // Builds a minimal self-signed certificate with the given comma-separated
    // subjectAltName value (e.g. "IP:203.0.113.5" or "IP:203.0.113.5,IP:2001:db8::1"), so
    // certificateMatchesPeerIp() can be exercised with just an X509* and a string -- no
    // live socket, TLS handshake, or on-disk fixture required.
    X509Ptr makeSelfSignedCertificate(const char* subjectAltName)
    {
        EvpPkeyPtr pkey {EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "prime256v1"), &EVP_PKEY_free};
        if (!pkey)
        {
            throw std::runtime_error("Failed to generate test EC key pair");
        }

        X509Ptr certificate {X509_new(), &X509_free};
        if (!certificate)
        {
            throw std::runtime_error("Failed to allocate test X509 certificate");
        }

        X509_set_version(certificate.get(), 2); // X509v3
        ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), 1);
        X509_gmtime_adj(X509_get_notBefore(certificate.get()), 0);
        X509_gmtime_adj(X509_get_notAfter(certificate.get()), 60L * 60L);

        X509_NAME* name = X509_get_subject_name(certificate.get());
        X509_NAME_add_entry_by_txt(
            name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("remoted-test"), -1, -1, 0);
        X509_set_issuer_name(certificate.get(), name);

        X509_set_pubkey(certificate.get(), pkey.get());

        X509V3_CTX ctx;
        X509V3_set_ctx_nodb(&ctx);
        X509V3_set_ctx(&ctx, certificate.get(), certificate.get(), nullptr, nullptr, 0);

        X509_EXTENSION* extension = X509V3_EXT_conf_nid(nullptr, &ctx, NID_subject_alt_name, subjectAltName);
        if (extension == nullptr)
        {
            throw std::runtime_error("Failed to build test subjectAltName extension");
        }
        X509_add_ext(certificate.get(), extension, -1);
        X509_EXTENSION_free(extension);

        if (X509_sign(certificate.get(), pkey.get(), EVP_sha256()) == 0)
        {
            throw std::runtime_error("Failed to sign test certificate");
        }

        return certificate;
    }
    // Generates a throwaway self-signed cert/key pair (via the `openssl` CLI, already a
    // build/runtime dependency) so start() can be exercised for real instead of only against the
    // missing/malformed-certificate failure paths above. HttpServerConfig takes paths (not PEM
    // content), so the files must stay on disk for the duration of the test -- only cleaned up
    // once this object goes out of scope.
    class TempCert
    {
    public:
        TempCert()
        {
            char dirTemplate[] = "/tmp/httpServerTestXXXXXX";
            m_dir = mkdtemp(dirTemplate);
            m_certPath = m_dir + "/cert.pem";
            m_keyPath = m_dir + "/key.pem";

            const std::string cmd = "openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=test -keyout " +
                                     m_keyPath + " -out " + m_certPath + " >/dev/null 2>&1";
            if (std::system(cmd.c_str()) != 0)
            {
                ADD_FAILURE() << "Failed to generate a throwaway TLS certificate for testing";
            }
        }

        ~TempCert()
        {
            std::remove(m_certPath.c_str());
            std::remove(m_keyPath.c_str());
            rmdir(m_dir.c_str());
        }

        const std::string& certPath() const { return m_certPath; }
        const std::string& keyPath() const { return m_keyPath; }

    private:
        std::string m_dir;
        std::string m_certPath;
        std::string m_keyPath;
    };
} // namespace

// ---------------------------------------------------------------------------
// Config builder
// ---------------------------------------------------------------------------

TEST(HttpServerConfigTest, DefaultsWhenEmpty)
{
    const auto config = buildHttpServerConfig(zeroedConfig());

    EXPECT_EQ(config.bindAddress, "127.0.0.1");
    EXPECT_EQ(config.port, 1517);
    EXPECT_EQ(config.ioThreads, static_cast<std::size_t>(cpp_get_nproc()));
    EXPECT_EQ(config.workerThreads, 2U * static_cast<std::size_t>(cpp_get_nproc()));
    EXPECT_EQ(config.maxBodySize, 20U * 1024U * 1024U);
    EXPECT_EQ(config.readTimeoutSec, 10U);
    EXPECT_EQ(config.writeTimeoutSec, 10U);
    EXPECT_EQ(config.requestTimeoutSec, 30U);
    EXPECT_EQ(config.maxUrlSize, 2048U);
    EXPECT_EQ(config.maxHeaderNameSize, 256U);
    EXPECT_EQ(config.maxHeaderValueSize, 8192U);
    EXPECT_EQ(config.maxHeaderCount, 64U);
    EXPECT_EQ(config.maxPipelinedRequests, 4U);
    EXPECT_EQ(config.concurrentAccepts, 2U);
    EXPECT_EQ(config.bufferSize, 8192U);
    EXPECT_EQ(config.streamChunkSize, 64U * 1024U);
    EXPECT_EQ(config.maxInFlightBytes, 256U * 1024U * 1024U);
    EXPECT_EQ(config.maxParallelConnections, 512U);
    EXPECT_EQ(config.certificatePath, "etc/https-manager.cert");
    EXPECT_EQ(config.privateKeyPath, "etc/https-manager.key");
    EXPECT_EQ(config.caPath, "etc/https-manager-ca.pem");
    EXPECT_EQ(config.ciphers, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256");
    EXPECT_EQ(config.verificationMode, ClientVerificationMode::None);
    // Unset, not Disabled: buildHttpServerConfig() intentionally leaves this distinct
    // from an explicit "no" so RestinioHttpServer::start()'s "dual_stack only applies to
    // an IPv6 bind_addr" warning doesn't fire for this (the default, IPv4) bind_addr.
    // RestinioHttpServer::start() treats Unset the same as Disabled when actually
    // setting the IPV6_V6ONLY socket option, so the effective behavior is still
    // IPv6-only by default -- see DualStackYesFromStructOverridesDefault and friends.
    EXPECT_EQ(config.dualStackMode, DualStackMode::Unset);
}

TEST(HttpServerConfigTest, InFlightBytesStructWinsElseDefault)
{
    // remoted config field wins when positive.
    auto raw = zeroedConfig();
    raw.max_inflight_bytes = 5U * 1024U * 1024U;
    EXPECT_EQ(buildHttpServerConfig(raw).maxInFlightBytes, 5U * 1024U * 1024U);

    // Unset (<=0) -> built-in default (this setting is not env-driven).
    raw.max_inflight_bytes = 0;
    EXPECT_EQ(buildHttpServerConfig(raw).maxInFlightBytes, 256U * 1024U * 1024U);
}

TEST(HttpServerConfigTest, MaxConnectionsStructWinsElseDefault)
{
    auto raw = zeroedConfig();
    raw.max_parallel_connections = 128;
    EXPECT_EQ(buildHttpServerConfig(raw).maxParallelConnections, 128U);

    // Unset (<=0) -> built-in default (this setting is not env-driven).
    raw.max_parallel_connections = 0;
    EXPECT_EQ(buildHttpServerConfig(raw).maxParallelConnections, 512U);
}

TEST(HttpServerConfigTest, StructValuesWin)
{
    auto raw = zeroedConfig();
    raw.port = 12345;
    raw.io_threads = 3;
    raw.http_worker_threads = 7;
    raw.http_max_body_size = 1048576;
    raw.http_read_timeout = 20;
    raw.http_write_timeout = 15;
    raw.http_request_timeout = 45;
    raw.http_max_url_size = 4096;
    raw.http_max_header_name_size = 512;
    raw.http_max_header_value_size = 16384;
    raw.http_max_header_count = 128;
    raw.http_max_pipelined_requests = 8;
    raw.http_concurrent_accepts = 4;
    raw.http_buffer_size = 16384;
    raw.http_stream_chunk_size = 262144;
    raw.verification_mode = REMOTED_MODULE_HTTPS_VERIFY_CERTIFICATE;
    std::snprintf(raw.certificate_path, sizeof(raw.certificate_path), "/custom/cert.pem");
    std::snprintf(raw.private_key_path, sizeof(raw.private_key_path), "/custom/key.pem");
    std::snprintf(raw.bind_address, sizeof(raw.bind_address), "0.0.0.0");
    std::snprintf(raw.ca_path, sizeof(raw.ca_path), "/custom/ca.pem");
    std::snprintf(raw.ciphers, sizeof(raw.ciphers), "HIGH:!ADH");

    const auto config = buildHttpServerConfig(raw);

    EXPECT_EQ(config.port, 12345);
    EXPECT_EQ(config.ioThreads, 3U);
    EXPECT_EQ(config.workerThreads, 7U);
    EXPECT_EQ(config.maxBodySize, 1048576U);
    EXPECT_EQ(config.readTimeoutSec, 20U);
    EXPECT_EQ(config.writeTimeoutSec, 15U);
    EXPECT_EQ(config.requestTimeoutSec, 45U);
    EXPECT_EQ(config.maxUrlSize, 4096U);
    EXPECT_EQ(config.maxHeaderNameSize, 512U);
    EXPECT_EQ(config.maxHeaderValueSize, 16384U);
    EXPECT_EQ(config.maxHeaderCount, 128U);
    EXPECT_EQ(config.maxPipelinedRequests, 8U);
    EXPECT_EQ(config.concurrentAccepts, 4U);
    EXPECT_EQ(config.bufferSize, 16384U);
    EXPECT_EQ(config.streamChunkSize, 262144U);
    EXPECT_EQ(config.certificatePath, "/custom/cert.pem");
    EXPECT_EQ(config.privateKeyPath, "/custom/key.pem");
    EXPECT_EQ(config.bindAddress, "0.0.0.0");
    EXPECT_EQ(config.caPath, "/custom/ca.pem");
    EXPECT_EQ(config.ciphers, "HIGH:!ADH");
    EXPECT_EQ(config.verificationMode, ClientVerificationMode::Certificate);
}

// Negative values can't come from remoted (getDefine_Int_default's own min bound
// keeps them out), but buildHttpServerConfig() only trusts "positive", so a
// leftover/garbage negative must fall back to the default like 0 does, not
// underflow when cast to the unsigned HttpServerConfig fields.
TEST(HttpServerConfigTest, NegativeValuesFallBackToDefaults)
{
    auto raw = zeroedConfig();
    raw.port = -1;
    raw.io_threads = -5;
    raw.http_max_url_size = -2048;

    const auto config = buildHttpServerConfig(raw);

    EXPECT_EQ(config.port, 1517);
    EXPECT_EQ(config.ioThreads, static_cast<std::size_t>(cpp_get_nproc()));
    EXPECT_EQ(config.maxUrlSize, 2048U);
}

TEST(HttpServerConfigTest, VerificationModeFullFromStruct)
{
    auto raw = zeroedConfig();
    raw.verification_mode = REMOTED_MODULE_HTTPS_VERIFY_FULL;

    EXPECT_EQ(buildHttpServerConfig(raw).verificationMode, ClientVerificationMode::Full);
}

TEST(HttpServerConfigTest, VerificationModeExplicitNoneStaysNone)
{
    // An explicit <verification_mode>none</verification_mode> (REMOTED_MODULE_HTTPS_VERIFY_NONE,
    // which is 0) must resolve to None via the same "configValue != UNSET" branch as
    // Certificate/Full, not be misread as REMOTED_MODULE_HTTPS_VERIFY_UNSET (-1).
    auto raw = zeroedConfig();
    raw.verification_mode = REMOTED_MODULE_HTTPS_VERIFY_NONE;

    EXPECT_EQ(buildHttpServerConfig(raw).verificationMode, ClientVerificationMode::None);
}

TEST(HttpServerConfigTest, DualStackYesFromStruct)
{
    auto raw = zeroedConfig();
    raw.dual_stack = REMOTED_MODULE_HTTPS_DUAL_STACK_YES;

    EXPECT_EQ(buildHttpServerConfig(raw).dualStackMode, DualStackMode::Enabled);
}

TEST(HttpServerConfigTest, DualStackExplicitNoFromStruct)
{
    auto raw = zeroedConfig();
    raw.dual_stack = REMOTED_MODULE_HTTPS_DUAL_STACK_NO;

    EXPECT_EQ(buildHttpServerConfig(raw).dualStackMode, DualStackMode::Disabled);
}

// ---------------------------------------------------------------------------
// Interface / registration (no network, no TLS)
// ---------------------------------------------------------------------------

TEST(HttpServerTest, RegisterRoutesDoesNotThrow)
{
    auto server = makeHttpServer();
    ASSERT_NE(server, nullptr);

    EXPECT_NO_THROW({
        server->addRoute(Method::Get,
                         "/",
                         [](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> r)
                         { r->send(HttpResponse::json(200, "{}")); });
        server->addRoute(Method::Post,
                         "/events",
                         [](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> r)
                         { r->send(HttpResponse::json(202, "{}")); });
    });
}

TEST(HttpServerTest, StartWithMissingCertificateThrowsAndStaysStopped)
{
    auto server = makeHttpServer();

    HttpServerConfig config;
    config.port = 0; // ask the OS for a free port (never actually bound: TLS fails first)
    config.certificatePath = "/nonexistent/remoted-tests/server.crt";
    config.privateKeyPath = "/nonexistent/remoted-tests/server.key";

    EXPECT_THROW(server->start(config), std::exception);

    // stopAccepting()/stop() must be safe after a failed start, and idempotent.
    EXPECT_NO_THROW(server->stopAccepting());
    EXPECT_NO_THROW(server->stop());
    EXPECT_NO_THROW(server->stop());
}

TEST(HttpServerTest, StartWithInvalidCiphersThrows)
{
    auto server = makeHttpServer();

    HttpServerConfig config;
    config.port = 0;
    // SSL_CTX_set_ciphersuites() is checked before the certificate/key are loaded, so this
    // throws regardless of certificatePath/privateKeyPath being unset/nonexistent.
    config.ciphers = "NOT-A-REAL-CIPHERSUITE-STRING";

    EXPECT_THROW(server->start(config), std::exception);
    EXPECT_NO_THROW(server->stop());
}

TEST(HttpServerTest, StartWithValidTls13CiphersuitesDoesNotThrowFromCipherSetup)
{
    auto server = makeHttpServer();

    HttpServerConfig config;
    config.port = 0;
    config.certificatePath = "/nonexistent/remoted-tests/server.crt";
    config.privateKeyPath = "/nonexistent/remoted-tests/server.key";
    config.ciphers = "TLS_AES_256_GCM_SHA384";

    // A syntactically valid TLS 1.3 ciphersuite name must be accepted by
    // SSL_CTX_set_ciphersuites(): start() should fail later, on the missing
    // certificate/key, not on cipher setup.
    try
    {
        server->start(config);
        FAIL() << "Expected start() to throw on the missing certificate/key";
    }
    catch (const std::exception& e)
    {
        EXPECT_EQ(std::string {e.what()}.find("cipher"), std::string::npos)
            << "start() threw from cipher setup instead of the missing certificate/key: " << e.what();
    }

    EXPECT_NO_THROW(server->stop());
}

TEST(HttpServerTest, StopWithoutStartIsSafe)
{
    auto server = makeHttpServer();
    EXPECT_NO_THROW(server->stop());
}

TEST(HttpServerTest, StopAcceptingWithoutStartIsSafe)
{
    auto server = makeHttpServer();
    EXPECT_NO_THROW(server->stopAccepting());
}

TEST(HttpServerTest, StopAcceptingIsIdempotentAndStopStillFullyTearsDown)
{
    auto server = makeHttpServer();

    // Calling stopAccepting() repeatedly, then stop() repeatedly, must never re-invoke RESTinio's
    // own stop()/wait() a second time (documented as unsafe) -- the guard flag must hold up.
    EXPECT_NO_THROW(server->stopAccepting());
    EXPECT_NO_THROW(server->stopAccepting());
    EXPECT_NO_THROW(server->stop());
    EXPECT_NO_THROW(server->stop());
}

// NOTE: with a nonexistent certificate/key, start() throws while loading the server
// certificate, before the verification_mode/ca handling ever runs. This proves start()
// still fails closed (no partial bind) when verificationMode is set alongside a missing
// cert/key.
TEST(HttpServerTest, StartWithMissingCertificateAndVerificationModeStillThrows)
{
    auto server = makeHttpServer();

    HttpServerConfig config;
    config.port = 0;
    config.certificatePath = "/nonexistent/remoted-tests/server.crt";
    config.privateKeyPath = "/nonexistent/remoted-tests/server.key";
    config.verificationMode = ClientVerificationMode::Certificate;
    // caPath intentionally left empty -- httpServerConfig.cpp would normally resolve this to
    // DEFAULT_CA_PATH; this test exercises the HttpServerConfig struct directly, so it's testing
    // start()'s cert/key check, not caPath resolution.

    EXPECT_THROW(server->start(config), std::exception);
    EXPECT_NO_THROW(server->stop());
}

// ---------------------------------------------------------------------------
// Certificate verification (ClientVerificationMode::Full peer-IP-vs-SAN check)
// ---------------------------------------------------------------------------

TEST(CertificateVerificationTest, MatchingIpv4AddressReturnsTrue)
{
    auto certificate = makeSelfSignedCertificate("IP:203.0.113.5");

    EXPECT_TRUE(certificateMatchesPeerIp(certificate.get(), "203.0.113.5"));
}

TEST(CertificateVerificationTest, NonMatchingIpv4AddressReturnsFalse)
{
    auto certificate = makeSelfSignedCertificate("IP:203.0.113.5");

    EXPECT_FALSE(certificateMatchesPeerIp(certificate.get(), "203.0.113.6"));
}

TEST(CertificateVerificationTest, MatchingIpv6AddressReturnsTrue)
{
    auto certificate = makeSelfSignedCertificate("IP:2001:db8::1");

    EXPECT_TRUE(certificateMatchesPeerIp(certificate.get(), "2001:db8::1"));
}

TEST(CertificateVerificationTest, MultipleSanEntriesMatchesAnyOfThem)
{
    auto certificate = makeSelfSignedCertificate("IP:203.0.113.5,IP:2001:db8::1");

    EXPECT_TRUE(certificateMatchesPeerIp(certificate.get(), "203.0.113.5"));
    EXPECT_TRUE(certificateMatchesPeerIp(certificate.get(), "2001:db8::1"));
    EXPECT_FALSE(certificateMatchesPeerIp(certificate.get(), "203.0.113.9"));
}

TEST(CertificateVerificationTest, NoSanExtensionReturnsFalse)
{
    // No IP SAN present at all -- a certificate with only a CN and no subjectAltName.
    EvpPkeyPtr pkey {EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "prime256v1"), &EVP_PKEY_free};
    ASSERT_TRUE(pkey);

    X509Ptr certificate {X509_new(), &X509_free};
    ASSERT_TRUE(certificate);

    X509_set_version(certificate.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), 1);
    X509_gmtime_adj(X509_get_notBefore(certificate.get()), 0);
    X509_gmtime_adj(X509_get_notAfter(certificate.get()), 60L * 60L);

    X509_NAME* name = X509_get_subject_name(certificate.get());
    X509_NAME_add_entry_by_txt(
        name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("remoted-test-no-san"), -1, -1, 0);
    X509_set_issuer_name(certificate.get(), name);
    X509_set_pubkey(certificate.get(), pkey.get());
    ASSERT_NE(X509_sign(certificate.get(), pkey.get(), EVP_sha256()), 0);

    EXPECT_FALSE(certificateMatchesPeerIp(certificate.get(), "203.0.113.5"));
}

TEST(CertificateVerificationTest, NullCertificateReturnsFalse)
{
    EXPECT_FALSE(certificateMatchesPeerIp(nullptr, "203.0.113.5"));
}

// ---------------------------------------------------------------------------
// In-flight budget reservations (tryReserveInFlightBytes())
// ---------------------------------------------------------------------------

TEST(HttpServerTest, ReserveInFlightBytesFailsBeforeStart)
{
    auto server = makeHttpServer();

    // No budget exists until start() builds it, so there is nothing to reserve against. Fails
    // closed rather than silently granting untracked memory.
    EXPECT_FALSE(server->tryReserveInFlightBytes(1024).has_value());
}

TEST(HttpServerTest, ReserveInFlightBytesAlwaysGrantsWhenBudgetDisabled)
{
    TempCert cert;
    auto server = makeHttpServer();

    HttpServerConfig config;
    config.port = 0; // ephemeral
    config.certificatePath = cert.certPath();
    config.privateKeyPath = cert.keyPath();
    config.maxInFlightBytes = 0; // explicitly disabled

    ASSERT_NO_THROW(server->start(config));

    // Granted, but tracking nothing: a disabled budget admits unconditionally (bytes() == 0).
    auto reservation = server->tryReserveInFlightBytes(64U * 1024U * 1024U);
    ASSERT_TRUE(reservation.has_value());
    EXPECT_EQ(reservation->bytes(), 0U);

    server->stop();
}

TEST(HttpServerTest, ReserveInFlightBytesEnforcesConfiguredCapacityAfterStart)
{
    TempCert cert;
    auto server = makeHttpServer();

    HttpServerConfig config;
    config.port = 0; // ephemeral
    config.certificatePath = cert.certPath();
    config.privateKeyPath = cert.keyPath();
    // Comfortably above maxBodySize + the transport's per-request overhead, so start()'s own
    // "raise it to at least one max-size request" clamp never kicks in and the configured capacity
    // is what actually applies here.
    config.maxBodySize = 1U * 1024U * 1024U;
    config.maxInFlightBytes = 50U * 1024U * 1024U;

    ASSERT_NO_THROW(server->start(config));

    {
        // Nothing else is in flight (no request has been dispatched), so the whole configured
        // capacity is reservable -- exactly, and not a byte more.
        auto whole = server->tryReserveInFlightBytes(50U * 1024U * 1024U);
        ASSERT_TRUE(whole.has_value());
        EXPECT_EQ(whole->bytes(), 50U * 1024U * 1024U);
        EXPECT_FALSE(server->tryReserveInFlightBytes(1).has_value()); // exhausted
    }

    // `whole` released at the end of the scope above: capacity is back.
    EXPECT_TRUE(server->tryReserveInFlightBytes(50U * 1024U * 1024U).has_value());

    server->stop();
}

// ---------------------------------------------------------------------------
// Async responder contract (independent of the transport library)
// ---------------------------------------------------------------------------

TEST(HttpResponderContractTest, ImmediateResponseMapping)
{
    RouteHandler handler = [](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> responder)
    {
        responder->send(HttpResponse::json(201, R"({"created":true})"));
    };

    auto request = std::make_shared<HttpRequest>();
    request->method = Method::Post;
    request->target = "/thing";

    auto responder = std::make_shared<CapturingResponder>();
    handler(request, responder);

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(responder->captured->status, 201);
    EXPECT_EQ(responder->captured->body, R"({"created":true})");
    ASSERT_FALSE(responder->captured->headers.empty());
    EXPECT_EQ(responder->captured->headers.front().first, "Content-Type");
    EXPECT_EQ(responder->captured->headers.front().second, "application/json");
}

TEST(HttpResponderContractTest, DeferredResponseFromAnotherThread)
{
    std::shared_ptr<IHttpResponder> held;
    std::shared_ptr<const HttpRequest> heldRequest;

    // Handler defers: it stashes the request AND the responder and returns without answering.
    RouteHandler handler =
        [&held, &heldRequest](std::shared_ptr<const HttpRequest> request, std::shared_ptr<IHttpResponder> responder)
    {
        heldRequest = std::move(request);
        held = std::move(responder);
    };

    auto responder = std::make_shared<CapturingResponder>();
    {
        // The request the transport would build; it drops at the end of this scope.
        auto request = std::make_shared<const HttpRequest>();
        handler(request, responder);
    }

    // The shared request survived the handler call: it can travel across deferred stages.
    ASSERT_NE(heldRequest, nullptr);
    ASSERT_FALSE(responder->captured.has_value()); // not answered yet

    // Complete the response later, from a different thread.
    std::thread worker([&held] { held->send(HttpResponse::json(200, R"({"late":true})")); });
    worker.join();

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(responder->captured->status, 200);
    EXPECT_EQ(responder->captured->body, R"({"late":true})");
}

TEST(HttpResponderContractTest, SecondSendIsIgnored)
{
    auto responder = std::make_shared<CapturingResponder>();
    responder->send(HttpResponse::json(200, "first"));
    responder->send(HttpResponse::json(500, "second"));

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(responder->captured->body, "first");
}

// ---------------------------------------------------------------------------
// Streamed responses over a REAL TLS server
//
// StreamPump and RestinioStreamableResponder live in RestinioHttpServer.cpp's anonymous namespace,
// so the only way to exercise them is through an actual server on a socket. These cover the three
// things the manual tooling used to be the only evidence for: the chunked framing, the configured
// chunk size actually reaching the pump, and an aborted transfer not emitting a terminator.
// ---------------------------------------------------------------------------

namespace
{
    /// Serves a fixed buffer, one read at a time. Records when it is destroyed so a test can prove
    /// an aborted transfer still releases the source (and with it, a real endpoint's file handle).
    class BufferByteSource final : public IByteSource
    {
    public:
        BufferByteSource(std::string payload, std::shared_ptr<std::atomic_bool> destroyed = nullptr)
            : m_payload {std::move(payload)}
            , m_destroyed {std::move(destroyed)}
        {
        }

        ~BufferByteSource() override
        {
            if (m_destroyed)
            {
                m_destroyed->store(true);
            }
        }

        std::size_t read(char* buffer, std::size_t capacity) override
        {
            const auto remaining = m_payload.size() - m_offset;
            const auto count = std::min(capacity, remaining);
            std::memcpy(buffer, m_payload.data() + m_offset, count);
            m_offset += count;
            return count;
        }

    private:
        std::string m_payload;
        std::shared_ptr<std::atomic_bool> m_destroyed;
        std::size_t m_offset {0};
    };

    std::string patternPayload(std::size_t size)
    {
        std::string payload;
        payload.reserve(size);
        for (std::size_t i = 0; i < size; ++i)
        {
            payload.push_back(static_cast<char>('A' + (i % 26)));
        }
        return payload;
    }

    /// A server wired the way the facade wires a streaming route, on a free-ish port.
    struct StreamingFixture
    {
        std::unique_ptr<IHttpServer> server;
        HttpServerConfig config;
    };

    bool headerPresent(const std::string& head, const std::string& needle)
    {
        std::string lowered;
        lowered.resize(head.size());
        std::transform(head.begin(), head.end(), lowered.begin(), [](unsigned char c) { return std::tolower(c); });
        std::string target = needle;
        std::transform(target.begin(), target.end(), target.begin(), [](unsigned char c) { return std::tolower(c); });
        return lowered.find(target) != std::string::npos;
    }
} // namespace

TEST(HttpServerStreamingTest, StreamsAMultiChunkBodyByteExactly)
{
    auto certOpt = remoted::test::generateTestCertificate("rmt_stream_happy");
    if (!certOpt)
    {
        GTEST_SKIP() << "openssl not available to generate a test certificate";
    }
    remoted::test::ScratchFileCleanup cleanup {{certOpt->certPath, certOpt->keyPath}};

    // Deliberately not a multiple of the chunk size: the final short chunk is the case most likely
    // to be mishandled.
    const std::string payload = patternPayload(70000);

    auto server = makeHttpServer();
    server->addRoute(
        Method::Post,
        "/stream",
        [&payload](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> responder)
        {
            StreamResponse response;
            response.headers.emplace_back("Content-Type", "application/octet-stream");
            response.source = std::make_shared<BufferByteSource>(payload);
            responder->stream(std::move(response));
        },
        /*countAgainstBudget=*/true,
        ResponseMode::Streamable);

    HttpServerConfig config;
    config.port = static_cast<std::uint16_t>(21000 + (::getpid() % 5000));
    config.certificatePath = certOpt->certPath;
    config.privateKeyPath = certOpt->keyPath;
    server->start(config);

    const auto raw = remoted::test::sendSignedRequest(config.port, remoted::test::testAgentKey(), "/stream", "{}");
    server->stop();

    ASSERT_FALSE(raw.empty()) << "no response from the streaming server";
    const auto [head, body] = remoted::test::splitResponse(raw);

    EXPECT_TRUE(headerPresent(head, "transfer-encoding: chunked")) << head;
    // Chunked and Content-Length are mutually exclusive; a Content-Length here would mean the body
    // was buffered after all.
    EXPECT_FALSE(headerPresent(head, "content-length:")) << head;

    std::vector<std::size_t> sizes;
    bool complete = false;
    const auto decoded = remoted::test::decodeChunked(body, sizes, complete);

    EXPECT_TRUE(complete) << "the terminating 0-length chunk is missing";
    EXPECT_EQ(decoded.size(), payload.size());
    EXPECT_EQ(decoded, payload);
    EXPECT_GT(sizes.size(), 1U) << "expected the body to span several chunks";
}

TEST(HttpServerStreamingTest, ChunkSizeFollowsTheConfiguredValue)
{
    // The knob is remoted.http_stream_chunk_size -> HttpServerConfig::streamChunkSize. Asserting on
    // the chunk sizes ON THE WIRE is what proves it reaches the pump; a decoded-body comparison
    // would pass even if the value were ignored.
    auto certOpt = remoted::test::generateTestCertificate("rmt_stream_size");
    if (!certOpt)
    {
        GTEST_SKIP() << "openssl not available to generate a test certificate";
    }
    remoted::test::ScratchFileCleanup cleanup {{certOpt->certPath, certOpt->keyPath}};

    constexpr std::size_t kChunk = 8192;
    const std::string payload = patternPayload(kChunk * 3 + 100); // 3 full chunks + a short one

    auto server = makeHttpServer();
    server->addRoute(
        Method::Post,
        "/stream",
        [&payload](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> responder)
        {
            StreamResponse response;
            response.source = std::make_shared<BufferByteSource>(payload);
            // chunkSize left at 0 on purpose: the server's configured value must be applied.
            responder->stream(std::move(response));
        },
        /*countAgainstBudget=*/true,
        ResponseMode::Streamable);

    HttpServerConfig config;
    config.port = static_cast<std::uint16_t>(22000 + (::getpid() % 5000));
    config.certificatePath = certOpt->certPath;
    config.privateKeyPath = certOpt->keyPath;
    config.streamChunkSize = kChunk;
    server->start(config);

    const auto raw = remoted::test::sendSignedRequest(config.port, remoted::test::testAgentKey(), "/stream", "{}");
    server->stop();

    ASSERT_FALSE(raw.empty());
    const auto [head, body] = remoted::test::splitResponse(raw);
    (void)head;

    std::vector<std::size_t> sizes;
    bool complete = false;
    const auto decoded = remoted::test::decodeChunked(body, sizes, complete);

    EXPECT_TRUE(complete);
    EXPECT_EQ(decoded, payload);
    ASSERT_GE(sizes.size(), 4U);
    // Every chunk but the last carries exactly the configured size.
    for (std::size_t i = 0; i + 1 < sizes.size(); ++i)
    {
        EXPECT_EQ(sizes[i], kChunk) << "chunk " << i << " did not use the configured size";
    }
    EXPECT_EQ(sizes.back(), 100U);
}

TEST(HttpServerStreamingTest, AbortedTransferSendsNoTerminatorAndReleasesTheSource)
{
    // An agent that walks away mid-transfer must NOT receive a terminating 0-length chunk: that
    // would mark a truncated body as complete. The source must still be released, which is what
    // frees a real endpoint's file descriptor.
    auto certOpt = remoted::test::generateTestCertificate("rmt_stream_abort");
    if (!certOpt)
    {
        GTEST_SKIP() << "openssl not available to generate a test certificate";
    }
    remoted::test::ScratchFileCleanup cleanup {{certOpt->certPath, certOpt->keyPath}};

    // Large enough that the client can close long before the server finishes writing.
    const std::string payload = patternPayload(16 * 1024 * 1024);
    auto destroyed = std::make_shared<std::atomic_bool>(false);

    auto server = makeHttpServer();
    server->addRoute(
        Method::Post,
        "/stream",
        [&payload, destroyed](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> responder)
        {
            StreamResponse response;
            response.source = std::make_shared<BufferByteSource>(payload, destroyed);
            responder->stream(std::move(response));
        },
        /*countAgainstBudget=*/true,
        ResponseMode::Streamable);

    HttpServerConfig config;
    config.port = static_cast<std::uint16_t>(23000 + (::getpid() % 5000));
    config.certificatePath = certOpt->certPath;
    config.privateKeyPath = certOpt->keyPath;
    server->start(config);

    // Read only the first 64 KiB, then drop the connection.
    const auto raw =
        remoted::test::sendSignedRequest(config.port, remoted::test::testAgentKey(), "/stream", "{}", 64 * 1024);

    ASSERT_FALSE(raw.empty());
    const auto [head, body] = remoted::test::splitResponse(raw);
    EXPECT_TRUE(headerPresent(head, "transfer-encoding: chunked")) << head;

    std::vector<std::size_t> sizes;
    bool complete = false;
    remoted::test::decodeChunked(body, sizes, complete);
    EXPECT_FALSE(complete) << "an aborted transfer must not carry the terminating 0-length chunk";

    // The pump notices the failed write and drops the source. Give it a moment: the abort is
    // observed on the connection's strand, not on this thread.
    for (int i = 0; i < 100 && !destroyed->load(); ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds {20});
    }
    EXPECT_TRUE(destroyed->load()) << "the byte source outlived an aborted transfer (descriptor leak)";

    // The server must still be healthy for the next request. Read this one to COMPLETION rather
    // than aborting again: a second abort would leave its pump in flight at stop() below, and
    // "serves a whole response" is the stronger health check anyway.
    const auto second = remoted::test::sendSignedRequest(config.port, remoted::test::testAgentKey(), "/stream", "{}");
    ASSERT_FALSE(second.empty()) << "the server stopped serving after an aborted transfer";

    const auto [secondHead, secondBody] = remoted::test::splitResponse(second);
    std::vector<std::size_t> secondSizes;
    bool secondComplete = false;
    const auto decoded = remoted::test::decodeChunked(secondBody, secondSizes, secondComplete);
    EXPECT_TRUE(secondComplete) << "the transfer after an aborted one was itself truncated";
    EXPECT_EQ(decoded, payload) << "the transfer after an aborted one did not deliver the payload";

    server->stop();
}

namespace
{
    /// Yields a fixed payload but sleeps before each chunk, so a transfer takes a controllable
    /// amount of wall-clock time regardless of how fast the link is.
    class SlowByteSource final : public IByteSource
    {
    public:
        SlowByteSource(std::string payload, std::chrono::milliseconds perChunk)
            : m_payload {std::move(payload)}
            , m_perChunk {perChunk}
        {
        }

        std::size_t read(char* buffer, std::size_t capacity) override
        {
            const auto remaining = m_payload.size() - m_offset;
            if (remaining == 0)
            {
                return 0;
            }
            std::this_thread::sleep_for(m_perChunk);
            const auto count = std::min(capacity, remaining);
            std::memcpy(buffer, m_payload.data() + m_offset, count);
            m_offset += count;
            return count;
        }

    private:
        std::string m_payload;
        std::chrono::milliseconds m_perChunk;
        std::size_t m_offset {0};
    };
} // namespace

TEST(HttpServerStreamingTest, HealthyTransferOutlastingTheRequestTimeoutIsNotCut)
{
    // http_request_timeout bounds a request end to end and defaults to 30 s, while a real 100 MB
    // WPK over a 1 MiB/s WAN link takes ~2 minutes. All the throughput evidence so far is loopback
    // at hundreds of MiB/s, which never approaches that timer -- so this drives a transfer that
    // deliberately outlasts it (scaled down: a 1 s cap against a ~2.5 s transfer) and asserts it
    // still completes. The timer must rearm between chunks rather than bound the whole response.
    auto certOpt = remoted::test::generateTestCertificate("rmt_stream_slow");
    if (!certOpt)
    {
        GTEST_SKIP() << "openssl not available to generate a test certificate";
    }
    remoted::test::ScratchFileCleanup cleanup {{certOpt->certPath, certOpt->keyPath}};

    constexpr std::size_t kChunk = 4096;
    const std::string payload = patternPayload(kChunk * 10); // 10 chunks
    const auto perChunk = std::chrono::milliseconds {250};   // ~2.5 s total

    auto server = makeHttpServer();
    server->addRoute(
        Method::Post,
        "/slow",
        [&payload, perChunk](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> responder)
        {
            StreamResponse response;
            response.source = std::make_shared<SlowByteSource>(payload, perChunk);
            responder->stream(std::move(response));
        },
        /*countAgainstBudget=*/true,
        ResponseMode::Streamable);

    HttpServerConfig config;
    config.port = static_cast<std::uint16_t>(25000 + (::getpid() % 5000));
    config.certificatePath = certOpt->certPath;
    config.privateKeyPath = certOpt->keyPath;
    config.streamChunkSize = kChunk;
    config.requestTimeoutSec = 1; // deliberately shorter than the transfer
    config.writeTimeoutSec = 1;
    server->start(config);

    const auto started = std::chrono::steady_clock::now();
    const auto raw = remoted::test::sendSignedRequest(config.port, remoted::test::testAgentKey(), "/slow", "{}");
    const auto elapsed = std::chrono::steady_clock::now() - started;
    server->stop();

    ASSERT_FALSE(raw.empty());
    const auto parts = remoted::test::splitResponse(raw);

    std::vector<std::size_t> sizes;
    bool complete = false;
    const auto decoded = remoted::test::decodeChunked(parts.second, sizes, complete);

    EXPECT_GT(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count(), 1000)
        << "the transfer finished too fast to have outlasted the request timeout";
    EXPECT_TRUE(complete) << "a healthy but slow transfer was cut short";
    EXPECT_EQ(decoded, payload);
}

TEST(HttpServerStreamingTest, TrickleReaderKeepsTheTransferAliveBeyondTheWriteTimeout)
{
    // Documents the exposure raised in review: with chunked output every flush is its own write
    // group, so http_write_timeout rearms PER CHUNK. It kills a client that stops reading entirely
    // (covered by the abort test), but a client that keeps reading a trickle renews the timer
    // indefinitely and can hold a stream open for as long as it likes.
    //
    // There is no per-stream concurrency limit today -- the only bound is maxParallelConnections --
    // so this pins the CURRENT behaviour and will need revisiting if a stream limiter is added.
    auto certOpt = remoted::test::generateTestCertificate("rmt_stream_trickle");
    if (!certOpt)
    {
        GTEST_SKIP() << "openssl not available to generate a test certificate";
    }
    remoted::test::ScratchFileCleanup cleanup {{certOpt->certPath, certOpt->keyPath}};

    constexpr std::size_t kChunk = 2048;
    const std::string payload = patternPayload(kChunk * 8);

    auto server = makeHttpServer();
    server->addRoute(
        Method::Post,
        "/trickle",
        [&payload](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> responder)
        {
            StreamResponse response;
            response.source = std::make_shared<BufferByteSource>(payload);
            responder->stream(std::move(response));
        },
        /*countAgainstBudget=*/true,
        ResponseMode::Streamable);

    HttpServerConfig config;
    config.port = static_cast<std::uint16_t>(26000 + (::getpid() % 5000));
    config.certificatePath = certOpt->certPath;
    config.privateKeyPath = certOpt->keyPath;
    config.streamChunkSize = kChunk;
    config.writeTimeoutSec = 1;   // one second per write group...
    config.requestTimeoutSec = 1; // ...and per gap between them
    server->start(config);

    // 512 bytes every 150 ms: several seconds in total, many times the 1 s timers, but no single
    // gap ever exceeds them.
    const auto started = std::chrono::steady_clock::now();
    const auto raw = remoted::test::sendSignedRequestTrickle(config.port,
                                                             remoted::test::testAgentKey(),
                                                             "/trickle",
                                                             "{}",
                                                             512,
                                                             std::chrono::milliseconds {150},
                                                             std::chrono::seconds {30});
    const auto elapsed = std::chrono::steady_clock::now() - started;
    server->stop();

    ASSERT_FALSE(raw.empty());
    const auto parts = remoted::test::splitResponse(raw);

    std::vector<std::size_t> sizes;
    bool complete = false;
    const auto decoded = remoted::test::decodeChunked(parts.second, sizes, complete);

    EXPECT_GT(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count(), 2000)
        << "the trickle was not slow enough to outlast the configured timers";
    EXPECT_TRUE(complete) << "a trickling reader was cut off; the per-write timer did not rearm";
    EXPECT_EQ(decoded, payload);
}
