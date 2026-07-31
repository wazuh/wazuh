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

#include <gtest/gtest.h>

#include <cstring>
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
