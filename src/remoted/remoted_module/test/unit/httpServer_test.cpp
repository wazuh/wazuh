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

#include "ca_bundle/ca_bundle.hpp"
#include "http_server/IHttpServer.hpp"
#include "http_server/RestinioHttpServer.hpp"
#include "http_server/caCertificateSource.hpp"
#include "http_server/caPublicationRecord.hpp"
#include "http_server/caRecordEvents.hpp"
#include "http_server/httpServerConfig.hpp"
#include "http_server/httpServerFactory.hpp"
#include "http_server/tlsCertificateStatus.hpp"
#include "proc.hpp"

#include "testCertificates.hpp"
#include "testTlsServer.hpp"

#include <gtest/gtest.h>

#include <asio/connect.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/read_until.hpp>
#include <asio/ssl.hpp>
#include <asio/streambuf.hpp>
#include <asio/write.hpp>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <sys/stat.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <istream>
#include <iterator>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

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
    // https.verification_mode was never configured -- RemotedConfig() pre-initializes
    // it to REMOTED_HTTPS_VERIFY_UNSET before parsing, and secure.c copies it through
    // unconditionally. 0 is reserved for an explicit <verification_mode>none</verification_mode>.
    remoted_module_config_t zeroedConfig()
    {
        remoted_module_config_t config;
        std::memset(&config, 0, sizeof(config));
        config.verification_mode = REMOTED_MODULE_HTTPS_VERIFY_UNSET;
        return config;
    }

    // EvpPkeyPtr, makeTestKey(), makeCertificate() and writePemFile() moved to testCertificates.hpp
    // (shared with caCertificateSource_test.cpp): using-declarations, not a new namespace import, so
    // this stays unambiguous next to `using namespace remoted::http;` above.
    using remoted::test::EvpPkeyPtr;
    using remoted::test::makeCertificate;
    using remoted::test::makeTestKey;
    using remoted::test::writePemFile;
    // X509Ptr is remoted::http's (tlsCertificateStatus.hpp), so certificates built here feed the
    // status functions directly.

    // Builds a minimal self-signed certificate with the given comma-separated subjectAltName value
    // (e.g. "IP:203.0.113.5" or "IP:203.0.113.5,IP:2001:db8::1"), so certificateMatchesPeerIp() can
    // be exercised with just an X509* and a string -- no live socket, TLS handshake, or on-disk
    // fixture required. The end-to-end behaviour of ClientVerificationMode::Full is covered
    // separately, over a real connection, by FullModeTest below.
    X509Ptr makeSelfSignedCertificate(const char* subjectAltName)
    {
        const auto key = makeTestKey();
        return makeCertificate("remoted-test", 0, 60L * 60L, key.get(), key.get(), nullptr, subjectAltName);
    }

    std::string scratchPath(const char* name)
    {
        return "/tmp/httpServerTest_" + std::string {name} + "_" + std::to_string(::getpid()) + ".pem";
    }

    // loadCertificates()/evaluateCertificateStatus() are gone (issue #39318): CaCertificateSource
    // is the one reader now. This is the read-only half a plain loadCertificates() call used to
    // give the CA-coherence tests below -- the bounded/failure-aware half is CaCertificateSource's
    // own job and is exercised through it (statusFrom(leaf, CaCertificateSource{...}.snapshot())).
    std::vector<X509Ptr> readPemCertificates(const std::string& path)
    {
        std::ifstream in {path, std::ios::binary};
        if (!in)
        {
            return {};
        }
        std::string pem {std::istreambuf_iterator<char> {in}, std::istreambuf_iterator<char> {}};
        return ca_bundle::parseBundle(pem).certificates;
    }

    // Generates a throwaway self-signed cert/key pair (via the `openssl` CLI, already a
    // build/runtime dependency) so start() can be exercised for real instead of only against the
    // missing/malformed-certificate failure paths above. HttpServerConfig takes paths (not PEM
    // content), so the files must stay on disk for the duration of the test -- only cleaned up
    // once this object goes out of scope.
    class TempCert
    {
    public:
        /// @param days Validity, so the expiry-status tests can pick a leaf inside or outside the
        ///             30-day warning window.
        explicit TempCert(int days = 1)
        {
            char dirTemplate[] = "/tmp/httpServerTestXXXXXX";
            m_dir = mkdtemp(dirTemplate);
            m_certPath = m_dir + "/cert.pem";
            m_keyPath = m_dir + "/key.pem";

            const std::string cmd = "openssl req -x509 -newkey rsa:2048 -nodes -days " + std::to_string(days) +
                                    " -subj /CN=test -keyout " + m_keyPath + " -out " + m_certPath + " >/dev/null 2>&1";
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

        const std::string& certPath() const
        {
            return m_certPath;
        }
        const std::string& keyPath() const
        {
            return m_keyPath;
        }

    private:
        std::string m_dir;
        std::string m_certPath;
        std::string m_keyPath;
    };

    /// Throwaway directory for a publication record (same mold as downloadEndpoint_test.cpp's
    /// TempDir: mkdtemp for per-instance/per-process uniqueness, std::filesystem for teardown,
    /// since CaPublicationRecord writes names this file does not predict).
    class TempDir
    {
    public:
        TempDir()
        {
            std::string tmpl = "/tmp/wazuh-httpServerTest-record-XXXXXX";
            std::vector<char> buffer(tmpl.begin(), tmpl.end());
            buffer.push_back('\0');

            const char* created = ::mkdtemp(buffer.data());
            if (created == nullptr)
            {
                throw std::runtime_error("mkdtemp failed for the httpServer test's scratch directory");
            }
            m_path = created;
        }

        ~TempDir()
        {
            std::error_code ignored;
            std::filesystem::remove_all(m_path, ignored);
        }

        TempDir(const TempDir&) = delete;
        TempDir& operator=(const TempDir&) = delete;

        const std::string& path() const
        {
            return m_path;
        }

    private:
        std::string m_path;
    };
} // namespace

// ---------------------------------------------------------------------------
// Config builder
// ---------------------------------------------------------------------------

TEST(HttpServerConfigTest, DefaultsWhenEmpty)
{
    const auto config = buildHttpServerConfig(zeroedConfig());

    EXPECT_EQ(config.bindAddress, "0.0.0.0");
    // Empty C-ABI buffer -> "" == no prefix, today's behavior (D3: an absent tag changes nothing).
    EXPECT_EQ(config.globalPrefix, "");
    EXPECT_EQ(config.port, 1517);
    EXPECT_EQ(config.ioThreads, static_cast<std::size_t>(cpp_get_nproc()));
    EXPECT_EQ(config.workerThreads, 2U * static_cast<std::size_t>(cpp_get_nproc()));
    EXPECT_EQ(config.maxBodySize, 10U * 1024U * 1024U);
    EXPECT_EQ(config.readTimeoutSec, 10U);
    EXPECT_EQ(config.writeTimeoutSec, 10U);
    EXPECT_EQ(config.requestTimeoutSec, 30U);
    EXPECT_EQ(config.maxUrlSize, 2048U);
    EXPECT_EQ(config.maxHeaderNameSize, 256U);
    EXPECT_EQ(config.maxHeaderValueSize, 8192U);
    EXPECT_EQ(config.maxHeaderCount, 64U);
    EXPECT_EQ(config.maxPipelinedRequests, 4U);
    // nproc, floored at 2 (a single-vCPU host/cgroup must not regress below the old fixed
    // default) -- see MIN_CONCURRENT_ACCEPTS in httpServerConfig.cpp.
    EXPECT_EQ(config.concurrentAccepts, std::max<std::size_t>(static_cast<std::size_t>(cpp_get_nproc()), 2U));
    EXPECT_EQ(config.bufferSize, 8192U);
    EXPECT_EQ(config.streamChunkSize, 64U * 1024U);
    EXPECT_EQ(config.maxInFlightBytes, 256U * 1024U * 1024U);
    EXPECT_EQ(config.maxParallelConnections, 256U);
    EXPECT_EQ(config.certificatePath, "etc/certs/remoted.pem");
    EXPECT_EQ(config.privateKeyPath, "etc/certs/remoted-key.pem");
    EXPECT_EQ(config.caPath, "etc/certs/root-ca.pem");
    EXPECT_EQ(config.caCertificatePath, "etc/certs/root-ca.pem");
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

TEST(HttpServerConfigTest, CaCertificateDefaultsToRootCa)
{
    // remote.https.ca_certificate never configured (empty C-ABI buffer): the CA that signs the
    // listener certificate defaults to the installer's root CA, independently of `ca` (the
    // client-verification bundle), which keeps its own default.
    const auto config = buildHttpServerConfig(zeroedConfig());
    EXPECT_EQ(config.caCertificatePath, "etc/certs/root-ca.pem");
    EXPECT_EQ(config.caPath, "etc/certs/root-ca.pem");
}

TEST(HttpServerConfigTest, CaCertificateOverrideFromConfig)
{
    auto raw = zeroedConfig();
    std::snprintf(raw.ca_certificate_path, sizeof(raw.ca_certificate_path), "/custom/listener-ca.pem");
    // ca_path deliberately left empty: the two fields must not leak into each other.
    const auto config = buildHttpServerConfig(raw);
    EXPECT_EQ(config.caCertificatePath, "/custom/listener-ca.pem");
    EXPECT_EQ(config.caPath, "etc/certs/root-ca.pem");
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

    // Unset (<=0) -> built-in default (this setting is not env-driven). Must equal secure.c's own
    // default for the same option, or an embedder passing a zeroed struct is limited differently
    // from remoted itself.
    raw.max_parallel_connections = 0;
    EXPECT_EQ(buildHttpServerConfig(raw).maxParallelConnections, 256U);
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
    std::snprintf(raw.global_prefix, sizeof(raw.global_prefix), "/wazuh-manager/");
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
    // VERBATIM copy (trailing slash kept): canonicalization is RestinioHttpServer::start()'s
    // single job -- see NormalizeGlobalPrefixTest for that contract.
    EXPECT_EQ(config.globalPrefix, "/wazuh-manager/");
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

// A value outside the three known ones can only reach us from a config library built against a
// different revision of the C-ABI, and the one thing it must NOT do is resolve to None: that would
// turn a stale build into a silent downgrade to no client-certificate verification at all.
TEST(HttpServerConfigTest, UnknownVerificationModeFailsClosed)
{
    auto raw = zeroedConfig();
    raw.verification_mode = 99;

    EXPECT_EQ(buildHttpServerConfig(raw).verificationMode, ClientVerificationMode::Certificate);
}

TEST(HttpServerConfigTest, VerificationModeExplicitNoneStaysNone)
{
    // An explicit <verification_mode>none</verification_mode> (REMOTED_MODULE_HTTPS_VERIFY_NONE,
    // which is 0) must resolve to None, not be misread as REMOTED_MODULE_HTTPS_VERIFY_UNSET (-1)
    // -- both end up at None here, but only one of them is the operator's explicit choice.
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
// certificateMatchesPeerIp(): the comparison behind ClientVerificationMode::Full
//
// These cover the comparison in isolation. They are deliberately NOT the only coverage of the
// Full mode: an earlier implementation passed tests just like these while rejecting every real
// connection, because it read the peer address through SSL_get_fd(), which returns -1 under asio.
// FullModeTest below is what closes that gap, over a real TLS connection.
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

// A DNS-only SAN must not satisfy an address check: the two are different name types, and
// accepting one for the other is exactly the kind of near-miss that looks like it works.
TEST(CertificateVerificationTest, DnsSanDoesNotSatisfyAnAddressCheck)
{
    auto certificate = makeSelfSignedCertificate("DNS:agent-1001.example");

    EXPECT_FALSE(certificateMatchesPeerIp(certificate.get(), "203.0.113.5"));
}

TEST(CertificateVerificationTest, NullCertificateReturnsFalse)
{
    EXPECT_FALSE(certificateMatchesPeerIp(nullptr, "203.0.113.5"));
}

// ---------------------------------------------------------------------------
// Certificate status (expiry + CA coherence), from certificates built in memory
// ---------------------------------------------------------------------------

namespace
{
    constexpr long kDay {24L * 60L * 60L};

    // A CA, a leaf it signed, and an unrelated CA -- the whole cast of the coherence tests. `ca` and
    // `foreignCa` carry CA:TRUE (isCa) so the chainValidates() tests can use them as trust anchors;
    // `leaf` stays without it -- a served certificate is never itself a CA.
    struct StatusPki
    {
        EvpPkeyPtr caKey {makeTestKey()};
        X509Ptr ca {makeCertificate("status-ca", -kDay, 30 * kDay, caKey.get(), caKey.get(), nullptr, nullptr, true)};
        EvpPkeyPtr leafKey {makeTestKey()};
        X509Ptr leaf {makeCertificate("localhost", -kDay, 10 * kDay, leafKey.get(), caKey.get(), ca.get())};
        EvpPkeyPtr foreignKey {makeTestKey()};
        X509Ptr foreignCa {makeCertificate(
            "foreign-ca", -kDay, 30 * kDay, foreignKey.get(), foreignKey.get(), nullptr, nullptr, true)};
    };

    // Duplicates an owning reference to an already-built certificate, so the SAME X509 object can
    // sit in two independent bundles (std::vector<X509Ptr>) without a double free -- needed when a
    // test reuses one StatusPki's `ca` across two chainValidates() calls.
    X509Ptr upRef(const X509Ptr& certificate)
    {
        X509* raw = certificate.get();
        if (raw != nullptr)
        {
            X509_up_ref(raw);
        }
        return X509Ptr {raw};
    }
} // namespace

TEST(TlsCertificateStatusTest, DaysUntilExpiryOfTestCert)
{
    const auto key = makeTestKey();
    const auto cert = makeCertificate("leaf", 0, 10 * kDay, key.get(), key.get(), nullptr);

    // Truncated whole days: the seconds elapsed since the certificate was built make it 9.
    const auto days = daysUntilExpiry(cert.get());
    ASSERT_TRUE(days.has_value());
    EXPECT_GE(*days, 9);
    EXPECT_LE(*days, 10);
}

TEST(TlsCertificateStatusTest, DaysUntilExpiryIsNegativeOnceExpired)
{
    const auto key = makeTestKey();
    const auto cert = makeCertificate("leaf", -3 * kDay, -2 * kDay, key.get(), key.get(), nullptr);

    const auto days = daysUntilExpiry(cert.get());
    ASSERT_TRUE(days.has_value());
    EXPECT_LE(*days, -1);

    // The first 24 h past notAfter read -1, never 0: "negative" is a strict synonym of "expired".
    const auto justExpired = makeCertificate("leaf", -kDay, -60, key.get(), key.get(), nullptr);
    EXPECT_EQ(daysUntilExpiry(justExpired.get()), -1);

    EXPECT_FALSE(daysUntilExpiry(nullptr).has_value());
}

TEST(TlsCertificateStatusTest, CaSignsLeafTrue)
{
    StatusPki pki;
    const auto caPath = scratchPath("ca_true");
    remoted::test::ScratchFileCleanup cleanup {{caPath}};
    writePemFile(caPath, {pki.ca.get()});

    std::vector<X509Ptr> cas = readPemCertificates(caPath);
    ASSERT_EQ(cas.size(), 1U);
    EXPECT_TRUE(anyCaSignsLeaf(pki.leaf.get(), cas));

    const auto status = statusFrom(pki.leaf.get(), CaCertificateSource {caPath, pki.leaf.get()}.snapshot());
    EXPECT_EQ(status.caMatchesLeaf, true);
    ASSERT_TRUE(status.expiryDays.has_value());
    EXPECT_GE(*status.expiryDays, 9);
    EXPECT_EQ(status.evaluations, 0U); // counting is the monitor's job
    EXPECT_NE(status.leafSubject.find("localhost"), std::string::npos) << status.leafSubject;
    EXPECT_NE(status.caSubjects.find("status-ca"), std::string::npos) << status.caSubjects;
}

TEST(TlsCertificateStatusTest, CaSignsLeafFalse)
{
    StatusPki pki;
    const auto caPath = scratchPath("ca_false");
    remoted::test::ScratchFileCleanup cleanup {{caPath}};
    writePemFile(caPath, {pki.foreignCa.get()});

    EXPECT_FALSE(anyCaSignsLeaf(pki.leaf.get(), readPemCertificates(caPath)));
    EXPECT_EQ(statusFrom(pki.leaf.get(), CaCertificateSource {caPath, pki.leaf.get()}.snapshot()).caMatchesLeaf, false);
    // A null leaf never matches anything either.
    EXPECT_FALSE(anyCaSignsLeaf(nullptr, readPemCertificates(caPath)));
}

TEST(TlsCertificateStatusTest, CaSignsLeafUnreadable)
{
    StatusPki pki;
    const auto missing = "/nonexistent/remoted-tests/root-ca.pem";

    EXPECT_TRUE(readPemCertificates(missing).empty());
    EXPECT_TRUE(readPemCertificates("").empty());

    // Unknown, not mismatch: the caller must be able to tell "cannot read the CA" from "the CA is
    // the wrong one" (GET /cacerts serves on the former, refuses on the latter). A missing file is
    // also a read FAILURE (issue #39318): the source could not open it, and says so.
    const auto status = statusFrom(pki.leaf.get(), CaCertificateSource {missing, pki.leaf.get()}.snapshot());
    EXPECT_FALSE(status.caMatchesLeaf.has_value());
    EXPECT_TRUE(status.caSubjects.empty());
    ASSERT_TRUE(status.expiryDays.has_value()); // the leaf side is still evaluated
    ASSERT_TRUE(status.caReadFailure.has_value());
    EXPECT_EQ(status.caReadFailure->status, ReadStatus::CannotOpen);
    EXPECT_EQ(status.caReadFailure->error, ENOENT);

    // A file with no CERTIFICATE block is the same as no file for the verdict -- but unlike the
    // missing path above, the READ itself succeeded, so there is no failure to report.
    const auto garbage = scratchPath("ca_garbage");
    remoted::test::ScratchFileCleanup cleanup {{garbage}};
    {
        std::ofstream out {garbage};
        out << "not a pem\n";
    }
    EXPECT_TRUE(readPemCertificates(garbage).empty());
    const auto garbageStatus = statusFrom(pki.leaf.get(), CaCertificateSource {garbage, pki.leaf.get()}.snapshot());
    EXPECT_FALSE(garbageStatus.caMatchesLeaf.has_value());
    EXPECT_FALSE(garbageStatus.caReadFailure.has_value());
}

// ---------------------------------------------------------------------------
// leafHasUsableSan(): the one certificate question the manager can settle on its own.
//
// Not "does the leaf cover the address this agent dials" -- behind NAT, a load balancer or a
// worker, the manager does not know that address, and the agent checks it for real at upgrade
// time. This is the weaker, decidable question: is there ANY name here a remote agent could match.
// The subtracted set is passed explicitly so the table does not depend on what the build machine
// happens to be called.
// ---------------------------------------------------------------------------
namespace
{
    const std::vector<std::string> kLocalNames {
        "localhost", "localhost.localdomain", "build-host.example.net", "build-host"};

    bool usableSan(const char* subjectAltName)
    {
        const auto key = makeTestKey();
        const auto cert = makeCertificate("leaf", 0, 10 * kDay, key.get(), key.get(), nullptr, subjectAltName);
        return remoted::http::leafHasUsableSan(cert.get(), kLocalNames);
    }
} // namespace

TEST(LeafHasUsableSanTest, NoSanExtensionAtAllIsUnusable)
{
    // RFC 6125 has clients ignore the subject CN, so a certificate with no SAN identifies no host
    // to anyone -- however good its CN looks.
    EXPECT_FALSE(usableSan(nullptr));
    EXPECT_FALSE(remoted::http::leafHasUsableSan(nullptr, kLocalNames));
}

TEST(LeafHasUsableSanTest, LoopbackOnlyIsUnusable)
{
    EXPECT_FALSE(usableSan("IP:127.0.0.1"));
    EXPECT_FALSE(usableSan("IP:127.0.0.53")); // the whole 127.0.0.0/8, not just .1
    EXPECT_FALSE(usableSan("IP:::1"));
    EXPECT_FALSE(usableSan("IP:127.0.0.1,IP:::1"));
}

TEST(LeafHasUsableSanTest, LocalNamesOnlyAreUnusable)
{
    // The shape a self-signed quickstart certificate has. Catching it is the whole reason the test
    // is "no USABLE SAN" rather than the simpler "no SAN at all".
    EXPECT_FALSE(usableSan("DNS:localhost"));
    EXPECT_FALSE(usableSan("DNS:localhost.localdomain"));
    EXPECT_FALSE(usableSan("DNS:build-host"));
    EXPECT_FALSE(usableSan("DNS:build-host.example.net"));
    EXPECT_FALSE(usableSan("DNS:localhost,IP:127.0.0.1,DNS:build-host"));
}

TEST(LeafHasUsableSanTest, LocalNameComparisonIsCaseInsensitive)
{
    // DNS names are case-insensitive, so a certificate that spells the local host in capitals is
    // exactly as useless as one that does not -- and must not slip through as "some other name".
    EXPECT_FALSE(usableSan("DNS:LocalHost"));
    EXPECT_FALSE(usableSan("DNS:BUILD-HOST.EXAMPLE.NET"));
}

TEST(LeafHasUsableSanTest, OneRoutableEntryIsEnough)
{
    EXPECT_TRUE(usableSan("IP:203.0.113.5"));
    EXPECT_TRUE(usableSan("IP:2001:db8::1"));
    EXPECT_TRUE(usableSan("DNS:manager.example.com"));
    EXPECT_TRUE(usableSan("DNS:*.example.com"));
    // Loopback plus something real: the filter subtracts, it does not disqualify the whole set.
    EXPECT_TRUE(usableSan("DNS:localhost,IP:127.0.0.1,IP:203.0.113.5"));
    EXPECT_TRUE(usableSan("IP:127.0.0.1,DNS:manager.example.com"));
}

TEST(LeafHasUsableSanTest, ShortLocalNameDoesNotSubtractAnFqdn)
{
    // localHostNames() only ever REDUCES a hostname to its short form, never expands a short one to
    // a guessed FQDN. "build-host.other.example" is a name this code has no business claiming
    // describes only the local host, so it counts -- warning is the loud action, and being
    // conservative about NOT warning is the right direction.
    EXPECT_TRUE(usableSan("DNS:build-host.other.example"));
}

TEST(LeafHasUsableSanTest, NonIdentityEntryTypesNeitherCountNorDisqualify)
{
    // A TLS client never matches a server identity against a URI or an email address.
    EXPECT_FALSE(usableSan("URI:https://manager.example.com/"));
    EXPECT_FALSE(usableSan("email:admin@example.com"));
    EXPECT_TRUE(usableSan("URI:https://manager.example.com/,DNS:manager.example.com"));
}

TEST(LeafHasUsableSanTest, LocalHostNamesAlwaysCarriesTheLoopbackNames)
{
    const auto names = remoted::http::localHostNames();
    EXPECT_NE(std::find(names.begin(), names.end(), "localhost"), names.end());
    EXPECT_NE(std::find(names.begin(), names.end(), "localhost.localdomain"), names.end());
    // gethostname() may fail in a restricted sandbox, so the only guarantee beyond the two literals
    // is that nothing empty is ever added -- an empty entry would subtract every empty dNSName.
    for (const auto& name : names)
    {
        EXPECT_FALSE(name.empty());
    }
}

TEST(TlsCertificateStatusTest, BundleWithTheSigningCaMatches)
{
    StatusPki pki;
    const auto bundlePath = scratchPath("ca_bundle");
    remoted::test::ScratchFileCleanup cleanup {{bundlePath}};
    // The signing CA is NOT the first block: every block must be tried.
    writePemFile(bundlePath, {pki.foreignCa.get(), pki.ca.get()});

    const auto cas = readPemCertificates(bundlePath);
    ASSERT_EQ(cas.size(), 2U);
    EXPECT_TRUE(anyCaSignsLeaf(pki.leaf.get(), cas));
    const auto status = statusFrom(pki.leaf.get(), CaCertificateSource {bundlePath, pki.leaf.get()}.snapshot());
    EXPECT_EQ(status.caMatchesLeaf, true);
    EXPECT_NE(status.caSubjects.find("foreign-ca"), std::string::npos) << status.caSubjects;
    EXPECT_NE(status.caSubjects.find("status-ca"), std::string::npos) << status.caSubjects;
}

// ---------------------------------------------------------------------------
// chainValidates(): does the served leaf VALIDATE with the bundle as its trust store (issue
// #39318) -- a stricter, separate question from anyCaSignsLeaf()'s plain signature check. Every
// GTEST_LOG_(INFO) line below is deliberate: the exact OpenSSL wording is what the operator-facing
// WARN/INFO lines in RestinioHttpServer.cpp quote, so it belongs in the test output, not only in a
// failure diagnostic.
// ---------------------------------------------------------------------------

namespace
{
    // root (CA) -> intermediate (CA, signed by root) -> leaf (signed by intermediate): the shape
    // that lets ChainValidWithAnIntermediateAnchor and ChainValidRootOnlyWithMissingIntermediate
    // show the difference between "some CA in the bundle signs the leaf" and "the leaf's own chain
    // is complete against the bundle".
    struct IntermediatePki
    {
        EvpPkeyPtr rootKey {makeTestKey()};
        X509Ptr root {
            makeCertificate("status-root", -kDay, 30 * kDay, rootKey.get(), rootKey.get(), nullptr, nullptr, true)};
        EvpPkeyPtr intermediateKey {makeTestKey()};
        X509Ptr intermediate {makeCertificate(
            "status-intermediate", -kDay, 30 * kDay, intermediateKey.get(), rootKey.get(), root.get(), nullptr, true)};
        EvpPkeyPtr leafKey {makeTestKey()};
        X509Ptr leaf {
            makeCertificate("localhost", -kDay, 10 * kDay, leafKey.get(), intermediateKey.get(), intermediate.get())};
    };
} // namespace

TEST(TlsCertificateStatusTest, ChainValidWithAnIntermediateAnchor)
{
    IntermediatePki pki;
    std::vector<X509Ptr> cas;
    cas.push_back(std::move(pki.intermediate));

    // X509_V_FLAG_PARTIAL_CHAIN makes the intermediate itself a trust anchor: the root need not be
    // in the bundle for the chain to be complete.
    EXPECT_TRUE(anyCaSignsLeaf(pki.leaf.get(), cas));
    const auto verdict = chainValidates(pki.leaf.get(), cas);
    GTEST_LOG_(INFO) << "ChainValidWithAnIntermediateAnchor chainError: \"" << verdict.error << "\"";
    ASSERT_TRUE(verdict.valid.has_value());
    EXPECT_TRUE(*verdict.valid) << verdict.error;
    EXPECT_TRUE(verdict.error.empty()) << verdict.error;
}

TEST(TlsCertificateStatusTest, ChainValidRootOnlyWithMissingIntermediate)
{
    IntermediatePki pki;
    std::vector<X509Ptr> cas;
    cas.push_back(std::move(pki.root));

    // The root does not sign the leaf directly (the intermediate does), and it is not the leaf's
    // named issuer either: the chain cannot be completed from the root alone.
    EXPECT_FALSE(anyCaSignsLeaf(pki.leaf.get(), cas));
    const auto verdict = chainValidates(pki.leaf.get(), cas);
    GTEST_LOG_(INFO) << "ChainValidRootOnlyWithMissingIntermediate chainError: \"" << verdict.error << "\"";
    ASSERT_TRUE(verdict.valid.has_value());
    EXPECT_FALSE(*verdict.valid);
    EXPECT_EQ(verdict.error, "unable to get local issuer certificate");
}

TEST(TlsCertificateStatusTest, ChainValidExpiredCa)
{
    auto caKey = makeTestKey();
    auto ca = makeCertificate("status-expired-ca", -3 * kDay, -kDay, caKey.get(), caKey.get(), nullptr, nullptr, true);
    auto leafKey = makeTestKey();
    // The LEAF is still within its validity window; only the CA that signed it has expired.
    auto leaf = makeCertificate("localhost", -kDay, 10 * kDay, leafKey.get(), caKey.get(), ca.get());

    std::vector<X509Ptr> cas;
    cas.push_back(std::move(ca));

    EXPECT_TRUE(anyCaSignsLeaf(leaf.get(), cas));
    const auto verdict = chainValidates(leaf.get(), cas);
    GTEST_LOG_(INFO) << "ChainValidExpiredCa chainError: \"" << verdict.error << "\"";
    ASSERT_TRUE(verdict.valid.has_value());
    EXPECT_FALSE(*verdict.valid);
    EXPECT_EQ(verdict.error, "certificate has expired");
}

TEST(TlsCertificateStatusTest, ChainValidNonCaSigner)
{
    // A plain leaf-shaped certificate (no isCa: no basicConstraints/keyUsage at all) used as a
    // signer -- exactly what makeCertificate() has always built. It still signs the leaf; the
    // exact OpenSSL wording for why the CHAIN then fails is left to the test's own log line rather
    // than pinned here.
    auto signerKey = makeTestKey();
    auto signer = makeCertificate("status-non-ca-signer", -kDay, 30 * kDay, signerKey.get(), signerKey.get(), nullptr);
    auto leafKey = makeTestKey();
    auto leaf = makeCertificate("localhost", -kDay, 10 * kDay, leafKey.get(), signerKey.get(), signer.get());

    std::vector<X509Ptr> cas;
    cas.push_back(std::move(signer));

    EXPECT_TRUE(anyCaSignsLeaf(leaf.get(), cas));
    const auto verdict = chainValidates(leaf.get(), cas);
    GTEST_LOG_(INFO) << "ChainValidNonCaSigner chainError: \"" << verdict.error << "\"";
    ASSERT_TRUE(verdict.valid.has_value());
    EXPECT_FALSE(*verdict.valid);
    EXPECT_FALSE(verdict.error.empty());
}

TEST(TlsCertificateStatusTest, ChainValidSelfSignedCa)
{
    StatusPki pki;

    std::vector<X509Ptr> singleCa;
    singleCa.push_back(upRef(pki.ca));

    EXPECT_TRUE(anyCaSignsLeaf(pki.leaf.get(), singleCa));
    const auto singleVerdict = chainValidates(pki.leaf.get(), singleCa);
    GTEST_LOG_(INFO) << "ChainValidSelfSignedCa (ca only) chainError: \"" << singleVerdict.error << "\"";
    ASSERT_TRUE(singleVerdict.valid.has_value());
    EXPECT_TRUE(*singleVerdict.valid) << singleVerdict.error;
    EXPECT_TRUE(singleVerdict.error.empty()) << singleVerdict.error;

    // Same self-signed CA, now alongside an unrelated one: an extra, irrelevant bundle entry must
    // not change the verdict.
    std::vector<X509Ptr> bundleWithForeign;
    bundleWithForeign.push_back(upRef(pki.foreignCa));
    bundleWithForeign.push_back(upRef(pki.ca));

    EXPECT_TRUE(anyCaSignsLeaf(pki.leaf.get(), bundleWithForeign));
    const auto bundleVerdict = chainValidates(pki.leaf.get(), bundleWithForeign);
    GTEST_LOG_(INFO) << "ChainValidSelfSignedCa (foreignCa+ca) chainError: \"" << bundleVerdict.error << "\"";
    ASSERT_TRUE(bundleVerdict.valid.has_value());
    EXPECT_TRUE(*bundleVerdict.valid) << bundleVerdict.error;
    EXPECT_TRUE(bundleVerdict.error.empty()) << bundleVerdict.error;
}

TEST(TlsCertificateStatusTest, ChainValidUnknownWithoutLeafOrBundle)
{
    StatusPki pki;
    std::vector<X509Ptr> cas;
    cas.push_back(upRef(pki.ca));

    const auto noLeaf = chainValidates(nullptr, cas);
    EXPECT_FALSE(noLeaf.valid.has_value());
    EXPECT_TRUE(noLeaf.error.empty());

    const auto noBundle = chainValidates(pki.leaf.get(), {});
    EXPECT_FALSE(noBundle.valid.has_value());
    EXPECT_TRUE(noBundle.error.empty());
}

// ---------------------------------------------------------------------------
// The transport's own evaluation: at start (before listening) and on the monitor's ticks
// ---------------------------------------------------------------------------

TEST(HttpServerTest, CertificateStatusIsEmptyBeforeStart)
{
    auto server = makeHttpServer();

    const auto status = server->certificateStatus();
    EXPECT_EQ(status.evaluations, 0U);
    EXPECT_FALSE(status.expiryDays.has_value());
    EXPECT_FALSE(status.caMatchesLeaf.has_value());
}

TEST(HttpServerTest, CertificateStatusIsEvaluatedBeforeListening)
{
    TempCert cert; // 1 day: inside the WARN window, so this also walks the warning branch
    auto server = makeHttpServer();

    HttpServerConfig config;
    config.caPublicationRecordPath = ""; // not under test here (avoids the default var/run WARN, addendum §1)
    config.port = 0;
    config.certificatePath = cert.certPath();
    config.privateKeyPath = cert.keyPath();
    config.caCertificatePath = cert.certPath(); // self-signed: its own CA

    ASSERT_NO_THROW(server->start(config));

    // Exactly the start-time evaluation -- the 24 h monitor has not ticked -- and it is already
    // there the moment start() returns, so no request can ever observe "not evaluated yet".
    const auto status = server->certificateStatus();
    EXPECT_EQ(status.evaluations, 1U);
    ASSERT_TRUE(status.expiryDays.has_value());
    EXPECT_GE(*status.expiryDays, 0);
    EXPECT_LE(*status.expiryDays, 1);
    EXPECT_EQ(status.caMatchesLeaf, true);

    server->stop();
}

TEST(HttpServerTest, StartUpStatusCarriesTheChainVerdict)
{
    // openssl req -x509 stamps basicConstraints=critical,CA:TRUE by default (OpenSSL 3,
    // testTlsServer.hpp), so this self-signed certificate validates as its own CA, not merely
    // "matches" it.
    TempCert cert;
    auto server = makeHttpServer();

    HttpServerConfig config;
    config.caPublicationRecordPath = ""; // not under test here (avoids the default var/run WARN, addendum §1)
    config.port = 0;
    config.certificatePath = cert.certPath();
    config.privateKeyPath = cert.keyPath();
    config.caCertificatePath = cert.certPath(); // self-signed: its own CA

    ASSERT_NO_THROW(server->start(config));

    const auto status = server->certificateStatus();
    EXPECT_EQ(status.caMatchesLeaf, true);
    ASSERT_TRUE(status.chainValid.has_value());
    EXPECT_TRUE(*status.chainValid) << status.chainError;
    EXPECT_TRUE(status.chainError.empty()) << status.chainError;

    server->stop();
}

namespace
{
    // Bounded wait for the monitor to have produced at least @p minimum evaluations.
    bool waitForEvaluations(const IHttpServer& server, std::uint64_t minimum, std::chrono::milliseconds maxWait)
    {
        const auto deadline = std::chrono::steady_clock::now() + maxWait;
        while (std::chrono::steady_clock::now() < deadline)
        {
            if (server.certificateStatus().evaluations >= minimum)
            {
                return true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds {50});
        }
        return server.certificateStatus().evaluations >= minimum;
    }
} // namespace

TEST(HttpServerTest, ExpiryWarningRunsAgainOnTimerTick)
{
    TempCert cert {10}; // inside the 30-day window: every tick walks the WARN path the start did
    auto server = makeHttpServer();

    HttpServerConfig config;
    config.caPublicationRecordPath = ""; // not under test here (avoids the default var/run WARN, addendum §1)
    config.port = 0;
    config.certificatePath = cert.certPath();
    config.privateKeyPath = cert.keyPath();
    config.caCertificatePath = cert.certPath();
    config.certificateStatusInterval = std::chrono::seconds {1};

    ASSERT_NO_THROW(server->start(config));
    EXPECT_EQ(server->certificateStatus().evaluations, 1U);

    // The monitor re-evaluates (and re-logs) every interval: a second evaluation lands well
    // inside 5 s, and it carries the same verdict as the first.
    ASSERT_TRUE(waitForEvaluations(*server, 2, std::chrono::seconds {5}));
    const auto status = server->certificateStatus();
    EXPECT_GE(status.evaluations, 2U);
    EXPECT_EQ(status.caMatchesLeaf, true);
    ASSERT_TRUE(status.expiryDays.has_value());
    EXPECT_GE(*status.expiryDays, 9);

    server->stop();
}

TEST(HttpServerTest, StopAcceptingJoinsTheCertificateMonitor)
{
    TempCert cert {10};
    auto server = makeHttpServer();

    HttpServerConfig config;
    config.caPublicationRecordPath = ""; // not under test here (avoids the default var/run WARN, addendum §1)
    config.port = 0;
    config.certificatePath = cert.certPath();
    config.privateKeyPath = cert.keyPath();
    config.caCertificatePath = cert.certPath();
    config.certificateStatusInterval = std::chrono::seconds {1};

    ASSERT_NO_THROW(server->start(config));
    ASSERT_TRUE(waitForEvaluations(*server, 2, std::chrono::seconds {5}));

    // stopAccepting() wakes the monitor instead of waiting out its interval, and joins it.
    const auto before = std::chrono::steady_clock::now();
    server->stopAccepting();
    EXPECT_LT(std::chrono::steady_clock::now() - before, std::chrono::seconds {2});

    // Joined: the count no longer moves, even across what would have been the next tick. The last
    // snapshot stays readable (the pulls quiesce through the facade's weak_ptr, not here).
    const auto frozen = server->certificateStatus().evaluations;
    EXPECT_GE(frozen, 2U);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds {1500};
    while (std::chrono::steady_clock::now() < deadline)
    {
        ASSERT_EQ(server->certificateStatus().evaluations, frozen);
        std::this_thread::sleep_for(std::chrono::milliseconds {100});
    }

    server->stop();
}

// The shared CaCertificateSource (issue #39318): the start-time verdict comes from the same
// reader GET /cacerts answers from, so a broken CA at start is visible through both entry points
// at once, each describing the exact failure rather than a bare "unreadable".
TEST(HttpServerTest, StartUpStatusComesFromTheSharedSource)
{
    TempCert cert; // valid leaf/key; only the configured CA path is broken

    char dirTemplate[] = "/tmp/httpServerTestCaDirXXXXXX";
    const std::string caDir = ::mkdtemp(dirTemplate);
    ASSERT_FALSE(caDir.empty());

    auto server = makeHttpServer();

    HttpServerConfig config;
    config.caPublicationRecordPath = ""; // not under test here (avoids the default var/run WARN, addendum §1)
    config.port = 0;
    config.certificatePath = cert.certPath();
    config.privateKeyPath = cert.keyPath();
    config.caCertificatePath = caDir; // open(2) succeeds on a directory; read(2) refuses it (EISDIR)

    ASSERT_NO_THROW(server->start(config));

    const auto status = server->certificateStatus();
    EXPECT_EQ(status.evaluations, 1U);
    EXPECT_FALSE(status.caMatchesLeaf.has_value());
    ASSERT_TRUE(status.caReadFailure.has_value());
    EXPECT_EQ(status.caReadFailure->status, ReadStatus::ReadError);
    EXPECT_EQ(status.caReadFailure->error, EISDIR);

    const auto caSnapshot = server->caCertificateSnapshot();
    EXPECT_EQ(caSnapshot.certificates, 0U);
    ASSERT_TRUE(caSnapshot.lastReadFailure.has_value());
    EXPECT_EQ(caSnapshot.lastReadFailure->status, ReadStatus::ReadError);
    EXPECT_EQ(caSnapshot.lastReadFailure->error, EISDIR);

    server->stop();
    ::rmdir(caDir.c_str());
}

// ---------------------------------------------------------------------------
// caDescriptor() (issue #39319, RF-3): the notify hot path's own view of the bundle, distinct from
// caCertificateSnapshot() above -- it carries only the generation, revalidated at most once a
// second (CaCertificateSource::kDescriptorRefresh, C8/C18). Both tests below start a real server
// so RestinioHttpServer::caDescriptor() itself -- the weak_ptr dance under m_mutex, CA-15 -- is
// exercised, not just CaCertificateSource in isolation (that is caCertificateSource_test.cpp's
// job).
// ---------------------------------------------------------------------------

TEST(HttpServerTest, CaDescriptorReturnsThePublishedGeneration)
{
    if (std::system("openssl version >/dev/null 2>&1") != 0)
    {
        GTEST_SKIP() << "openssl not available to generate the test PKI";
    }

    auto pki = remoted::test::generateCaSignedCertificate("httpserver_ca_descriptor");
    if (!pki)
    {
        GTEST_SKIP() << "could not generate the throwaway CA-signed certificate";
    }
    remoted::test::ScratchFileCleanup cleanup {pki->files()};

    // Seal the CA file the way `wazuh-manager-certs` would (issue #39319, D9): the block, then the
    // certificate it describes -- a separate file from the leaf, so sealing it cannot disturb what
    // the listener loads into its TLS context.
    std::string rawCa;
    {
        std::ifstream in {pki->caCertPath, std::ios::binary};
        rawCa.assign(std::istreambuf_iterator<char> {in}, std::istreambuf_iterator<char> {});
    }
    const auto certificates = ca_bundle::parseBundle(rawCa).certificates;
    ASSERT_EQ(certificates.size(), 1U);

    constexpr std::int64_t kPublication {1758000000};
    ca_bundle::PublicationBlock block;
    block.publication = kPublication;
    block.contentSha256 = ca_bundle::contentSha256(certificates);
    block.updated = "2026-09-19T00:00:00Z";
    block.writtenBy = "httpServerTest";
    {
        std::ofstream out {pki->caCertPath, std::ios::binary | std::ios::trunc};
        out << ca_bundle::renderBlock(block) << ca_bundle::serializeCertificates(certificates);
        ASSERT_FALSE(out.fail());
    }

    auto server = makeHttpServer();
    HttpServerConfig config;
    config.caPublicationRecordPath = ""; // not under test here (avoids the default var/run WARN, addendum §1)
    config.port = 0;
    config.certificatePath = pki->certPath;
    config.privateKeyPath = pki->keyPath;
    config.caCertificatePath = pki->caCertPath;

    ASSERT_NO_THROW(server->start(config));

    const auto descriptor = server->caDescriptor();
    ASSERT_TRUE(descriptor.generation.has_value());
    EXPECT_EQ(*descriptor.generation, kPublication);

    server->stop();
}

TEST(HttpServerTest, CaDescriptorReturnsNulloptWithNoServableBundle)
{
    TempCert cert; // leaf only; caCertificatePath is left at its default (empty: nothing configured)

    auto server = makeHttpServer();
    HttpServerConfig config;
    config.caPublicationRecordPath = ""; // not under test here (avoids the default var/run WARN, addendum §1)
    config.port = 0;
    config.certificatePath = cert.certPath();
    config.privateKeyPath = cert.keyPath();

    ASSERT_NO_THROW(server->start(config));

    // No CA configured at all is exactly the "no servable bundle" case: `null` on the wire, the
    // same value a manager whose bundle was emptied or is unreadable would answer with.
    EXPECT_FALSE(server->caDescriptor().generation.has_value());

    server->stop();
}

TEST(HttpServerTest, CaLeafSignerPemReturnsTheSigningCertificate)
{
    if (std::system("openssl version >/dev/null 2>&1") != 0)
    {
        GTEST_SKIP() << "openssl not available to generate the test PKI";
    }

    auto pki = remoted::test::generateCaSignedCertificate("httpserver_leaf_signer");
    if (!pki)
    {
        GTEST_SKIP() << "could not generate the throwaway CA-signed certificate";
    }
    remoted::test::ScratchFileCleanup cleanup {pki->files()};

    // The rotation case, through the transport: a sealed bundle of TWO CAs with the signer second.
    // What a 4.x agent may be handed mid-upgrade is one certificate out of that -- never the file,
    // which pkg_installer.sh would refuse for carrying more than one (issue #39319, C7).
    auto foreign = remoted::test::generateCaSignedCertificate("httpserver_leaf_signer_other");
    if (!foreign)
    {
        GTEST_SKIP() << "could not generate the second throwaway CA";
    }
    remoted::test::ScratchFileCleanup cleanupForeign {foreign->files()};

    const auto readAllBytes = [](const std::string& path)
    {
        std::ifstream in {path, std::ios::binary};
        return std::string {std::istreambuf_iterator<char> {in}, std::istreambuf_iterator<char> {}};
    };

    auto certificates = ca_bundle::parseBundle(readAllBytes(foreign->caCertPath)).certificates;
    for (auto& certificate : ca_bundle::parseBundle(readAllBytes(pki->caCertPath)).certificates)
    {
        certificates.push_back(std::move(certificate));
    }
    ASSERT_EQ(certificates.size(), 2U);

    ca_bundle::PublicationBlock block;
    block.publication = 1758000100;
    block.contentSha256 = ca_bundle::contentSha256(certificates);
    block.updated = "2026-09-19T00:00:00Z";
    block.writtenBy = "httpServerTest";
    {
        std::ofstream out {pki->caCertPath, std::ios::binary | std::ios::trunc};
        out << ca_bundle::renderBlock(block) << ca_bundle::serializeCertificates(certificates);
        ASSERT_FALSE(out.fail());
    }

    auto server = makeHttpServer();
    HttpServerConfig config;
    config.caPublicationRecordPath = ""; // not under test here (avoids the default var/run WARN, addendum §1)
    config.port = 0;
    config.certificatePath = pki->certPath;
    config.privateKeyPath = pki->keyPath;
    config.caCertificatePath = pki->caCertPath;

    ASSERT_NO_THROW(server->start(config));

    std::array<char, 8192> buffer {};
    const auto written = server->caLeafSignerPem(buffer.data(), buffer.size());
    ASSERT_GT(written, 0);

    const std::string delivered {buffer.data(), static_cast<std::size_t>(written)};
    EXPECT_EQ(delivered.find("##"), std::string::npos);
    std::size_t begins = 0;
    for (std::size_t at = delivered.find("-----BEGIN CERTIFICATE-----"); at != std::string::npos;
         at = delivered.find("-----BEGIN CERTIFICATE-----", at + 1))
    {
        ++begins;
    }
    EXPECT_EQ(begins, 1U);

    // And it is the signer, not merely "one of them": the whole bundle is still what /cacerts
    // serves, so a wrong pick here would be invisible to every other assertion.
    EXPECT_EQ(server->caCertificateSnapshot().certificates, 2U);

    const auto leaves = ca_bundle::parseBundle(readAllBytes(pki->certPath)).certificates;
    const auto deliveredCas = ca_bundle::parseBundle(delivered).certificates;
    ASSERT_FALSE(leaves.empty());
    ASSERT_EQ(deliveredCas.size(), 1U);
    EXPECT_TRUE(ca_bundle::anyCaSignsLeaf(leaves.front().get(), deliveredCas));

    server->stop();
}

TEST(HttpServerTest, CaLeafSignerPemReturnsZeroWithNoServableBundle)
{
    TempCert cert; // leaf only; caCertificatePath is left at its default (empty: nothing configured)

    auto server = makeHttpServer();
    HttpServerConfig config;
    config.caPublicationRecordPath = ""; // not under test here (avoids the default var/run WARN, addendum §1)
    config.port = 0;
    config.certificatePath = cert.certPath();
    config.privateKeyPath = cert.keyPath();

    // Before start() there is no source at all, and with nothing configured there never is one:
    // both answer 0 -- "nothing to deliver" -- rather than -1, so the legacy poller logs the reason
    // and lets the upgrade proceed without an anchor instead of reporting a buffer problem.
    std::array<char, 8192> buffer {};
    EXPECT_EQ(server->caLeafSignerPem(buffer.data(), buffer.size()), 0);

    ASSERT_NO_THROW(server->start(config));
    EXPECT_EQ(server->caLeafSignerPem(buffer.data(), buffer.size()), 0);

    server->stop();
}

// A read failure mid-flight (not just at start) is a window, not a decision: the monitor keeps
// ticking through it and the status keeps the last good verdict next to the fresh cause. What the
// tick LOGS on each pass is not observable from this binary (testLogRecorder.hpp), so this pins the
// state the status reports and that the monitor did not stop -- not the log line itself.
TEST(HttpServerTest, MonitorTickKeepsEvaluatingThroughAReadFailure)
{
    TempCert cert {10};

    // A copy of the leaf under its own path: TempCert's destructor removes cert.certPath() itself,
    // and the configured CA path below is about to be replaced by a directory, so it must not be
    // the same file the listener's own certificate lives at.
    const auto caPath = scratchPath("ca_monitor_tick");
    {
        std::ifstream in {cert.certPath(), std::ios::binary};
        std::ofstream out {caPath, std::ios::binary};
        out << in.rdbuf();
    }

    auto server = makeHttpServer();

    HttpServerConfig config;
    config.caPublicationRecordPath = ""; // not under test here (avoids the default var/run WARN, addendum §1)
    config.port = 0;
    config.certificatePath = cert.certPath();
    config.privateKeyPath = cert.keyPath();
    config.caCertificatePath = caPath;
    config.certificateStatusInterval = std::chrono::seconds {1};

    ASSERT_NO_THROW(server->start(config));
    EXPECT_EQ(server->certificateStatus().caMatchesLeaf, true);

    // Replace the CA file with a directory: same "open succeeds, read(2) fails EISDIR" case as
    // CaCertificateSource's own tests, observed here through the monitor's tick.
    ASSERT_EQ(std::remove(caPath.c_str()), 0);
    ASSERT_EQ(::mkdir(caPath.c_str(), 0700), 0);

    ASSERT_TRUE(waitForEvaluations(*server, 2, std::chrono::seconds {5}));
    const auto status = server->certificateStatus();
    ASSERT_TRUE(status.caReadFailure.has_value());
    EXPECT_EQ(status.caReadFailure->status, ReadStatus::ReadError);
    EXPECT_EQ(status.caReadFailure->error, EISDIR);
    EXPECT_EQ(status.caMatchesLeaf, true); // the last good verdict, kept through the failed read
    EXPECT_GE(status.evaluations, 2U);

    server->stop();
    ::rmdir(caPath.c_str());
}

// ---------------------------------------------------------------------------
// The publication record wired through start() (issue #39319, C21b): HttpServerConfig::
// onCaRecordReady is how a caller OUTSIDE the transport (the facade's GET /cacerts handler, stood
// in for here by draining the mailbox directly) gets at the CA source and its record events
// without IHttpServer growing a method for it.
// ---------------------------------------------------------------------------

TEST(HttpServerTest, MissingRecordDirectoryWarnsOnceAndKeepsServing)
{
    TempCert cert; // self-signed: its own CA, so the bundle is servable from the first read
    auto server = makeHttpServer();

    std::shared_ptr<CaCertificateSource> capturedSource;
    std::shared_ptr<CaRecordEventMailbox> capturedMailbox;

    HttpServerConfig config;
    config.port = 0;
    config.certificatePath = cert.certPath();
    config.privateKeyPath = cert.keyPath();
    config.caCertificatePath = cert.certPath();
    // Deliberately pointed at a directory that does not exist and is never created in this test:
    // ensureRecordDirectory() (best-effort) cannot create it either, since ITS parent is missing
    // too -- mkdir(2) is not recursive (by design, C25).
    config.caPublicationRecordPath = "/tmp/httpServerTest-no-such-directory-e2a/deeper/record.json";
    config.onCaRecordReady = [&capturedSource, &capturedMailbox](auto source, auto mailbox)
    {
        capturedSource = std::move(source);
        capturedMailbox = std::move(mailbox);
    };

    ASSERT_NO_THROW(server->start(config));
    ASSERT_TRUE(capturedSource != nullptr);
    ASSERT_TRUE(capturedMailbox != nullptr);

    // createTlsContext() already drained the FIRST event (first_time_unpublished, INFO, logged) and
    // then tried to flush it -- which is where the missing directory actually bites: exactly one
    // record_unwritable is left waiting for us, once per streak (C19/C19b).
    auto events = capturedMailbox->drain();
    ASSERT_EQ(events.size(), 1U);
    EXPECT_EQ(events[0].kind, remoted::http::RecordEvent::record_unwritable);
    EXPECT_FALSE(events[0].stored);
    EXPECT_NE(events[0].error, 0);

    // Keeps serving despite the record being unwritable: the bundle never depended on it.
    const auto snapshot = server->caCertificateSnapshot();
    EXPECT_GT(snapshot.certificates, 0U);
    EXPECT_FALSE(snapshot.pem.empty());

    // A second flush attempt fails again but is the SAME streak: no second warning.
    capturedSource->flushPendingRecord();
    EXPECT_TRUE(capturedMailbox->drain().empty());

    server->stop();
}

TEST(HttpServerTest, RestartSameServerStartsAFreshMailbox)
{
    TempCert cert;
    TempDir recordDir;

    // A separate file for the CA (never the listener's own certificate, which TempCert's
    // destructor removes and which start() needs to keep reading on every restart below).
    const auto caPath = scratchPath("restart_fresh_mailbox_ca");
    {
        std::ifstream in {cert.certPath(), std::ios::binary};
        std::ofstream out {caPath, std::ios::binary};
        out << in.rdbuf();
    }

    auto server = makeHttpServer();

    std::shared_ptr<CaCertificateSource> source1;
    std::shared_ptr<CaCertificateSource> source2;
    std::shared_ptr<CaRecordEventMailbox> mailbox1;
    std::shared_ptr<CaRecordEventMailbox> mailbox2;

    HttpServerConfig config;
    config.port = 0;
    config.certificatePath = cert.certPath();
    config.privateKeyPath = cert.keyPath();
    config.caCertificatePath = caPath;
    config.caPublicationRecordPath = recordDir.path() + "/record.json";
    config.onCaRecordReady = [&](auto source, auto mailbox)
    {
        if (!source1)
        {
            source1 = std::move(source);
            mailbox1 = std::move(mailbox);
        }
        else
        {
            source2 = std::move(source);
            mailbox2 = std::move(mailbox);
        }
    };

    ASSERT_NO_THROW(server->start(config));
    ASSERT_TRUE(source1 != nullptr);
    ASSERT_TRUE(mailbox1 != nullptr);
    // The start-time evaluation already drained its own first_time_unpublished event (INFO,
    // logged) before handing the mailbox to onCaRecordReady.
    EXPECT_TRUE(mailbox1->drain().empty());

    // A NEW event on the SAME (still running) source/mailbox, left deliberately undrained: the
    // ordinary CA file's bytes change (still no publication block), so this is changed_outside_tool.
    {
        std::ofstream out {caPath, std::ios::binary | std::ios::app};
        out << "\n";
    }
    // Forces the re-read that posts the event; deliberately NOT drained from here on -- the point
    // of this test is what a restart does (or does not do) to that undrained leftover.
    (void)server->caCertificateSnapshot();

    server->stop();
    ASSERT_NO_THROW(server->start(config));
    ASSERT_TRUE(source2 != nullptr);
    ASSERT_TRUE(mailbox2 != nullptr);

    // A genuinely NEW source and a genuinely NEW mailbox -- not the ones from before the restart.
    EXPECT_NE(source1.get(), source2.get());
    EXPECT_NE(mailbox1.get(), mailbox2.get());

    // The new cycle's own mailbox never saw the leftover event from the old one: nothing from the
    // previous cycle survives INTO the new one.
    EXPECT_TRUE(mailbox2->drain().empty());

    // And the leftover itself was never silently dropped either -- draining the OLD mailbox
    // directly still shows it, because nothing but drain() ever removes an event from it.
    const auto leftover = mailbox1->drain();
    ASSERT_EQ(leftover.size(), 1U);
    EXPECT_EQ(leftover[0].kind, remoted::http::RecordEvent::changed_outside_tool);

    server->stop();
    std::remove(caPath.c_str());
}

// ---------------------------------------------------------------------------
// ClientVerificationMode::Full, over a REAL connection
//
// This is the coverage the previous implementation lacked. It read the peer address with
// SSL_get_fd(), which returns -1 because asio wires the SSL object onto a BIO pair, so the check
// bailed out and rejected every certificate -- while unit tests that called the comparison
// directly with a synthetic certificate kept passing. Only a real handshake, from a real socket,
// distinguishes the two.
//
// Both cases below present a VALID certificate signed by the configured CA, so the chain check
// passes and what is being measured is purely the address requirement:
//   * a certificate listing 127.0.0.1 (where the client actually comes from) must be served
//   * a certificate listing some other address must be refused, on every route
// ---------------------------------------------------------------------------

namespace
{
    // A CA, a server certificate and two client certificates: one whose SAN carries the loopback
    // address the test client connects from, one whose SAN carries a different address. Built with
    // the `openssl` CLI, as TempCert above already does.
    class FullModePki
    {
    public:
        FullModePki()
        {
            char dirTemplate[] = "/tmp/httpServerFullModeXXXXXX";
            m_dir = mkdtemp(dirTemplate);

            run("openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=test-ca -keyout " + key("ca") + " -out " +
                cert("ca"));

            issue("server", "test-server", "IP:127.0.0.1,DNS:localhost");
            issue("matching", "agent-matching", "IP:127.0.0.1");
            issue("mismatched", "agent-mismatched", "IP:203.0.113.5");
        }

        ~FullModePki()
        {
            for (const auto* name : {"ca", "server", "matching", "mismatched"})
            {
                std::remove(cert(name).c_str());
                std::remove(key(name).c_str());
            }
            std::remove((m_dir + "/openssl.cnf").c_str());
            rmdir(m_dir.c_str());
        }

        std::string cert(const std::string& name) const
        {
            return m_dir + "/" + name + ".crt";
        }
        std::string key(const std::string& name) const
        {
            return m_dir + "/" + name + ".key";
        }

    private:
        void issue(const std::string& name, const std::string& commonName, const std::string& san)
        {
            // Written from C++ rather than through run(): that helper appends its own
            // ">/dev/null", which would be a SECOND stdout redirection and would silently leave
            // this file empty -- producing certificates with no SAN at all, and a test that fails
            // for a reason that has nothing to do with what it measures.
            const std::string extFile = m_dir + "/openssl.cnf";
            {
                std::ofstream extensions {extFile};
                extensions << "subjectAltName=" << san << "\nbasicConstraints=CA:FALSE\n";
                if (!extensions)
                {
                    ADD_FAILURE() << "could not write the OpenSSL extension file " << extFile;
                }
            }

            run("openssl req -newkey rsa:2048 -nodes -subj /CN=" + commonName + " -keyout " + key(name) + " -out " +
                m_dir + "/" + name + ".csr");
            run("openssl x509 -req -in " + m_dir + "/" + name + ".csr -days 1 -CA " + cert("ca") + " -CAkey " +
                key("ca") + " -CAcreateserial -extfile " + extFile + " -out " + cert(name));
            std::remove((m_dir + "/" + name + ".csr").c_str());
        }

        static void run(const std::string& command)
        {
            if (std::system((command + " >/dev/null 2>&1").c_str()) != 0)
            {
                ADD_FAILURE() << "PKI setup command failed: " << command;
            }
        }

        std::string m_dir;
    };

    // Sends `GET /` -- the unauthenticated liveness probe, chosen on purpose: if a rejected
    // connection were served anywhere, it would be here. Returns the HTTP status code, or 0 when
    // the exchange could not be completed at all.
    int getStatusWithClientCertificate(std::uint16_t port,
                                       const std::string& clientCert,
                                       const std::string& clientKey,
                                       const std::string& caCert)
    {
        try
        {
            asio::io_context ioc;
            asio::ssl::context sslContext {asio::ssl::context::tls_client};
            sslContext.set_verify_mode(asio::ssl::verify_none); // the server's identity is not what we measure
            sslContext.use_certificate_file(clientCert, asio::ssl::context::pem);
            sslContext.use_private_key_file(clientKey, asio::ssl::context::pem);
            sslContext.load_verify_file(caCert);

            asio::ssl::stream<asio::ip::tcp::socket> stream {ioc, sslContext};
            asio::ip::tcp::resolver resolver {ioc};
            asio::connect(stream.next_layer(), resolver.resolve("127.0.0.1", std::to_string(port)));
            stream.handshake(asio::ssl::stream_base::client);

            const std::string request = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
            asio::write(stream, asio::buffer(request));

            asio::streambuf response;
            asio::error_code ec;
            asio::read_until(stream, response, "\r\n", ec);

            std::istream stream_in {&response};
            std::string version;
            int status {0};
            stream_in >> version >> status;
            return status;
        }
        catch (const std::exception&)
        {
            return 0;
        }
    }

    // Two sequential requests on two connections, where the second RESUMES the first's TLS
    // session -- which is what a reverse proxy does by default. Returns each connection's status
    // (0 when the exchange could not be completed), plus whether the second one actually resumed:
    // if no session ticket ever arrived there is nothing to resume, and the pair of 200s would
    // prove nothing.
    struct ResumedExchange
    {
        int first {0};
        int second {0};
        bool resumed {false};
    };

    // In TLS 1.3 the session ticket is a post-handshake message, and OpenSSL's documented way to
    // get hold of a RESUMABLE session is this callback: SSL_get1_session() called after the
    // handshake hands back a session that predates the ticket and resumes nothing, which looks
    // exactly like a server that refuses to resume. Returning 1 takes ownership of the session.
    SSL_SESSION* g_capturedSession {nullptr};

    extern "C" int captureNewSession(SSL*, SSL_SESSION* session)
    {
        if (g_capturedSession != nullptr)
        {
            SSL_SESSION_free(g_capturedSession);
        }
        g_capturedSession = session;
        return 1;
    }

    ResumedExchange getStatusResumingSession(std::uint16_t port,
                                             const std::string& clientCert,
                                             const std::string& clientKey,
                                             const std::string& caCert)
    {
        ResumedExchange result;
        std::unique_ptr<SSL_SESSION, decltype(&SSL_SESSION_free)> session {nullptr, &SSL_SESSION_free};

        asio::ssl::context sslContext {asio::ssl::context::tls_client};
        sslContext.set_verify_mode(asio::ssl::verify_none);
        sslContext.use_certificate_file(clientCert, asio::ssl::context::pem);
        sslContext.use_private_key_file(clientKey, asio::ssl::context::pem);
        sslContext.load_verify_file(caCert);
        SSL_CTX_set_session_cache_mode(sslContext.native_handle(),
                                       SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
        SSL_CTX_sess_set_new_cb(sslContext.native_handle(), captureNewSession);
        if (g_capturedSession != nullptr)
        {
            SSL_SESSION_free(g_capturedSession);
            g_capturedSession = nullptr;
        }

        const auto exchange = [&](bool resume) -> int
        {
            try
            {
                asio::io_context ioc;
                asio::ssl::stream<asio::ip::tcp::socket> stream {ioc, sslContext};
                asio::ip::tcp::resolver resolver {ioc};
                asio::connect(stream.next_layer(), resolver.resolve("127.0.0.1", std::to_string(port)));

                if (resume && session)
                {
                    SSL_set_session(stream.native_handle(), session.get());
                }

                stream.handshake(asio::ssl::stream_base::client);

                if (resume)
                {
                    result.resumed = SSL_session_reused(stream.native_handle()) == 1;
                }

                // Keep-alive on purpose, where the other helpers in this file ask for
                // 'Connection: close'. Two reasons, both of which silently produce a session that
                // resumes nothing: in TLS 1.3 the ticket is a POST-handshake message that only
                // arrives once the server writes, and OpenSSL marks a session unresumable when
                // the connection ends without a clean shutdown -- which is exactly what asking
                // the server to close gets you here.
                const std::string request = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
                asio::write(stream, asio::buffer(request));

                asio::streambuf response;
                asio::error_code ec;
                asio::read_until(stream, response, "\r\n\r\n", ec);

                // Closed cleanly (close_notify) rather than just dropped: OpenSSL flags a session
                // as not-resumable when its connection ends without one, and it flags the very
                // object captured above, so an abrupt close here would quietly turn the session
                // collected a moment ago into one that cannot resume anything.
                asio::error_code shutdownError;
                stream.shutdown(shutdownError);

                if (!resume)
                {
                    session.reset(g_capturedSession);
                    g_capturedSession = nullptr;
                }

                std::istream stream_in {&response};
                std::string version;
                int status {0};
                stream_in >> version >> status;
                return status;
            }
            catch (const std::exception&)
            {
                return 0;
            }
        };

        result.first = exchange(/*resume=*/false);
        result.second = exchange(/*resume=*/true);
        return result;
    }

    HttpServerConfig fullModeConfig(const FullModePki& pki, std::uint16_t port)
    {
        HttpServerConfig config;
        config.caPublicationRecordPath = ""; // not under test here (avoids the default var/run WARN, addendum §1)
        config.bindAddress = "127.0.0.1";
        config.port = port;
        config.certificatePath = pki.cert("server");
        config.privateKeyPath = pki.key("server");
        config.caPath = pki.cert("ca");
        config.verificationMode = ClientVerificationMode::Full;
        return config;
    }
} // namespace

TEST(FullModeTest, CertificateListingThePeerAddressIsServed)
{
    if (std::system("openssl version >/dev/null 2>&1") != 0)
    {
        GTEST_SKIP() << "openssl not available to generate the test PKI";
    }

    FullModePki pki;
    auto server = makeHttpServer();
    const auto port = static_cast<std::uint16_t>(34517);

    server->addRoute(
        Method::Get,
        "/",
        [](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> responder)
        { responder->send(HttpResponse::json(200, R"({"status":"ok"})")); },
        /*countAgainstBudget=*/false);

    ASSERT_NO_THROW(server->start(fullModeConfig(pki, port)));

    EXPECT_EQ(getStatusWithClientCertificate(port, pki.cert("matching"), pki.key("matching"), pki.cert("ca")), 200)
        << "a client certificate listing the address the client connects from must be accepted; "
           "before this was fixed, the peer address could not be read at all and every certificate "
           "was rejected";

    server->stop();
}

TEST(FullModeTest, CertificateListingAnotherAddressIsRefusedOnEveryRoute)
{
    if (std::system("openssl version >/dev/null 2>&1") != 0)
    {
        GTEST_SKIP() << "openssl not available to generate the test PKI";
    }

    FullModePki pki;
    auto server = makeHttpServer();
    const auto port = static_cast<std::uint16_t>(34518);

    // The unauthenticated liveness probe: the route most likely to leak a rejected connection.
    server->addRoute(
        Method::Get,
        "/",
        [](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> responder)
        { responder->send(HttpResponse::json(200, R"({"status":"ok"})")); },
        /*countAgainstBudget=*/false);

    ASSERT_NO_THROW(server->start(fullModeConfig(pki, port)));

    EXPECT_EQ(getStatusWithClientCertificate(port, pki.cert("mismatched"), pki.key("mismatched"), pki.cert("ca")), 403)
        << "the certificate is valid and signed by the CA, but lists 203.0.113.5 while the client "
           "connects from 127.0.0.1: Full mode must refuse it";

    server->stop();
}

// ---------------------------------------------------------------------------
// TLS session resumption while client certificates are required
//
// OpenSSL refuses to resume a session whose peer presented a certificate unless the server has
// declared a session id context, and it refuses FATALLY: the resumed handshake is aborted with an
// 'internal error' alert rather than falling back to a full one. Reverse proxies resume by
// default, so without that context every connection a proxy opens after the first one fails and
// the agents behind it see intermittent 502s.
//
// Covered for BOTH modes that request certificates: the defect belonged to the TLS context, not
// to the peer-address check, so Certificate was affected exactly as much as Full.
// ---------------------------------------------------------------------------

namespace
{
    void expectResumptionIsServed(ClientVerificationMode mode, std::uint16_t port)
    {
        if (std::system("openssl version >/dev/null 2>&1") != 0)
        {
            GTEST_SKIP() << "openssl not available to generate the test PKI";
        }

        FullModePki pki;
        auto server = makeHttpServer();

        server->addRoute(
            Method::Get,
            "/",
            [](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> responder)
            { responder->send(HttpResponse::json(200, R"({"status":"ok"})")); },
            /*countAgainstBudget=*/false);

        auto config = fullModeConfig(pki, port);
        config.verificationMode = mode;
        ASSERT_NO_THROW(server->start(config));

        const auto exchange = getStatusResumingSession(port, pki.cert("matching"), pki.key("matching"), pki.cert("ca"));

        EXPECT_EQ(exchange.first, 200) << "the first connection is an ordinary full handshake";
        EXPECT_TRUE(exchange.resumed) << "the second connection did not resume the first one's session, so this "
                                         "test would pass without measuring anything";
        EXPECT_EQ(exchange.second, 200) << "a resumed session must be served: without a session id context OpenSSL "
                                           "aborts this handshake with an 'internal error' alert";

        server->stop();
    }
} // namespace

TEST(TlsSessionResumptionTest, ResumedSessionIsServedWithCertificateMode)
{
    expectResumptionIsServed(ClientVerificationMode::Certificate, 34519);
}

TEST(TlsSessionResumptionTest, ResumedSessionIsServedWithFullMode)
{
    expectResumptionIsServed(ClientVerificationMode::Full, 34520);
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
    config.caPublicationRecordPath = ""; // not under test here (avoids the default var/run WARN, addendum §1)
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
    config.caPublicationRecordPath = ""; // not under test here (avoids the default var/run WARN, addendum §1)
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

// diagnostics() is the source of the remoted.server.budget.* pull metrics: all zeros before
// start() (the documented quiescent value), live budget state while running. Auxiliary
// reservations (tryReserveInFlightBytes()) belong to already-admitted requests, so they must show
// up ONLY as bytes -- never as in-flight requests, and their refusal is never a shed.
TEST(HttpServerTest, DiagnosticsReportZerosBeforeStartAndTrackTheBudgetAfter)
{
    constexpr std::size_t MiB = 1024U * 1024U;
    TempCert cert;
    auto server = makeHttpServer();

    auto d = server->diagnostics();
    EXPECT_EQ(d.budgetAvailableBytes, 0U);
    EXPECT_EQ(d.budgetInFlightBytes, 0U);
    EXPECT_EQ(d.budgetInFlightCount, 0U);
    EXPECT_EQ(d.budgetRejectedTotal, 0U);
    EXPECT_EQ(d.connectionsOpen, 0U);
    EXPECT_EQ(d.connectionsMax, 0U); // no ceiling reported until one is configured

    HttpServerConfig config;
    config.caPublicationRecordPath = ""; // not under test here (avoids the default var/run WARN, addendum §1)
    config.port = 0; // ephemeral
    config.certificatePath = cert.certPath();
    config.privateKeyPath = cert.keyPath();
    // Same clamp-avoidance as the reservation test above: keep the configured capacity in charge.
    config.maxBodySize = 1U * MiB;
    config.maxInFlightBytes = 50U * MiB;

    ASSERT_NO_THROW(server->start(config));

    d = server->diagnostics();
    EXPECT_EQ(d.budgetAvailableBytes, 50U * MiB);
    EXPECT_EQ(d.budgetInFlightBytes, 0U);
    EXPECT_EQ(d.budgetInFlightCount, 0U);
    EXPECT_EQ(d.budgetRejectedTotal, 0U);
    EXPECT_EQ(d.connectionsOpen, 0U);                           // nobody has connected yet
    EXPECT_EQ(d.connectionsMax, config.maxParallelConnections); // the ceiling actually in force

    {
        auto reservation = server->tryReserveInFlightBytes(10U * MiB);
        ASSERT_TRUE(reservation.has_value());
        EXPECT_FALSE(server->tryReserveInFlightBytes(50U * MiB).has_value()); // refused, not shed

        d = server->diagnostics();
        EXPECT_EQ(d.budgetAvailableBytes, 40U * MiB);
        EXPECT_EQ(d.budgetInFlightBytes, 10U * MiB);
        EXPECT_EQ(d.budgetInFlightCount, 0U); // auxiliary bytes are not requests
        EXPECT_EQ(d.budgetRejectedTotal, 0U); // and refusing them turned no request away
    }

    server->stop();

    d = server->diagnostics();
    EXPECT_EQ(d.budgetAvailableBytes, 50U * MiB); // reservation released
    EXPECT_EQ(d.budgetInFlightCount, 0U);
    EXPECT_EQ(d.budgetRejectedTotal, 0U);
}

// The shed total moves only when the transport refuses to ADMIT a request, so driving it takes a
// real one: hold the whole budget through an auxiliary reservation, watch an actual request
// bounce off admission with a 503 without its handler ever running, and -- because the budget
// survives a normal stop() -- see the cumulative total still reported afterwards, which is what
// lets the facade's final stop() dump report it.
TEST(HttpServerTest, DiagnosticsCountARealAdmissionShed)
{
    constexpr std::size_t MiB = 1024U * 1024U;
    TempCert cert;
    std::atomic_bool handlerRan {false}; // declared before the server: its route holds a reference
    auto server = makeHttpServer();

    server->addRoute(
        Method::Post,
        "/events",
        [&handlerRan](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> responder)
        {
            handlerRan = true;
            responder->send(HttpResponse::json(200, "{}"));
        },
        /*countAgainstBudget=*/true,
        ResponseMode::Buffered);

    HttpServerConfig config;
    config.caPublicationRecordPath = ""; // not under test here (avoids the default var/run WARN, addendum §1)
    config.port = static_cast<std::uint16_t>(26000 + (::getpid() % 5000));
    config.certificatePath = cert.certPath();
    config.privateKeyPath = cert.keyPath();
    config.maxBodySize = 1U * MiB;
    config.maxInFlightBytes = 50U * MiB;

    ASSERT_NO_THROW(server->start(config));

    auto whole = server->tryReserveInFlightBytes(50U * MiB);
    ASSERT_TRUE(whole.has_value()); // the budget is now fully held

    const auto raw = remoted::test::sendSignedRequest(config.port, remoted::test::testAgentKey(), "/events", "{}");
    whole.reset();
    server->stop();

    ASSERT_FALSE(raw.empty()) << "no response from the server";
    const auto [head, body] = remoted::test::splitResponse(raw);
    EXPECT_NE(head.find("503"), std::string::npos) << head;
    EXPECT_FALSE(handlerRan.load()) << "a shed request must never reach its route handler";

    const auto d = server->diagnostics();
    EXPECT_EQ(d.budgetRejectedTotal, 1U); // exactly the one refused admission
    EXPECT_EQ(d.budgetInFlightCount, 0U);
    EXPECT_EQ(d.budgetAvailableBytes, 50U * MiB);
}

// The connection ceiling is the one capacity limit that rejects nothing when reached (RESTinio
// postpones the accept), so `connectionsOpen` is the ONLY evidence an operator gets that it is being
// approached -- and it is fed by a RESTinio state-listener callback, not by our own request path. A
// listener that is never notified would leave it reading 0 forever and nothing else would notice,
// which is exactly what this test exists to catch: it drives a real TLS connection and requires the
// counter to have moved while the handler was running.
TEST(HttpServerTest, DiagnosticsCountARealConnection)
{
    constexpr std::size_t MiB = 1024U * 1024U;
    TempCert cert;
    std::atomic<std::size_t> openDuringRequest {0};
    auto server = makeHttpServer();
    auto* serverPtr = server.get();

    server->addRoute(
        Method::Post,
        "/events",
        [serverPtr, &openDuringRequest](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> responder)
        {
            // Sampled from inside the handler: the connection serving this very request is open, so
            // the count cannot legitimately be 0 here.
            openDuringRequest = serverPtr->diagnostics().connectionsOpen;
            responder->send(HttpResponse::json(200, "{}"));
        },
        /*countAgainstBudget=*/true,
        ResponseMode::Buffered);

    HttpServerConfig config;
    config.caPublicationRecordPath = ""; // not under test here (avoids the default var/run WARN, addendum §1)
    config.port = static_cast<std::uint16_t>(21000 + (::getpid() % 5000));
    config.certificatePath = cert.certPath();
    config.privateKeyPath = cert.keyPath();
    config.maxBodySize = 1U * MiB;
    config.maxInFlightBytes = 50U * MiB;
    config.maxParallelConnections = 64U;

    ASSERT_NO_THROW(server->start(config));
    EXPECT_EQ(server->diagnostics().connectionsMax, 64U);

    const auto raw = remoted::test::sendSignedRequest(config.port, remoted::test::testAgentKey(), "/events", "{}");
    ASSERT_FALSE(raw.empty()) << "no response from the server";

    EXPECT_GE(openDuringRequest.load(), 1U) << "the state listener never counted the live connection";

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
    config.caPublicationRecordPath = ""; // not under test here (avoids the default var/run WARN, addendum §1)
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
    config.caPublicationRecordPath = ""; // not under test here (avoids the default var/run WARN, addendum §1)
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
    config.caPublicationRecordPath = ""; // not under test here (avoids the default var/run WARN, addendum §1)
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
    config.caPublicationRecordPath = ""; // not under test here (avoids the default var/run WARN, addendum §1)
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
    config.caPublicationRecordPath = ""; // not under test here (avoids the default var/run WARN, addendum §1)
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

// ---------------------------------------------------------------------------
// Global endpoint prefix (issue #38491)
// ---------------------------------------------------------------------------

// The canonicalization contract of HttpServerConfig::globalPrefix, exercised without sockets.
// The single runtime call site is RestinioHttpServer::start().
TEST(NormalizeGlobalPrefixTest, IdentityForms)
{
    EXPECT_EQ(normalizeGlobalPrefix(""), "");
    EXPECT_EQ(normalizeGlobalPrefix("/"), "");
    EXPECT_EQ(normalizeGlobalPrefix("///"), "");
}

TEST(NormalizeGlobalPrefixTest, CanonicalForms)
{
    EXPECT_EQ(normalizeGlobalPrefix("/wazuh-manager"), "/wazuh-manager");
    EXPECT_EQ(normalizeGlobalPrefix("/wazuh-manager/"), "/wazuh-manager");
    EXPECT_EQ(normalizeGlobalPrefix("/p///"), "/p");
    EXPECT_EQ(normalizeGlobalPrefix("/edge/wazuh-5"), "/edge/wazuh-5");
    EXPECT_EQ(normalizeGlobalPrefix("/v5.0_beta~1"), "/v5.0_beta~1");
    // Defensive: the C-side validator requires the leading '/', but a directly-constructed
    // config gets the same canonical form instead of a corrupted concatenation.
    EXPECT_EQ(normalizeGlobalPrefix("wazuh-manager"), "/wazuh-manager");
}

TEST(NormalizeGlobalPrefixTest, EmptyInteriorSegmentThrows)
{
    EXPECT_THROW(normalizeGlobalPrefix("/a//b"), std::invalid_argument);
}

TEST(NormalizeGlobalPrefixTest, InvalidCharactersThrow)
{
    for (const auto* bad : {"/p x", "/p?x", "/p#f", "/p:id", "/p(x)", "/p*", "/p%2F", "/p+q", "/p\\q"})
    {
        EXPECT_THROW(normalizeGlobalPrefix(bad), std::invalid_argument) << "accepted: " << bad;
    }
}

namespace
{
    // Real TLS server with a RAW ("/wazuh-manager/", trailing slash on purpose: start() must
    // normalize) global prefix and UNPREFIXED route registrations -- the transport applies the
    // prefix. No auth: routing is what this suite measures; the signed path is
    // globalPrefixE2E_test.cpp's job.
    class GlobalPrefixTransportTest : public ::testing::Test
    {
    protected:
        void SetUp() override
        {
            if (std::system("openssl version >/dev/null 2>&1") != 0)
            {
                GTEST_SKIP() << "openssl not available to generate the test certificate";
            }
            m_cert = remoted::test::generateTestCertificate("global_prefix_transport");
            if (!m_cert)
            {
                GTEST_SKIP() << "could not generate a throwaway TLS certificate";
            }
            m_cleanup = std::make_unique<remoted::test::ScratchFileCleanup>(
                std::vector<std::string> {m_cert->certPath, m_cert->keyPath});
        }

        // Starts a fresh server with the given raw prefix and the two canonical routes.
        void startServer(const std::string& rawPrefix)
        {
            m_port = static_cast<std::uint16_t>(29000 + (::getpid() % 4000) + m_portOffset++);
            m_server = makeHttpServer();
            m_server->addRoute(
                Method::Get,
                "/",
                [](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> r)
                { r->send(HttpResponse::json(200, R"({"status":"ok"})")); },
                /*countAgainstBudget=*/false);
            // Echoes the target the handler observed: with the prefix in effect it must be the
            // RAW prefixed target (the transport never rewrites it -- the auth layer signs it).
            m_server->addRoute(Method::Post,
                               "/echo",
                               [](std::shared_ptr<const HttpRequest> request, std::shared_ptr<IHttpResponder> r)
                               { r->send(HttpResponse::json(200, request->target)); });

            HttpServerConfig config;
            config.caPublicationRecordPath = ""; // not under test here (avoids the default var/run WARN, addendum §1)
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

        static int statusOf(const std::string& rawResponse)
        {
            const auto space = rawResponse.find(' ');
            if (space == std::string::npos || space + 4 > rawResponse.size())
            {
                return 0;
            }
            return std::atoi(rawResponse.c_str() + space + 1);
        }

        std::string post(const std::string& target)
        {
            return remoted::test::sendRawOverTls(m_port,
                                                 "POST " + target +
                                                     " HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: "
                                                     "0\r\nConnection: close\r\n\r\n");
        }

        std::uint16_t m_port {0};
        int m_portOffset {0};
        std::shared_ptr<IHttpServer> m_server;
        std::optional<remoted::test::TestCertificate> m_cert;
        std::unique_ptr<remoted::test::ScratchFileCleanup> m_cleanup;
    };
} // namespace

TEST_F(GlobalPrefixTransportTest, PrefixedRoutesAnswerAndTargetStaysRaw)
{
    startServer("/wazuh-manager/"); // raw form: start() must normalize the trailing slash

    EXPECT_EQ(statusOf(remoted::test::sendGetRequest(m_port, "/wazuh-manager/")), 200);

    const auto echoed = post("/wazuh-manager/echo?a=1&b=2");
    EXPECT_EQ(statusOf(echoed), 200);
    // The query survives and the target is the raw PREFIXED one -- never rewritten (D1).
    EXPECT_NE(echoed.find("/wazuh-manager/echo?a=1&b=2"), std::string::npos) << echoed;
}

TEST_F(GlobalPrefixTransportTest, UnprefixedPathsAnswer404)
{
    startServer("/wazuh-manager/");

    const auto health = remoted::test::sendGetRequest(m_port, "/");
    EXPECT_EQ(statusOf(health), 404);
    EXPECT_NE(health.find(R"({"error":"not_found"})"), std::string::npos) << health;

    EXPECT_EQ(statusOf(post("/echo")), 404);
}

TEST_F(GlobalPrefixTransportTest, HealthAnswersBothSpellingsUnderPrefix)
{
    startServer("/wazuh-manager/");

    // Pinned RESTinio behavior (routerSemanticsSpike_test.cpp S2/S9): the "/" route is
    // registered as the BARE prefix, so both spellings -- and a query -- answer.
    EXPECT_EQ(statusOf(remoted::test::sendGetRequest(m_port, "/wazuh-manager")), 200);
    EXPECT_EQ(statusOf(remoted::test::sendGetRequest(m_port, "/wazuh-manager/")), 200);
    EXPECT_EQ(statusOf(remoted::test::sendGetRequest(m_port, "/wazuh-manager?probe=1")), 200);
}

TEST_F(GlobalPrefixTransportTest, CaseVariantMatches)
{
    startServer("/wazuh-manager/");

    // Pinned RESTinio behavior (spike S3): express matching is case-insensitive. Same surface
    // as today -- on authenticated routes the MAC covers the real bytes either way.
    EXPECT_EQ(statusOf(remoted::test::sendGetRequest(m_port, "/WAZUH-MANAGER/")), 200);
}

TEST_F(GlobalPrefixTransportTest, PercentEncodedSpellingsRouteButTheTargetStaysRaw)
{
    startServer("/wazuh-manager/");

    // Pinned RESTinio behavior: the express router percent-DECODES ordinary bytes before
    // matching ("%2D" == '-', so this spelling routes), while an encoded slash ("%2F") never
    // becomes a path separator (spike S5, and the second assertion below). Predates the prefix
    // -- it applies to every route equally -- and is harmless under the verbatim-MAC contract:
    // the handler-observed target stays the RAW encoded bytes, so the MAC covers exactly what
    // was sent either way.
    const auto encoded = post("/wazuh%2Dmanager/echo");
    EXPECT_EQ(statusOf(encoded), 200);
    EXPECT_NE(encoded.find("/wazuh%2Dmanager/echo"), std::string::npos)
        << "the transport must never hand the decoded spelling to handlers/auth: " << encoded;

    EXPECT_EQ(statusOf(post("/wazuh-manager%2Fecho")), 404);
}

TEST_F(GlobalPrefixTransportTest, IdentityPrefixBehavesAsToday)
{
    for (const auto* identity : {"", "/"})
    {
        startServer(identity);

        EXPECT_EQ(statusOf(remoted::test::sendGetRequest(m_port, "/")), 200) << "prefix: '" << identity << "'";
        EXPECT_EQ(statusOf(remoted::test::sendGetRequest(m_port, "/wazuh-manager/")), 404)
            << "prefix: '" << identity << "'";

        const auto echoed = post("/echo?x=1");
        EXPECT_EQ(statusOf(echoed), 200) << "prefix: '" << identity << "'";
        EXPECT_NE(echoed.find("/echo?x=1"), std::string::npos) << echoed;

        m_server->stop();
    }
}

TEST_F(GlobalPrefixTransportTest, StartWithInvalidPrefixThrowsAndStaysStopped)
{
    m_port = static_cast<std::uint16_t>(29000 + (::getpid() % 4000) + 500);
    m_server = makeHttpServer();
    m_server->addRoute(Method::Get,
                       "/",
                       [](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> r)
                       { r->send(HttpResponse::json(200, "{}")); });

    HttpServerConfig config;
    config.caPublicationRecordPath = ""; // not under test here (avoids the default var/run WARN, addendum §1)
    config.port = m_port;
    config.certificatePath = m_cert->certPath;
    config.privateKeyPath = m_cert->keyPath;
    config.globalPrefix = "/bad prefix";

    EXPECT_THROW(m_server->start(config), std::invalid_argument);

    // Same discipline as StartWithMissingCertificateThrowsAndStaysStopped: a failed start leaves
    // a stoppable, restartable server.
    EXPECT_NO_THROW(m_server->stop());
    config.globalPrefix = "/wazuh-manager";
    ASSERT_NO_THROW(m_server->start(config));
    EXPECT_EQ(statusOf(remoted::test::sendGetRequest(m_port, "/wazuh-manager/")), 200);
}
