/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 23, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/*
 * Real TLS verification over the actual curl path: HC_VERIFY_FULL against a
 * CA file on disk, with a genuine handshake to an in-process TLS server whose
 * certificate carries a matching SAN. The rest of the component suite runs
 * plaintext + HC_VERIFY_NONE (to isolate the bearer interop), so this is where
 * the fail-closed TLS policy of #37828 is proven end to end -- both that a
 * trusted cert is accepted and that an untrusted one is rejected (so the
 * positive case cannot be passing with verification silently off).
 */

#include "curlHandle.hpp"
#include "curlPerformer.hpp"
#include "jwtSigner.hpp"
#include "keyProvider.hpp"
#include "moduleConfig.hpp"
#include "sysSeams.hpp"

#include "external/cpp-httplib/httplib.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <gtest/gtest.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <thread>

#include <unistd.h>

namespace
{
    const std::string KEY_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    void addExtension(X509* cert, int nid, const char* value)
    {
        X509V3_CTX ctx;
        X509V3_set_ctx_nodb(&ctx);
        X509V3_set_ctx(&ctx, cert, cert, nullptr, nullptr, 0);
        X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value);

        if (ext != nullptr)
        {
            X509_add_ext(cert, ext, -1);
            X509_EXTENSION_free(ext);
        }
    }

    // A self-signed cert usable as its own CA: CA:TRUE so it validates as a
    // trust anchor, and SAN IP:127.0.0.1 so full (hostname) verification of a
    // request to 127.0.0.1 passes.
    void makeSelfSigned(EVP_PKEY** keyOut, X509** certOut)
    {
        EVP_PKEY* pkey = EVP_RSA_gen(2048);
        X509* cert = X509_new();
        ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
        X509_gmtime_adj(X509_get_notBefore(cert), 0);
        X509_gmtime_adj(X509_get_notAfter(cert), 60L * 60L);
        X509_set_pubkey(cert, pkey);
        X509_NAME* name = X509_get_subject_name(cert);
        X509_NAME_add_entry_by_txt(
            name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("127.0.0.1"), -1, -1, 0);
        X509_set_issuer_name(cert, name);
        addExtension(cert, NID_basic_constraints, "critical,CA:TRUE");
        addExtension(cert, NID_subject_alt_name, "IP:127.0.0.1");
        X509_sign(cert, pkey, EVP_sha256());
        *keyOut = pkey;
        *certOut = cert;
    }

    // A self-signed CA with a caller-chosen, distinct CN -- unlike makeSelfSigned() (which
    // hardcodes CN=127.0.0.1 for every caller, fine when each test only ever uses ONE such
    // cert as the peer's own leaf identity, but wrong when a test needs several DIFFERENT CA
    // certs to coexist in the same verification: OpenSSL's issuer lookup during chain
    // building matches by subject NAME, not by key, so two unrelated self-signed CAs sharing
    // the identical name (both "CN=127.0.0.1") can cause OpenSSL to pick the wrong one as a
    // certificate's presumed issuer, surfacing as a bogus X509_V_ERR_CERT_SIGNATURE_FAILURE
    // instead of the actual untrusted-issuer error the test means to exercise). No SAN: only
    // ever used as a CA in a chain, never dialed directly as the peer's own leaf identity.
    void makeSelfSignedCa(const char* commonName, EVP_PKEY** keyOut, X509** certOut)
    {
        EVP_PKEY* pkey = EVP_RSA_gen(2048);
        X509* cert = X509_new();
        ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
        X509_gmtime_adj(X509_get_notBefore(cert), 0);
        X509_gmtime_adj(X509_get_notAfter(cert), 60L * 60L);
        X509_set_pubkey(cert, pkey);
        X509_NAME* name = X509_get_subject_name(cert);
        X509_NAME_add_entry_by_txt(
            name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(commonName), -1, -1, 0);
        X509_set_issuer_name(cert, name);
        addExtension(cert, NID_basic_constraints, "critical,CA:TRUE");
        X509_sign(cert, pkey, EVP_sha256());
        *keyOut = pkey;
        *certOut = cert;
    }

    // A leaf genuinely signed by the given CA (unlike makeSelfSigned(), issuer/signer is
    // caKey, not the leaf's own key), with a caller-chosen SAN -- lets a test build a
    // perfectly valid chain for the wrong identity. notBefore/notAfter default to "valid
    // now, for an hour" (the original shape); the date-failure tests below override them
    // to isolate a certificate-validity-period failure from the hostname check.
    void makeCaSignedLeaf(X509* caCert, EVP_PKEY* caKey, const char* san, EVP_PKEY** keyOut, X509** certOut,
                          long notBeforeOffsetSeconds = 0, long notAfterOffsetSeconds = 60L * 60L)
    {
        EVP_PKEY* pkey = EVP_RSA_gen(2048);
        X509* cert = X509_new();
        ASN1_INTEGER_set(X509_get_serialNumber(cert), 2);
        X509_gmtime_adj(X509_get_notBefore(cert), notBeforeOffsetSeconds);
        X509_gmtime_adj(X509_get_notAfter(cert), notAfterOffsetSeconds);
        X509_set_pubkey(cert, pkey);
        X509_NAME* name = X509_get_subject_name(cert);
        X509_NAME_add_entry_by_txt(
            name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("leaf"), -1, -1, 0);
        X509_set_issuer_name(cert, X509_get_subject_name(caCert));
        addExtension(cert, NID_subject_alt_name, san);
        X509_sign(cert, caKey, EVP_sha256());
        *keyOut = pkey;
        *certOut = cert;
    }

    // Writes a cert as PEM to a unique temp path so a client can trust it as a
    // CA. Returns the path (empty on failure).
    std::string writeCertPem(X509* cert, const std::string& tag)
    {
        const std::string path = ::testing::TempDir() + "hc_tls_" + tag + "_" + std::to_string(::getpid()) + ".crt";
        std::FILE* file = std::fopen(path.c_str(), "wb");

        if (file == nullptr)
        {
            return {};
        }

        PEM_write_X509(file, cert);
        std::fclose(file);
        return path;
    }

    // An in-process TLS server (own thread) that answers /stateless with 200.
    // The payload is irrelevant here -- a 200 proves the client completed the
    // verified handshake; a verification failure would surface as TlsFail
    // before any HTTP status.
    class TlsServer
    {
        public:
            // extraChainCert, when given, is appended after `cert` via SSL_CTX_add1_chain_cert,
            // which bumps its own refcount -- the caller still owns/frees its X509* like every
            // other cert here (e.g. a genuine CA an attacker leaf doesn't actually chain up to).
            TlsServer(X509* cert, EVP_PKEY* key, uint16_t port, X509* extraChainCert = nullptr)
                : m_server(cert, key)
            {
                if (extraChainCert != nullptr)
                {
                    SSL_CTX_add1_chain_cert(m_server.ssl_context(), extraChainCert);
                }

                m_server.Post("/stateless",
                              [](const httplib::Request&, httplib::Response & response)
                {
                    response.status = 200;
                    response.set_content("ok", "text/plain");
                });
                m_thread = std::thread([this, port] { m_server.listen("127.0.0.1", port); });
                waitUntilReady(port);
            }

            ~TlsServer()
            {
                m_server.stop();

                if (m_thread.joinable())
                {
                    m_thread.join();
                }
            }

            TlsServer(const TlsServer&) = delete;
            TlsServer& operator=(const TlsServer&) = delete;

        private:
            static void waitUntilReady(uint16_t port)
            {
                httplib::Client probe {"https://127.0.0.1:" + std::to_string(port)};
                probe.enable_server_certificate_verification(false);

                for (int attempt = 0; attempt < 200; attempt++)
                {
                    if (auto result = probe.Post("/stateless"))
                    {
                        return;
                    }

                    usleep(20 * 1000);
                }
            }

            httplib::SSLServer m_server;
            std::thread m_thread;
    };

    ModuleConfig tlsFullConfig(uint16_t port, const std::string& caPath)
    {
        hc_config_t config {};
        std::strncpy(config.server_host, "127.0.0.1", sizeof(config.server_host) - 1);
        config.server_port = port;
        std::strncpy(config.agent_id, "001", sizeof(config.agent_id) - 1);
        config.verify_mode = HC_VERIFY_FULL; // Verify the peer AND the hostname.
        std::strncpy(config.ca_path, caPath.c_str(), sizeof(config.ca_path) - 1);
        config.request_timeout_ms = 3000;
        config.backoff_base_ms = 10;
        config.backoff_cap_ms = 50;
        return ModuleConfig::fromC(config); // scheme stays "https".
    }

    // verify_mode=system never sets ca_path (validateTls rejects a config that
    // does, see moduleConfig_test.cpp) -- the trust anchor comes from an
    // injected IFsProbe instead, below.
    // fallbackCaPath: #39123's local-anchor fallback (empty -> not configured, today's
    // behavior; CurlPerformer never retries past what the OS bundle stand-in decides).
    ModuleConfig tlsSystemConfig(uint16_t port, const std::string& fallbackCaPath = "")
    {
        hc_config_t config {};
        std::strncpy(config.server_host, "127.0.0.1", sizeof(config.server_host) - 1);
        config.server_port = port;
        std::strncpy(config.agent_id, "001", sizeof(config.agent_id) - 1);
        config.verify_mode = HC_VERIFY_SYSTEM;
        config.request_timeout_ms = 3000;
        config.backoff_base_ms = 10;
        config.backoff_cap_ms = 50;

        if (!fallbackCaPath.empty())
        {
            std::strncpy(config.system_fallback_ca_path, fallbackCaPath.c_str(),
                         sizeof(config.system_fallback_ca_path) - 1);
        }

        return ModuleConfig::fromC(config);
    }

    // Stands in for "the OS trust store" without touching the real one: points
    // findSystemCaBundle() at a file this test controls, so the real curl/OpenSSL
    // handshake exercises the actual verify_mode=system code path end to end
    // (CurlPerformer's constructor resolution -> applyTrustAnchors -> CURLOPT_CAINFO)
    // without needing root or mutating the test machine's real CA store.
    class FixedFsProbe final : public IFsProbe
    {
        public:
            explicit FixedFsProbe(std::string bundlePath)
                : m_bundlePath(std::move(bundlePath))
            {
            }

            bool isReadableFile(const std::string&) const override
            {
                return true;
            }

            std::string findSystemCaBundle() const override
            {
                return m_bundlePath;
            }

        private:
            std::string m_bundlePath;
    };

    HttpResponse sendSigned(CurlPerformer& performer, const JwtSigner& signer, const std::string& body)
    {
        const auto headers = signer.sign(SystemClock {}.wallSeconds());
        HttpRequestSpec spec;
        spec.target = "/stateless";
        spec.body = reinterpret_cast<const uint8_t*>(body.data());
        spec.bodyLength = body.size();
        spec.timeoutMs = 3000;
        spec.headers = {headers->protocolVersion, headers->authorization};
        return performer.perform(spec);
    }
} // namespace

TEST(TlsVerificationTest, FullVerificationAgainstAMatchingCaCompletesTheHandshake)
{
    constexpr uint16_t port = 44857;
    EVP_PKEY* key = nullptr;
    X509* cert = nullptr;
    makeSelfSigned(&key, &cert);
    const std::string caPath = writeCertPem(cert, "trusted");
    ASSERT_FALSE(caPath.empty());

    TlsServer server {cert, key, port};
    X509_free(cert);
    EVP_PKEY_free(key);

    const auto config = tlsFullConfig(port, caPath);
    ConfigKeyProvider keyProvider {KEY_HEX};
    JwtSigner signer {"001", keyProvider};
    CurlPerformer performer {config, defaultCurlHandleFactory()};

    const auto response = sendSigned(performer, signer, "H {}\nE 1:l:tls\n");
    EXPECT_EQ(TransportStatus::Ok, response.status); // Handshake verified: CA + hostname.
    EXPECT_EQ(200, response.httpCode);

    std::remove(caPath.c_str());
}

TEST(TlsVerificationTest, FullVerificationRejectsAnUntrustedCertificate)
{
    constexpr uint16_t port = 44858;
    // The server presents cert A; the client is told to trust an unrelated
    // cert B as its only CA. Full verification must fail the handshake --
    // proving the positive test is not passing with verification disabled.
    EVP_PKEY* serverKey = nullptr;
    X509* serverCert = nullptr;
    makeSelfSigned(&serverKey, &serverCert);

    EVP_PKEY* otherKey = nullptr;
    X509* otherCert = nullptr;
    makeSelfSigned(&otherKey, &otherCert);
    const std::string wrongCaPath = writeCertPem(otherCert, "untrusted");
    ASSERT_FALSE(wrongCaPath.empty());

    TlsServer server {serverCert, serverKey, port};
    X509_free(serverCert);
    EVP_PKEY_free(serverKey);
    X509_free(otherCert);
    EVP_PKEY_free(otherKey);

    const auto config = tlsFullConfig(port, wrongCaPath);
    ConfigKeyProvider keyProvider {KEY_HEX};
    JwtSigner signer {"001", keyProvider};
    CurlPerformer performer {config, defaultCurlHandleFactory()};

    const auto response = sendSigned(performer, signer, "H {}\nE 1:l:tls\n");
    EXPECT_EQ(TransportStatus::TlsFail, response.status); // Untrusted: no HTTP status reached.
    // Not one of the two classified causes: proves the hostname-mismatch elimination fallback
    // (chain clean + CURLE_PEER_FAILED_VERIFICATION => HostnameMismatch) does NOT misfire here,
    // where the chain itself is what failed. Also #39123's isUnclassifiedChainFailure() sees
    // this exact shape (TlsFail + kind==None) as the one verify_mode=system's local-anchor
    // fallback may act on.
    EXPECT_EQ(TlsFailureKind::None, response.tlsFailure.kind);

    std::remove(wrongCaPath.c_str());
}

// A self-signed leaf with the genuine trusted CA appended alongside it in the chain: a
// verifier that merely checks whether the trusted CA's bytes appear somewhere in the sent
// chain (instead of validating the signature path from leaf to root) would wrongly accept
// this, since the leaf's signature only verifies against its own key.
TEST(TlsVerificationTest, FullVerificationRejectsASelfSignedLeafWithTheGenuineCaAppended)
{
    constexpr uint16_t port = 44861;
    EVP_PKEY* caKey = nullptr;
    X509* caCert = nullptr;
    makeSelfSigned(&caKey, &caCert);
    const std::string caPath = writeCertPem(caCert, "genuine");
    ASSERT_FALSE(caPath.empty());

    // Unrelated to caCert/caKey: its own self-signed identity, never touches the CA's key.
    EVP_PKEY* attackerKey = nullptr;
    X509* attackerCert = nullptr;
    makeSelfSigned(&attackerKey, &attackerCert);

    // The server's certificate is the attacker's leaf; the genuine CA rides along as an
    // extra chain cert, exactly as an attacker hoping for a presence-only check would send it.
    TlsServer server {attackerCert, attackerKey, port, caCert};
    X509_free(attackerCert);
    EVP_PKEY_free(attackerKey);
    X509_free(caCert);
    EVP_PKEY_free(caKey);

    const auto config = tlsFullConfig(port, caPath);
    ConfigKeyProvider keyProvider {KEY_HEX};
    JwtSigner signer {"001", keyProvider};
    CurlPerformer performer {config, defaultCurlHandleFactory()};

    const auto response = sendSigned(performer, signer, "H {}\nE 1:l:tls\n");
    EXPECT_EQ(TransportStatus::TlsFail, response.status);
    // Same elimination-fallback concern as FullVerificationRejectsAnUntrustedCertificate above:
    // this must not read as a hostname mismatch, since the identity check never even runs on a
    // chain that fails first.
    EXPECT_EQ(TlsFailureKind::None, response.tlsFailure.kind);

    std::remove(caPath.c_str());
}

// A perfectly valid chain (leaf genuinely signed by the trusted CA) for an identity other
// than the one dialed -- isolates the hostname check from the chain check, since a valid
// signature chain alone must not be sufficient.
TEST(TlsVerificationTest, FullVerificationRejectsACaSignedCertForTheWrongHostname)
{
    constexpr uint16_t port = 44862;
    EVP_PKEY* caKey = nullptr;
    X509* caCert = nullptr;
    makeSelfSigned(&caKey, &caCert);
    const std::string caPath = writeCertPem(caCert, "wronghost_ca");
    ASSERT_FALSE(caPath.empty());

    // Genuinely signed by caKey, but SAN'd for a different address than the one this test
    // connects to (127.0.0.1) -- the chain is entirely valid, only the identity disagrees.
    EVP_PKEY* leafKey = nullptr;
    X509* leafCert = nullptr;
    makeCaSignedLeaf(caCert, caKey, "IP:10.0.0.99", &leafKey, &leafCert);

    TlsServer server {leafCert, leafKey, port};
    X509_free(leafCert);
    EVP_PKEY_free(leafKey);
    X509_free(caCert);
    EVP_PKEY_free(caKey);

    const auto config = tlsFullConfig(port, caPath);
    ConfigKeyProvider keyProvider {KEY_HEX};
    JwtSigner signer {"001", keyProvider};
    CurlPerformer performer {config, defaultCurlHandleFactory()};

    const auto response = sendSigned(performer, signer, "H {}\nE 1:l:tls\n");
    EXPECT_EQ(TransportStatus::TlsFail, response.status);
    // #39062 objective requirement 6: a name mismatch is classified (and, in curlHandle.cpp,
    // logged at normal level) rather than reading as a generic Unreachable/TlsFail -- the chain
    // was entirely valid, so this proves the classifier is not just echoing a chain failure.
    EXPECT_EQ(TlsFailureKind::HostnameMismatch, response.tlsFailure.kind);
    // The dialed address (127.0.0.1) is not among the leaf's SANs -- only the one this leaf
    // was actually minted for.
    ASSERT_EQ(1u, response.tlsFailure.certNames.size());
    EXPECT_EQ("IP Address:10.0.0.99", response.tlsFailure.certNames.front());

    std::remove(caPath.c_str());
}

// Isolates a certificate-date failure from both the chain and hostname checks: a leaf
// genuinely signed by the trusted CA, correctly SAN'd for the dialed address, whose notBefore
// is still in the future.
TEST(TlsVerificationTest, FullVerificationRejectsACertificateNotYetValid)
{
    constexpr uint16_t port = 44863;
    EVP_PKEY* caKey = nullptr;
    X509* caCert = nullptr;
    makeSelfSigned(&caKey, &caCert);
    const std::string caPath = writeCertPem(caCert, "notyetvalid_ca");
    ASSERT_FALSE(caPath.empty());

    // notBefore one day from now, notAfter two days from now: a well-formed window, just not
    // open yet.
    EVP_PKEY* leafKey = nullptr;
    X509* leafCert = nullptr;
    makeCaSignedLeaf(caCert, caKey, "IP:127.0.0.1", &leafKey, &leafCert, 24L * 60L * 60L, 48L * 60L * 60L);

    TlsServer server {leafCert, leafKey, port};
    X509_free(leafCert);
    EVP_PKEY_free(leafKey);
    X509_free(caCert);
    EVP_PKEY_free(caKey);

    const auto config = tlsFullConfig(port, caPath);
    ConfigKeyProvider keyProvider {KEY_HEX};
    JwtSigner signer {"001", keyProvider};
    CurlPerformer performer {config, defaultCurlHandleFactory()};

    const auto response = sendSigned(performer, signer, "H {}\nE 1:l:tls\n");
    EXPECT_EQ(TransportStatus::TlsFail, response.status);
    EXPECT_EQ(TlsFailureKind::CertNotYetValid, response.tlsFailure.kind);
    EXPECT_FALSE(response.tlsFailure.notBefore.empty());

    std::remove(caPath.c_str());
}

// As above, isolating the opposite date failure: a leaf whose notAfter has already passed.
TEST(TlsVerificationTest, FullVerificationRejectsAnExpiredCertificate)
{
    constexpr uint16_t port = 44864;
    EVP_PKEY* caKey = nullptr;
    X509* caCert = nullptr;
    makeSelfSigned(&caKey, &caCert);
    const std::string caPath = writeCertPem(caCert, "expired_ca");
    ASSERT_FALSE(caPath.empty());

    // notBefore two days ago, notAfter one day ago: a well-formed window that already closed.
    EVP_PKEY* leafKey = nullptr;
    X509* leafCert = nullptr;
    makeCaSignedLeaf(caCert, caKey, "IP:127.0.0.1", &leafKey, &leafCert, -48L * 60L * 60L, -24L * 60L * 60L);

    TlsServer server {leafCert, leafKey, port};
    X509_free(leafCert);
    EVP_PKEY_free(leafKey);
    X509_free(caCert);
    EVP_PKEY_free(caKey);

    const auto config = tlsFullConfig(port, caPath);
    ConfigKeyProvider keyProvider {KEY_HEX};
    JwtSigner signer {"001", keyProvider};
    CurlPerformer performer {config, defaultCurlHandleFactory()};

    const auto response = sendSigned(performer, signer, "H {}\nE 1:l:tls\n");
    EXPECT_EQ(TransportStatus::TlsFail, response.status);
    EXPECT_EQ(TlsFailureKind::CertExpired, response.tlsFailure.kind);
    EXPECT_FALSE(response.tlsFailure.notAfter.empty());

    std::remove(caPath.c_str());
}

// verify_mode=system's Linux path (an injected OS-bundle stand-in, per FixedFsProbe
// above) is not meaningful on Windows/macOS, which trust their native store instead
// (see openssl-vendoring.md / questions.md: proven there by manual VM evidence, not
// a component test that would otherwise have to fake out a real OS certificate store).
#if !defined(WIN32) && !defined(__APPLE__)

TEST(TlsVerificationTest, SystemVerificationAgainstAnOsTrustedCaCompletesTheHandshake)
{
    constexpr uint16_t port = 44859;
    EVP_PKEY* key = nullptr;
    X509* cert = nullptr;
    makeSelfSigned(&key, &cert);
    const std::string bundlePath = writeCertPem(cert, "system_trusted");
    ASSERT_FALSE(bundlePath.empty());

    TlsServer server {cert, key, port};
    X509_free(cert);
    EVP_PKEY_free(key);

    const auto config = tlsSystemConfig(port);
    ConfigKeyProvider keyProvider {KEY_HEX};
    JwtSigner signer {"001", keyProvider};
    FixedFsProbe fsProbe {bundlePath};
    CurlPerformer performer {config, defaultCurlHandleFactory(), fsProbe};

    const auto response = sendSigned(performer, signer, "H {}\nE 1:l:tls\n");
    // Proves the real code path, not just the config: no certificate_authorities was
    // ever set (tlsSystemConfig leaves ca_path empty) -- the CA came entirely from
    // CurlPerformer resolving it through the injected "OS bundle" at construction.
    EXPECT_EQ(TransportStatus::Ok, response.status);
    EXPECT_EQ(200, response.httpCode);

    std::remove(bundlePath.c_str());
}

TEST(TlsVerificationTest, SystemVerificationRejectsACertificateNotInTheOsBundle)
{
    constexpr uint16_t port = 44860;
    // Same shape as FullVerificationRejectsAnUntrustedCertificate: the server
    // presents cert A, but the "OS bundle" the agent is told to trust only has
    // unrelated cert B -- system must fail closed exactly like full does.
    EVP_PKEY* serverKey = nullptr;
    X509* serverCert = nullptr;
    makeSelfSigned(&serverKey, &serverCert);

    EVP_PKEY* otherKey = nullptr;
    X509* otherCert = nullptr;
    makeSelfSigned(&otherKey, &otherCert);
    const std::string bundlePath = writeCertPem(otherCert, "system_untrusted");
    ASSERT_FALSE(bundlePath.empty());

    TlsServer server {serverCert, serverKey, port};
    X509_free(serverCert);
    EVP_PKEY_free(serverKey);
    X509_free(otherCert);
    EVP_PKEY_free(otherKey);

    const auto config = tlsSystemConfig(port);
    ConfigKeyProvider keyProvider {KEY_HEX};
    JwtSigner signer {"001", keyProvider};
    FixedFsProbe fsProbe {bundlePath};
    CurlPerformer performer {config, defaultCurlHandleFactory(), fsProbe};

    const auto response = sendSigned(performer, signer, "H {}\nE 1:l:tls\n");
    // TlsFail + kind==None (#39123's isUnclassifiedChainFailure()) is the one outcome the
    // fallback below can act on. No system_fallback_ca_path is set here, so there is nothing
    // to fall back to and this is the final result, exactly like today.
    EXPECT_EQ(TransportStatus::TlsFail, response.status);
    EXPECT_EQ(TlsFailureKind::None, response.tlsFailure.kind);

    std::remove(bundlePath.c_str());
}

// #39123: the OS bundle stand-in does not know the server's certificate, but a fallback
// anchor that does is configured -- CurlPerformer must retry against it transparently
// (one warning, no operator action) instead of leaving the connection unverified or failing.
TEST(TlsVerificationTest, SystemVerificationFallsBackToTheLocalAnchorWhenTheOsBundleDoesNotVerify)
{
    constexpr uint16_t port = 44863;
    EVP_PKEY* serverKey = nullptr;
    X509* serverCert = nullptr;
    makeSelfSigned(&serverKey, &serverCert);
    const std::string fallbackPath = writeCertPem(serverCert, "system_fallback_trusted");
    ASSERT_FALSE(fallbackPath.empty());

    EVP_PKEY* otherKey = nullptr;
    X509* otherCert = nullptr;
    makeSelfSigned(&otherKey, &otherCert);
    const std::string bundlePath = writeCertPem(otherCert, "system_fallback_os_bundle");
    ASSERT_FALSE(bundlePath.empty());

    TlsServer server {serverCert, serverKey, port};
    X509_free(serverCert);
    EVP_PKEY_free(serverKey);
    X509_free(otherCert);
    EVP_PKEY_free(otherKey);

    const auto config = tlsSystemConfig(port, fallbackPath);
    ConfigKeyProvider keyProvider {KEY_HEX};
    JwtSigner signer {"001", keyProvider};
    FixedFsProbe fsProbe {bundlePath};
    CurlPerformer performer {config, defaultCurlHandleFactory(), fsProbe};

    const auto response = sendSigned(performer, signer, "H {}\nE 1:l:tls\n");
    EXPECT_EQ(TransportStatus::Ok, response.status);
    EXPECT_EQ(200, response.httpCode);

    // Latched: a second request must dial the fallback anchor directly, never the OS
    // bundle again, and still succeed.
    const auto secondResponse = sendSigned(performer, signer, "H {}\nE 1:l:tls\n");
    EXPECT_EQ(TransportStatus::Ok, secondResponse.status);

    std::remove(fallbackPath.c_str());
    std::remove(bundlePath.c_str());
}

// #39123: neither the OS bundle nor the fallback anchor verifies the server -- the result
// must still be a verification failure (never a silent unverified connection), so the
// caller's normal fail-closed handling applies. The LOGFN_CRITICAL this path also emits is
// a safe no-op in this test binary (GLOBAL_LOG_FUNCTION is never assigned, see
// tests/unit/main.cpp/tests/component/main.cpp) -- only the real agent's bridge wires it to
// mtLoggingFunctionsWrapper's exit(1).
TEST(TlsVerificationTest, SystemVerificationFailsWhenNeitherTheOsBundleNorTheFallbackAnchorVerify)
{
    constexpr uint16_t port = 44864;
    EVP_PKEY* serverKey = nullptr;
    X509* serverCert = nullptr;
    makeSelfSigned(&serverKey, &serverCert);

    EVP_PKEY* bundleKey = nullptr;
    X509* bundleCert = nullptr;
    makeSelfSigned(&bundleKey, &bundleCert);
    const std::string bundlePath = writeCertPem(bundleCert, "system_both_fail_os_bundle");
    ASSERT_FALSE(bundlePath.empty());

    EVP_PKEY* fallbackKey = nullptr;
    X509* fallbackCert = nullptr;
    makeSelfSigned(&fallbackKey, &fallbackCert);
    const std::string fallbackPath = writeCertPem(fallbackCert, "system_both_fail_fallback");
    ASSERT_FALSE(fallbackPath.empty());

    TlsServer server {serverCert, serverKey, port};
    X509_free(serverCert);
    EVP_PKEY_free(serverKey);
    X509_free(bundleCert);
    EVP_PKEY_free(bundleKey);
    X509_free(fallbackCert);
    EVP_PKEY_free(fallbackKey);

    const auto config = tlsSystemConfig(port, fallbackPath);
    ConfigKeyProvider keyProvider {KEY_HEX};
    JwtSigner signer {"001", keyProvider};
    FixedFsProbe fsProbe {bundlePath};
    CurlPerformer performer {config, defaultCurlHandleFactory(), fsProbe};

    const auto response = sendSigned(performer, signer, "H {}\nE 1:l:tls\n");
    EXPECT_EQ(TransportStatus::TlsFail, response.status);
    EXPECT_EQ(TlsFailureKind::None, response.tlsFailure.kind);

    std::remove(bundlePath.c_str());
    std::remove(fallbackPath.c_str());
}

// #39123 follow-up (contrarian-reviewer round): every other CURLE_SSL_CACERT_BADFILE-related
// assertion lives in curlPerformer_test.cpp against a MockCurlHandle with caFileLoadFailed()
// scripted by hand -- that proves CurlPerformer::perform()'s branching is correct GIVEN that
// value, not that curlHandle.cpp's real perform() actually produces it from a real curl/
// OpenSSL failure. This test closes that gap: the fallback anchor path names a file that is
// not a certificate at all, so the real load happens against real curl/OpenSSL, exactly the
// way an admin's corrupted/partially-written AGENT_ANCHOR_CA would fail in production.
TEST(TlsVerificationTest, SystemVerificationFailsClosedWhenTheFallbackAnchorFileIsCorrupt)
{
    constexpr uint16_t port = 44869;
    EVP_PKEY* serverKey = nullptr;
    X509* serverCert = nullptr;
    makeSelfSigned(&serverKey, &serverCert);

    EVP_PKEY* bundleKey = nullptr;
    X509* bundleCert = nullptr;
    makeSelfSigned(&bundleKey, &bundleCert);
    const std::string bundlePath = writeCertPem(bundleCert, "system_corrupt_fallback_os_bundle");
    ASSERT_FALSE(bundlePath.empty());

    // Not a certificate: real curl/OpenSSL rejects this at load time
    // (CURLE_SSL_CACERT_BADFILE), before any handshake or verify callback runs.
    const std::string fallbackPath =
        ::testing::TempDir() + "hc_tls_system_corrupt_fallback_" + std::to_string(::getpid()) + ".crt";
    std::FILE* corruptFile = std::fopen(fallbackPath.c_str(), "wb");
    ASSERT_NE(nullptr, corruptFile);
    std::fputs("not a certificate", corruptFile);
    std::fclose(corruptFile);

    TlsServer server {serverCert, serverKey, port};
    X509_free(serverCert);
    EVP_PKEY_free(serverKey);
    X509_free(bundleCert);
    EVP_PKEY_free(bundleKey);

    const auto config = tlsSystemConfig(port, fallbackPath);
    ConfigKeyProvider keyProvider {KEY_HEX};
    JwtSigner signer {"001", keyProvider};
    FixedFsProbe fsProbe {bundlePath};
    CurlPerformer performer {config, defaultCurlHandleFactory(), fsProbe};

    const auto response = sendSigned(performer, signer, "H {}\nE 1:l:tls\n");
    EXPECT_EQ(TransportStatus::TlsFail, response.status);
    EXPECT_TRUE(response.caFileLoadFailed);
    // Confirms isCaFileLoadFailure() is what caught this, not isUnclassifiedChainFailure():
    // a bad CA file is rejected before OpenSSL's verify callback ever runs, so no
    // certificate was ever inspected for this (the fallback) attempt.
    EXPECT_FALSE(response.tlsFailure.sawDepth0);

    std::remove(bundlePath.c_str());
    std::remove(fallbackPath.c_str());
}

// #39123 follow-up: this used to pin a KNOWN LIMITATION (contrarian-reviewer round) where the
// fallback never engaged here at all. The #39123 fallback used to be gated on sawDepth0 alone
// (curlPerformer.cpp's isUnclassifiedChainFailure()), which is only ever set true when
// OpenSSL's verify callback actually reaches the leaf (depth 0) certificate. For a
// single-certificate chain (every other test in this suite), an untrusted root is discovered
// exactly there, so sawDepth0 is true and the fallback gets its chance. For a
// MULTI-certificate chain (leaf + intermediate, as a manager fronted by a subordinate CA
// would present), OpenSSL's build_chain()/verify_chain()
// (src/external/openssl/crypto/x509/x509_vfy.c) can reject the chain at the intermediate's
// depth (>0) and return before internal_verify() ever runs depth 0 at all -- so sawDepth0
// stayed false and the fallback anchor was never even attempted, even though it was
// configured here to correctly trust the intermediate CA that actually signed the leaf.
// Fixed by capturing a chain-trust rejection at ANY depth (curlHandle.cpp's
// isChainBuildingTrustFailure(), TlsFailureDetail::chainTrustRejectedAboveDepth0), which
// isUnclassifiedChainFailure() now accepts as a second, independent path alongside the
// original sawDepth0-based one. This test now pins the fixed behavior instead of the
// limitation.
TEST(TlsVerificationTest, SystemVerificationFallsBackWhenTheUntrustedCaIsAnIntermediateNotTheLeaf)
{
    constexpr uint16_t port = 44865;

    // The intermediate CA that actually signs the leaf below -- and the exact CA the
    // fallback anchor is configured to trust, further down. A distinct CN
    // ("intermediate-ca", not the 127.0.0.1 every makeSelfSigned() cert shares): OpenSSL's
    // issuer lookup during chain building matches by subject name, and this test
    // deliberately has THREE different self-signed CAs in play (this one, the OS bundle
    // stand-in, and none other here) -- sharing a name across them would let OpenSSL's chain
    // builder pick the wrong one as a candidate issuer regardless of which key actually
    // signed the leaf, producing a bogus signature-failure instead of exercising the
    // untrusted-issuer path this test means to reach.
    EVP_PKEY* intermediateKey = nullptr;
    X509* intermediateCert = nullptr;
    makeSelfSignedCa("intermediate-ca", &intermediateKey, &intermediateCert);
    const std::string fallbackPath = writeCertPem(intermediateCert, "system_chain_depth_fallback");
    ASSERT_FALSE(fallbackPath.empty());

    EVP_PKEY* leafKey = nullptr;
    X509* leafCert = nullptr;
    makeCaSignedLeaf(intermediateCert, intermediateKey, "IP:127.0.0.1", &leafKey, &leafCert);

    // An OS bundle that trusts neither the intermediate nor the leaf -- unrelated to both,
    // like every other "the OS store does not vouch for this manager" test above. A distinct
    // CN from intermediate-ca, for the same reason.
    EVP_PKEY* bundleKey = nullptr;
    X509* bundleCert = nullptr;
    makeSelfSignedCa("os-bundle-ca", &bundleKey, &bundleCert);
    const std::string bundlePath = writeCertPem(bundleCert, "system_chain_depth_os_bundle");
    ASSERT_FALSE(bundlePath.empty());

    // The server presents BOTH the leaf and the intermediate that signed it -- a manager
    // fronted by a subordinate CA, not the single-certificate shape every other test here
    // uses.
    TlsServer server {leafCert, leafKey, port, /*extraChainCert=*/intermediateCert};
    X509_free(leafCert);
    EVP_PKEY_free(leafKey);
    X509_free(intermediateCert);
    EVP_PKEY_free(intermediateKey);
    X509_free(bundleCert);
    EVP_PKEY_free(bundleKey);

    const auto config = tlsSystemConfig(port, fallbackPath);
    ConfigKeyProvider keyProvider {KEY_HEX};
    JwtSigner signer {"001", keyProvider};
    FixedFsProbe fsProbe {bundlePath};
    CurlPerformer performer {config, defaultCurlHandleFactory(), fsProbe};

    const auto response = sendSigned(performer, signer, "H {}\nE 1:l:tls\n");

    // The fallback anchor (the intermediate CA) verifies this exact leaf, so the overall
    // attempt now succeeds -- even though OpenSSL never reaches depth 0's internal_verify()
    // against the OS bundle attempt at all. Real curl error observed on THAT first attempt
    // while writing this test: "(60) ... self-signed certificate in certificate chain (19)"
    // -- OpenSSL rejects the untrusted intermediate at ITS OWN depth (1), confirming
    // sawDepth0 stays false for that attempt rather than just assuming it from
    // source-reading alone; chainTrustRejectedAboveDepth0 is what catches it instead.
    EXPECT_EQ(TransportStatus::Ok, response.status);
    EXPECT_EQ(200, response.httpCode);

    std::remove(fallbackPath.c_str());
    std::remove(bundlePath.c_str());
}

#endif // !defined(WIN32) && !defined(__APPLE__)
