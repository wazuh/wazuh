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
 * plaintext + HC_VERIFY_NONE (to isolate the CMAC interop), so this is where
 * the fail-closed TLS policy of #37828 is proven end to end -- both that a
 * trusted cert is accepted and that an untrusted one is rejected (so the
 * positive case cannot be passing with verification silently off).
 */

#include "cmacSigner.hpp"
#include "curlHandle.hpp"
#include "curlPerformer.hpp"
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
    const std::string KEY_HEX = "000102030405060708090a0b0c0d0e0f";

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
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                   reinterpret_cast<const unsigned char*>("127.0.0.1"), -1, -1, 0);
        X509_set_issuer_name(cert, name);
        addExtension(cert, NID_basic_constraints, "critical,CA:TRUE");
        addExtension(cert, NID_subject_alt_name, "IP:127.0.0.1");
        X509_sign(cert, pkey, EVP_sha256());
        *keyOut = pkey;
        *certOut = cert;
    }

    // Writes a cert as PEM to a unique temp path so a client can trust it as a
    // CA. Returns the path (empty on failure).
    std::string writeCertPem(X509* cert, const std::string& tag)
    {
        const std::string path =
            ::testing::TempDir() + "hc_tls_" + tag + "_" + std::to_string(::getpid()) + ".crt";
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
            TlsServer(X509* cert, EVP_PKEY* key, uint16_t port)
                : m_server(cert, key)
            {
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

    HttpResponse sendSigned(CurlPerformer& performer, const CmacSigner& signer,
                            const std::string& body)
    {
        const auto headers = signer.sign("POST", "/stateless",
                                         reinterpret_cast<const uint8_t*>(body.data()), body.size(),
                                         SystemClock {}.wallSeconds());
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
    CmacSigner signer {"001", keyProvider};
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
    CmacSigner signer {"001", keyProvider};
    CurlPerformer performer {config, defaultCurlHandleFactory()};

    const auto response = sendSigned(performer, signer, "H {}\nE 1:l:tls\n");
    EXPECT_EQ(TransportStatus::TlsFail, response.status); // Untrusted: no HTTP status reached.

    std::remove(wrongCaPath.c_str());
}
