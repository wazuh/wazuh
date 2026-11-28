/*
 * Wazuh indexer client
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

// Self-tests of the fake's TLS side: the material factory, the HTTPS and mTLS servers, the
// TLS 1.1 cap and the decoded Authorization header, driven by cpp-httplib's own SSLClient.

#include "fakeIndexer.hpp"
#include "tlsMaterialFactory.hpp"

#include "httplib.h"
#include <gtest/gtest.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <chrono>
#include <filesystem>
#include <memory>
#include <string>
#include <utility>
#include <vector>

using indexer_client::testing::FakeIndexer;
using indexer_client::testing::FakeIndexerOptions;
using indexer_client::testing::FakeTlsOptions;
using indexer_client::testing::Rule;
using indexer_client::testing::TlsMaterialFactory;
using namespace std::chrono_literals;

namespace
{
    using CertPtr = std::unique_ptr<X509, decltype(&X509_free)>;
    using KeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;

    std::vector<CertPtr> readCertificates(const std::string& file)
    {
        std::vector<CertPtr> certificates;
        std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new_file(file.c_str(), "r"), &BIO_free);
        if (bio == nullptr)
        {
            return certificates;
        }
        while (X509* cert = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr))
        {
            certificates.emplace_back(cert, &X509_free);
        }
        ERR_clear_error();
        return certificates;
    }

    KeyPtr readKey(const std::string& file, const char* passphrase = nullptr)
    {
        std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new_file(file.c_str(), "r"), &BIO_free);
        if (bio == nullptr)
        {
            return {nullptr, &EVP_PKEY_free};
        }
        // A null callback with null userdata would prompt on the terminal; a failing callback never does.
        pem_password_cb* failing = [](char*, int, int, void*) -> int
        {
            return -1;
        };
        KeyPtr key(PEM_read_bio_PrivateKey(
                       bio.get(), nullptr, passphrase != nullptr ? nullptr : failing, const_cast<char*>(passphrase)),
                   &EVP_PKEY_free);
        ERR_clear_error();
        return key;
    }

    /// Verifies @p leaf (plus @p untrusted intermediates) against the CA file @p caFile.
    bool chainsTo(X509* leaf, const std::vector<X509*>& untrusted, const std::string& caFile)
    {
        std::unique_ptr<X509_STORE, decltype(&X509_STORE_free)> store(X509_STORE_new(), &X509_STORE_free);
        if (X509_STORE_load_file(store.get(), caFile.c_str()) != 1)
        {
            ERR_clear_error();
            return false;
        }
        const auto freeStack = [](STACK_OF(X509) * stack)
        {
            sk_X509_free(stack); // a macro: no address to take
        };
        std::unique_ptr<STACK_OF(X509), decltype(freeStack)> chain(sk_X509_new_null(), freeStack);
        for (X509* cert : untrusted)
        {
            sk_X509_push(chain.get(), cert);
        }
        std::unique_ptr<X509_STORE_CTX, decltype(&X509_STORE_CTX_free)> ctx(X509_STORE_CTX_new(), &X509_STORE_CTX_free);
        X509_STORE_CTX_init(ctx.get(), store.get(), leaf, chain.get());
        const bool ok = X509_verify_cert(ctx.get()) == 1;
        ERR_clear_error();
        return ok;
    }

    std::unique_ptr<FakeIndexer> startFake(FakeTlsOptions tls)
    {
        FakeIndexerOptions options;
        options.tls = std::move(tls);
        auto fake = std::make_unique<FakeIndexer>(std::move(options));
        fake->start();
        return fake;
    }

    void bound(httplib::SSLClient& client)
    {
        client.set_connection_timeout(std::chrono::seconds(5));
        client.set_read_timeout(std::chrono::seconds(5));
    }

    /// An SSLClient that trusts @p caFile, optionally presenting the pair (@p certificate, @p key) as a chain file.
    std::unique_ptr<httplib::SSLClient> makeClient(const FakeIndexer& fake,
                                                   const std::string& caFile,
                                                   const std::string& certificate = {},
                                                   const std::string& key = {})
    {
        auto client = std::make_unique<httplib::SSLClient>("127.0.0.1", fake.port());
        bound(*client);
        client->set_ca_cert_path(caFile);
        if (!certificate.empty())
        {
            SSL_CTX* context = static_cast<SSL_CTX*>(client->tls_context());
            EXPECT_EQ(SSL_CTX_use_certificate_chain_file(context, certificate.c_str()), 1);
            EXPECT_EQ(SSL_CTX_use_PrivateKey_file(context, key.c_str(), SSL_FILETYPE_PEM), 1);
        }
        return client;
    }

    class FakeTlsTest : public ::testing::Test
    {
    protected:
        TlsMaterialFactory m_material;

        FakeTlsOptions serverTls() const
        {
            return FakeTlsOptions {m_material.serverCertificate(), m_material.serverKey(), {}, false};
        }

        FakeTlsOptions mutualTls() const
        {
            return FakeTlsOptions {
                m_material.serverCertificate(), m_material.serverKey(), m_material.caCertificate(), false};
        }
    };
} // namespace

TEST_F(FakeTlsTest, FactoryWritesAbsolutePathsInItsOwnDirectoryAndRemovesIt)
{
    std::string directory;
    {
        TlsMaterialFactory material;
        directory = material.directory();
        ASSERT_TRUE(std::filesystem::path(directory).is_absolute());
        ASSERT_TRUE(std::filesystem::is_directory(directory));
        for (const auto& file : {material.caCertificate(),
                                 material.otherCaCertificate(),
                                 material.caBundleOtherThenGood(),
                                 material.serverCertificate(),
                                 material.serverKey(),
                                 material.wrongNameServerCertificate(),
                                 material.wrongNameServerKey(),
                                 material.clientCertificate(),
                                 material.clientKey(),
                                 material.intermediateCaCertificate(),
                                 material.chainCertificate(),
                                 material.chainKey(),
                                 material.encryptedClientKey(),
                                 material.otherKey(),
                                 material.malformedCa(),
                                 material.emptyFile(),
                                 material.keyOnlyPem()})
        {
            EXPECT_TRUE(std::filesystem::path(file).is_absolute()) << file;
            EXPECT_EQ(std::filesystem::path(file).parent_path(), std::filesystem::path(directory)) << file;
            EXPECT_TRUE(std::filesystem::is_regular_file(file)) << file;
        }
        EXPECT_NE(TlsMaterialFactory().directory(), directory);
    }
    EXPECT_FALSE(std::filesystem::exists(directory));
}

TEST_F(FakeTlsTest, FactoryMaterialHasTheAdvertisedProperties)
{
    const auto ca = readCertificates(m_material.caCertificate());
    const auto otherCa = readCertificates(m_material.otherCaCertificate());
    ASSERT_EQ(ca.size(), 1U);
    ASSERT_EQ(otherCa.size(), 1U);
    EXPECT_EQ(X509_check_ca(ca[0].get()), 1);
    EXPECT_NE(X509_cmp(ca[0].get(), otherCa[0].get()), 0);
    EXPECT_TRUE(chainsTo(ca[0].get(), {}, m_material.caCertificate()));
    EXPECT_FALSE(chainsTo(otherCa[0].get(), {}, m_material.caCertificate()));

    const auto bundle = readCertificates(m_material.caBundleOtherThenGood());
    ASSERT_EQ(bundle.size(), 2U);
    EXPECT_EQ(X509_cmp(bundle[0].get(), otherCa[0].get()), 0);
    EXPECT_EQ(X509_cmp(bundle[1].get(), ca[0].get()), 0);

    // Server: SAN IP 127.0.0.1, by the good CA; the wrong-name one: SAN DNS only, also by the good CA.
    const auto server = readCertificates(m_material.serverCertificate());
    ASSERT_EQ(server.size(), 1U);
    EXPECT_EQ(X509_check_ip_asc(server[0].get(), "127.0.0.1", 0), 1);
    EXPECT_TRUE(chainsTo(server[0].get(), {}, m_material.caCertificate()));
    EXPECT_FALSE(chainsTo(server[0].get(), {}, m_material.otherCaCertificate()));
    const auto wrong = readCertificates(m_material.wrongNameServerCertificate());
    ASSERT_EQ(wrong.size(), 1U);
    EXPECT_NE(X509_check_ip_asc(wrong[0].get(), "127.0.0.1", 0), 1);
    EXPECT_EQ(X509_check_host(wrong[0].get(), TlsMaterialFactory::wrongName().c_str(), 0, 0, nullptr), 1);
    EXPECT_TRUE(chainsTo(wrong[0].get(), {}, m_material.caCertificate()));

    // Pairs match their keys; the other key matches nothing.
    const auto serverKey = readKey(m_material.serverKey());
    const auto client = readCertificates(m_material.clientCertificate());
    const auto clientKey = readKey(m_material.clientKey());
    const auto otherKey = readKey(m_material.otherKey());
    ASSERT_EQ(client.size(), 1U);
    ASSERT_NE(serverKey, nullptr);
    ASSERT_NE(clientKey, nullptr);
    ASSERT_NE(otherKey, nullptr);
    EXPECT_EQ(X509_check_private_key(server[0].get(), serverKey.get()), 1);
    EXPECT_EQ(X509_check_private_key(client[0].get(), clientKey.get()), 1);
    EXPECT_NE(X509_check_private_key(client[0].get(), otherKey.get()), 1);
    EXPECT_NE(X509_check_private_key(server[0].get(), otherKey.get()), 1);
    EXPECT_TRUE(chainsTo(client[0].get(), {}, m_material.caCertificate()));
    ERR_clear_error();

    // Leaf + intermediate in one file: the leaf alone does not chain, with the intermediate it does.
    const auto chain = readCertificates(m_material.chainCertificate());
    const auto intermediate = readCertificates(m_material.intermediateCaCertificate());
    const auto chainKey = readKey(m_material.chainKey());
    ASSERT_EQ(chain.size(), 2U);
    ASSERT_EQ(intermediate.size(), 1U);
    ASSERT_NE(chainKey, nullptr);
    EXPECT_EQ(X509_cmp(chain[1].get(), intermediate[0].get()), 0);
    EXPECT_EQ(X509_check_ca(intermediate[0].get()), 1);
    EXPECT_EQ(X509_check_private_key(chain[0].get(), chainKey.get()), 1);
    EXPECT_FALSE(chainsTo(chain[0].get(), {}, m_material.caCertificate()));
    EXPECT_TRUE(chainsTo(chain[0].get(), {chain[1].get()}, m_material.caCertificate()));

    // The encrypted key needs the passphrase and is the client's key.
    EXPECT_EQ(readKey(m_material.encryptedClientKey()), nullptr);
    EXPECT_EQ(readKey(m_material.encryptedClientKey(), "wrong"), nullptr);
    const auto decrypted = readKey(m_material.encryptedClientKey(), TlsMaterialFactory::passphrase().c_str());
    ASSERT_NE(decrypted, nullptr);
    EXPECT_EQ(EVP_PKEY_eq(decrypted.get(), clientKey.get()), 1);

    // The broken files.
    EXPECT_TRUE(readCertificates(m_material.malformedCa()).empty());
    EXPECT_GT(std::filesystem::file_size(m_material.malformedCa()), 0U);
    EXPECT_EQ(std::filesystem::file_size(m_material.emptyFile()), 0U);
    EXPECT_TRUE(readCertificates(m_material.keyOnlyPem()).empty());
    EXPECT_NE(readKey(m_material.keyOnlyPem()), nullptr);
}

TEST_F(FakeTlsTest, HandshakeWithTheGoodCa)
{
    auto fake = startFake(serverTls());
    EXPECT_TRUE(fake->tls());
    EXPECT_EQ(fake->baseUrl(), "https://127.0.0.1:" + std::to_string(fake->port()));

    auto client = makeClient(*fake, m_material.caCertificate());
    const auto res = client->Get("/");
    ASSERT_TRUE(res) << httplib::to_string(res.error());
    EXPECT_EQ(res->status, 200);
    EXPECT_EQ(res->body, "{}");

    // [foreign, good] in one CA file is also accepted.
    auto bundleClient = makeClient(*fake, m_material.caBundleOtherThenGood());
    const auto bundleRes = bundleClient->Get("/");
    ASSERT_TRUE(bundleRes) << httplib::to_string(bundleRes.error());
    EXPECT_EQ(bundleRes->status, 200);
}

TEST_F(FakeTlsTest, ForeignCaIsRejected)
{
    auto fake = startFake(serverTls());
    auto client = makeClient(*fake, m_material.otherCaCertificate());
    const auto res = client->Get("/");
    EXPECT_FALSE(res);
    EXPECT_EQ(res.error(), httplib::Error::SSLServerVerification);
    EXPECT_EQ(fake->requestCount(), 0U);
}

TEST_F(FakeTlsTest, WrongNameCertificateFailsOnlyTheHostnameCheck)
{
    auto fake =
        startFake(FakeTlsOptions {m_material.wrongNameServerCertificate(), m_material.wrongNameServerKey(), {}, false});

    auto client = makeClient(*fake, m_material.caCertificate());
    const auto res = client->Get("/");
    EXPECT_FALSE(res);
    EXPECT_EQ(res.error(), httplib::Error::SSLServerHostnameVerification);

    // Same CA, hostname check off: it chains, so the name is the only defect.
    auto lenient = makeClient(*fake, m_material.caCertificate());
    lenient->enable_server_hostname_verification(false);
    const auto lenientRes = lenient->Get("/");
    ASSERT_TRUE(lenientRes) << httplib::to_string(lenientRes.error());
    EXPECT_EQ(lenientRes->status, 200);
}

TEST_F(FakeTlsTest, MutualTlsRequiresTheClientPair)
{
    auto fake = startFake(mutualTls());

    auto anonymous = makeClient(*fake, m_material.caCertificate());
    EXPECT_FALSE(anonymous->Get("/"));

    auto foreignPair =
        makeClient(*fake, m_material.caCertificate(), m_material.serverCertificate(), m_material.serverKey());
    // The server pair is also signed by the good CA, but it is not a client certificate (EKU serverAuth only).
    EXPECT_FALSE(foreignPair->Get("/"));
    EXPECT_EQ(fake->requestCount(), 0U);

    auto paired = makeClient(*fake, m_material.caCertificate(), m_material.clientCertificate(), m_material.clientKey());
    const auto res = paired->Get("/");
    ASSERT_TRUE(res) << httplib::to_string(res.error());
    EXPECT_EQ(res->status, 200);
    EXPECT_EQ(fake->requestCount(), 1U);
}

TEST_F(FakeTlsTest, MutualTlsAcceptsLeafPlusIntermediateInOneFile)
{
    auto fake = startFake(mutualTls());

    auto chained = makeClient(*fake, m_material.caCertificate(), m_material.chainCertificate(), m_material.chainKey());
    const auto res = chained->Get("/");
    ASSERT_TRUE(res) << httplib::to_string(res.error());
    EXPECT_EQ(res->status, 200);

    // The leaf alone, without its intermediate, does not chain. httplib's path constructor loads the whole chain
    // file (0.51), so the leaf goes in a file of its own.
    const auto chain = readCertificates(m_material.chainCertificate());
    ASSERT_EQ(chain.size(), 2U);
    const auto leafFile = (std::filesystem::path(m_material.directory()) / "chain-leaf-only.pem").string();
    {
        std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new_file(leafFile.c_str(), "w"), &BIO_free);
        ASSERT_NE(bio, nullptr);
        ASSERT_EQ(PEM_write_bio_X509(bio.get(), chain[0].get()), 1);
    }
    httplib::SSLClient leafOnly("127.0.0.1", fake->port(), leafFile, m_material.chainKey());
    bound(leafOnly);
    leafOnly.set_ca_cert_path(m_material.caCertificate());
    EXPECT_FALSE(leafOnly.Get("/"));
    EXPECT_EQ(fake->requestCount(), 1U);
}

TEST_F(FakeTlsTest, TlsCapAtVersion11IsEnforced)
{
    auto options = serverTls();
    options.maxTls11 = true;
    auto fake = startFake(options);

    // A client with a TLS 1.2 floor (httplib's default, and what the transport demands) cannot talk to it.
    auto modern = makeClient(*fake, m_material.caCertificate());
    const auto refused = modern->Get("/");
    EXPECT_FALSE(refused);
    EXPECT_EQ(refused.error(), httplib::Error::SSLConnection);

    // A client that allows TLS 1.0/1.1 does: the fake is up and the cap is the only obstacle.
    auto legacy = makeClient(*fake, m_material.caCertificate());
    SSL_CTX* context = static_cast<SSL_CTX*>(legacy->tls_context());
    SSL_CTX_set_security_level(context, 0);
    ASSERT_EQ(SSL_CTX_set_min_proto_version(context, TLS1_VERSION), 1);
    const auto res = legacy->Get("/");
    ASSERT_TRUE(res) << httplib::to_string(res.error());
    EXPECT_EQ(res->status, 200);
    EXPECT_EQ(fake->requestCount(), 1U);

    // The same client against an uncapped fake negotiates above 1.1, so it is not the client that is limited.
    auto uncapped = startFake(serverTls());
    auto pinned = makeClient(*uncapped, m_material.caCertificate());
    SSL_CTX* pinnedContext = static_cast<SSL_CTX*>(pinned->tls_context());
    SSL_CTX_set_security_level(pinnedContext, 0);
    ASSERT_EQ(SSL_CTX_set_min_proto_version(pinnedContext, TLS1_VERSION), 1);
    ASSERT_EQ(SSL_CTX_set_max_proto_version(pinnedContext, TLS1_1_VERSION), 1);
    EXPECT_FALSE(pinned->Get("/"));
}

TEST_F(FakeTlsTest, RulesHoldAndRecordingWorkOverTls)
{
    FakeIndexerOptions options;
    options.tls = serverTls();
    options.recordBodies = true;
    FakeIndexer fake(std::move(options));
    fake.start();
    const auto rule = fake.addRule(Rule {"POST", "/_bulk", 503, R"({"error":"busy"})", 0ms, std::string("7")});

    auto client = makeClient(fake, m_material.caCertificate());
    const auto res = client->Post("/_bulk?refresh=false", "payload", "application/x-ndjson");
    ASSERT_TRUE(res) << httplib::to_string(res.error());
    EXPECT_EQ(res->status, 503);
    EXPECT_EQ(res->body, R"({"error":"busy"})");
    EXPECT_EQ(res->get_header_value("Retry-After"), "7");
    EXPECT_EQ(fake.hits(rule), 1U);

    const auto recorded = fake.requests();
    ASSERT_EQ(recorded.size(), 1U);
    EXPECT_EQ(recorded[0].method, "POST");
    EXPECT_EQ(recorded[0].path, "/_bulk");
    EXPECT_EQ(recorded[0].target, "/_bulk?refresh=false");
    EXPECT_EQ(recorded[0].body, "payload");
    EXPECT_EQ(recorded[0].remoteAddr, "127.0.0.1");

    Rule held;
    held.pathRegex = "/held";
    held.hold = true;
    fake.addRule(held);
    httplib::Result heldRes;
    std::thread waiter([&] { heldRes = client->Get("/held"); });
    EXPECT_TRUE(fake.waitHeld(1, 5s));
    fake.releaseHeld();
    waiter.join();
    ASSERT_TRUE(heldRes) << httplib::to_string(heldRes.error());
    EXPECT_EQ(heldRes->status, 200);
}

TEST_F(FakeTlsTest, AuthorizationIsDecodedExactly)
{
    auto fake = startFake(serverTls());
    auto client = makeClient(*fake, m_material.caCertificate());

    const std::vector<std::pair<std::string, std::string>> pairs {
        {"admin", "admin"}, {"us\xc3\xa9r", "p:ss\xe2\x9c\x93"}, {"other", "a:b:c:"}, {"", "only-password"}};
    for (const auto& [user, password] : pairs)
    {
        client->set_basic_auth(user, password);
        const auto res = client->Get("/");
        ASSERT_TRUE(res) << httplib::to_string(res.error());
    }
    // Raw headers: another scheme, broken base64, no ':' and a case-insensitive scheme with two spaces.
    const std::vector<std::string> raw {"Bearer abc", "Basic dXNlcjpwYXNz=", "Basic dXNlcg==", "bAsIc  dTpw"};
    httplib::SSLClient plain("127.0.0.1", fake->port());
    bound(plain);
    plain.set_ca_cert_path(m_material.caCertificate());
    for (const auto& value : raw)
    {
        const auto res = plain.Get("/", httplib::Headers {{"Authorization", value}});
        ASSERT_TRUE(res) << httplib::to_string(res.error());
    }
    ASSERT_TRUE(plain.Get("/"));

    const auto recorded = fake->requests();
    ASSERT_EQ(recorded.size(), pairs.size() + raw.size() + 1);
    for (std::size_t i = 0; i < pairs.size(); ++i)
    {
        ASSERT_TRUE(recorded[i].basicAuthorization.has_value()) << i;
        EXPECT_EQ(recorded[i].basicAuthorization->user, pairs[i].first);
        EXPECT_EQ(recorded[i].basicAuthorization->password, pairs[i].second);
    }
    const auto base = pairs.size();
    EXPECT_FALSE(recorded[base + 0].basicAuthorization.has_value());
    EXPECT_FALSE(recorded[base + 1].basicAuthorization.has_value());
    EXPECT_FALSE(recorded[base + 2].basicAuthorization.has_value());
    ASSERT_TRUE(recorded[base + 3].basicAuthorization.has_value());
    EXPECT_EQ(recorded[base + 3].basicAuthorization->user, "u");
    EXPECT_EQ(recorded[base + 3].basicAuthorization->password, "p");
    EXPECT_FALSE(recorded[base + 4].basicAuthorization.has_value());
}

TEST_F(FakeTlsTest, Base64DecoderIsStrict)
{
    EXPECT_EQ(FakeIndexer::decodeBase64(""), std::string {});
    EXPECT_EQ(FakeIndexer::decodeBase64("Zg=="), std::string("f"));
    EXPECT_EQ(FakeIndexer::decodeBase64("Zm8="), std::string("fo"));
    EXPECT_EQ(FakeIndexer::decodeBase64("Zm9v"), std::string("foo"));
    EXPECT_EQ(FakeIndexer::decodeBase64("+/+/"), std::string("\xfb\xff\xbf"));
    EXPECT_EQ(FakeIndexer::decodeBase64("AA=="), std::string(1, '\0'));
    EXPECT_FALSE(FakeIndexer::decodeBase64("Zg"));       // unpadded
    EXPECT_FALSE(FakeIndexer::decodeBase64("Zh=="));     // non-zero padding bits
    EXPECT_FALSE(FakeIndexer::decodeBase64("Zm9=Zm9v")); // padding before the end
    EXPECT_FALSE(FakeIndexer::decodeBase64("Zm 9"));     // whitespace
    EXPECT_FALSE(FakeIndexer::decodeBase64("Zm9-"));     // URL alphabet
    EXPECT_FALSE(FakeIndexer::decodeBase64("===="));
}
