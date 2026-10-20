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

// TLS of the transport (plan 18, plan-E2a-2 §Tests: CA-19, I48, D22): handshakes against the HTTPS/mTLS fake with the
// material of <indexer>.ssl, the failures the node is blamed for, a cancel in the middle of a handshake, and every
// configuration refusal of RuntimeOwner::start (InvalidConfig before any thread exists).

#include <algorithm>
#include <iterator>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "componentFixture.hpp"
#include "fakeIndexer.hpp"
#include "rawTcpServer.hpp"
#include "tlsMaterialFactory.hpp"

using namespace component;
using indexer_client::Cause;
using indexer_client::Credentials;
using indexer_client::testing::FakeIndexer;
using indexer_client::testing::FakeIndexerOptions;
using indexer_client::testing::FakeTlsOptions;
using indexer_client::testing::SilentServer;
using indexer_client::testing::TlsMaterialFactory;

namespace
{
    /// `<indexer>` section as manager_config hands it over: hosts plus the optional ssl block.
    struct Section final
    {
        std::vector<std::string> hosts;
        std::vector<std::string> certificateAuthorities;
        std::optional<std::string> certificate;
        std::optional<std::string> key;
    };

    std::string quote(const std::string& text)
    {
        std::string out {"\""};
        for (const char c : text)
        {
            if (c == '"' || c == '\\')
            {
                out.push_back('\\');
            }
            out.push_back(c);
        }
        out.push_back('"');
        return out;
    }

    std::string list(const std::vector<std::string>& values)
    {
        std::string out {"["};
        for (std::size_t i = 0; i < values.size(); ++i)
        {
            out += (i == 0 ? "" : ",") + quote(values[i]);
        }
        return out + "]";
    }

    std::string toJson(const Section& section)
    {
        std::string ssl;
        const auto add = [&ssl](const std::string& member)
        {
            ssl += (ssl.empty() ? "" : ",") + member;
        };
        if (!section.certificateAuthorities.empty())
        {
            add("\"certificate_authorities\":" + list(section.certificateAuthorities));
        }
        if (section.certificate)
        {
            add("\"certificate\":" + quote(*section.certificate));
        }
        if (section.key)
        {
            add("\"key\":" + quote(*section.key));
        }
        return "{\"hosts\":" + list(section.hosts) + (ssl.empty() ? "" : ",\"ssl\":{" + ssl + "}") + "}";
    }

    /// Test-owned source with a chosen <indexer> section and credentials; K = 1, M = 2.
    class SectionSource final : public indexer_client::IConfigSource
    {
    public:
        explicit SectionSource(const Section& section, Credentials credentials = {"user", "pass"})
            : m_json(toJson(section))
            , m_credentials(std::move(credentials))
        {
        }

        std::optional<std::string> raw(std::string_view key) const override
        {
            const auto it = m_values.find(std::string(key));
            if (it == m_values.end())
            {
                return std::nullopt;
            }
            return it->second;
        }

        std::vector<std::string> keysWithPrefix(std::string_view prefix) const override
        {
            std::vector<std::string> keys;
            for (const auto& [key, value] : m_values)
            {
                if (key.compare(0, prefix.size(), prefix) == 0)
                {
                    keys.push_back(key);
                }
            }
            return keys;
        }

        std::string indexerSectionJson() const override
        {
            return m_json;
        }

        Credentials credentials() const override
        {
            return m_credentials;
        }

    private:
        std::map<std::string, std::string> m_values {{"analysisd.indexer_client_network_threads", "1"},
                                                     {"analysisd.indexer_client_cpu_threads", "2"}};
        std::string m_json;
        Credentials m_credentials;
    };

    bool contains(const std::string& text, const std::string& part)
    {
        return text.find(part) != std::string::npos;
    }
} // namespace

class TransportTlsTest : public ::testing::Test
{
protected:
    TlsMaterialFactory m_material;
    std::vector<std::shared_ptr<FakeIndexer>> m_fakes;

    void SetUp() override
    {
        indexer_client::testing_hooks::resetAll();
    }

    void TearDown() override
    {
        indexer_client::RuntimeOwner::shutdown();
        // After the runtime: curl has closed its keep-alive connections, so the TLS fakes stop at once instead of
        // waiting for httplib's keep-alive timeout on an idle TLS connection (5 s per test).
        m_fakes.clear();
        indexer_client::testing_hooks::resetAll();
        EXPECT_FALSE(indexer_client::RuntimeOwner::running());
    }

    std::shared_ptr<FakeIndexer> startFake(FakeTlsOptions tls)
    {
        FakeIndexerOptions options;
        options.tls = std::move(tls);
        auto fake = std::make_shared<FakeIndexer>(std::move(options));
        fake->start();
        m_fakes.push_back(fake); // Stopped in TearDown, after the runtime.
        return fake;
    }

    FakeTlsOptions serverTls() const
    {
        return FakeTlsOptions {m_material.serverCertificate(), m_material.serverKey(), {}, false};
    }

    FakeTlsOptions mutualTls() const
    {
        return FakeTlsOptions {
            m_material.serverCertificate(), m_material.serverKey(), m_material.caCertificate(), false};
    }

    /// Starts the runtime through RuntimeOwner::start and returns its transport (null on failure, with a failure).
    std::shared_ptr<Transport> startRuntime(const Section& section)
    {
        auto started =
            indexer_client::RuntimeOwner::start(indexer_client::ProcessId::Analysisd, SectionSource(section));
        EXPECT_TRUE(started.ok()) << indexer_client::toString(started.cause) << ": " << started.reason;
        return indexer_client::detail::runtimeTransport();
    }

    /// One GET, waited for with a bound.
    std::optional<HttpResult> get(Transport& transport, const std::string& url)
    {
        auto collector = Collector::create();
        const auto sent = submitTo(transport, collector, request(HttpMethod::Get, url));
        EXPECT_TRUE(sent.admission.admitted) << url;
        if (!sent.admission.admitted || !collector->waitKey(sent.key, 15s))
        {
            ADD_FAILURE() << "no result for " << url;
            return std::nullopt;
        }
        return collector->result(sent.key);
    }

    /// I48: start() refuses the section with InvalidConfig whose reason carries every `part`, creates no thread and
    /// leaves no runtime behind.
    void expectInvalidConfig(const Section& section, const std::vector<std::string>& parts)
    {
        const auto before = settledTasks();
        const auto started =
            indexer_client::RuntimeOwner::start(indexer_client::ProcessId::Analysisd, SectionSource(section));
        const auto after = settledTasks();
        EXPECT_EQ(started.cause, Cause::InvalidConfig) << started.reason;
        for (const auto& part : parts)
        {
            EXPECT_TRUE(contains(started.reason, part)) << "'" << started.reason << "' lacks '" << part << "'";
        }
        EXPECT_FALSE(indexer_client::RuntimeOwner::running());
        // Only new threads count: a thread left by a previous test (a fake's worker) may still be exiting meanwhile.
        std::vector<std::string> created;
        std::set_difference(after.begin(), after.end(), before.begin(), before.end(), std::back_inserter(created));
        EXPECT_TRUE(created.empty()) << "a refused start created threads: " << created.size();
        EXPECT_EQ(indexer_client::detail::runtimeTransport(), nullptr);
    }

    std::string missingPath() const
    {
        return m_material.directory() + "/missing-ca.pem";
    }
};

// CA-19: a handshake against the configured CA; the transfer reports the TLS phase.
TEST_F(TransportTlsTest, TlsHandshakeWithConfiguredCa)
{
    auto fake = startFake(serverTls());
    ASSERT_EQ(fake->baseUrl().rfind("https://127.0.0.1:", 0), 0u);
    auto transport = startRuntime({{fake->baseUrl()}, {m_material.caCertificate()}, {}, {}});
    ASSERT_NE(transport, nullptr);

    const auto result = get(*transport, fake->baseUrl() + "/");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->status, 200);
    EXPECT_EQ(result->cause, TransportCause::None);
    EXPECT_EQ(result->curlCode, 0);
    EXPECT_GT(result->timings.appConnect.count(), 0) << "appConnect is the end of the TLS handshake";
    EXPECT_GE(result->timings.appConnect, result->timings.connect);
    EXPECT_EQ(fake->requestCount(), 1u);
}

// CA-19: a CA that did not sign the server is the node's TLS failure (curl 60); verification is never off.
TEST_F(TransportTlsTest, TlsBadCaFails)
{
    auto fake = startFake(serverTls());
    auto transport = startRuntime({{fake->baseUrl()}, {m_material.otherCaCertificate()}, {}, {}});
    ASSERT_NE(transport, nullptr);

    const auto result = get(*transport, fake->baseUrl() + "/");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->status, 0);
    EXPECT_EQ(result->cause, TransportCause::Tls);
    EXPECT_EQ(result->curlCode, 60);
    EXPECT_TRUE(result->nodeAttributable);
    EXPECT_EQ(fake->requestCount(), 0u);
}

// CA-19: a certificate signed by the good CA for another name fails the hostname check (curl 60).
TEST_F(TransportTlsTest, TlsHostnameMismatchFails)
{
    auto fake =
        startFake(FakeTlsOptions {m_material.wrongNameServerCertificate(), m_material.wrongNameServerKey(), {}, false});
    auto transport = startRuntime({{fake->baseUrl()}, {m_material.caCertificate()}, {}, {}});
    ASSERT_NE(transport, nullptr);

    const auto result = get(*transport, fake->baseUrl() + "/");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->status, 0);
    EXPECT_EQ(result->cause, TransportCause::Tls);
    EXPECT_EQ(result->curlCode, 60);
    EXPECT_TRUE(result->nodeAttributable);
    EXPECT_EQ(fake->requestCount(), 0u);
}

// I48: every configured CA is trusted, not only the first: [foreign, good] as two files, and as one bundle file.
TEST_F(TransportTlsTest, TlsSecondCaValid)
{
    auto fake = startFake(serverTls());
    {
        auto transport =
            startRuntime({{fake->baseUrl()}, {m_material.otherCaCertificate(), m_material.caCertificate()}, {}, {}});
        ASSERT_NE(transport, nullptr);
        const auto result = get(*transport, fake->baseUrl() + "/two-files");
        ASSERT_TRUE(result.has_value());
        EXPECT_EQ(result->status, 200) << toString(result->cause) << " curl " << result->curlCode;
    }
    ASSERT_EQ(indexer_client::RuntimeOwner::shutdown(), Cause::None);

    auto transport = startRuntime({{fake->baseUrl()}, {m_material.caBundleOtherThenGood()}, {}, {}});
    ASSERT_NE(transport, nullptr);
    const auto result = get(*transport, fake->baseUrl() + "/one-bundle");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->status, 200) << toString(result->cause) << " curl " << result->curlCode;
    EXPECT_EQ(fake->requestCount(), 2u);
}

// I48: mTLS with the configured client pair.
TEST_F(TransportTlsTest, TlsMutualOk)
{
    auto fake = startFake(mutualTls());
    auto transport = startRuntime(
        {{fake->baseUrl()}, {m_material.caCertificate()}, m_material.clientCertificate(), m_material.clientKey()});
    ASSERT_NE(transport, nullptr);

    const auto result = get(*transport, fake->baseUrl() + "/");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->status, 200) << toString(result->cause) << " curl " << result->curlCode;
    EXPECT_EQ(fake->requestCount(), 1u);
}

// I48: the certificate file is leaf + intermediate; the whole file travels, so the server can build the chain.
TEST_F(TransportTlsTest, TlsMutualChainInOneFile)
{
    auto fake = startFake(mutualTls());
    auto transport = startRuntime(
        {{fake->baseUrl()}, {m_material.caCertificate()}, m_material.chainCertificate(), m_material.chainKey()});
    ASSERT_NE(transport, nullptr);

    const auto result = get(*transport, fake->baseUrl() + "/");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->status, 200) << toString(result->cause) << " curl " << result->curlCode;
    EXPECT_EQ(fake->requestCount(), 1u);
}

// I48: an mTLS server and no pair. Under TLS 1.3 the server's alert arrives after the client's Finished, so curl may
// report it as a handshake, send or receive failure; all of them are the node's.
TEST_F(TransportTlsTest, TlsMutualMissingClientCertFails)
{
    auto fake = startFake(mutualTls());
    auto transport = startRuntime({{fake->baseUrl()}, {m_material.caCertificate()}, {}, {}});
    ASSERT_NE(transport, nullptr);

    const auto result = get(*transport, fake->baseUrl() + "/");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->status, 0);
    EXPECT_TRUE(result->nodeAttributable);
    EXPECT_TRUE(result->cause == TransportCause::Tls || result->cause == TransportCause::SendError ||
                result->cause == TransportCause::RecvError)
        << toString(result->cause);
    EXPECT_TRUE(result->curlCode == 35 || result->curlCode == 55 || result->curlCode == 56 || result->curlCode == 98)
        << "curl " << result->curlCode;
    EXPECT_EQ(fake->requestCount(), 0u);
}

// I48: the transport demands TLS 1.2 or newer; a node capped at TLS 1.1 is a TLS failure.
TEST_F(TransportTlsTest, TlsMinimumVersion)
{
    auto options = serverTls();
    options.maxTls11 = true;
    auto fake = startFake(options);
    auto transport = startRuntime({{fake->baseUrl()}, {m_material.caCertificate()}, {}, {}});
    ASSERT_NE(transport, nullptr);

    const auto result = get(*transport, fake->baseUrl() + "/");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->status, 0);
    EXPECT_EQ(result->cause, TransportCause::Tls) << "curl " << result->curlCode;
    EXPECT_TRUE(result->nodeAttributable);
    EXPECT_EQ(fake->requestCount(), 0u);
}

// D22: cancelling a transfer stuck in the TLS handshake (the server accepts, reads the ClientHello and stays silent):
// the request was never about to be written, the easy leaves the multi and the connection closes at once.
TEST_F(TransportTlsTest, CancelDuringTlsHandshake)
{
    SilentServer silent;
    const auto url = "https://127.0.0.1:" + std::to_string(silent.port());
    auto transport = startRuntime({{url}, {m_material.caCertificate()}, {}, {}});
    ASSERT_NE(transport, nullptr);
    auto collector = Collector::create();

    const auto sent = submitTo(
        *transport, collector, request(HttpMethod::Get, url + "/handshake", nullptr, indexer_client::Duration {20000}));
    ASSERT_TRUE(sent.admission.admitted);
    ASSERT_TRUE(silent.waitForAccepted(1, 10s)) << "the TCP connection was never made";
    ASSERT_TRUE(eventually([&] { return silent.connections()[0].bytesRead > 0; }, 5s)) << "no ClientHello arrived";
    EXPECT_EQ(collector->count(sent.key), 0) << "the handshake cannot finish against a silent server";
    EXPECT_EQ(sumOf(transport->stats().inFlightPerLoop), 1u);

    const auto cancelledAt = std::chrono::steady_clock::now();
    ASSERT_TRUE(transport->cancel(sent.admission.id));
    ASSERT_TRUE(collector->waitKey(sent.key, 10s));
    const auto result = collector->result(sent.key);
    EXPECT_EQ(result->cause, TransportCause::Cancelled);
    EXPECT_EQ(result->status, 0);
    EXPECT_FALSE(result->nodeAttributable);
    EXPECT_FALSE(result->mayHaveSent) << "the connection never became ready for the request";
    EXPECT_EQ(result->uploadedBytes, 0u);
    // curl 8.20 sets CONNECT_TIME only once the whole filter chain (TLS included) is connected, so a cancelled
    // handshake reports 0 for both; the TCP connection is proven by the ClientHello the server read (bytesRead > 0,
    // above).
    EXPECT_EQ(result->timings.appConnect.count(), 0) << "the TLS handshake never finished";
    EXPECT_EQ(sumOf(transport->stats().inFlightPerLoop), 0u) << "the easy is still inside the multi";

    const auto eof = silent.waitForEof(0, 2s);
    ASSERT_TRUE(eof.has_value()) << "the silent server never saw the connection close";
    EXPECT_LE(*eof - cancelledAt, 100ms)
        << "EOF " << std::chrono::duration_cast<std::chrono::milliseconds>(*eof - cancelledAt).count()
        << " ms after cancel()";
}

// ---- I48: configuration refusals of RuntimeOwner::start (InvalidConfig, no thread) ----

TEST_F(TransportTlsTest, TlsConfigHttpsWithoutCa)
{
    expectInvalidConfig({{"http://127.0.0.1:9200", "https://127.0.0.1:9201"}, {}, {}, {}},
                        {"https://127.0.0.1:9201", "certificate_authorities"});
}

TEST_F(TransportTlsTest, TlsConfigMissingCaFile)
{
    expectInvalidConfig({{"https://127.0.0.1:9200"}, {m_material.caCertificate(), missingPath()}, {}, {}},
                        {missingPath(), "cannot read"});
}

TEST_F(TransportTlsTest, TlsConfigMalformedCa)
{
    expectInvalidConfig({{"https://127.0.0.1:9200"}, {m_material.malformedCa()}, {}, {}},
                        {m_material.malformedCa(), "malformed PEM content"});
}

// I48 (G-diff objection 1): a good CA followed by a malformed block. curl parses CAINFO_BLOB with
// PEM_X509_INFO_read_bio over the whole blob and refuses it (77 on every transfer); start() must refuse it first.
TEST_F(TransportTlsTest, TlsConfigCaBundleTrailingGarbage)
{
    expectInvalidConfig(
        {{"https://127.0.0.1:9200"}, {m_material.caCertificate(), m_material.caThenMalformed()}, {}, {}},
        {m_material.caThenMalformed(), "malformed PEM content"});
}

// I48 (G-diff objection 1): leaf + intermediate followed by a malformed block. curl reads SSLCERT_BLOB as a leaf and
// then certificates until PEM_R_NO_START_LINE, and refuses anything else (58 on every transfer).
TEST_F(TransportTlsTest, TlsConfigChainTrailingGarbage)
{
    expectInvalidConfig({{"https://127.0.0.1:9200"},
                         {m_material.caCertificate()},
                         m_material.chainThenMalformed(),
                         m_material.chainKey()},
                        {m_material.chainThenMalformed(), "not a PEM certificate chain"});
}

// I48 (G-diff objection 3): each file is at most 1 MiB (here a valid CA padded to 1 MiB + 1 byte), and the CA files
// together stay below curl's blob limit (8 000 000 bytes; curl would refuse the blob with 43 on every transfer).
TEST_F(TransportTlsTest, TlsConfigOversizedFile)
{
    expectInvalidConfig({{"https://127.0.0.1:9200"}, {m_material.caCertificate(), m_material.oversizedCa()}, {}, {}},
                        {m_material.oversizedCa(), "larger than 1048576 bytes"});

    const std::vector<std::string> eight(8, m_material.largeCaBundle());
    expectInvalidConfig({{"https://127.0.0.1:9200"}, eight, {}, {}}, {m_material.largeCaBundle(), "curl's blob limit"});
}

TEST_F(TransportTlsTest, TlsConfigCaWithoutCertificate)
{
    // A well-formed PEM file whose only entry is a private key.
    expectInvalidConfig({{"https://127.0.0.1:9200"}, {m_material.keyOnlyPem()}, {}, {}},
                        {m_material.keyOnlyPem(), "no PEM certificate"});
}

TEST_F(TransportTlsTest, TlsConfigEmptyCaFile)
{
    expectInvalidConfig({{"https://127.0.0.1:9200"}, {m_material.emptyFile()}, {}, {}},
                        {m_material.emptyFile(), "no PEM certificate"});
}

TEST_F(TransportTlsTest, TlsConfigCertWithoutKey)
{
    expectInvalidConfig({{"https://127.0.0.1:9200"}, {m_material.caCertificate()}, m_material.clientCertificate(), {}},
                        {m_material.clientCertificate(), "both or neither"});
    expectInvalidConfig({{"https://127.0.0.1:9200"}, {m_material.caCertificate()}, m_material.clientCertificate(), ""},
                        {m_material.clientCertificate(), "both or neither"});
}

TEST_F(TransportTlsTest, TlsConfigKeyWithoutCert)
{
    expectInvalidConfig({{"https://127.0.0.1:9200"}, {m_material.caCertificate()}, {}, m_material.clientKey()},
                        {m_material.clientKey(), "both or neither"});
    expectInvalidConfig({{"https://127.0.0.1:9200"}, {m_material.caCertificate()}, "", m_material.clientKey()},
                        {m_material.clientKey(), "both or neither"});
}

TEST_F(TransportTlsTest, TlsConfigMalformedKey)
{
    expectInvalidConfig({{"https://127.0.0.1:9200"},
                         {m_material.caCertificate()},
                         m_material.clientCertificate(),
                         m_material.malformedCa()},
                        {m_material.malformedCa(), "no readable PEM private key"});
}

TEST_F(TransportTlsTest, TlsConfigEncryptedKey)
{
    expectInvalidConfig({{"https://127.0.0.1:9200"},
                         {m_material.caCertificate()},
                         m_material.clientCertificate(),
                         m_material.encryptedClientKey()},
                        {m_material.encryptedClientKey(), "the key is encrypted"});
}

TEST_F(TransportTlsTest, TlsConfigMismatchedPair)
{
    expectInvalidConfig({{"https://127.0.0.1:9200"},
                         {m_material.caCertificate()},
                         m_material.clientCertificate(),
                         m_material.otherKey()},
                        {m_material.otherKey(), m_material.clientCertificate(), "does not match"});
}

TEST_F(TransportTlsTest, TlsConfigBadScheme)
{
    expectInvalidConfig({{"http://127.0.0.1:9200", "ftp://127.0.0.1:21"}, {}, {}, {}},
                        {"ftp://127.0.0.1:21", "http or https"});
}

// I48: the material is validated whatever the scheme: a typo in the CA path does not wait for the day of https.
TEST_F(TransportTlsTest, TlsConfigHttpHostsStillValidateCa)
{
    expectInvalidConfig({{"http://127.0.0.1:9200"}, {missingPath()}, {}, {}}, {missingPath(), "cannot read"});
}

// I48: manager_config fills "" for absent members: certificate "" and key "" mean no mTLS, and the runtime starts.
TEST_F(TransportTlsTest, TlsConfigEmptyStringsMeanAbsent)
{
    auto fake = startFake(serverTls());
    auto transport = startRuntime({{fake->baseUrl()}, {m_material.caCertificate()}, "", ""});
    ASSERT_NE(transport, nullptr);
    EXPECT_TRUE(indexer_client::RuntimeOwner::running());

    const auto result = get(*transport, fake->baseUrl() + "/");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->status, 200) << toString(result->cause) << " curl " << result->curlCode;
}

// Defect A of E2a-2 step 5: with no CA configured there is no trust anchor, so https is not admitted at all; curl would
// otherwise fall back to the CA bundle compiled into it (the system's CAs on some distributions). No connection is
// made.
TEST_F(TransportTlsTest, HttpsNotAdmittedWithoutConfiguredCa)
{
    SilentServer silent;
    auto transport = startRuntime({{"http://127.0.0.1:" + std::to_string(silent.port())}, {}, {}, {}});
    ASSERT_NE(transport, nullptr);
    auto collector = Collector::create();

    const auto sent = submitTo(
        *transport, collector, request(HttpMethod::Get, "https://127.0.0.1:" + std::to_string(silent.port()) + "/"));
    EXPECT_FALSE(sent.admission.admitted);
    EXPECT_EQ(sent.admission.cause, indexer_client::Cause::InvalidArgument);
    EXPECT_FALSE(silent.waitForAccepted(1, 300ms)) << "an https request without a CA opened a connection";
    EXPECT_EQ(collector->total(), 0u);

    const auto plain = submitTo(
        *transport, collector, request(HttpMethod::Get, "http://127.0.0.1:" + std::to_string(silent.port()) + "/"));
    EXPECT_TRUE(plain.admission.admitted) << "http stays admitted without a CA";
    ASSERT_TRUE(transport->cancel(plain.admission.id) || collector->waitKey(plain.key, 10s));
}
