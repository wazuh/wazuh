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

// Credentials of the transport (plan 18, plan-E2a-2 §Tests: RF-19, I42, I55): read once through
// IConfigSource::credentials() in RuntimeOwner::start, copied, and sent on every request exactly as given.

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "componentFixture.hpp"
#include "fakeIndexer.hpp"
#include "tlsMaterialFactory.hpp"

using namespace component;
using indexer_client::Cause;
using indexer_client::Credentials;
using indexer_client::testing::FakeIndexer;
using indexer_client::testing::FakeIndexerOptions;
using indexer_client::testing::FakeTlsOptions;
using indexer_client::testing::RecordedRequest;
using indexer_client::testing::TlsMaterialFactory;

namespace
{
    /// Test-owned source: one host, an optional CA, the given credentials; K = 1, M = 2.
    class CredentialsSource final : public indexer_client::IConfigSource
    {
    public:
        CredentialsSource(const std::string& host, Credentials credentials, const std::string& caFile = {})
            : m_json("{\"hosts\":[\"" + host + "\"]" +
                     (caFile.empty() ? std::string() : ",\"ssl\":{\"certificate_authorities\":[\"" + caFile + "\"]}") +
                     "}")
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
} // namespace

class TransportCredentialsTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        indexer_client::testing_hooks::resetAll();
    }

    void TearDown() override
    {
        indexer_client::RuntimeOwner::shutdown();
        indexer_client::testing_hooks::resetAll();
        EXPECT_FALSE(indexer_client::RuntimeOwner::running());
    }

    static std::shared_ptr<Transport> startWith(const indexer_client::IConfigSource& source)
    {
        auto started = indexer_client::RuntimeOwner::start(indexer_client::ProcessId::Analysisd, source);
        EXPECT_TRUE(started.ok()) << indexer_client::toString(started.cause) << ": " << started.reason;
        return indexer_client::detail::runtimeTransport();
    }

    /// One GET, waited for with a bound; true when the fake answered 200.
    static bool getOk(Transport& transport, const std::string& url)
    {
        auto collector = Collector::create();
        const auto sent = submitTo(transport, collector, request(HttpMethod::Get, url));
        if (!sent.admission.admitted || !collector->waitKey(sent.key, 15s))
        {
            ADD_FAILURE() << "no result for " << url;
            return false;
        }
        const auto result = collector->result(sent.key);
        EXPECT_EQ(result->status, 200) << toString(result->cause) << " curl " << result->curlCode;
        return result->status == 200;
    }

    static void expectPair(const RecordedRequest& recorded, const Credentials& expected)
    {
        ASSERT_TRUE(recorded.basicAuthorization.has_value()) << recorded.target << ": no Basic Authorization";
        EXPECT_EQ(recorded.basicAuthorization->user, expected.user) << recorded.target;
        EXPECT_EQ(recorded.basicAuthorization->password, expected.password) << recorded.target;
    }
};

// RF-19, I42: each runtime sends the pair its own source gave at start, exactly; a restart does not keep the old one.
TEST_F(TransportCredentialsTest, CredentialsExactValueTwoPairs)
{
    FakeIndexer fake;
    fake.start();
    const std::vector<Credentials> pairs {{"alice", "first-secret"}, {"bob", "second secret!"}};
    for (std::size_t i = 0; i < pairs.size(); ++i)
    {
        auto transport = startWith(CredentialsSource(fake.baseUrl(), pairs[i]));
        ASSERT_NE(transport, nullptr);
        for (int n = 0; n < 2; ++n) // Every request carries the pair, not only the first one of a connection.
        {
            ASSERT_TRUE(getOk(*transport, fake.baseUrl() + "/run" + std::to_string(i) + "/" + std::to_string(n)));
        }
        transport.reset();
        ASSERT_EQ(indexer_client::RuntimeOwner::shutdown(), Cause::None);
    }

    const auto recorded = fake.requests();
    ASSERT_EQ(recorded.size(), 4u);
    for (std::size_t r = 0; r < recorded.size(); ++r)
    {
        expectPair(recorded[r], pairs[r / 2]);
    }
}

// I55: separate USERNAME/PASSWORD: a ':' and UTF-8 in the password arrive byte for byte (over https).
TEST_F(TransportCredentialsTest, CredentialsPasswordWithColonAndUtf8)
{
    TlsMaterialFactory material;
    FakeIndexerOptions options;
    options.tls = FakeTlsOptions {material.serverCertificate(), material.serverKey(), {}, false};
    FakeIndexer fake(std::move(options));
    fake.start();

    const Credentials pair {"us\xc3\xa9r", "p:ss\xe2\x9c\x93"}; // "usér", "p:ss✓"
    auto transport = startWith(CredentialsSource(fake.baseUrl(), pair, material.caCertificate()));
    ASSERT_NE(transport, nullptr);
    ASSERT_TRUE(getOk(*transport, fake.baseUrl() + "/"));

    const auto recorded = fake.requests();
    ASSERT_EQ(recorded.size(), 1u);
    expectPair(recorded[0], pair);
    // Shut the runtime down before the TLS fake goes out of scope: curl closes its keep-alive connection first, so the
    // fake does not wait for httplib's keep-alive timeout on an idle TLS connection.
    EXPECT_EQ(indexer_client::RuntimeOwner::shutdown(), indexer_client::Cause::None);
}

// I42: the runtime keeps its own copy; the source may be gone after start.
TEST_F(TransportCredentialsTest, CredentialsSurviveSourceDestroyed)
{
    FakeIndexer fake;
    fake.start();
    const Credentials pair {"keeper", "kept-secret"};
    std::shared_ptr<Transport> transport;
    {
        auto source = std::make_unique<CredentialsSource>(fake.baseUrl(), pair);
        transport = startWith(*source);
        ASSERT_NE(transport, nullptr);
        // The source object is destroyed before any request.
        source.reset();
    }
    ASSERT_TRUE(getOk(*transport, fake.baseUrl() + "/after"));

    const auto recorded = fake.requests();
    ASSERT_EQ(recorded.size(), 1u);
    expectPair(recorded[0], pair);
}
