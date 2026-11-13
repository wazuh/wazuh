/*
 * Wazuh content manager - unit tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

// The indexer_client adapter against a REAL OpenSearch. Skipped unless INDEXER_URL names one
// (e.g. http://127.0.0.1:9201, security disabled): the fake indexer cannot prove what the real PIT API does.

#include "fakes/realIndexerFixture.hpp"
#include "gtest/gtest.h"
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <numeric>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

using namespace std::chrono_literals;
using cmtest::docSort;
using cmtest::matchAll;
using cmtest::RealIndexer;
using cmtest::waitUntil;

namespace
{
    constexpr int DOCUMENTS = 2000;

    /// Creates an index with DOCUMENTS documents `{"n": i}` and deletes it at the end.
    class SeededIndex
    {
    public:
        SeededIndex(httplib::Client& http, std::string name)
            : m_http {http}
            , m_name {std::move(name)}
        {
            m_http.Delete("/" + m_name);
            const auto created = m_http.Put("/" + m_name, R"({"settings":{"number_of_shards":2}})", "application/json");
            m_ok = created && created->status == 200;
            if (!m_ok)
            {
                return;
            }
            std::string body;
            for (int i = 0; i < DOCUMENTS; ++i)
            {
                body +=
                    nlohmann::json {{"index", {{"_index", m_name}, {"_id", "d" + std::to_string(i)}}}}.dump() + "\n";
                body += nlohmann::json {{"n", i}}.dump() + "\n";
            }
            const auto bulk = m_http.Post("/_bulk?refresh=true", body, "application/x-ndjson");
            m_ok = bulk && bulk->status == 200 && !nlohmann::json::parse(bulk->body).at("errors").get<bool>();
        }

        ~SeededIndex()
        {
            m_http.Delete("/" + m_name);
        }

        bool ok() const
        {
            return m_ok;
        }

        const std::string& name() const
        {
            return m_name;
        }

    private:
        httplib::Client& m_http;
        std::string m_name;
        bool m_ok {false};
    };

    /// PITs the cluster lists now.
    std::size_t listedPits(httplib::Client& http)
    {
        const auto response = http.Get("/_search/point_in_time/_all");
        if (!response || response->status != 200)
        {
            return 0;
        }
        const auto body = nlohmann::json::parse(response->body, nullptr, false);
        return body.is_object() && body.contains("pits") ? body.at("pits").size() : 0;
    }
} // namespace

TEST(ContentIndexerClientAdapterReal, SlicesCoverOnce)
{
    const char* url = std::getenv("INDEXER_URL");
    if (url == nullptr || *url == '\0')
    {
        GTEST_SKIP() << "INDEXER_URL is not set";
    }

    httplib::Client http {url};
    http.set_connection_timeout(5, 0);
    http.set_read_timeout(30, 0);
    SeededIndex index {http, "cm-e9-" + std::to_string(::getpid())};
    ASSERT_TRUE(index.ok()) << "could not seed an index in " << url;
    const auto pitsBefore = listedPits(http);

    RealIndexer env;
    const auto reason = env.startWith(url,
                                      "wazuh_modules.indexer_client_network_threads=1\n"
                                      "wazuh_modules.indexer_client_cpu_threads=2\n"
                                      "wazuh_modules.indexer_client_probe_interval_ms=500\n");
    ASSERT_TRUE(reason.empty()) << reason;
    ASSERT_TRUE(env.makeClient()) << env.startError;
    auto adapter = env.adapter();

    // The PIT counters are the process's: earlier suites of this binary leave theirs in them.
    const auto metricsBefore = env.ref.snapshot().pit;
    const auto pit = adapter->openPit({index.name()}, "5m", false);

    constexpr std::size_t SLICES = 2;
    std::vector<std::vector<std::int64_t>> seen(SLICES);
    std::vector<std::string> errors(SLICES);
    std::vector<std::thread> workers;
    for (std::size_t slice = 0; slice < SLICES; ++slice)
    {
        workers.emplace_back(
            [&, slice]
            {
                try
                {
                    const nlohmann::json sliceSpec {{"id", slice}, {"max", SLICES}};
                    std::optional<nlohmann::json> after;
                    for (;;)
                    {
                        const auto hits =
                            adapter->search(pit, 200, matchAll(), docSort(), after, std::nullopt, sliceSpec);
                        if (hits.at("hits").empty())
                        {
                            break;
                        }
                        for (const auto& hit : hits.at("hits"))
                        {
                            seen[slice].push_back(hit.at("_source").at("n").get<std::int64_t>());
                        }
                        after = hits.at("hits").back().at("sort");
                    }
                }
                catch (const std::exception& e)
                {
                    errors[slice] = e.what();
                }
            });
    }
    for (auto& worker : workers)
    {
        worker.join();
    }
    for (std::size_t slice = 0; slice < SLICES; ++slice)
    {
        EXPECT_TRUE(errors[slice].empty()) << "slice " << slice << ": " << errors[slice];
        EXPECT_FALSE(seen[slice].empty()) << "slice " << slice << " got nothing";
    }

    // Every document exactly once across the slices.
    std::vector<std::int64_t> all;
    for (const auto& part : seen)
    {
        all.insert(all.end(), part.begin(), part.end());
    }
    std::sort(all.begin(), all.end());
    std::vector<std::int64_t> expected(DOCUMENTS);
    std::iota(expected.begin(), expected.end(), 0);
    EXPECT_EQ(all, expected);

    // One PIT created, and deleted in the background once the adapter lets go.
    adapter->closePit(pit);
    EXPECT_TRUE(
        waitUntil([&] { return env.ref.snapshot().pit.deletesConfirmed >= metricsBefore.deletesConfirmed + 1; }, 10s));
    const auto metrics = env.ref.snapshot().pit;
    EXPECT_EQ(metrics.created - metricsBefore.created, 1U);
    EXPECT_EQ(metrics.deletesConfirmed - metricsBefore.deletesConfirmed, 1U);
    EXPECT_TRUE(waitUntil([&] { return listedPits(http) <= pitsBefore; }, 10s)) << "the PIT is still listed";
}

// The whole-response cap of content pages against a real catalog (e.g. the CTI vulnerabilities index): the document
// CM_REAL_DOC_ID, larger than the query cap (max_response_bytes / QUERY_DOM_FACTOR = 8 MiB by default) but within
// max_response_bytes, comes back from a content page (a PIT the adapter opened), while the same lookup as a plain query
// fails with ResponseTooLargeError. Read only. Skipped unless INDEXER_URL and CM_REAL_DOC_ID are set;
// INDEXER_USER/INDEXER_PASSWORD (default admin/admin), INDEXER_CA (a PEM; "verify_certificates" false without it) and
// CM_REAL_INDEX (default .wazuh-threatintel-vulnerabilities) are optional.
TEST(ContentIndexerClientAdapterReal, LargeDocumentFromARealCatalog)
{
    const char* url = std::getenv("INDEXER_URL");
    const char* docId = std::getenv("CM_REAL_DOC_ID");
    if (url == nullptr || *url == '\0' || docId == nullptr || *docId == '\0')
    {
        GTEST_SKIP() << "INDEXER_URL or CM_REAL_DOC_ID is not set";
    }
    const auto env_or = [](const char* name, const char* fallback)
    {
        const char* value = std::getenv(name);
        return std::string {value != nullptr && *value != '\0' ? value : fallback};
    };
    const auto index = env_or("CM_REAL_INDEX", ".wazuh-threatintel-vulnerabilities");
    const auto ca = env_or("INDEXER_CA", "");
    nlohmann::json config {{"hosts", nlohmann::json::array({url})}};
    config["ssl"] = ca.empty() ? nlohmann::json {{"verify_certificates", false}}
                               : nlohmann::json {{"certificate_authorities", nlohmann::json::array({ca})}};

    RealIndexer env;
    const auto reason = env.startWithConfig(
        config.dump(),
        "wazuh_modules.indexer_client_network_threads=1\n"
        "wazuh_modules.indexer_client_cpu_threads=2\n",
        indexer_client::Credentials {env_or("INDEXER_USER", "admin"), env_or("INDEXER_PASSWORD", "admin")});
    ASSERT_TRUE(reason.empty()) << reason;
    ASSERT_TRUE(env.makeClient()) << env.startError;
    auto adapter = env.adapter();

    const nlohmann::json byId {{"ids", {{"values", nlohmann::json::array({docId})}}}};
    const auto sort = nlohmann::json::array({nlohmann::json {{"_doc", "asc"}}, nlohmann::json {{"_id", "asc"}}});

    const auto pit = adapter->openPit({index}, "5m", true);
    const auto hits = adapter->search(pit, 1, byId, sort, std::nullopt, std::nullopt, std::nullopt);
    ASSERT_EQ(hits.at("hits").size(), 1U);
    EXPECT_EQ(hits.at("hits").at(0).at("_id").get<std::string>(), docId);
    const auto bytes = hits.at("hits").at(0).dump().size();
    std::printf("[ REAL     ] %s: %zu bytes from a content page\n", docId, bytes);
    adapter->closePit(pit);

    EXPECT_THROW(adapter->searchIndex(index, 1, byId, std::nullopt), content_manager::ResponseTooLargeError)
        << "the plain query keeps the query cap";
}
