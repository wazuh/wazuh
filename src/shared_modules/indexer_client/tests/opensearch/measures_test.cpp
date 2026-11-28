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

// Informative measures against a real OpenSearch: response sizes with and without gzip, steady bulk latency
// and the fail-fast of the gate.

#include <atomic>
#include <cmath>
#include <iostream>
#include <limits>
#include <thread>

#include <gtest/gtest-spi.h>

#include "openSearchSupport.hpp"

using namespace indexer_client;
using namespace indexer_client::opensearch;
using namespace std::chrono_literals;

namespace
{
    constexpr int SIZE_DOCS = 1000;
    const std::map<std::string, std::string> GZIP = {{"Accept-Encoding", "gzip"}};

    /// Sends the same request with and without Accept-Encoding: gzip and prints both sizes; returns the identity one.
    RawResponse measure(const std::string& label,
                        const std::string& method,
                        const std::string& path,
                        const std::string& body,
                        const std::string& contentType)
    {
        const auto identity = raw(method, path, body, contentType);
        const auto gzip = raw(method, path, body, contentType, GZIP);
        std::cout << MEASURE << label << " status=" << identity.status << " identity_bytes=" << identity.body.size()
                  << " gzip_bytes=" << gzip.body.size()
                  << " gzip_content_encoding=" << (gzip.contentEncoding.empty() ? "none" : gzip.contentEncoding)
                  << " ratio="
                  << (identity.body.empty()
                          ? 0.0
                          : static_cast<double>(gzip.body.size()) / static_cast<double>(identity.body.size()))
                  << "\n";
        EXPECT_EQ(gzip.status, identity.status);
        return identity;
    }

    /// p-quantile of a histogram, as the upper bound (ms) of the bucket where it falls; 0 without samples.
    double quantileMs(const LatencyHistogram& histogram, double q)
    {
        if (histogram.count == 0)
        {
            return 0;
        }
        const auto target = static_cast<std::uint64_t>(std::ceil(q * static_cast<double>(histogram.count)));
        std::uint64_t seen = 0;
        for (std::size_t i = 0; i < histogram.counts.size(); ++i)
        {
            seen += histogram.counts[i];
            if (seen >= target)
            {
                return i < LATENCY_BOUNDS_MS.size() ? LATENCY_BOUNDS_MS[i] : std::numeric_limits<double>::infinity();
            }
        }
        return std::numeric_limits<double>::infinity();
    }
} // namespace

class OpenSearchSizes : public OpenSearchTest
{
};

class OpenSearchLoad : public OpenSearchTest
{
protected:
    std::map<std::string, std::string> runtimeOptions() const override
    {
        auto options = OpenSearchTest::runtimeOptions();
        options["global_quota_bytes"] = std::to_string(256u << 20);
        return options;
    }
};

TEST_F(OpenSearchSizes, ResponseSizesBulkMappingErrors)
{
    const auto created = raw(
        "PUT",
        "/" + m_index,
        R"({"settings":{"number_of_shards":1,"number_of_replicas":0},"mappings":{"properties":{"n":{"type":"integer"}}}})");
    ASSERT_EQ(created.status, 200) << created.body;
    std::string body;
    for (int i = 0; i < SIZE_DOCS; ++i)
    {
        body += nlohmann::json {{"index", {{"_index", m_index}, {"_id", "e" + std::to_string(i)}}}}.dump() + "\n";
        body += nlohmann::json {{"n", "not-a-number-" + std::to_string(i)}}.dump() + "\n";
    }
    const auto identity = measure("sizes.bulk_1000_mapping_errors", "POST", "/_bulk", body, "application/x-ndjson");
    ASSERT_EQ(identity.status, 200);
    const auto response = nlohmann::json::parse(identity.body);
    EXPECT_TRUE(response.at("errors").get<bool>());
    int errors = 0;
    for (const auto& item : response.at("items"))
    {
        errors += item.at("index").contains("error") ? 1 : 0;
    }
    EXPECT_EQ(errors, SIZE_DOCS);
    std::cout << MEASURE << "sizes.bulk_1000_mapping_errors.request_bytes=" << body.size()
              << " first_error=" << response.at("items").at(0).at("index").at("error").at("type") << "\n";
}

TEST_F(OpenSearchSizes, ResponseSizesSearchPage)
{
    const auto created = raw("PUT", "/" + m_index, R"({"settings":{"number_of_shards":1,"number_of_replicas":0}})");
    ASSERT_EQ(created.status, 200) << created.body;
    std::string body;
    for (int i = 0; i < SIZE_DOCS; ++i)
    {
        body += nlohmann::json {{"index", {{"_index", m_index}, {"_id", "h" + std::to_string(i)}}}}.dump() + "\n";
        body += nlohmann::json {{"agent", {{"id", "001"}, {"name", "agent-001"}}},
                                {"package", {{"name", "pkg-" + std::to_string(i)}, {"version", "1.2.3-4"}}},
                                {"n", i}}
                    .dump() +
                "\n";
    }
    const auto bulk = raw("POST", "/_bulk?refresh=true", body, "application/x-ndjson");
    ASSERT_EQ(bulk.status, 200);
    ASSERT_FALSE(nlohmann::json::parse(bulk.body).at("errors").get<bool>());
    const nlohmann::json search = {{"size", SIZE_DOCS}, {"sort", nlohmann::json::array({"_doc"})}};
    const auto identity =
        measure("sizes.search_page_1000_hits", "POST", "/" + m_index + "/_search", search.dump(), "application/json");
    ASSERT_EQ(identity.status, 200);
    EXPECT_EQ(nlohmann::json::parse(identity.body).at("hits").at("hits").size(), static_cast<std::size_t>(SIZE_DOCS));
}

TEST_F(OpenSearchLoad, SteadyBulkLatency)
{
    // Up to 256 MiB of documents in bulks of an explicit bulk_max_bytes, until the deadline; informative except for
    // 0 Failed.
    constexpr std::uint64_t BUDGET_BYTES = 256u << 20;
    constexpr std::size_t BULK_MAX_BYTES = 4u << 20;
    const auto deadline = after(indexer_client::testing::scaled(120s));

    const auto created = raw("PUT", "/" + m_index, R"({"settings":{"number_of_shards":1,"number_of_replicas":0}})");
    ASSERT_EQ(created.status, 200) << created.body;

    auto spec = quickBucket("load");
    spec.quotaBytes = 64u << 20;
    spec.bulk.maxBytes = BULK_MAX_BYTES;
    spec.bulk.maxDocs = 100000;
    spec.bulk.maxAge = Duration {200};
    spec.overflow.kind = Overflow::Kind::Block;
    spec.overflow.blockTimeout = Duration {1000};
    auto client = makeClient("os-load", {spec});
    ASSERT_NE(client, nullptr);
    auto writer = client->writer("load");

    // Shared with the callbacks, which may outlive this frame if the drain does not finish before the deadline.
    struct Counters
    {
        std::atomic<std::uint64_t> ok {0};
        std::atomic<std::uint64_t> failed {0};
        std::atomic<std::uint64_t> dropped {0};
    };
    const auto counters = std::make_shared<Counters>();
    auto& ok = counters->ok;
    auto& failed = counters->failed;
    auto& dropped = counters->dropped;
    std::uint64_t accepted = 0;
    std::uint64_t submittedBytes = 0;
    std::uint64_t refused = 0;
    const std::string padding(1800, 'x');
    const auto begin = std::chrono::steady_clock::now();
    for (std::uint64_t i = 0; submittedBytes < BUDGET_BYTES && std::chrono::steady_clock::now() < deadline; ++i)
    {
        Op op;
        op.kind = Op::Kind::Index;
        op.index = m_index;
        op.id = "l" + std::to_string(i);
        op.body = nlohmann::json {{"agent", {{"id", std::to_string(i % 1000)}}}, {"n", i}, {"pad", padding}}.dump();
        const auto bytes = op.body.size();
        auto submit = writer->submit(std::move(op),
                                     [counters](const OpResult& result)
                                     {
                                         if (result.status == Status::Ok)
                                         {
                                             counters->ok.fetch_add(1);
                                         }
                                         else if (result.status == Status::Failed)
                                         {
                                             counters->failed.fetch_add(1);
                                         }
                                         else
                                         {
                                             counters->dropped.fetch_add(1);
                                         }
                                     });
        if (!submit.accepted)
        {
            ++refused; // SubmitTimeout while the bucket is full: the loop retries with the next document.
            continue;
        }
        ++accepted;
        submittedBytes += bytes;
    }
    const auto submitEnd = std::chrono::steady_clock::now();
    const auto drainEnd = std::max(deadline, submitEnd) + indexer_client::testing::scaled(60s);
    while (ok.load() + failed.load() + dropped.load() < accepted && std::chrono::steady_clock::now() < drainEnd)
    {
        std::this_thread::sleep_for(50ms);
    }
    const auto end = std::chrono::steady_clock::now();
    const auto seconds = std::chrono::duration<double>(end - begin).count();

    const auto snapshot = m_ref.snapshot();
    const auto metrics = client->metrics();
    ASSERT_FALSE(snapshot.nodes.empty());
    ASSERT_FALSE(metrics.buckets.empty());
    const auto& node = snapshot.nodes[0];
    const auto& bucket = metrics.buckets[0];
    const auto mean = node.latency.count == 0 ? 0.0
                                              : static_cast<double>(node.latency.sumMicros) /
                                                    static_cast<double>(node.latency.count) / 1000.0;
    std::cout << MEASURE << "load.bulk_max_bytes=" << BULK_MAX_BYTES << " submitted_bytes=" << submittedBytes
              << " accepted=" << accepted << " refused=" << refused << " ok=" << ok.load()
              << " failed=" << failed.load() << " dropped=" << dropped.load() << " seconds=" << seconds
              << " mib_per_s=" << (static_cast<double>(submittedBytes) / (1 << 20) / seconds) << "\n";
    std::cout << MEASURE << "load.latency p50_ms<=" << quantileMs(node.latency, 0.50)
              << " p95_ms<=" << quantileMs(node.latency, 0.95) << " p99_ms<=" << quantileMs(node.latency, 0.99)
              << " mean_ms=" << mean << " samples=" << node.latency.count
              << " decreases_latency=" << node.decreasesLatency << " decreases_429=" << node.decreases429
              << " decreases_throttled=" << node.decreasesThrottled << " window=" << node.window
              << " bulk_target=" << node.bulkTarget << " bulk_requests=" << bucket.bulkRequests
              << " bulk_bytes=" << bucket.bulkBytes
              << " avg_bulk_bytes=" << (bucket.bulkRequests == 0 ? 0 : bucket.bulkBytes / bucket.bulkRequests) << "\n";
    EXPECT_EQ(failed.load(), 0U);
    EXPECT_EQ(dropped.load(), 0U);
    EXPECT_EQ(ok.load(), accepted) << "every accepted write resolves within the drain";
}

TEST(OpenSearchHealth, RequireClusterFailsFast)
{
    requireCluster(std::getenv(URL_ENV), indexer_client::testing::scaled(120s));
    if (::testing::Test::HasFatalFailure() || ::testing::Test::IsSkipped())
    {
        return;
    }
    const auto start = std::chrono::steady_clock::now();
    EXPECT_FATAL_FAILURE(requireCluster("http://127.0.0.1:1", indexer_client::testing::scaled(2s)),
                         "did not answer /_cluster/health");
    const auto elapsed = std::chrono::steady_clock::now() - start;
    std::cout << MEASURE << "health.require_cluster_fail_ms="
              << std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count() << "\n";
    EXPECT_LT(elapsed, indexer_client::testing::scaled(10s));
}
