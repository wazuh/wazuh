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

// The metrics catalog without a runtime (plan-E5c §Tests, I100, I103): LatencyHistogram::observe bucket by bucket,
// the cumulative publication, the sanitized and dense names of forEachMetric, and the README's catalog and
// configuration row against what forEachMetric emits.

#include <cstdint>
#include <fstream>
#include <map>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include <gtest/gtest.h>

#include "indexer_client/metrics.hpp"

namespace
{
    namespace ic = indexer_client;

    using Values = std::map<std::string, double>;

    template<class T>
    Values collect(const T& metrics, std::map<std::string, ic::MetricKind>* kinds = nullptr)
    {
        Values out;
        ic::forEachMetric(metrics,
                          [&](std::string_view name, ic::MetricKind kind, double value)
                          {
                              EXPECT_TRUE(out.emplace(std::string(name), value).second) << "duplicated: " << name;
                              if (kinds)
                              {
                                  (*kinds)[std::string(name)] = kind;
                              }
                          });
        return out;
    }

    /// The bucket index a sample of `micros` lands in.
    std::size_t bucketOf(std::uint64_t micros)
    {
        ic::LatencyHistogram h;
        h.observe(micros);
        for (std::size_t i = 0; i < h.counts.size(); ++i)
        {
            if (h.counts[i] == 1)
            {
                return i;
            }
        }
        return h.counts.size();
    }

    ic::BucketMetrics bucket(std::string name)
    {
        ic::BucketMetrics b;
        b.consumer = "VD-Scanner";
        b.bucket = std::move(name);
        return b;
    }

    /// The suffixes every bucket emits after `indexer_client.bucket.<consumer>.<bucket>.`, in the contract's order.
    std::vector<std::string> bucketFields()
    {
        std::vector<std::string> out {"accepted"};
        for (std::size_t i = 0; i < static_cast<std::size_t>(ic::RejectCause::Count); ++i)
        {
            out.push_back(std::string("rejected.") + ic::toString(static_cast<ic::RejectCause>(i)));
        }
        for (std::size_t i = 0; i < static_cast<std::size_t>(ic::DropCause::Count); ++i)
        {
            out.push_back(std::string("dropped.") + ic::toString(static_cast<ic::DropCause>(i)));
        }
        out.push_back("ok");
        for (std::size_t i = 0; i < static_cast<std::size_t>(ic::FailCause::Count); ++i)
        {
            out.push_back(std::string("failed.") + ic::toString(static_cast<ic::FailCause>(i)));
        }
        for (std::size_t i = 0; i < static_cast<std::size_t>(ic::RetryCause::Count); ++i)
        {
            out.push_back(std::string("retries.") + ic::toString(static_cast<ic::RetryCause>(i)));
        }
        for (const auto* field :
             {"late_results", "retained_bytes", "charge_bytes", "quota_bytes", "bulk_requests", "bulk_bytes"})
        {
            out.emplace_back(field);
        }
        for (const auto bound : ic::LATENCY_BOUNDS_MS)
        {
            out.push_back("latency.le_" + std::to_string(bound));
        }
        for (const auto* field : {"latency.le_inf", "latency.sum_micros", "latency.count"})
        {
            out.emplace_back(field);
        }
        return out;
    }

    std::string readme()
    {
        const std::string here = __FILE__;
        const auto path = here.substr(0, here.rfind("/tests/unit/")) + "/README.md";
        std::ifstream in(path);
        EXPECT_TRUE(in.good()) << path;
        std::ostringstream text;
        text << in.rdbuf();
        return text.str();
    }

    /// The text of the README section that starts with `heading` (up to the next "## ").
    std::string section(const std::string& text, const std::string& heading)
    {
        const auto begin = text.find("\n" + heading + "\n");
        if (begin == std::string::npos)
        {
            ADD_FAILURE() << "no section " << heading;
            return {};
        }
        const auto end = text.find("\n## ", begin + 1);
        return text.substr(begin, end == std::string::npos ? std::string::npos : end - begin);
    }
} // namespace

// I103 (unit part of LatencyHistogramBuckets †): a sample lands in the first bucket whose bound covers its milliseconds
// rounded up; a sample exactly on a bound stays in that bucket (a strict bound moves 1 ms to le_2). Mutant: strict.
TEST(MetricsCatalogTest, LatencyHistogramBuckets)
{
    EXPECT_EQ(bucketOf(0), 0u);         // 0 ms
    EXPECT_EQ(bucketOf(1000), 0u);      // 1 ms: on the bound of le_1
    EXPECT_EQ(bucketOf(1001), 1u);      // rounded up to 2 ms
    EXPECT_EQ(bucketOf(3000), 2u);      // 3 ms: le_4
    EXPECT_EQ(bucketOf(4000), 2u);      // on the bound of le_4
    EXPECT_EQ(bucketOf(40000), 6u);     // 40 ms: le_64
    EXPECT_EQ(bucketOf(300000), 9u);    // 300 ms: le_512
    EXPECT_EQ(bucketOf(32768000), 15u); // on the last bound
    EXPECT_EQ(bucketOf(32768001), 16u); // inf
    EXPECT_EQ(bucketOf(UINT64_MAX / 2), 16u);

    ic::ClientMetrics m;
    m.consumer = "c";
    m.buckets.push_back(bucket("b"));
    for (const std::uint64_t micros : {0ULL, 1000ULL, 3000ULL, 40000ULL, 300000ULL})
    {
        m.buckets[0].latency.observe(micros);
    }
    EXPECT_EQ(m.buckets[0].latency.count, 5u);
    EXPECT_EQ(m.buckets[0].latency.sumMicros, 344000u);
    const auto v = collect(m);
    const std::string p = "indexer_client.bucket.c.b.latency.";
    // Cumulative: le_1 = {0, 1}, le_4 adds 3 ms, le_64 adds 40 ms, le_512 adds 300 ms.
    const std::map<std::string, double> expected {{"le_1", 2},
                                                  {"le_2", 2},
                                                  {"le_4", 3},
                                                  {"le_8", 3},
                                                  {"le_32", 3},
                                                  {"le_64", 4},
                                                  {"le_256", 4},
                                                  {"le_512", 5},
                                                  {"le_32768", 5},
                                                  {"le_inf", 5},
                                                  {"sum_micros", 344000},
                                                  {"count", 5}};
    for (const auto& [field, value] : expected)
    {
        EXPECT_EQ(v.at(p + field), value) << field;
    }
}

// I100 (unit part of CatalogNamesAreSaneAndStable): the sanitized names, and a dense catalog: every member of every
// closed set, zeros included, with the same names whatever the values.
TEST(MetricsCatalogTest, CatalogNamesAreSaneAndStable)
{
    EXPECT_EQ(ic::sanitizeMetricName("VD-Scanner"), "vd_scanner");
    EXPECT_EQ(ic::sanitizeMetricName("states.v2"), "states_v2");
    EXPECT_EQ(ic::sanitizeMetricName("---"), "_");
    EXPECT_EQ(ic::sanitizeMetricName(""), "_");
    EXPECT_EQ(ic::sanitizeMetricName("__"), "_");
    EXPECT_EQ(ic::sanitizeMetricName("a_B9"), "a_b9");
    EXPECT_EQ(ic::sanitizeMetricName("-a-"), "_a_");
    EXPECT_EQ(ic::sanitizeMetricName("\xc3\xb1"), "_") << "non-ASCII bytes become separators";

    ic::ClientMetrics m;
    m.consumer = "VD-Scanner";
    m.buckets = {bucket("states.v2"), bucket("---")};
    std::map<std::string, ic::MetricKind> kinds;
    const auto zero = collect(m, &kinds);
    ASSERT_EQ(zero.size(), 2u * 51u + 3u);
    std::set<std::string> expected;
    for (const auto* b : {"states_v2", "_"})
    {
        for (const auto& field : bucketFields())
        {
            expected.insert(std::string("indexer_client.bucket.vd_scanner.") + b + "." + field);
        }
    }
    for (const auto* field : {"callbacks_skipped", "callback_overruns", "callback_max_duration_ms"})
    {
        expected.insert(std::string("indexer_client.client.vd_scanner.") + field);
    }
    std::set<std::string> names;
    const std::regex shape(R"(indexer_client\.(bucket|client)\.[a-z0-9_]+(\.[a-z0-9_]+)+)");
    for (const auto& [name, value] : zero)
    {
        names.insert(name);
        EXPECT_TRUE(std::regex_match(name, shape)) << name;
        EXPECT_EQ(value, 0) << name;
    }
    EXPECT_EQ(names, expected);
    EXPECT_EQ(kinds.at("indexer_client.bucket.vd_scanner.states_v2.retained_bytes"), ic::MetricKind::Gauge);
    EXPECT_EQ(kinds.at("indexer_client.bucket.vd_scanner.states_v2.rejected.queue_full"), ic::MetricKind::Counter);
    EXPECT_EQ(kinds.at("indexer_client.client.vd_scanner.callback_max_duration_ms"), ic::MetricKind::Gauge);

    // The same names after every counter moved.
    for (auto& b : m.buckets)
    {
        b.accepted = 7;
        b.rejected.fill(1);
        b.dropped.fill(2);
        b.failed.fill(3);
        b.retries.fill(4);
        b.latency.observe(5000);
    }
    m.callbackOverruns = 9;
    const auto moved = collect(m);
    std::set<std::string> movedNames;
    for (const auto& [name, value] : moved)
    {
        movedNames.insert(name);
    }
    EXPECT_EQ(movedNames, names);
    EXPECT_EQ(moved.at("indexer_client.bucket.vd_scanner._.failed.invalid_state"), 3);
    EXPECT_EQ(moved.at("indexer_client.client.vd_scanner.callback_overruns"), 9);

    // N27: an empty or moved-from client has no names.
    EXPECT_TRUE(collect(ic::ClientMetrics {}).empty());

    // The runtime side: 7 + 8 + 10 names plus 31 per node, `<i>` the node's position; state 0/1/2.
    ic::MetricsSnapshot s;
    s.nodes.resize(2);
    s.nodes[0].state = ic::HealthView::NodeState::Available;
    s.nodes[1].state = ic::HealthView::NodeState::Throttled;
    const auto snap = collect(s);
    EXPECT_EQ(snap.size(), 7u + 8u + 10u + 2u * 31u);
    EXPECT_EQ(snap.at("indexer_client.node.0.state"), 0);
    EXPECT_EQ(snap.at("indexer_client.node.1.state"), 1);
    s.nodes[1].state = ic::HealthView::NodeState::Down;
    EXPECT_EQ(collect(s).at("indexer_client.node.1.state"), 2);
    for (const auto& [name, value] : snap)
    {
        EXPECT_EQ(name.find("indexer_client.bucket."), std::string::npos) << "no bucket in the snapshot: " << name;
    }
}

// RF-18 / README sync: the README's catalog counts and every leaf name forEachMetric emits, and the configuration row
// of log_summary_interval_ms (RuntimeConfigTest.LogSummaryIntervalKey checks the bounds and the 19 keys).
TEST(MetricsCatalogTest, ReadmeMatchesCatalog)
{
    const auto text = readme();
    EXPECT_NE(text.find("| `log_summary_interval_ms` | unsigned integer | ms | 1000 – 3600000 (1 h) | 60000 |"),
              std::string::npos)
        << "the configuration row of log_summary_interval_ms";

    ic::ClientMetrics m;
    m.consumer = "c";
    m.buckets.push_back(bucket("b"));
    ic::MetricsSnapshot s;
    s.nodes.resize(1);
    std::map<std::string, std::size_t> counts;
    std::set<std::string> leaves;
    const auto count = [&](const Values& values)
    {
        for (const auto& [name, value] : values)
        {
            const std::string_view rest(name.c_str() + std::string_view("indexer_client.").size());
            const auto kind = std::string(rest.substr(0, rest.find('.')));
            ++counts[kind];
            // The field after the prefix (bucket and client: two labels; node: one index).
            std::size_t skip = kind == "bucket" ? 3 : (kind == "client" || kind == "node") ? 2 : 1;
            std::size_t at = 0;
            for (std::size_t i = 0; i < skip; ++i)
            {
                at = rest.find('.', at) + 1;
            }
            leaves.insert(std::string(rest.substr(at)));
        }
    };
    count(collect(m));
    count(collect(s));
    const std::string line = "Counts per prefix: bucket " + std::to_string(counts["bucket"]) + ", client " +
                             std::to_string(counts["client"]) + ", runtime " + std::to_string(counts["runtime"]) +
                             ", query " + std::to_string(counts["query"]) + ", PIT " + std::to_string(counts["pit"]) +
                             ", node " + std::to_string(counts["node"]) + ".";
    EXPECT_NE(text.find(line), std::string::npos) << "expected: " << line;

    const auto metrics = section(text, "## Metrics (E5c)");
    for (const auto& leaf : leaves)
    {
        // A closed-set member is listed in its set's row (`<set>.<cause>` in the catalog); latency bounds by range.
        const auto dot = leaf.find('.');
        const auto group = dot == std::string::npos ? std::string() : leaf.substr(0, dot);
        const auto last = dot == std::string::npos ? leaf : leaf.substr(dot + 1);
        if (group == "rejected" || group == "dropped" || group == "failed" || group == "retries")
        {
            EXPECT_NE(metrics.find("`" + group + ".<cause>`"), std::string::npos) << leaf;
            EXPECT_NE(metrics.find("`" + last + "`"), std::string::npos) << leaf;
            continue;
        }
        if (group == "latency" && last.rfind("le_", 0) == 0 && last != "le_1" && last != "le_32768" && last != "le_inf")
        {
            continue; // Listed as `latency.le_1` … `latency.le_32768`.
        }
        const bool listed = metrics.find("`" + leaf + "`") != std::string::npos ||
                            (dot != std::string::npos && metrics.find("`" + last + "`") != std::string::npos &&
                             metrics.find("`" + group + ".") != std::string::npos);
        EXPECT_TRUE(listed) << "not in the README catalog: " << leaf;
    }
}
