/*
 * Wazuh shared metrics
 * Copyright (C) 2015, Wazuh Inc.
 * August 6, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

#include <json.hpp>

#include <wazuh_metrics/jsonDump.hpp>
#include <wazuh_metrics/manager.hpp>

using namespace wazuh::metrics;
using json = nlohmann::json;

namespace
{
    // A value strictly above 2^53 (the largest integer double can represent
    // exactly): if it survived a detour through double, it would be mangled.
    constexpr uint64_t kBeyondDoublePrecision {9007199254740995ULL};

    // Finds the metric entry with the given name inside a parsed dump, or
    // fails the current test.
    json findMetric(const json& doc, const std::string& name)
    {
        for (const auto& entry : doc.at("metrics"))
        {
            if (entry.at("name").get<std::string>() == name)
            {
                return entry;
            }
        }
        ADD_FAILURE() << "metric not found: " << name;
        return {};
    }
} // namespace

class JsonDumpTest : public ::testing::Test
{
protected:
    Manager manager;

    void populate()
    {
        auto bigCounter = manager.getOrCreateCounter("alpha.counter", "A counter with desc", "count");
        bigCounter->add(kBeyondDoublePrecision);

        // Registered without description/unit: the dump must omit both keys.
        manager.getOrCreateCounter("no.metadata.counter")->add(5);

        auto gauge = manager.getOrCreateGaugeInt("gauge.negative", "Negative gauge", "items");
        gauge->set(-42);

        manager.registerPullMetricDouble("pull.ratio", []() { return 0.75; }, "Pull ratio", "ratio");

        auto histogram = manager.getOrCreateHistogram("histogram.latency", "Latency histogram", "microseconds");
        histogram->observe(10);
        histogram->observe(20);
        histogram->observe(30);

        // A name carrying characters that must be escaped in JSON.
        manager.getOrCreateCounter("we\"ird\\name")->add(1);
    }
};

// ============================================================
// Envelope: name / timestamp / metrics
// ============================================================

TEST_F(JsonDumpTest, EnvelopeHasNameTimestampAndMetrics)
{
    populate();

    DumpOptions options;
    options.daemonName = "test-daemon";
    options.timestampISO = "2026-08-06T12:00:00Z";

    const auto dumped = dumpJson(manager, options);
    const auto doc = json::parse(dumped);

    ASSERT_TRUE(doc.contains("name"));
    ASSERT_TRUE(doc.contains("timestamp"));
    ASSERT_TRUE(doc.contains("metrics"));
    EXPECT_EQ(doc.at("name").get<std::string>(), "test-daemon");
    EXPECT_TRUE(doc.at("metrics").is_array());
}

TEST_F(JsonDumpTest, TimestampIsInjectedVerbatim)
{
    populate();

    DumpOptions options;
    options.daemonName = "test-daemon";
    options.timestampISO = "2026-08-06T12:00:00Z";

    const auto doc = json::parse(dumpJson(manager, options));
    EXPECT_EQ(doc.at("timestamp").get<std::string>(), "2026-08-06T12:00:00Z");
}

TEST_F(JsonDumpTest, EmptyTimestampFallsBackToNowIso8601)
{
    manager.getOrCreateCounter("only.counter")->add(1);

    DumpOptions options;
    options.daemonName = "test-daemon";
    // options.timestampISO left empty on purpose.

    const auto doc = json::parse(dumpJson(manager, options));
    const auto timestamp = doc.at("timestamp").get<std::string>();

    // "YYYY-MM-DDTHH:MM:SSZ"
    ASSERT_EQ(timestamp.size(), 20U);
    EXPECT_EQ(timestamp.back(), 'Z');
}

// ============================================================
// Ordering: metrics sorted alphabetically by name
// ============================================================

TEST_F(JsonDumpTest, MetricsAreSortedAlphabeticallyByName)
{
    populate();

    DumpOptions options;
    options.daemonName = "test-daemon";
    options.timestampISO = "2026-08-06T12:00:00Z";

    const auto doc = json::parse(dumpJson(manager, options));

    std::vector<std::string> names;
    for (const auto& entry : doc.at("metrics"))
    {
        names.push_back(entry.at("name").get<std::string>());
    }

    auto sortedNames = names;
    std::sort(sortedNames.begin(), sortedNames.end());

    EXPECT_EQ(names, sortedNames);
    ASSERT_EQ(names.size(), 6U);
}

// ============================================================
// Exact integer encoding: counters/histograms bypass double
// ============================================================

TEST_F(JsonDumpTest, CounterEmitsExactIntegerBeyondDoublePrecision)
{
    populate();

    const auto dumped = dumpJson(manager, {"test-daemon", "2026-08-06T12:00:00Z", false});

    // Pin the exact digit sequence in the raw JSON text: if the value had
    // gone through a double, it would not round-trip to this literal.
    EXPECT_NE(dumped.find("9007199254740995"), std::string::npos);

    const auto doc = json::parse(dumped);
    const auto entry = findMetric(doc, "alpha.counter");

    EXPECT_EQ(entry.at("type").get<std::string>(), "counter");
    EXPECT_EQ(entry.at("value").get<uint64_t>(), kBeyondDoublePrecision);
    EXPECT_EQ(entry.at("description").get<std::string>(), "A counter with desc");
    EXPECT_EQ(entry.at("unit").get<std::string>(), "count");
    EXPECT_TRUE(entry.at("enabled").get<bool>());
}

// ============================================================
// Negative gauge, encoded as a signed integer
// ============================================================

TEST_F(JsonDumpTest, NegativeGaugeEncodedAsSignedInteger)
{
    populate();

    const auto dumped = dumpJson(manager, {"test-daemon", "2026-08-06T12:00:00Z", false});

    EXPECT_NE(dumped.find("-42"), std::string::npos);

    const auto doc = json::parse(dumped);
    const auto entry = findMetric(doc, "gauge.negative");

    EXPECT_EQ(entry.at("type").get<std::string>(), "gauge_int");
    EXPECT_EQ(entry.at("value").get<int64_t>(), -42);
    EXPECT_EQ(entry.at("description").get<std::string>(), "Negative gauge");
    EXPECT_EQ(entry.at("unit").get<std::string>(), "items");
}

// ============================================================
// description/unit only appear when registered
// ============================================================

TEST_F(JsonDumpTest, DescriptionAndUnitOmittedWhenNotRegistered)
{
    populate();

    const auto doc = json::parse(dumpJson(manager, {"test-daemon", "2026-08-06T12:00:00Z", false}));
    const auto entry = findMetric(doc, "no.metadata.counter");

    EXPECT_EQ(entry.at("value").get<uint64_t>(), 5U);
    EXPECT_FALSE(entry.contains("description"));
    EXPECT_FALSE(entry.contains("unit"));
}

// ============================================================
// Pull metric: value emitted as double, metadata preserved
// ============================================================

TEST_F(JsonDumpTest, PullMetricEmitsDoubleValueWithMetadata)
{
    populate();

    const auto doc = json::parse(dumpJson(manager, {"test-daemon", "2026-08-06T12:00:00Z", false}));
    const auto entry = findMetric(doc, "pull.ratio");

    EXPECT_EQ(entry.at("type").get<std::string>(), "pull");
    EXPECT_DOUBLE_EQ(entry.at("value").get<double>(), 0.75);
    EXPECT_EQ(entry.at("description").get<std::string>(), "Pull ratio");
    EXPECT_EQ(entry.at("unit").get<std::string>(), "ratio");
}

// ============================================================
// Histogram: value==count, summary carries the full distribution
// ============================================================

TEST_F(JsonDumpTest, HistogramValueEqualsCountAndSummaryIsComplete)
{
    populate();

    const auto doc = json::parse(dumpJson(manager, {"test-daemon", "2026-08-06T12:00:00Z", false}));
    const auto entry = findMetric(doc, "histogram.latency");

    EXPECT_EQ(entry.at("type").get<std::string>(), "histogram");
    EXPECT_EQ(entry.at("value").get<uint64_t>(), 3U);
    EXPECT_EQ(entry.at("description").get<std::string>(), "Latency histogram");
    EXPECT_EQ(entry.at("unit").get<std::string>(), "microseconds");

    ASSERT_TRUE(entry.contains("summary"));
    const auto& summary = entry.at("summary");
    EXPECT_EQ(summary.at("count").get<uint64_t>(), 3U);
    EXPECT_EQ(summary.at("sum").get<uint64_t>(), 60U);
    EXPECT_EQ(summary.at("min").get<uint64_t>(), 10U);
    EXPECT_EQ(summary.at("max").get<uint64_t>(), 30U);
    EXPECT_TRUE(summary.contains("p50"));
    EXPECT_TRUE(summary.contains("p90"));
    EXPECT_TRUE(summary.contains("p99"));
}

// ============================================================
// Pretty-printing
// ============================================================

TEST_F(JsonDumpTest, PrettyOptionProducesLineBreaks)
{
    populate();

    const auto compact = dumpJson(manager, {"test-daemon", "2026-08-06T12:00:00Z", false});
    const auto pretty = dumpJson(manager, {"test-daemon", "2026-08-06T12:00:00Z", true});

    EXPECT_EQ(compact.find('\n'), std::string::npos);
    EXPECT_NE(pretty.find('\n'), std::string::npos);

    // Both encode the same data.
    EXPECT_EQ(json::parse(compact), json::parse(pretty));
}

// ============================================================
// Names carrying characters that must be escaped stay parseable
// ============================================================

TEST_F(JsonDumpTest, MetricNameWithQuotesAndBackslashIsEscapedAndParseable)
{
    populate();

    const auto dumped = dumpJson(manager, {"test-daemon", "2026-08-06T12:00:00Z", false});

    // The raw text must never contain an unescaped quote breaking the
    // "name" string -- json::parse below is the real proof, this is belt
    // and suspenders.
    const auto doc = json::parse(dumped);
    const auto entry = findMetric(doc, "we\"ird\\name");

    EXPECT_EQ(entry.at("name").get<std::string>(), "we\"ird\\name");
    EXPECT_EQ(entry.at("value").get<uint64_t>(), 1U);
}

// ============================================================
// Racing a clear(): dumpJson must not crash or produce a broken
// document if a metric disappears between getAllNames() and get().
// ============================================================

TEST_F(JsonDumpTest, EmptyManagerDumpsAnEmptyMetricsArray)
{
    const auto doc = json::parse(dumpJson(manager, {"test-daemon", "2026-08-06T12:00:00Z", false}));

    ASSERT_TRUE(doc.at("metrics").is_array());
    EXPECT_TRUE(doc.at("metrics").empty());
}
