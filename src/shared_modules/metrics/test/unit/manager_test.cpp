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
#include <stdexcept>
#include <thread>
#include <vector>

#include <wazuh_metrics/manager.hpp>

#include <wazuh_metrics/mockCounter.hpp>
#include <wazuh_metrics/mockGauge.hpp>
#include <wazuh_metrics/mockHistogram.hpp>
#include <wazuh_metrics/mockManager.hpp>

using namespace wazuh::metrics;

class ManagerTest : public ::testing::Test
{
protected:
    Manager manager;
};

// ============================================================
// getOrCreate idempotence
// ============================================================

TEST_F(ManagerTest, GetOrCreateCounterIdempotent)
{
    auto counter1 = manager.getOrCreateCounter("test.counter");
    auto counter2 = manager.getOrCreateCounter("test.counter");

    // Same underlying metric: incrementing through one handle is visible
    // through the other.
    counter1->add(10);
    EXPECT_EQ(counter2->get(), 10U);

    counter2->add(5);
    EXPECT_EQ(counter1->get(), 15U);
}

TEST_F(ManagerTest, GetOrCreateGaugeIntIdempotent)
{
    auto gauge1 = manager.getOrCreateGaugeInt("test.gauge");
    auto gauge2 = manager.getOrCreateGaugeInt("test.gauge");

    gauge1->set(42);
    EXPECT_EQ(gauge2->get(), 42);

    gauge2->add(8);
    EXPECT_EQ(gauge1->get(), 50);
}

TEST_F(ManagerTest, GetOrCreateHistogramIdempotent)
{
    auto histogram1 = manager.getOrCreateHistogram("test.histogram");
    auto histogram2 = manager.getOrCreateHistogram("test.histogram");

    histogram1->observe(100);
    EXPECT_EQ(histogram2->snapshot().count, 1U);

    histogram2->observe(200);
    EXPECT_EQ(histogram1->snapshot().count, 2U);
}

// ============================================================
// Type conflicts
// ============================================================

TEST_F(ManagerTest, CounterThenGaugeThrows)
{
    manager.getOrCreateCounter("test.metric");
    EXPECT_THROW(manager.getOrCreateGaugeInt("test.metric"), std::invalid_argument);
}

TEST_F(ManagerTest, GaugeThenCounterThrows)
{
    manager.getOrCreateGaugeInt("test.metric");
    EXPECT_THROW(manager.getOrCreateCounter("test.metric"), std::invalid_argument);
}

TEST_F(ManagerTest, CounterThenHistogramThrows)
{
    manager.getOrCreateCounter("test.metric");
    EXPECT_THROW(manager.getOrCreateHistogram("test.metric"), std::invalid_argument);
}

TEST_F(ManagerTest, HistogramThenGaugeThrows)
{
    manager.getOrCreateHistogram("test.metric");
    EXPECT_THROW(manager.getOrCreateGaugeInt("test.metric"), std::invalid_argument);
}

TEST_F(ManagerTest, HistogramThenCounterThrows)
{
    manager.getOrCreateHistogram("test.metric");
    EXPECT_THROW(manager.getOrCreateCounter("test.metric"), std::invalid_argument);
}

TEST_F(ManagerTest, PullThenCounterThrows)
{
    manager.registerPullMetric("test.metric", []() { return uint64_t {1}; });
    EXPECT_THROW(manager.getOrCreateCounter("test.metric"), std::invalid_argument);
}

TEST_F(ManagerTest, PullThenGaugeThrows)
{
    manager.registerPullMetric("test.metric", []() { return uint64_t {1}; });
    EXPECT_THROW(manager.getOrCreateGaugeInt("test.metric"), std::invalid_argument);
}

TEST_F(ManagerTest, PullThenHistogramThrows)
{
    manager.registerPullMetric("test.metric", []() { return uint64_t {1}; });
    EXPECT_THROW(manager.getOrCreateHistogram("test.metric"), std::invalid_argument);
}

// ============================================================
// registerPullMetric does not overwrite
// ============================================================

TEST_F(ManagerTest, RegisterPullMetricDoesNotOverwriteCounter)
{
    auto counter = manager.getOrCreateCounter("test.metric");
    counter->add(7);

    // Attempting to register a pull metric under an existing name is a no-op.
    manager.registerPullMetric("test.metric", []() { return uint64_t {999}; });

    auto metric = manager.get("test.metric");
    ASSERT_NE(metric, nullptr);
    EXPECT_EQ(metric->type(), MetricType::COUNTER);
    EXPECT_EQ(std::dynamic_pointer_cast<ICounter>(metric)->get(), 7U);
}

TEST_F(ManagerTest, RegisterPullMetricSecondCallIsNoOp)
{
    manager.registerPullMetric("test.pull", []() { return uint64_t {1}; });
    manager.registerPullMetric("test.pull", []() { return uint64_t {2}; });

    EXPECT_EQ(manager.get("test.pull")->value(), 1.0);
}

// ============================================================
// Metadata
// ============================================================

TEST_F(ManagerTest, GetMetadataReturnsRegisteredValues)
{
    manager.getOrCreateCounter("test.counter", "A test counter", "events");

    auto metadata = manager.getMetadata("test.counter");
    EXPECT_EQ(metadata.description, "A test counter");
    EXPECT_EQ(metadata.unit, "events");
}

TEST_F(ManagerTest, GetMetadataEmptyForUnknownName)
{
    auto metadata = manager.getMetadata("nonexistent");
    EXPECT_TRUE(metadata.description.empty());
    EXPECT_TRUE(metadata.unit.empty());
}

TEST_F(ManagerTest, GetMetadataEmptyForRegisteredMetricWithoutMetadata)
{
    manager.getOrCreateCounter("test.counter"); // no description/unit

    auto metadata = manager.getMetadata("test.counter");
    EXPECT_TRUE(metadata.description.empty());
    EXPECT_TRUE(metadata.unit.empty());
}

TEST_F(ManagerTest, MetadataNotOverwrittenOnSecondGetOrCreate)
{
    manager.getOrCreateCounter("test.counter", "Original description", "count");
    // Second get-or-create with different (or empty) metadata must not change it.
    manager.getOrCreateCounter("test.counter", "New description", "bytes");

    auto metadata = manager.getMetadata("test.counter");
    EXPECT_EQ(metadata.description, "Original description");
    EXPECT_EQ(metadata.unit, "count");
}

TEST_F(ManagerTest, MetadataPartialFieldsAreStored)
{
    manager.getOrCreateGaugeInt("test.gauge", "", "connections");

    auto metadata = manager.getMetadata("test.gauge");
    EXPECT_TRUE(metadata.description.empty());
    EXPECT_EQ(metadata.unit, "connections");
}

// ============================================================
// enableAll / disableAll
// ============================================================

TEST_F(ManagerTest, DisableAllAffectsExistingMetrics)
{
    auto counter = manager.getOrCreateCounter("test.counter");
    auto gauge = manager.getOrCreateGaugeInt("test.gauge");
    auto histogram = manager.getOrCreateHistogram("test.histogram");

    manager.disableAll();

    EXPECT_FALSE(manager.isEnabled());
    EXPECT_FALSE(counter->isEnabled());
    EXPECT_FALSE(gauge->isEnabled());
    EXPECT_FALSE(histogram->isEnabled());

    counter->add(10);
    gauge->set(100);
    histogram->observe(50);
    EXPECT_EQ(counter->get(), 0U);
    EXPECT_EQ(gauge->get(), 0);
    EXPECT_EQ(histogram->snapshot().count, 0U);
}

TEST_F(ManagerTest, EnableAllReenablesExistingMetrics)
{
    auto counter = manager.getOrCreateCounter("test.counter");

    manager.disableAll();
    manager.enableAll();

    EXPECT_TRUE(manager.isEnabled());
    EXPECT_TRUE(counter->isEnabled());

    counter->add(10);
    EXPECT_EQ(counter->get(), 10U);
}

TEST_F(ManagerTest, MetricCreatedUnderDisableAllStartsDisabled)
{
    manager.disableAll();

    // A metric created *after* a global disable must be born disabled.
    auto counter = manager.getOrCreateCounter("late.counter");
    EXPECT_FALSE(counter->isEnabled());

    counter->add(5);
    EXPECT_EQ(counter->get(), 0U);

    manager.enableAll();
    EXPECT_TRUE(counter->isEnabled());
    counter->add(5);
    EXPECT_EQ(counter->get(), 5U);
}

TEST_F(ManagerTest, ManagerStartsEnabled)
{
    EXPECT_TRUE(manager.isEnabled());
}

// ============================================================
// clear()
// ============================================================

TEST_F(ManagerTest, ClearRemovesMetricsAndMetadata)
{
    manager.getOrCreateCounter("test.counter", "desc", "unit");
    manager.getOrCreateGaugeInt("test.gauge");

    EXPECT_EQ(manager.count(), 2U);

    manager.clear();

    EXPECT_EQ(manager.count(), 0U);
    EXPECT_FALSE(manager.exists("test.counter"));
    EXPECT_EQ(manager.get("test.counter"), nullptr);

    auto metadata = manager.getMetadata("test.counter");
    EXPECT_TRUE(metadata.description.empty());
    EXPECT_TRUE(metadata.unit.empty());
}

TEST_F(ManagerTest, ClearAllowsRecreatingWithDifferentType)
{
    manager.getOrCreateCounter("test.metric");
    manager.clear();

    // Now safe to recreate under a different type.
    EXPECT_NO_THROW(manager.getOrCreateGaugeInt("test.metric"));
}

// ============================================================
// count() / exists() / getAllNames()
// ============================================================

TEST_F(ManagerTest, CountTracksRegistrations)
{
    EXPECT_EQ(manager.count(), 0U);

    manager.getOrCreateCounter("metric.one");
    EXPECT_EQ(manager.count(), 1U);

    manager.getOrCreateCounter("metric.two");
    EXPECT_EQ(manager.count(), 2U);

    // Getting existing metric doesn't increase count
    manager.getOrCreateCounter("metric.one");
    EXPECT_EQ(manager.count(), 2U);
}

TEST_F(ManagerTest, ExistsReflectsRegistrations)
{
    manager.getOrCreateCounter("test.counter");

    EXPECT_TRUE(manager.exists("test.counter"));
    EXPECT_FALSE(manager.exists("nonexistent"));
}

TEST_F(ManagerTest, GetAllNamesListsEveryRegisteredMetric)
{
    manager.getOrCreateCounter("metric.one");
    manager.getOrCreateCounter("metric.two");
    manager.getOrCreateGaugeInt("metric.three");
    manager.registerPullMetric("metric.four", []() { return uint64_t {0}; });

    auto names = manager.getAllNames();

    EXPECT_EQ(names.size(), 4U);
    EXPECT_NE(std::find(names.begin(), names.end(), "metric.one"), names.end());
    EXPECT_NE(std::find(names.begin(), names.end(), "metric.two"), names.end());
    EXPECT_NE(std::find(names.begin(), names.end(), "metric.three"), names.end());
    EXPECT_NE(std::find(names.begin(), names.end(), "metric.four"), names.end());
}

TEST_F(ManagerTest, GetReturnsNullptrForUnknownMetric)
{
    EXPECT_EQ(manager.get("nonexistent"), nullptr);
}

// ============================================================
// Concurrency (registration races across types)
// ============================================================

TEST_F(ManagerTest, ConcurrentGetOrCreateSameNameReturnsSingleMetric)
{
    constexpr int NUM_THREADS = 16;

    std::vector<std::thread> threads;
    for (int i = 0; i < NUM_THREADS; ++i)
    {
        threads.emplace_back(
            [this]()
            {
                auto counter = manager.getOrCreateCounter("shared.metric");
                counter->add(1);
            });
    }

    for (auto& t : threads)
    {
        t.join();
    }

    EXPECT_EQ(manager.count(), 1U);
    auto counter = std::dynamic_pointer_cast<ICounter>(manager.get("shared.metric"));
    ASSERT_NE(counter, nullptr);
    EXPECT_EQ(counter->get(), static_cast<uint64_t>(NUM_THREADS));
}

// ============================================================
// Mock compile-time smoke tests: every pure virtual of the
// interfaces must be overridden or these mocks would be abstract
// and fail to instantiate.
// ============================================================

TEST(ManagerMocksTest, AllMocksAreInstantiable)
{
    mocks::MockManager mockManager;
    mocks::MockCounter mockCounter;
    mocks::MockGaugeInt mockGauge;
    mocks::MockHistogram mockHistogram;

    EXPECT_CALL(mockManager, count()).WillOnce(::testing::Return(0));
    EXPECT_EQ(mockManager.count(), 0U);

    EXPECT_CALL(mockCounter, get()).WillOnce(::testing::Return(5));
    EXPECT_EQ(mockCounter.get(), 5U);

    EXPECT_CALL(mockGauge, get()).WillOnce(::testing::Return(-3));
    EXPECT_EQ(mockGauge.get(), -3);

    IHistogram::Snapshot snapshot;
    snapshot.count = 1;
    EXPECT_CALL(mockHistogram, snapshot()).WillOnce(::testing::Return(snapshot));
    EXPECT_EQ(mockHistogram.snapshot().count, 1U);
}
