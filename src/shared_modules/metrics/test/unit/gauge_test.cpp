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

#include <wazuh_metrics/atomicGauge.hpp>

using namespace wazuh::metrics;

TEST(GaugeIntTest, BasicOperations)
{
    AtomicGaugeInt gauge("test.gauge");

    EXPECT_EQ(gauge.name(), "test.gauge");
    EXPECT_EQ(gauge.type(), MetricType::GAUGE_INT);
    EXPECT_TRUE(gauge.isEnabled());

    // Initial value
    EXPECT_EQ(gauge.get(), 0);

    // Set value
    gauge.set(100);
    EXPECT_EQ(gauge.get(), 100);

    // Add
    gauge.add(50);
    EXPECT_EQ(gauge.get(), 150);

    // Subtract
    gauge.sub(30);
    EXPECT_EQ(gauge.get(), 120);
}

TEST(GaugeIntTest, NegativeValues)
{
    AtomicGaugeInt gauge("test.gauge");

    gauge.set(10);
    gauge.sub(20);
    EXPECT_EQ(gauge.get(), -10);
    EXPECT_DOUBLE_EQ(gauge.value(), -10.0);

    gauge.add(5);
    EXPECT_EQ(gauge.get(), -5);

    gauge.set(-100);
    EXPECT_EQ(gauge.get(), -100);
}

TEST(GaugeIntTest, Reset)
{
    AtomicGaugeInt gauge("test.gauge");

    gauge.set(999);
    EXPECT_EQ(gauge.get(), 999);

    gauge.reset();
    EXPECT_EQ(gauge.get(), 0);
}

TEST(GaugeIntTest, EnableDisable)
{
    AtomicGaugeInt gauge("test.gauge");

    gauge.set(100);
    EXPECT_EQ(gauge.get(), 100);

    gauge.disable();
    EXPECT_FALSE(gauge.isEnabled());

    // Updates should be ignored
    gauge.set(200);
    gauge.add(50);
    gauge.sub(10);
    EXPECT_EQ(gauge.get(), 100); // Unchanged
    EXPECT_DOUBLE_EQ(gauge.value(), 0.0);

    gauge.enable();
    gauge.set(200);
    EXPECT_EQ(gauge.get(), 200);
    EXPECT_DOUBLE_EQ(gauge.value(), 200.0);
}
