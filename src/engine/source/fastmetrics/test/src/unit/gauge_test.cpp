#include <gtest/gtest.h>

#include <fastmetrics/atomicGauge.hpp>

using namespace fastmetrics;

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

    gauge.enable();
    gauge.set(200);
    EXPECT_EQ(gauge.get(), 200);
}
