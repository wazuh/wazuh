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

TEST(GaugeDoubleTest, BasicOperations)
{
    AtomicGaugeDouble gauge("test.gauge");

    EXPECT_EQ(gauge.name(), "test.gauge");
    EXPECT_EQ(gauge.type(), MetricType::GAUGE_DBL);

    // Initial value
    EXPECT_DOUBLE_EQ(gauge.get(), 0.0);

    // Set value
    gauge.set(45.5);
    EXPECT_DOUBLE_EQ(gauge.get(), 45.5);

    gauge.set(99.9);
    EXPECT_DOUBLE_EQ(gauge.get(), 99.9);
}

TEST(GaugeDoubleTest, NegativeValues)
{
    AtomicGaugeDouble gauge("test.gauge");

    gauge.set(-10.5);
    EXPECT_DOUBLE_EQ(gauge.get(), -10.5);

    gauge.set(3.14159);
    EXPECT_NEAR(gauge.get(), 3.14159, 0.00001);
}

TEST(GaugeDoubleTest, Reset)
{
    AtomicGaugeDouble gauge("test.gauge");

    gauge.set(123.456);
    EXPECT_DOUBLE_EQ(gauge.get(), 123.456);

    gauge.reset();
    EXPECT_DOUBLE_EQ(gauge.get(), 0.0);
}

TEST(GaugeDoubleTest, EnableDisable)
{
    AtomicGaugeDouble gauge("test.gauge");

    gauge.set(50.5);
    EXPECT_DOUBLE_EQ(gauge.get(), 50.5);

    gauge.disable();
    gauge.set(100.0);
    EXPECT_DOUBLE_EQ(gauge.get(), 50.5); // Unchanged

    gauge.enable();
    gauge.set(100.0);
    EXPECT_DOUBLE_EQ(gauge.get(), 100.0);
}
