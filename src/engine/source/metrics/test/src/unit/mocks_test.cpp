#include <metrics/mockManager.hpp>
#include <metrics/mockMetric.hpp>
#include <metrics/noOpManager.hpp>
#include <metrics/noOpMetric.hpp>

#include <gtest/gtest.h>

using namespace metrics::mocks;

TEST(MockMetricsTest, mocks)
{
    MockMetricsManager mockMetricsManager;
    MockManager mockManager;
    MockMetric<uint64_t> mockMetricUint64;
    MockMetric<double> mockMetricDouble;
    MockMetric<int64_t> mockMetricInt64;
    NoOpManager noOpManager;

    ASSERT_NO_THROW(
        noOpManager.addMetric(metrics::MetricType::UINTCOUNTER, DotPath("module.noOpUintMetric"), "desc", "unit"));
    ASSERT_NO_THROW(
        noOpManager.addMetric(metrics::MetricType::DOUBLECOUNTER, DotPath("module.noOpDoubleMetric"), "desc", "unit"));
    ASSERT_NO_THROW(
        noOpManager.addMetric(metrics::MetricType::INTUPDOWNCOUNTER, DotPath("module.noOpIntMetric"), "desc", "unit"));

    ASSERT_NO_THROW(noOpManager.getMetric(DotPath("module.noOpUintMetric"))->update(1UL));
    ASSERT_NO_THROW(noOpManager.getMetric(DotPath("module.noOpDoubleMetric"))->update(1.0));
    ASSERT_NO_THROW(noOpManager.getMetric(DotPath("module.noOpIntMetric"))->update(1L));

    NoOpUintMetric noOpUintMetric;
    ASSERT_NO_THROW(noOpUintMetric.update(1UL));
    ASSERT_NO_THROW(noOpUintMetric.create());
    ASSERT_NO_THROW(noOpUintMetric.destroy());
    ASSERT_NO_THROW(noOpUintMetric.enable());
    ASSERT_NO_THROW(noOpUintMetric.disable());
    ASSERT_FALSE(noOpUintMetric.isEnabled());

    NoOpDoubleMetric noOpDoubleMetric;
    ASSERT_NO_THROW(noOpDoubleMetric.update(1.0));
    ASSERT_NO_THROW(noOpDoubleMetric.create());
    ASSERT_NO_THROW(noOpDoubleMetric.destroy());
    ASSERT_NO_THROW(noOpDoubleMetric.enable());
    ASSERT_NO_THROW(noOpDoubleMetric.disable());
    ASSERT_FALSE(noOpDoubleMetric.isEnabled());

    NoOpIntMetric noOpIntMetric;
    ASSERT_NO_THROW(noOpIntMetric.update(1L));
    ASSERT_NO_THROW(noOpIntMetric.create());
    ASSERT_NO_THROW(noOpIntMetric.destroy());
    ASSERT_NO_THROW(noOpIntMetric.enable());
    ASSERT_NO_THROW(noOpIntMetric.disable());
    ASSERT_FALSE(noOpIntMetric.isEnabled());
}
