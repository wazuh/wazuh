#include <metrics/mockManager.hpp>
#include <metrics/mockMetric.hpp>

#include <gtest/gtest.h>

using namespace metrics::mocks;

TEST(MetricsTest, mocks)
{
    MockMetricsManager mockMetricsManager;
    MockManager mockManager;
    MockBaseMetric<uint64_t> mockBaseMetric;
}
