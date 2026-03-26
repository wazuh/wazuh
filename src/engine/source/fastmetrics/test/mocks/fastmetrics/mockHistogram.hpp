#ifndef _FASTMETRICS_MOCK_HISTOGRAM_HPP
#define _FASTMETRICS_MOCK_HISTOGRAM_HPP

#include <gmock/gmock.h>
#include <fastmetrics/iMetric.hpp>

namespace fastmetrics
{

/**
 * @brief Mock implementation of IHistogram for testing
 */
class MockHistogram : public IHistogram
{
public:
    MOCK_METHOD(const std::string&, name, (), (const, override));
    MOCK_METHOD(MetricType, type, (), (const, override));
    MOCK_METHOD(bool, isEnabled, (), (const, override));
    MOCK_METHOD(void, enable, (), (override));
    MOCK_METHOD(void, disable, (), (override));
    MOCK_METHOD(void, reset, (), (override));
    MOCK_METHOD(void, record, (uint64_t), (override));
    MOCK_METHOD(uint64_t, count, (), (const, override));
    MOCK_METHOD(uint64_t, sum, (), (const, override));
    MOCK_METHOD(uint64_t, min, (), (const, override));
    MOCK_METHOD(uint64_t, max, (), (const, override));
    MOCK_METHOD(uint64_t, mean, (), (const, override));
};

} // namespace fastmetrics

#endif // _FASTMETRICS_MOCK_HISTOGRAM_HPP
