#ifndef _FASTMETRICS_MOCK_COUNTER_HPP
#define _FASTMETRICS_MOCK_COUNTER_HPP

#include <gmock/gmock.h>
#include <fastmetrics/iMetric.hpp>

namespace fastmetrics
{

/**
 * @brief Mock implementation of ICounter for testing
 */
class MockCounter : public ICounter
{
public:
    MOCK_METHOD(const std::string&, name, (), (const, override));
    MOCK_METHOD(MetricType, type, (), (const, override));
    MOCK_METHOD(bool, isEnabled, (), (const, override));
    MOCK_METHOD(void, enable, (), (override));
    MOCK_METHOD(void, disable, (), (override));
    MOCK_METHOD(void, reset, (), (override));
    MOCK_METHOD(void, add, (uint64_t), (override));
    MOCK_METHOD(double, value, (), (const, override));
    MOCK_METHOD(uint64_t, get, (), (const, override));
};

} // namespace fastmetrics

#endif // _FASTMETRICS_MOCK_COUNTER_HPP
