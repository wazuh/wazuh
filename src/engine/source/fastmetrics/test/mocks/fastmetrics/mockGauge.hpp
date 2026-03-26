#ifndef _FASTMETRICS_MOCK_GAUGE_HPP
#define _FASTMETRICS_MOCK_GAUGE_HPP

#include <gmock/gmock.h>
#include <fastmetrics/iMetric.hpp>

namespace fastmetrics
{

/**
 * @brief Mock implementation of IGaugeInt for testing
 */
class MockGaugeInt : public IGaugeInt
{
public:
    MOCK_METHOD(const std::string&, name, (), (const, override));
    MOCK_METHOD(MetricType, type, (), (const, override));
    MOCK_METHOD(bool, isEnabled, (), (const, override));
    MOCK_METHOD(void, enable, (), (override));
    MOCK_METHOD(void, disable, (), (override));
    MOCK_METHOD(void, reset, (), (override));
    MOCK_METHOD(void, set, (int64_t), (override));
    MOCK_METHOD(void, add, (int64_t), (override));
    MOCK_METHOD(void, sub, (int64_t), (override));
    MOCK_METHOD(int64_t, get, (), (const, override));
};

/**
 * @brief Mock implementation of IGaugeDouble for testing
 */
class MockGaugeDouble : public IGaugeDouble
{
public:
    MOCK_METHOD(const std::string&, name, (), (const, override));
    MOCK_METHOD(MetricType, type, (), (const, override));
    MOCK_METHOD(bool, isEnabled, (), (const, override));
    MOCK_METHOD(void, enable, (), (override));
    MOCK_METHOD(void, disable, (), (override));
    MOCK_METHOD(void, reset, (), (override));
    MOCK_METHOD(void, set, (double), (override));
    MOCK_METHOD(double, get, (), (const, override));
};

} // namespace fastmetrics

#endif // _FASTMETRICS_MOCK_GAUGE_HPP
