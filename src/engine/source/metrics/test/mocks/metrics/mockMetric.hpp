#ifndef _METRICS_MOCK_METRIC_HPP
#define _METRICS_MOCK_METRIC_HPP

#include <gmock/gmock.h>

#include <metrics/imetric.hpp>

namespace metrics::mocks
{

template<typename T>
class MockBaseMetric : public BaseMetric<T>
{
public:
    MOCK_METHOD(void, create, (), (override));
    MOCK_METHOD(void, enable, (), (override));
    MOCK_METHOD(void, disable, (), (override));
    MOCK_METHOD(bool, isEnabled, (), (const, override));
    MOCK_METHOD(void, update, (T value), (override));
};

} // namespace metrics::mocks

#endif // _METRICS_MOCK_METRIC_HPP
