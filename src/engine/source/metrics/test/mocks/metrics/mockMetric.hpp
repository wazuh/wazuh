#ifndef _METRICS_MOCK_METRIC_HPP
#define _METRICS_MOCK_METRIC_HPP

#include <gmock/gmock.h>

#include <metrics/imetric.hpp>

namespace metrics::mocks
{

class MockMetric : public IMetric
{
public:
    MOCK_METHOD(void, mockUpdate, ());

    template<typename T>
    void update(T value)
    {
        mockUpdate();
    }
};

} // namespace metrics::mocks

#endif // _METRICS_MOCK_METRIC_HPP
