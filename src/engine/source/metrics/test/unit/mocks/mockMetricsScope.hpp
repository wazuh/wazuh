#ifndef _MOCK_METRICS_SCOPE_HPP
#define _MOCK_METRICS_SCOPE_HPP

#include <gmock/gmock.h>

#include <metrics/iMetricsScope.hpp>

class MockMetricsScope : public metricsManager::IMetricsScope
{
public:
    MOCK_METHOD(std::shared_ptr<metricsManager::iCounter<double>>, getCounterDouble, (const std::string&), (override));
    MOCK_METHOD(std::shared_ptr<metricsManager::iCounter<uint64_t>>, getCounterUInteger, (const std::string&), (override));
    MOCK_METHOD(std::shared_ptr<metricsManager::iCounter<double>>, getUpDownCounterDouble, (const std::string&), (override));
    MOCK_METHOD(std::shared_ptr<metricsManager::iCounter<int64_t>>, getUpDownCounterInteger, (const std::string&), (override));
    MOCK_METHOD(std::shared_ptr<metricsManager::iHistogram<double>>, getHistogramDouble, (const std::string&), (override));
    MOCK_METHOD(std::shared_ptr<metricsManager::iHistogram<uint64_t>>, getHistogramUInteger, (const std::string&), (override));
    MOCK_METHOD(std::shared_ptr<metricsManager::iGauge<int64_t>>, getGaugeInteger, (const std::string&, int64_t), (override));
    MOCK_METHOD(std::shared_ptr<metricsManager::iGauge<double>>, getGaugeDouble, (const std::string&, double), (override));
};

#endif //_MOCK_METRICS_SCOPE_HPP
