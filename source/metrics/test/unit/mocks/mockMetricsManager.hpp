#ifndef _MOCK_METRICS_MANAGER_HPP
#define _MOCK_METRICS_MANAGER_HPP

#include <gmock/gmock.h>

#include <metrics/iMetricsManager.hpp>

class MockMetricsManager : public metricsManager::IMetricsManager
{
public:
    MOCK_METHOD(void, start, (), (override));
    MOCK_METHOD(bool, isRunning, (), (override));
    MOCK_METHOD(std::shared_ptr<metricsManager::IMetricsScope>, getMetricsScope, (const std::string&, bool, int, int), (override));
    MOCK_METHOD(std::vector<std::string>, getScopeNames, (), (override));
    MOCK_METHOD(json::Json, getAllMetrics, (), (override));
};

#endif //_MOCK_METRICS_MANAGER_HPP
