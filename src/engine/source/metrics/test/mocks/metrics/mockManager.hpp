#ifndef _METRICS_MOCK_MANAGER_HPP
#define _METRICS_MOCK_MANAGER_HPP

#include <gmock/gmock.h>

#include <metrics/imanager.hpp>

namespace metrics::mocks
{

class MockMetricsManager : public IMetricsManager
{
public:
    MOCK_METHOD(std::shared_ptr<IMetric>,
                addMetric,
                (MetricType metricType, const DotPath& name, const std::string& desc, const std::string& unit),
                (override));
    MOCK_METHOD(std::shared_ptr<IMetric>, getMetric, (const DotPath& name), (const, override));
};

class MockManager : public IManager
{
public:
    MOCK_METHOD(void, configure, (const std::shared_ptr<Config>& config), (override));
    MOCK_METHOD(std::shared_ptr<IMetric>,
                addMetric,
                (MetricType metricType, const DotPath& name, const std::string& desc, const std::string& unit),
                (override));
    MOCK_METHOD(std::shared_ptr<IMetric>, getMetric, (const DotPath& name), (const, override));
    MOCK_METHOD(void, enable, (), (override));
    MOCK_METHOD(bool, isEnabled, (), (const, override));
    MOCK_METHOD(bool, isEnabled, (const DotPath& name), (const, override));
    MOCK_METHOD(void, disable, (), (override));
    MOCK_METHOD(void, reload, (const std::shared_ptr<Config>& newConfig), (override));
    MOCK_METHOD(void, enableModule, (const DotPath& name), (override));
    MOCK_METHOD(void, disableModule, (const DotPath& name), (override));
};
} // namespace metrics::mocks

#endif // _METRICS_MOCK_MANAGER_HPP
