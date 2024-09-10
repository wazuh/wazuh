#ifndef _METRICS_MOCK_MANAGER_HPP
#define _METRICS_MOCK_MANAGER_HPP

#include <gmock/gmock.h>

#include <metrics/imanager.hpp>

namespace metrics::mocks
{
class MockManager : public IManager
{
public:
    MOCK_METHOD(void, configure, (const std::shared_ptr<Config>& config), (override));
    MOCK_METHOD(void, addMetric, (const std::shared_ptr<IMetric>& metric, const std::string& name), (override));
    MOCK_METHOD(std::shared_ptr<IMetric>, getMetric, (const std::string& name), (override));
    MOCK_METHOD(void, enable, (), (override));
    MOCK_METHOD(void, disable, (), (override));
    MOCK_METHOD(void, enableModule, (const std::string& name), (override));
    MOCK_METHOD(void, disableModule, (const std::string& name), (override));
    MOCK_METHOD(void, enableMetric, (const std::string& name), (override));
    MOCK_METHOD(void, disableMetric, (const std::string& name), (override));

    static void setInstance() { getPtr(std::make_unique<MockManager>()); }
};
} // namespace metrics::mocks
