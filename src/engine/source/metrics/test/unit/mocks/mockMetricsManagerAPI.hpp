#ifndef _MOCK_METRICS_MANAGER_API_HPP
#define _MOCK_METRICS_MANAGER_API_HPP

#include <gmock/gmock.h>

#include <metrics/iMetricsManagerAPI.hpp>

class MockMetricsManagerAPI : public metricsManager::IMetricsManagerAPI
{
public:
    MOCK_METHOD((std::variant<std::string, base::Error>), dumpCmd, (), (override));
    MOCK_METHOD(std::optional<base::Error>, enableCmd, (const std::string&, const std::string&, bool), (override));
    MOCK_METHOD((std::variant<std::string, base::Error>), getCmd, (const std::string&, const std::string&), (override));
    MOCK_METHOD(void, testCmd, (), (override));
    MOCK_METHOD((std::variant<std::string, base::Error>), listCmd, (), (override));
};

#endif //_MOCK_METRICS_MANAGER_API_HPP
