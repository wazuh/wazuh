#ifndef _FASTMETRICS_MOCK_MANAGER_HPP
#define _FASTMETRICS_MOCK_MANAGER_HPP

#include <fastmetrics/iManager.hpp>
#include <gmock/gmock.h>

namespace fastmetrics
{

/**
 * @brief Mock implementation of IManager for testing
 */
class MockManager : public IManager
{
public:
    MOCK_METHOD(std::shared_ptr<ICounter>,
                getOrCreateCounter,
                (const std::string&, const std::string&, const std::string&),
                (override));

    MOCK_METHOD(std::shared_ptr<IGaugeInt>,
                getOrCreateGaugeInt,
                (const std::string&, const std::string&, const std::string&),
                (override));

    MOCK_METHOD(void,
                registerPullMetric,
                (const std::string&, std::function<uint64_t()>, const std::string&, const std::string&),
                (override));

    MOCK_METHOD(void,
                registerPullMetricDouble,
                (const std::string&, std::function<double()>, const std::string&, const std::string&),
                (override));

    MOCK_METHOD(void, writeAllMetrics, (std::shared_ptr<streamlog::WriterEvent>), (const, override));

    MOCK_METHOD(std::shared_ptr<IMetric>, get, (const std::string&), (const, override));

    MOCK_METHOD(bool, exists, (const std::string&), (const, override));

    MOCK_METHOD(std::vector<std::string>, getAllNames, (), (const, override));

    MOCK_METHOD(size_t, count, (), (const, override));

    MOCK_METHOD(void, enableAll, (), (override));

    MOCK_METHOD(void, disableAll, (), (override));

    MOCK_METHOD(bool, isEnabled, (), (const, override));

    MOCK_METHOD(void, clear, (), (override));
};

} // namespace fastmetrics

#endif // _FASTMETRICS_MOCK_MANAGER_HPP
