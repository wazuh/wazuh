#ifndef _FAKE_METRIC_HPP
#define _FAKE_METRIC_HPP

#include <metrics/iMetricsInstruments.hpp>
#include <metrics/iMetricsManager.hpp>
#include <metrics/iMetricsScope.hpp>

template<typename T>
class FakeICounter : public metricsManager::iCounter<T>
{
    void addValue(const T& value) override {}
};

template<typename T>
class FakeIHistogram : public metricsManager::iHistogram<T>
{
    void recordValue(const T& value) override {}
};

template<typename T>
class FakeIGauge : public metricsManager::iGauge<T>
{
    void setValue(const T& value) override {}
};

class FakeMetricScope : public metricsManager::IMetricsScope
{
    std::shared_ptr<metricsManager::iCounter<double>> getCounterDouble(const std::string& name) override
    {
        return std::make_shared<FakeICounter<double>>();
    }

    std::shared_ptr<metricsManager::iCounter<uint64_t>> getCounterUInteger(const std::string& name) override
    {
        return std::make_shared<FakeICounter<uint64_t>>();
    }

    std::shared_ptr<metricsManager::iCounter<double>> getUpDownCounterDouble(const std::string& name) override
    {
        return std::make_shared<FakeICounter<double>>();
    }

    std::shared_ptr<metricsManager::iCounter<int64_t>> getUpDownCounterInteger(const std::string& name) override
    {
        return std::make_shared<FakeICounter<int64_t>>();
    }

    std::shared_ptr<metricsManager::iHistogram<double>> getHistogramDouble(const std::string& name) override
    {
        return std::make_shared<FakeIHistogram<double>>();
    }

    std::shared_ptr<metricsManager::iHistogram<uint64_t>> getHistogramUInteger(const std::string& name) override
    {
        return std::make_shared<FakeIHistogram<uint64_t>>();
    }

    std::shared_ptr<metricsManager::iGauge<double>> getGaugeDouble(const std::string& name, double defaultValue) override
    {
        return std::make_shared<FakeIGauge<double>>();
    }

    std::shared_ptr<metricsManager::iGauge<int64_t>> getGaugeInteger(const std::string& name, int64_t defaultValue) override
    {
        return std::make_shared<FakeIGauge<int64_t>>();
    }
};

class FakeMetricManager : public metricsManager::IMetricsManager
{
public:
    void start() override {}
    bool isRunning() override { return true; }
    std::shared_ptr<metricsManager::IMetricsScope>
    getMetricsScope(const std::string& name, bool delta, int exporterIntervalMS, int exporterTimeoutMS) override
    {
        return std::make_shared<FakeMetricScope>();
    }

    std::vector<std::string> getScopeNames() override { return {}; }
    json::Json getAllMetrics() { return {}; }
};

#endif // _FAKE_METRIC_HPP
