#ifndef _METRICS_MOCK_NOOPMANAGER_HPP
#define _METRICS_MOCK_NOOPMANAGER_HPP

#include <metrics/imanager.hpp>
#include <metrics/noOpMetric.hpp>

namespace metrics::mocks
{
class NoOpManager : public IManager
{
private:
    std::unordered_map<DotPath, std::shared_ptr<IMetric>> m_metrics;

public:
    void configure(const std::shared_ptr<Config>& config) override {}
    std::shared_ptr<IMetric>
    addMetric(MetricType metricType, const DotPath& name, const std::string& desc, const std::string& unit) override
    {
        switch (metricType)
        {
            case MetricType::UINTCOUNTER:
            case MetricType::UINTHISTOGRAM:
                m_metrics[name] = std::make_shared<NoOpUintMetric>();
                return m_metrics[name];
            case MetricType::DOUBLECOUNTER:
            case MetricType::DOUBLEHISTOGRAM:
                m_metrics[name] = std::make_shared<NoOpDoubleMetric>();
                return m_metrics[name];
            case MetricType::INTUPDOWNCOUNTER:
                m_metrics[name] = std::make_shared<NoOpIntMetric>();
                return m_metrics[name];
            default: throw std::logic_error("Unsupported metric type");
        }
    }
    std::shared_ptr<IMetric> getMetric(const DotPath& name) const override
    {
        auto it = m_metrics.find(name);
        if (it == m_metrics.end())
        {
            throw std::runtime_error("Metric not found");
        }
        return it->second;
    }
    void enable() override {}
    bool isEnabled() const override { return false; }
    bool isEnabled(const DotPath& name) const override { return false; }
    void disable() override {}
    void reload(const std::shared_ptr<Config>& newConfig) override {}
    void enableModule(const DotPath& name) override {}
    void disableModule(const DotPath& name) override {}
};
} // namespace metrics::mocks

#endif // _METRICS_MOCK_NOOPMANAGER_HPP
