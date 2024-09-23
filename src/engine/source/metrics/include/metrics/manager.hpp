#ifndef _METRICS_MANAGER_HPP
#define _METRICS_MANAGER_HPP

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <unordered_map>

#include <base/logging.hpp>
#include <indexerConnector/iindexerconnector.hpp>

#include <metrics/imanager.hpp>

namespace metrics
{

class Manager : public IManager
{
public:
    struct ManagerConfig : public Config
    {
        ManagerConfig()
            : indexerConnectorFactory(nullptr)
            , exportInterval(1000)
            , exportTimeout(333)
            , logLevel(logging::Level::Err)
        {
        }
        ~ManagerConfig() override = default;

        std::function<std::shared_ptr<IIndexerConnector>()> indexerConnectorFactory;
        std::chrono::milliseconds exportInterval;
        std::chrono::milliseconds exportTimeout;
        logging::Level logLevel;
    };

private:
    bool m_enabled;
    ManagerConfig m_config;
    std::unordered_map<DotPath, std::shared_ptr<ManagedMetric>> m_metrics;
    mutable std::shared_mutex m_mutex;

    void validateConfig(const std::shared_ptr<ManagerConfig>& config);

    void unsafeConfigure(const std::shared_ptr<Config>& config);

    void createOtPipeline();

    void destroyOtPipeline();

    void unsafeEnable();

    void unsafeDisable();

public:
    Manager()
        : m_enabled(false)
        , m_config()
    {
    }

    Manager(const Manager&) = delete;
    Manager(Manager&&) = delete;
    Manager& operator=(const Manager&) = delete;
    Manager& operator=(Manager&&) = delete;

    ~Manager() override = default;

    void configure(const std::shared_ptr<Config>& config) override;

    std::shared_ptr<IMetric>
    addMetric(MetricType metricType, const DotPath& name, const std::string& desc, const std::string& unit) override;

    std::shared_ptr<IMetric> getMetric(const DotPath& name) const override;

    void enable() override;

    bool isEnabled() const override { return m_enabled; }

    bool isEnabled(const DotPath& name) const override
    {
        if (!m_enabled)
        {
            return false;
        }

        auto it = m_metrics.find(name.str());
        return it != m_metrics.end() && it->second->isEnabled();
    }

    void disable() override;

    void reload(const std::shared_ptr<Config>& newConfig) override;

    void enableModule(const DotPath& name) override;

    void disableModule(const DotPath& name) override;
};

} // namespace metrics

#endif // _METRICS_MANAGER_HPP
