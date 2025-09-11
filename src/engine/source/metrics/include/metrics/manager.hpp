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
    struct ImplConfig : public IManager::Config
    {
        ImplConfig()
            : indexerConnectorFactory(nullptr)
            , exportInterval(1000)
            , exportTimeout(333)
            , logLevel(logging::Level::Err)
        {
        }

        ~ImplConfig() override = default;

        ImplConfig(const ImplConfig&) = default;
        ImplConfig(ImplConfig&&) = default;
        ImplConfig& operator=(const ImplConfig&) = default;
        ImplConfig& operator=(ImplConfig&&) = default;

        std::function<std::shared_ptr<IIndexerConnector>()> indexerConnectorFactory;
        std::chrono::milliseconds exportInterval;
        std::chrono::milliseconds exportTimeout;
        logging::Level logLevel;
    };

private:
    std::unique_ptr<ImplConfig> m_config;
    std::unordered_map<DotPath, std::shared_ptr<detail::IManagedMetric>> m_metrics;
    mutable std::shared_mutex m_mutex;
    bool m_enabled;

    bool unsafeEnabled() const;

    void validateConfig(const std::shared_ptr<ImplConfig>& config);

    void unsafeConfigure(const std::shared_ptr<Config>& config);

    void unsafeCreateOtPipeline();

    void unsafeDestroyOtPipeline();

    void unsafeEnable();

    void unsafeDisable();

public:
    Manager();
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

    bool isEnabled() const override;

    bool isEnabled(const DotPath& name) const override;

    void disable() override;

    void reload(const std::shared_ptr<Config>& newConfig) override;

    void enableModule(const DotPath& name) override;

    void disableModule(const DotPath& name) override;
};

} // namespace metrics

#endif // _METRICS_MANAGER_HPP
