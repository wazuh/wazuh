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
    struct ImplConfig;
    struct ImplOtPipeline;
    class ImplMetric;

private:
    std::unique_ptr<ImplConfig> m_config;
    std::unique_ptr<ImplOtPipeline> m_otPipeline;
    std::unordered_map<DotPath, std::shared_ptr<ImplMetric>> m_metrics;
    mutable std::shared_mutex m_mutex;

    bool unsafeEnabled() const;

    void validateConfig(const std::shared_ptr<ImplConfig>& config);

    void unsafeConfigure(const std::shared_ptr<Config>& config);

    void unsafeCreateOtPipeline();

    void unsafeDestroyOtPipeline();

    void unsafeEnable();

    void unsafeDisable();

public:
    Manager() = default;

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
