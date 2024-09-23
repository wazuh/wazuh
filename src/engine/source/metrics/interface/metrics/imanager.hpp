#ifndef _METRICS_IMANAGER_HPP
#define _METRICS_IMANAGER_HPP

#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <base/dotPath.hpp>
#include <base/utils/singletonLocator.hpp>

#include <metrics/imetric.hpp>

namespace metrics
{

class IMetricsManager
{
public:
    virtual ~IMetricsManager() = default;

    /**
     * @brief Add a metric to the manager.
     *
     * @param metricType The type of metric to add.
     * @param name Name of the metric. Follows the pattern "module.metric".
     * @param desc Description of the metric.
     * @param unit Unit of the metric.
     * @return std::shared_ptr<IMetric> The added metric.
     */
    virtual std::shared_ptr<IMetric>
    addMetric(MetricType metricType, const DotPath& name, const std::string& desc, const std::string& unit) = 0;

    /**
     * @brief Get a metric by name.
     *
     * @param name Name of the metric. Follows the pattern "module.metric".
     * @return std::shared_ptr<IMetric> The metric.
     */
    virtual std::shared_ptr<IMetric> getMetric(const DotPath& name) const = 0;
};

/**
 * @brief Metric manager interface. Singleton implementation, needs to be instantiated before use by the class
 * implementing the interface.
 *
 */
class IManager : public IMetricsManager
{
public:
    ~IManager() override = default;

    /**
     * @brief Config Interface.
     *
     */
    struct Config
    {
        virtual ~Config() = default;
    };

    /**
     * @brief Configure the manager. Exact behavior and Config implementation depends on the derived manager type.
     *
     * @param config The configuration object.
     */
    virtual void configure(const std::shared_ptr<Config>& config) = 0;

    /**
     * @brief Enable all metrics functionality.
     *
     */
    virtual void enable() = 0;

    /**
     * @brief Check if the manager is enabled.
     *
     * @return true if enabled, false otherwise.
     */
    virtual bool isEnabled() const = 0;

    /**
     * @brief Check if a specific metric or module is enabled.
     *
     * @param name Name of the metric. Follows the pattern "module.metric".
     * @return true if enabled, false otherwise.
     */
    virtual bool isEnabled(const DotPath& name) const = 0;

    /**
     * @brief Disable all metrics functionality.
     *
     */
    virtual void disable() = 0;

    /**
     * @brief Hot reload the configuration.
     *
     * @param newConfig
     */
    virtual void reload(const std::shared_ptr<Config>& newConfig) = 0;

    /**
     * @brief Enable all metrics of a module.
     *
     * @param name Name of the module.
     */
    virtual void enableModule(const DotPath& name) = 0;

    /**
     * @brief Disable all metrics of a module.
     *
     * @param name Name of the module.
     */
    virtual void disableModule(const DotPath& name) = 0;
};

/**
 * @brief Get the Manager instance.
 *
 * @return IManager&
 * @throw std::runtime_error if the Manager is not instantiated.
 */
inline IManager& getManager()
{
    return SingletonLocator::instance<IManager>();
}
} // namespace metrics

#endif // _METRICS_IMANAGER_HPP
