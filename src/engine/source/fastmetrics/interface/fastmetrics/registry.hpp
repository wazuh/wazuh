#ifndef FASTMETRICS_REGISTRY_HPP
#define FASTMETRICS_REGISTRY_HPP

#include <functional>

#include <base/utils/singletonLocator.hpp>
#include <base/utils/singletonLocatorStrategies.hpp>

#include <fastmetrics/iManager.hpp>
#include <fastmetrics/metric_names.hpp>

namespace fastmetrics
{

/**
 * @brief Register the default manager implementation in the singleton locator.
 * This should be called once during application initialization before any calls to manager() or FASTMETRICS_PULL.
 */
void registerManager();

/**
 * @brief Get the singleton metrics manager.
 *
 * @return Reference to the abstract manager interface.
 */
inline IManager& manager()
{
    return SingletonLocator::instance<IManager>();
}

/**
 * @brief Register a uint64_t pull metric through the manager interface.
 */
inline void registerPullMetric(const std::string& name, std::function<uint64_t()> getter)
{
    manager().registerPullMetric(name, std::move(getter));
}

/**
 * @brief Register a double pull metric through the manager interface.
 */
inline void registerPullMetric(const std::string& name, std::function<double()> getter)
{
    manager().registerPullMetricDouble(name, std::move(getter));
}

} // namespace fastmetrics

#define FASTMETRICS_PULL(type, name, getter) fastmetrics::registerPullMetric(name, std::function<type()>(getter))

#endif // FASTMETRICS_REGISTRY_HPP
