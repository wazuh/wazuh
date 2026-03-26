#ifndef _FASTMETRICS_MANAGER_HPP
#define _FASTMETRICS_MANAGER_HPP

#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include <fastmetrics/atomicCounter.hpp>
#include <fastmetrics/atomicGauge.hpp>
#include <fastmetrics/atomicHistogram.hpp>
#include <fastmetrics/iManager.hpp>

namespace fastmetrics
{

/**
 * @brief Thread-safe metric registry implementation
 *
 * Design:
 * - Metric registration: uses unique_lock (rare, cold path)
 * - Metric lookup: uses shared_lock (common, parallel reads OK)
 * - Metric updates: lock-free (ultra-common, hot path)
 */
class Manager : public IManager
{
private:
    mutable std::shared_mutex m_mutex;
    std::unordered_map<std::string, std::shared_ptr<IMetric>> m_metrics;
    std::atomic_bool m_globalEnabled;

public:
    Manager()
        : m_globalEnabled(true)
    {
    }

    ~Manager() override = default;

    // Non-copyable, non-movable
    Manager(const Manager&) = delete;
    Manager& operator=(const Manager&) = delete;
    Manager(Manager&&) = delete;
    Manager& operator=(Manager&&) = delete;

    std::shared_ptr<ICounter> getOrCreateCounter(const std::string& name,
                                                 const std::string& description = "",
                                                 const std::string& unit = "") override;

    std::shared_ptr<IGaugeInt> getOrCreateGaugeInt(const std::string& name,
                                                   const std::string& description = "",
                                                   const std::string& unit = "") override;

    std::shared_ptr<IGaugeDouble> getOrCreateGaugeDouble(const std::string& name,
                                                         const std::string& description = "",
                                                         const std::string& unit = "") override;

    std::shared_ptr<IHistogram> getOrCreateHistogram(const std::string& name,
                                                     const std::string& description = "",
                                                     const std::string& unit = "") override;

    std::shared_ptr<IMetric> get(const std::string& name) const override;

    bool exists(const std::string& name) const override;

    std::vector<std::string> getAllNames() const override;

    size_t count() const override;

    void enableAll() override;

    void disableAll() override;

    bool isEnabled() const override;

    void clear() override;
};

} // namespace fastmetrics

#endif // _FASTMETRICS_MANAGER_HPP
