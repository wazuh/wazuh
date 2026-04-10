#ifndef FASTMETRICS_MANAGER_HPP
#define FASTMETRICS_MANAGER_HPP

#include <memory>
#include <mutex>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

#include <streamlog/logger.hpp>

#include <fastmetrics/atomicCounter.hpp>
#include <fastmetrics/atomicGauge.hpp>
#include <fastmetrics/iManager.hpp>
#include <fastmetrics/pullMetric.hpp>

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

    /**
     * @brief Generic get-or-create helper for any metric type
     *
     * @tparam InterfaceT  The metric interface (ICounter, IGaugeInt, IGaugeDouble)
     * @tparam ConcreteT   The concrete implementation (AtomicCounter, AtomicGaugeInt, AtomicGaugeDouble)
     */
    template<typename InterfaceT, typename ConcreteT>
    std::shared_ptr<InterfaceT> getOrCreate(const std::string& name)
    {
        static_assert(std::is_base_of_v<IMetric, InterfaceT>, "InterfaceT must derive from IMetric");
        static_assert(std::is_base_of_v<InterfaceT, ConcreteT>, "ConcreteT must implement InterfaceT");
        static_assert(std::is_constructible_v<ConcreteT, std::string>,
                      "ConcreteT must be constructible from std::string");

        // Fast path: try to get existing metric with shared lock
        {
            std::shared_lock lock(m_mutex);
            auto it = m_metrics.find(name);
            if (it != m_metrics.end())
            {
                auto casted = std::dynamic_pointer_cast<InterfaceT>(it->second);
                if (!casted)
                {
                    throw std::invalid_argument("Metric '" + name + "' already exists with a different type");
                }
                return casted;
            }
        }

        // Slow path: create new metric with unique lock
        std::unique_lock lock(m_mutex);

        // Double-check after acquiring unique lock
        auto it = m_metrics.find(name);
        if (it != m_metrics.end())
        {
            auto casted = std::dynamic_pointer_cast<InterfaceT>(it->second);
            if (!casted)
            {
                throw std::invalid_argument("Metric '" + name + "' already exists with a different type");
            }
            return casted;
        }

        auto metric = std::make_shared<ConcreteT>(name);
        if (!m_globalEnabled.load(std::memory_order_relaxed))
        {
            metric->disable();
        }

        m_metrics[name] = metric;
        return metric;
    }

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
                                                 const std::string& unit = "") override
    {
        return getOrCreate<ICounter, AtomicCounter>(name);
    }

    std::shared_ptr<IGaugeInt> getOrCreateGaugeInt(const std::string& name,
                                                   const std::string& description = "",
                                                   const std::string& unit = "") override
    {
        return getOrCreate<IGaugeInt, AtomicGaugeInt>(name);
    }

    std::shared_ptr<IGaugeDouble> getOrCreateGaugeDouble(const std::string& name,
                                                         const std::string& description = "",
                                                         const std::string& unit = "") override
    {
        return getOrCreate<IGaugeDouble, AtomicGaugeDouble>(name);
    }

    template<typename T>
    void registerPullMetric(const std::string& name,
                            std::function<T()> getter,
                            const std::string& description = "",
                            const std::string& unit = "")
    {
        // Check if already exists (fast path with shared lock)
        {
            std::shared_lock lock(m_mutex);
            if (m_metrics.find(name) != m_metrics.end())
            {
                return; // Already registered, skip
            }
        }

        // Create new metric (slow path with unique lock)
        {
            std::unique_lock lock(m_mutex);
            // Double-check after acquiring unique lock (another thread might have created it)
            if (m_metrics.find(name) != m_metrics.end())
            {
                return;
            }

            auto metric = std::make_shared<PullMetric<T>>(name, std::move(getter));
            if (!m_globalEnabled.load(std::memory_order_relaxed))
            {
                metric->disable();
            }
            m_metrics[name] = metric;
        }
    }

    /**
     * @brief Write all metrics as JSON lines using the provided writer.
     * @param metricsWriter Writer to output each JSON line.
     */
    void writeAllMetrics(std::shared_ptr<streamlog::WriterEvent> metricsWriter) const;

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

#endif // FASTMETRICS_MANAGER_HPP
