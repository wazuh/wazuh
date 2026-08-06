/*
 * Wazuh shared metrics
 * Copyright (C) 2015, Wazuh Inc.
 * August 6, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _WAZUH_METRICS_MANAGER_HPP
#define _WAZUH_METRICS_MANAGER_HPP

#include <memory>
#include <mutex>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <vector>

#include <wazuh_metrics/atomicCounter.hpp>
#include <wazuh_metrics/atomicGauge.hpp>
#include <wazuh_metrics/atomicHistogram.hpp>
#include <wazuh_metrics/iManager.hpp>
#include <wazuh_metrics/pullMetric.hpp>

namespace wazuh::metrics
{

    /**
     * @brief Thread-safe metric registry implementation
     *
     * Design:
     * - Metric registration: uses unique_lock (rare, cold path)
     * - Metric lookup: uses shared_lock (common, parallel reads OK)
     * - Metric updates: lock-free (ultra-common, hot path)
     *
     * Instantiable on purpose (no singleton): each daemon owns one and injects it.
     */
    class Manager : public IManager
    {
    private:
        mutable std::shared_mutex m_mutex;
        std::unordered_map<std::string, std::shared_ptr<IMetric>> m_metrics;
        std::unordered_map<std::string, Metadata> m_metadata; ///< Only non-empty registrations. Guarded by m_mutex.
        std::atomic_bool m_globalEnabled;

        /// Stores non-empty metadata for a metric being created. Caller holds the unique lock.
        void storeMetadata(const std::string& name, const std::string& description, const std::string& unit)
        {
            if (!description.empty() || !unit.empty())
            {
                m_metadata[name] = Metadata {description, unit};
            }
        }

        /**
         * @brief Generic get-or-create helper for any metric type
         *
         * @tparam InterfaceT  The metric interface (ICounter, IGaugeInt, IHistogram)
         * @tparam ConcreteT   The concrete implementation (AtomicCounter, AtomicGaugeInt, AtomicHistogram)
         */
        template<typename InterfaceT, typename ConcreteT>
        std::shared_ptr<InterfaceT>
        getOrCreate(const std::string& name, const std::string& description, const std::string& unit)
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
            storeMetadata(name, description, unit);
            return metric;
        }

        template<typename T>
        void registerPullMetricImpl(const std::string& name,
                                    std::function<T()> getter,
                                    const std::string& description,
                                    const std::string& unit)
        {
            {
                std::shared_lock lock(m_mutex);
                if (m_metrics.find(name) != m_metrics.end())
                {
                    return;
                }
            }

            {
                std::unique_lock lock(m_mutex);
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
                storeMetadata(name, description, unit);
            }
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

        /** @copydoc IManager::getOrCreateCounter() */
        std::shared_ptr<ICounter> getOrCreateCounter(const std::string& name,
                                                     const std::string& description = "",
                                                     const std::string& unit = "") override
        {
            return getOrCreate<ICounter, AtomicCounter>(name, description, unit);
        }

        /** @copydoc IManager::getOrCreateGaugeInt() */
        std::shared_ptr<IGaugeInt> getOrCreateGaugeInt(const std::string& name,
                                                       const std::string& description = "",
                                                       const std::string& unit = "") override
        {
            return getOrCreate<IGaugeInt, AtomicGaugeInt>(name, description, unit);
        }

        /** @copydoc IManager::getOrCreateHistogram() */
        std::shared_ptr<IHistogram> getOrCreateHistogram(const std::string& name,
                                                         const std::string& description = "",
                                                         const std::string& unit = "") override
        {
            return getOrCreate<IHistogram, AtomicHistogram>(name, description, unit);
        }

        /** @copydoc IManager::registerPullMetric() */
        void registerPullMetric(const std::string& name,
                                std::function<uint64_t()> getter,
                                const std::string& description = "",
                                const std::string& unit = "") override
        {
            registerPullMetricImpl<uint64_t>(name, std::move(getter), description, unit);
        }

        /** @copydoc IManager::registerPullMetricDouble() */
        void registerPullMetricDouble(const std::string& name,
                                      std::function<double()> getter,
                                      const std::string& description = "",
                                      const std::string& unit = "") override
        {
            registerPullMetricImpl<double>(name, std::move(getter), description, unit);
        }

        /** @copydoc IManager::get() */
        std::shared_ptr<IMetric> get(const std::string& name) const override;

        /** @copydoc IManager::getMetadata() */
        Metadata getMetadata(const std::string& name) const override;

        /** @copydoc IManager::exists() */
        bool exists(const std::string& name) const override;

        /** @copydoc IManager::getAllNames() */
        std::vector<std::string> getAllNames() const override;

        /** @copydoc IManager::count() */
        size_t count() const override;

        /** @copydoc IManager::enableAll() */
        void enableAll() override;

        /** @copydoc IManager::disableAll() */
        void disableAll() override;

        /** @copydoc IManager::isEnabled() */
        bool isEnabled() const override;

        /** @copydoc IManager::clear() */
        void clear() override;
    };

} // namespace wazuh::metrics

#endif // _WAZUH_METRICS_MANAGER_HPP
