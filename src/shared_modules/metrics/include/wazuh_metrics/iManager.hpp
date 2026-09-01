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

#ifndef _WAZUH_METRICS_IMANAGER_HPP
#define _WAZUH_METRICS_IMANAGER_HPP

/**
 * @file iManager.hpp
 * @brief Interface for the metric registry.
 *
 * There is deliberately NO process-wide singleton: each daemon instantiates a
 * Manager and injects it (shared_ptr) where instrumentation lives, matching the
 * dependency-injection style of its facade. Consumers resolve their metrics
 * ONCE (constructor / cold path) and cache the returned shared_ptr; resolving
 * costs a shared lock + hash lookup and does not belong in a hot loop.
 */

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include <wazuh_metrics/iMetric.hpp>

namespace wazuh::metrics
{

    /**
     * @brief Metric manager interface
     *
     * Allows creating and accessing metrics. Thread-safe for concurrent access.
     */
    class IManager
    {
    public:
        virtual ~IManager() = default;

        /**
         * @brief Descriptive fields attached to a metric at registration time.
         */
        struct Metadata
        {
            std::string description;
            std::string unit;
        };

        /**
         * @brief Create or get an existing counter
         *
         * @param name Metric name (e.g., "module.component.events")
         * @param description Optional description
         * @param unit Optional unit (e.g., "count", "bytes")
         * @return Shared pointer to counter
         * @throws std::invalid_argument if the name is already registered with a different type
         */
        virtual std::shared_ptr<ICounter> getOrCreateCounter(const std::string& name,
                                                             const std::string& description = "",
                                                             const std::string& unit = "") = 0;

        /**
         * @brief Create or get an existing int64 gauge
         *
         * @param name Metric name
         * @param description Optional description
         * @param unit Optional unit (e.g., "items", "connections")
         * @return Shared pointer to gauge
         * @throws std::invalid_argument if the name is already registered with a different type
         */
        virtual std::shared_ptr<IGaugeInt> getOrCreateGaugeInt(const std::string& name,
                                                               const std::string& description = "",
                                                               const std::string& unit = "") = 0;

        /**
         * @brief Create or get an existing histogram
         *
         * @param name Metric name
         * @param description Optional description
         * @param unit Optional unit of the observed values (e.g., "microseconds", "bytes")
         * @return Shared pointer to histogram
         * @throws std::invalid_argument if the name is already registered with a different type
         */
        virtual std::shared_ptr<IHistogram> getOrCreateHistogram(const std::string& name,
                                                                 const std::string& description = "",
                                                                 const std::string& unit = "") = 0;

        /**
         * @brief Register a pull metric that returns a uint64_t value
         *
         * WARNING: the getter runs whenever the metric is read (e.g. a dump). The
         * caller must guarantee whatever it captures outlives this manager, or
         * unregister by never using pulls for short-lived objects (there is no
         * remove()); prefer a gauge updated by the object itself in that case.
         *
         * @param name Metric name
         * @param getter Function to get the metric value
         * @param description Optional description
         * @param unit Optional unit (e.g., "items", "connections")
         */
        virtual void registerPullMetric(const std::string& name,
                                        std::function<uint64_t()> getter,
                                        const std::string& description = "",
                                        const std::string& unit = "") = 0;

        /**
         * @brief Register a pull metric that returns a double value
         *
         * Same lifetime warning as registerPullMetric().
         *
         * @param name Metric name
         * @param getter Function to get the metric value
         * @param description Optional description
         * @param unit Optional unit (e.g., "items", "connections")
         */
        virtual void registerPullMetricDouble(const std::string& name,
                                              std::function<double()> getter,
                                              const std::string& description = "",
                                              const std::string& unit = "") = 0;

        /**
         * @brief Get an existing metric by name
         *
         * @param name Metric name
         * @return Shared pointer to metric, or nullptr if not found
         */
        virtual std::shared_ptr<IMetric> get(const std::string& name) const = 0;

        /**
         * @brief Get the metadata a metric was registered with
         *
         * @param name Metric name
         * @return The stored metadata; empty fields for an unknown name
         */
        virtual Metadata getMetadata(const std::string& name) const = 0;

        /**
         * @brief Check if a metric exists
         *
         * @param name Metric name
         * @return true if metric exists
         */
        virtual bool exists(const std::string& name) const = 0;

        /**
         * @brief Get all registered metric names
         *
         * @return Vector of metric names (unordered)
         */
        virtual std::vector<std::string> getAllNames() const = 0;

        /**
         * @brief Get number of registered metrics
         *
         * @return Count of metrics
         */
        virtual size_t count() const = 0;

        /**
         * @brief Enable all metrics
         */
        virtual void enableAll() = 0;

        /**
         * @brief Disable all metrics
         */
        virtual void disableAll() = 0;

        /**
         * @brief Check if metrics are globally enabled
         */
        virtual bool isEnabled() const = 0;

        /**
         * @brief Clear all metrics (for testing)
         */
        virtual void clear() = 0;
    };

} // namespace wazuh::metrics

#endif // _WAZUH_METRICS_IMANAGER_HPP
