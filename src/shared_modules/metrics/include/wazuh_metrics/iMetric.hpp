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

#ifndef _WAZUH_METRICS_IMETRIC_HPP
#define _WAZUH_METRICS_IMETRIC_HPP

/**
 * @file iMetric.hpp
 * @brief Interfaces for fast lock-free metrics.
 *
 * All mutating operations on concrete metrics are lock-free (std::atomic with
 * memory_order_relaxed). Consumers resolve a metric once (cold path) and keep
 * the shared_ptr; every update afterwards is a single relaxed atomic op.
 */

#include <cstdint>
#include <string>

namespace wazuh::metrics
{

    /**
     * @brief Metric type enumeration
     */
    enum class MetricType
    {
        COUNTER,   ///< Monotonically increasing counter (uint64_t) - PUSH
        GAUGE_INT, ///< Gauge that can go up/down (int64_t) - PUSH
        PULL,      ///< On-demand callback metric (any type) - PULL
        HISTOGRAM  ///< Value distribution with percentile snapshots - PUSH
    };

    /**
     * @brief Base interface for all metrics
     */
    class IMetric
    {
    public:
        virtual ~IMetric() = default;

        /**
         * @brief Get metric name
         */
        virtual const std::string& name() const = 0;

        /**
         * @brief Get metric type
         */
        virtual MetricType type() const = 0;

        /**
         * @brief Check if metric is enabled
         */
        virtual bool isEnabled() const = 0;

        /**
         * @brief Enable metric updates
         */
        virtual void enable() = 0;

        /**
         * @brief Disable metric updates (updates become no-ops)
         */
        virtual void disable() = 0;

        /**
         * @brief Reset metric to initial value
         */
        virtual void reset() = 0;

        /**
         * @brief Get current value as double (generic representation)
         *
         * For counters and gauges: the current value. For histograms: the
         * observation count (the distribution itself is in IHistogram::snapshot()).
         */
        virtual double value() const = 0;
    };

    /**
     * @brief Counter interface (monotonically increasing)
     */
    class ICounter : public IMetric
    {
    public:
        ~ICounter() override = default;

        /**
         * @brief Increment counter by delta
         * @param delta Amount to add (default: 1)
         */
        virtual void add(uint64_t delta = 1) = 0;

        /**
         * @brief Get current value
         */
        virtual uint64_t get() const = 0;
    };

    /**
     * @brief Integer gauge interface (can increase or decrease)
     */
    class IGaugeInt : public IMetric
    {
    public:
        ~IGaugeInt() override = default;

        /**
         * @brief Set gauge to specific value
         */
        virtual void set(int64_t value) = 0;

        /**
         * @brief Add to gauge value
         */
        virtual void add(int64_t delta) = 0;

        /**
         * @brief Subtract from gauge value
         */
        virtual void sub(int64_t delta) = 0;

        /**
         * @brief Get current value
         */
        virtual int64_t get() const = 0;
    };

    /**
     * @brief Distribution metric with cheap lock-free recording and on-demand
     * percentile snapshots.
     *
     * Values are unit-agnostic unsigned integers (microseconds, bytes, items...);
     * the chosen unit is metadata, not behavior. uint64_t on purpose: C++17 has no
     * fetch_add for atomic<double>, and an integer sum stays exact.
     */
    class IHistogram : public IMetric
    {
    public:
        ~IHistogram() override = default;

        /**
         * @brief Record one observation
         */
        virtual void observe(uint64_t value) = 0;

        /**
         * @brief Point-in-time aggregate of the distribution.
         *
         * Percentiles are bucket-resolution estimates (see AtomicHistogram), and
         * the whole snapshot is best-effort under concurrent observes — fine for
         * metrics, not for exact accounting.
         */
        struct Snapshot
        {
            uint64_t count {0};
            uint64_t sum {0};
            uint64_t min {0};
            uint64_t max {0};
            uint64_t p50 {0};
            uint64_t p90 {0};
            uint64_t p99 {0};
        };

        /**
         * @brief Compute the current snapshot (cold path)
         */
        virtual Snapshot snapshot() const = 0;
    };

} // namespace wazuh::metrics

#endif // _WAZUH_METRICS_IMETRIC_HPP
