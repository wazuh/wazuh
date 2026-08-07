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

#ifndef _WAZUH_METRICS_ATOMIC_COUNTER_HPP
#define _WAZUH_METRICS_ATOMIC_COUNTER_HPP

#include <atomic>
#include <string>

#include <wazuh_metrics/iMetric.hpp>

namespace wazuh::metrics
{

    /**
     * @brief Lock-free atomic counter implementation
     *
     * Uses std::atomic with memory_order_relaxed for maximum performance.
     * Monotonically increasing counter that never decreases (outside reset()).
     */
    class AtomicCounter : public ICounter
    {
    private:
        std::string m_name;
        std::atomic<uint64_t> m_value;
        std::atomic_bool m_enabled;

    public:
        explicit AtomicCounter(std::string name)
            : m_name(std::move(name))
            , m_value(0)
            , m_enabled(true)
        {
        }

        ~AtomicCounter() override = default;

        // Non-copyable, non-movable
        AtomicCounter(const AtomicCounter&) = delete;
        AtomicCounter& operator=(const AtomicCounter&) = delete;
        AtomicCounter(AtomicCounter&&) = delete;
        AtomicCounter& operator=(AtomicCounter&&) = delete;

        /** @copydoc wazuh::metrics::IMetric::name() */
        const std::string& name() const override
        {
            return m_name;
        }

        /** @copydoc wazuh::metrics::IMetric::type() */
        MetricType type() const override
        {
            return MetricType::COUNTER;
        }

        /** @copydoc wazuh::metrics::IMetric::isEnabled() */
        bool isEnabled() const override
        {
            return m_enabled.load(std::memory_order_relaxed);
        }

        /** @copydoc wazuh::metrics::IMetric::enable() */
        void enable() override
        {
            m_enabled.store(true, std::memory_order_relaxed);
        }

        /** @copydoc wazuh::metrics::IMetric::disable() */
        void disable() override
        {
            m_enabled.store(false, std::memory_order_relaxed);
        }

        /** @copydoc wazuh::metrics::IMetric::reset() */
        void reset() override
        {
            m_value.store(0, std::memory_order_relaxed);
        }

        /** @copydoc wazuh::metrics::IMetric::value() */
        double value() const override
        {
            if (!m_enabled.load(std::memory_order_relaxed))
            {
                return 0.0;
            }
            return static_cast<double>(get());
        }

        /** @copydoc wazuh::metrics::ICounter::add() */
        void add(uint64_t delta = 1) override
        {
            if (!m_enabled.load(std::memory_order_relaxed))
            {
                return;
            }

            m_value.fetch_add(delta, std::memory_order_relaxed);
        }

        /** @copydoc wazuh::metrics::ICounter::get() */
        uint64_t get() const override
        {
            return m_value.load(std::memory_order_relaxed);
        }
    };

} // namespace wazuh::metrics

#endif // _WAZUH_METRICS_ATOMIC_COUNTER_HPP
