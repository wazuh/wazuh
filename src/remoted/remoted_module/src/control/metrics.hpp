/*
 * Wazuh remoted module - Control endpoint metrics
 * Copyright (C) 2015, Wazuh Inc.
 * July 30, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_CONTROL_METRICS_HPP
#define _REMOTED_CONTROL_METRICS_HPP

#include <atomic>
#include <cstdint>

namespace remoted::control
{
    struct ControlMetrics
    {
        std::atomic<uint64_t> startupCount {0};
        std::atomic<uint64_t> notifyCount {0};
        std::atomic<uint64_t> shutdownCount {0};
        std::atomic<uint64_t> wdbErrorCount {0};
        std::atomic<uint64_t> taskFetchCount {0};
        std::atomic<uint64_t> taskFetchErrorCount {0};
    };

    inline void incStartup(ControlMetrics& m)
    {
        m.startupCount.fetch_add(1, std::memory_order_relaxed);
    }
    inline void incNotify(ControlMetrics& m)
    {
        m.notifyCount.fetch_add(1, std::memory_order_relaxed);
    }
    inline void incShutdown(ControlMetrics& m)
    {
        m.shutdownCount.fetch_add(1, std::memory_order_relaxed);
    }
    inline void incWdbError(ControlMetrics& m)
    {
        m.wdbErrorCount.fetch_add(1, std::memory_order_relaxed);
    }
    inline void incTaskFetch(ControlMetrics& m)
    {
        m.taskFetchCount.fetch_add(1, std::memory_order_relaxed);
    }
    inline void incTaskFetchError(ControlMetrics& m)
    {
        m.taskFetchErrorCount.fetch_add(1, std::memory_order_relaxed);
    }

} // namespace remoted::control

#endif // _REMOTED_CONTROL_METRICS_HPP
