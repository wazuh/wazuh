/*
 * Wazuh task manager module
 * Copyright (C) 2015, Wazuh Inc.
 * September 1, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _TASK_MANAGER_METRICS_TASK_METRICS_HPP
#define _TASK_MANAGER_METRICS_TASK_METRICS_HPP

#include "model/task.hpp"

#include <wazuh_metrics/iManager.hpp>

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>

namespace task_manager::metrics
{
    /**
     * @brief The module's instrumentation, resolved once and cached.
     *
     * This closes a gap the previous implementation could not: queue depth, executor occupancy and
     * handler duration are modulesd-side facts, and wazuh_metrics is a C++ library with no C ABI,
     * so a plain-C module could not publish any of them. Only the wazuh-db half of the picture --
     * query counts and SQL time -- was observable, which described the database rather than the
     * queue.
     *
     * Resolving a metric costs a shared lock and a hash lookup, so everything is resolved in the
     * constructor and on first use per task type, never in a worker loop.
     */
    class TaskMetrics
    {
    public:
        explicit TaskMetrics(std::shared_ptr<wazuh::metrics::IManager> manager);

        /// @brief A manager task reached a terminal state.
        void taskRetired(const std::string& taskType, TaskStatus status);

        /// @brief A manager task was claimed and its handler ran, taking `micros`.
        void handlerRan(const std::string& taskType, Outcome outcome, std::uint64_t micros);

        /// @brief A manager task row was created, coalesced, collided or refused.
        void taskCreated(const std::string& taskType, CreateResult result);

        /// @brief An agent task was created / handed out.
        void agentTaskCreated();
        void agentTasksDelivered(std::uint64_t count);

        /// @brief Executor occupancy, updated as workers take and release slots.
        void setBusyWorkers(std::int64_t count);

        /// @brief Rows the ownership sweep returned to pending.
        void tasksReclaimed(std::uint64_t count);

        /// @brief Register a getter the metrics endpoint reads on demand. The caller must
        ///        guarantee whatever it captures outlives this object -- there is no remove().
        void registerPull(const std::string& name,
                          std::function<std::uint64_t()> getter,
                          const std::string& description,
                          const std::string& unit);

        wazuh::metrics::IManager& manager() const noexcept { return *m_manager; }

    private:
        /// @brief Counters are per (task type, outcome), so they cannot all be resolved up front:
        ///        the type set is known at construction but the cross product is large and mostly
        ///        unused. Resolved on first use and cached behind this mutex, which is never taken
        ///        on a path that matters -- one lookup per (type, outcome) pair, ever.
        std::shared_ptr<wazuh::metrics::ICounter> counterFor(const std::string& name);

        std::shared_ptr<wazuh::metrics::IManager> m_manager;

        std::mutex m_mutex;
        std::map<std::string, std::shared_ptr<wazuh::metrics::ICounter>, std::less<>> m_counters;

        std::shared_ptr<wazuh::metrics::IHistogram> m_handlerDuration;
        std::shared_ptr<wazuh::metrics::IGaugeInt> m_busyWorkers;
        std::shared_ptr<wazuh::metrics::ICounter> m_agentTasksCreated;
        std::shared_ptr<wazuh::metrics::ICounter> m_agentTasksDelivered;
        std::shared_ptr<wazuh::metrics::ICounter> m_tasksReclaimed;
    };
} // namespace task_manager::metrics

#endif // _TASK_MANAGER_METRICS_TASK_METRICS_HPP
