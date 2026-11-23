/*
 * Wazuh task manager module
 * Copyright (C) Wazuh Inc.
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

#include <array>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

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
     * constructor and no name is ever formatted per event. The per-type families -- created,
     * retired and handler outcome -- are pre-created for the closed set: every registered type
     * times every member of the enum each family is keyed on, plus the one `unknown` bucket of the
     * created family (the only one a type this build does not register can reach). The maps
     * holding them are filled in the constructor and never modified, so they are read without a
     * lock.
     */
    class TaskMetrics
    {
    public:
        /**
         * @param manager The module's metrics manager.
         * @param registeredTypes Every type the registry knows; a create request for any other
         *        type is counted under `unknown`.
         * @throws std::invalid_argument if a registered type is named like the `unknown` bucket.
         */
        TaskMetrics(std::shared_ptr<wazuh::metrics::IManager> manager, const std::vector<std::string>& registeredTypes);

        /// @brief A manager task reached a terminal state. A non-terminal status, or a type that
        ///        was not registered at construction, is not counted: no metric exists for it.
        void taskRetired(const std::string& taskType, TaskStatus status);

        /// @brief A manager task was claimed and its handler ran, taking `micros`. The outcome of a
        ///        type that was not registered at construction is not counted; its duration is.
        void handlerRan(const std::string& taskType, Outcome outcome, std::uint64_t micros);

        /// @brief A manager task row was created, coalesced, collided or refused. A type that was not
        ///        registered at construction is counted under the `unknown` bucket.
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

        wazuh::metrics::IManager& manager() const noexcept
        {
            return *m_manager;
        }

    private:
        using CounterPtr = std::shared_ptr<wazuh::metrics::ICounter>;

        using CreatedCounters = std::array<CounterPtr, 4>; ///< By CreateResult.

        /// @brief Every per-type counter of one task type, each array indexed by its enum.
        struct TypeCounters
        {
            CreatedCounters created;
            std::array<CounterPtr, 4> retired; ///< By terminal TaskStatus, in TERMINAL_STATUSES order.
            std::array<CounterPtr, 7> outcome; ///< By Outcome.
        };

        CreatedCounters createCreatedCounters(std::string_view taskType);
        TypeCounters createTypeCounters(std::string_view taskType);

        /// @brief The type's counters, or nullptr for a type not registered.
        const TypeCounters* countersFor(std::string_view taskType) const;

        std::shared_ptr<wazuh::metrics::IManager> m_manager;

        /// @brief Filled in the constructor and never modified afterwards, so read without a lock.
        std::map<std::string, TypeCounters, std::less<>> m_byType;
        /// @brief Create requests for every type not registered: the one bucket such a type can reach.
        CreatedCounters m_unknownCreated;

        std::shared_ptr<wazuh::metrics::IHistogram> m_handlerDuration;
        std::shared_ptr<wazuh::metrics::IGaugeInt> m_busyWorkers;
        std::shared_ptr<wazuh::metrics::ICounter> m_agentTasksCreated;
        std::shared_ptr<wazuh::metrics::ICounter> m_agentTasksDelivered;
        std::shared_ptr<wazuh::metrics::ICounter> m_tasksReclaimed;
    };
} // namespace task_manager::metrics

#endif // _TASK_MANAGER_METRICS_TASK_METRICS_HPP
