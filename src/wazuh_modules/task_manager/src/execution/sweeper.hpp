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

#ifndef _TASK_MANAGER_EXECUTION_SWEEPER_HPP
#define _TASK_MANAGER_EXECUTION_SWEEPER_HPP

#include "executor.hpp"
#include "metrics/taskMetrics.hpp"
#include "registry/taskRegistry.hpp"
#include "storage/iTaskStore.hpp"

#include <chrono>
#include <cstdint>
#include <memory>

namespace task_manager::execution
{
    /**
     * @brief Recovers rows nobody is running, retires rows nobody can run, and reports rows that
     *        are taking too long.
     *
     * All three run on the scheduler thread. None of them can interrupt anything: there is no
     * cancellation primitive in this daemon, so the watchdog observes and the sweep only ever acts
     * on work that is demonstrably not running.
     */
    class Sweeper
    {
    public:
        struct Options
        {
            std::chrono::seconds claimGrace {30};
            /// @brief Slack added to a type's watchdog budget before a stall is reported. Without
            ///        it, work that legitimately runs to the edge of its budget would be reported
            ///        as stalled on every healthy pass.
            std::chrono::seconds watchdogMargin {30};
        };

        Sweeper(storage::ITaskStore& store,
                const registry::TaskRegistry& registry,
                Executor& executor,
                Options options,
                std::shared_ptr<metrics::TaskMetrics> metrics);

        /**
         * @brief Startup pass over EVERY claimed row, whoever owns it.
         *
         * These are the rows a previous process instance left behind. The result set is bounded by
         * nothing after repeated crashes, so it pages -- on TASK_ID, never on OFFSET, because rows
         * are being written concurrently and an offset walk would skip or repeat as the set shifts.
         *
         * @return Rows returned to pending.
         */
        std::int64_t sweepAll();

        /// @brief Periodic pass over this process's own workers' rows only. One indexed seek per
        ///        worker, so it stays cheap at the sweep interval.
        std::int64_t sweepOwn();

        /**
         * @brief Retire pending rows whose TASK_TYPE this build does not know -- renamed or
         *        removed across an upgrade. Such a row is never claimed, is never expired by age,
         *        and counts against the row ceiling forever.
         *
         * MUST run after a sweep. A claimed orphan only becomes pending once the sweep has
         * released it, so a reaper that ran first would miss it -- and would miss it again on
         * every subsequent boot.
         *
         * @return Rows retired.
         */
        std::int64_t reapOrphanedTypes();

        /// @brief Report any worker past its type's budget plus the margin. Observation only.
        void runWatchdog();

    private:
        std::int64_t sweepPages(const std::string& owner);

        /// @return true when the row was returned to pending.
        bool reclaim(const storage::ClaimedRow& row);

        storage::ITaskStore& m_store;
        const registry::TaskRegistry& m_registry;
        Executor& m_executor;
        Options m_options;
        std::shared_ptr<metrics::TaskMetrics> m_metrics;
    };
} // namespace task_manager::execution

#endif // _TASK_MANAGER_EXECUTION_SWEEPER_HPP
