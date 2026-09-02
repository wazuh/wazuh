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

#ifndef _TASK_MANAGER_SCHEDULE_SCHEDULER_HPP
#define _TASK_MANAGER_SCHEDULE_SCHEDULER_HPP

#include "cadence.hpp"
#include "execution/executor.hpp"
#include "execution/sweeper.hpp"
#include "host/iHostOps.hpp"
#include "metrics/taskMetrics.hpp"
#include "storage/iTaskStore.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

namespace task_manager::schedule
{
    /**
     * @brief The module's one timer thread: spawns scheduled runs, sweeps ownership, applies
     *        retention, and wakes the executor when a backed-off row becomes eligible.
     *
     * THERE IS NO POLL LOOP. The retired implementation ran a query every five seconds asking
     * which types had work. Owning the database makes that unnecessary: the store can report the
     * earliest NEXT_ATTEMPT_AT across all pending rows, so this thread sleeps until exactly that
     * instant -- or until an in-process producer signals it, which every create endpoint does.
     * `wakeBackstop` is a ceiling on that sleep, a safety net rather than the mechanism.
     *
     * The consequence worth stating: a task created through the HTTP surface starts immediately,
     * not up to five seconds later.
     */
    class Scheduler
    {
    public:
        struct Options
        {
            std::chrono::seconds wakeBackstop {60};
            std::chrono::seconds sweepInterval {60};
            std::chrono::seconds cleanupInterval {300};
            std::chrono::seconds vacuumInterval {86400};
            std::chrono::seconds sizeRotateInterval {60};

            /// @brief Agent-task TTL. Agent tasks DO age out while pending; manager tasks do not.
            std::chrono::seconds agentTaskTtl {3600};
            /// @brief How long an expired or delivered agent task is kept before removal.
            std::chrono::seconds agentTaskGrace {86400};

            int retentionDays {7};
            int deadLetterRetentionDays {30};
            int historyPerSchedule {20};
            int maxRows {100000};
        };

        Scheduler(storage::ITaskStore& store,
                  execution::Executor& executor,
                  execution::Sweeper& sweeper,
                  host::IHostOps& hostOps,
                  std::vector<Schedule> schedules,
                  Options options,
                  std::shared_ptr<metrics::TaskMetrics> metrics);
        ~Scheduler();

        Scheduler(const Scheduler&) = delete;
        Scheduler& operator=(const Scheduler&) = delete;

        /**
         * @brief Run the startup sequence, then launch the timer thread.
         *
         * The sequence order is load-bearing:
         *   1. sweep EVERY claimed row -- these belong to a previous process instance;
         *   2. reap pending rows of unknown types -- second, because a claimed orphan only becomes
         *      pending once step 1 has released it, so a reaper that ran first would miss it and
         *      would miss it again on every subsequent boot;
         *   3. reconcile schedules against configuration;
         *   4. seed the executor's ready set from the store.
         */
        void start();

        void stop();

        /// @brief Wake the timer thread now. Called by producers after an insert.
        void wake();

    private:
        void loop();
        void runStartupSequence();
        void reconcileSchedules();
        void spawnDueRuns(Timestamp now);
        void runRetention(Timestamp now);
        Timestamp computeNextWake(Timestamp now);

        storage::ITaskStore& m_store;
        execution::Executor& m_executor;
        execution::Sweeper& m_sweeper;
        host::IHostOps& m_hostOps;
        std::vector<Schedule> m_schedules;
        Options m_options;
        std::shared_ptr<metrics::TaskMetrics> m_metrics;

        std::atomic<bool> m_stopping {false};
        std::mutex m_mutex;
        std::condition_variable m_condition;
        std::thread m_thread;

        Timestamp m_nextSweep {0};
        Timestamp m_nextCleanup {0};
        Timestamp m_nextVacuum {0};
        Timestamp m_nextSizeRotate {0};
    };
} // namespace task_manager::schedule

#endif // _TASK_MANAGER_SCHEDULE_SCHEDULER_HPP
