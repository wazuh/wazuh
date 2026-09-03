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

#ifndef _TASK_MANAGER_EXECUTION_EXECUTOR_HPP
#define _TASK_MANAGER_EXECUTION_EXECUTOR_HPP

#include "handlers/iHandler.hpp"
#include "metrics/taskMetrics.hpp"
#include "ownership.hpp"
#include "registry/taskRegistry.hpp"
#include "storage/iTaskStore.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace task_manager::execution
{
    /**
     * @brief The worker pool that claims manager tasks and runs their handlers.
     *
     * WHAT REPLACED LANES. The retired implementation gave each task type -- or each group of
     * types with similar cadence -- its own dedicated threads: four for deletions, one for scans,
     * one shared by the three periodic types, plus a fixed rotation among that last lane's types
     * and an assertion that a routed lane carried exactly one type. Adding a type meant choosing a
     * lane and, often, adding one.
     *
     * Here there is a single pool over a ready set of task types, and isolation comes from a
     * per-group concurrency cap in the descriptor. A cap of one on `vd_scan` IS the old scan lane;
     * the old delete lane is a cap of four. What the group buys on top is that the three periodic
     * types no longer share a thread merely to save threads: only the two rotations actually
     * conflict, so only they share a group, and the disconnection sweep can now run while a
     * rotation is compressing.
     *
     * THE READY SET is types believed to have work due, each carrying a token. A worker that
     * claims nothing removes the type -- but only if the token has not moved, because a producer
     * may have inserted a row and signalled in between. Without that check the notification would
     * be swallowed and the row would wait for the scheduler's next backstop wake instead of
     * starting immediately.
     *
     * NOTHING HERE POLLS. Producers signal on insert, and the scheduler signals when a backed-off
     * row becomes eligible, having computed that instant from the store.
     */
    class Executor
    {
    public:
        struct Options
        {
            int workerCount {4};
            std::chrono::seconds claimGrace {30};
        };

        /**
         * @brief Recurring work that is deliberately NOT a task row.
         *
         * Size-triggered log rotation is the only one. Routing two stat() calls through insert,
         * claim, execute, outcome and retention would cost about 1440 rows a day for work that is
         * idempotent, instantaneous and harmless to miss -- a skipped tick just rotates a minute
         * later. It gets no schedule row either, because it has no task type.
         *
         * It still runs HERE rather than on the scheduler thread, for two reasons: rotation gzips
         * a file up to the size threshold inline, and the scheduler is also the sweeper and the
         * work poller; and sharing the `rotation` concurrency group with log_rotate_daily is what
         * guarantees the two rotations never run at once.
         */
        struct PeriodicAction
        {
            std::string name;
            std::string concurrencyGroup;
            std::function<void(const StopToken&)> run;
            /// @brief How long one run may take before the watchdog reports it. Zero is unwatched.
            ///
            /// An action has no row to record a stall on, which is exactly why this matters: with a
            /// budget it appears in the worker snapshot like any task and the watchdog names it, and
            /// without one a rotation gzipping a multi-gigabyte log holds an executor slot entirely
            /// invisibly -- the one failure the watchdog exists to make visible.
            std::chrono::seconds watchdogBudget {0};
        };

        /// @brief What one worker is doing, for the sweep and the watchdog.
        struct WorkerSnapshot
        {
            OwnerIdentity owner;
            /// @brief Empty when idle.
            std::string inflightTaskId;
            std::string inflightTaskType;
            Timestamp lastProgressAt {0};
            /// @brief The running type's watchdog budget. Zero when idle.
            std::chrono::seconds budget {0};
        };

        Executor(storage::ITaskStore& store,
                 const registry::TaskRegistry& registry,
                 Options options,
                 std::shared_ptr<metrics::TaskMetrics> metrics);
        ~Executor();

        Executor(const Executor&) = delete;
        Executor& operator=(const Executor&) = delete;

        /// @brief Register a periodic action. Must be called before start().
        void registerPeriodicAction(std::shared_ptr<PeriodicAction> action);

        /// @brief Ask for a periodic action to run once, soon. Repeated signals before it runs
        ///        COALESCE into one run -- a rotation that was already owed is not owed twice.
        void signalPeriodicAction(const std::string& name);

        void start();

        /// @brief Ask every worker to finish its current task and exit, then join them.
        ///
        /// Rows still in flight stay `claimed` on purpose: the next boot's startup sweep reclaims
        /// them, and every handler is idempotent. Forcing them back to pending here would race the
        /// handler that is still returning.
        void stop();

        /// @brief Tell the pool that `taskType` may have work due right now.
        void notify(const std::string& taskType);

        /// @brief Signal several types at once, from the scheduler's due-set computation.
        ///
        /// A distinct name rather than an overload: `notify({"a", "b"})` cannot pick between a
        /// std::string and a std::vector<std::string> parameter, and a caller should not have to
        /// write a cast to say which one it meant.
        void notifyTypes(const std::vector<std::string>& taskTypes);

        /// @brief Re-seed the ready set from the store. Used at startup and after a sweep returns
        ///        rows to pending.
        void notifyFromStore();

        std::vector<WorkerSnapshot> snapshot() const;

        /// @brief Owner strings for every worker, so the sweep can ask about its own rows only.
        std::vector<std::string> ownerStrings() const;

    private:
        struct WorkerState
        {
            OwnerIdentity owner;
            std::string ownerString;

            mutable std::mutex mutex;
            std::string inflightTaskId;
            std::string inflightTaskType;
            Timestamp lastProgressAt {0};
            std::chrono::seconds budget {0};
        };

        /// @brief What a worker picked up: either a task type to claim from, or a periodic action
        ///        to run once. Exactly one of the two pointers is set.
        struct Selection
        {
            const registry::TaskTypeDescriptor* descriptor {nullptr};
            const PeriodicAction* action {nullptr};
            std::uint64_t token {0};
            std::string group;
        };

        void workerLoop(int workerIndex);
        void runTask(WorkerState& worker, const Selection& selection);
        void runAction(WorkerState& worker, const Selection& selection);

        /// @brief Is anything runnable below its group's cap? The wait predicate, so a worker
        ///        sleeps instead of spinning when everything pending is already at capacity.
        bool hasEligibleLocked() const;

        /// @return The work this worker should take, with its group slot already reserved, or
        ///         nullopt when another worker took the last eligible slot first.
        std::optional<Selection> selectLocked();

        bool groupHasRoomLocked(const std::string& group, int cap) const;

        void releaseGroup(const std::string& group);
        void retireType(const std::string& taskType, std::uint64_t token);

        void publish(WorkerState& worker, const ClaimedTask& task, std::chrono::seconds budget);
        /// @brief The same, for work that has no row: a periodic action publishes its own name.
        ///        No MANAGER_TASKS.TASK_ID can collide with one, so the ownership sweep still reads
        ///        the worker as "not running that row", which is true.
        void publish(WorkerState& worker,
                     const std::string& inflightId,
                     const std::string& inflightType,
                     std::chrono::seconds budget);
        void unpublish(WorkerState& worker);

        void recordOutcome(const registry::TaskTypeDescriptor& descriptor,
                           const ClaimedTask& task,
                           const HandlerResult& result);

        storage::ITaskStore& m_store;
        const registry::TaskRegistry& m_registry;
        Options m_options;
        std::shared_ptr<metrics::TaskMetrics> m_metrics;

        StopToken m_stopToken;
        std::atomic<bool> m_stopping {false};

        /// @brief Workers currently inside a handler. Its own counter rather than a derivation
        ///        from m_groupInflight, which counts reserved slots including the claim that has
        ///        not produced a task yet.
        std::atomic<int> m_busyWorkers {0};

        mutable std::mutex m_mutex;
        std::condition_variable m_condition;

        /// @brief type -> token. The token moves on every notify, which is what makes an empty
        ///        claim safe to act on.
        std::map<std::string, std::uint64_t, std::less<>> m_ready;
        std::uint64_t m_nextToken {1};

        /// @brief group -> in-flight count, checked against TaskRegistry::groupLimits().
        std::map<std::string, int, std::less<>> m_groupInflight;

        std::vector<std::shared_ptr<PeriodicAction>> m_actions;
        /// @brief Names of actions owed a run. A set, so repeated signals coalesce.
        std::set<std::string, std::less<>> m_pendingActions;

        /// @brief Round-robin cursor over the descriptor list, so a busy type cannot starve a
        ///        quiet one that became ready at the same moment.
        std::size_t m_rotation {0};

        std::vector<std::unique_ptr<WorkerState>> m_workers;
        std::vector<std::thread> m_threads;
    };
} // namespace task_manager::execution

#endif // _TASK_MANAGER_EXECUTION_EXECUTOR_HPP
