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

#include "sweeper.hpp"

#include "taskManagerLog.hpp"

#include <algorithm>
#include <ctime>
#include <set>
#include <utility>

namespace
{
    using task_manager::Timestamp;

    Timestamp nowSeconds()
    {
        return static_cast<Timestamp>(std::time(nullptr));
    }

    constexpr int SWEEP_PAGE_SIZE {100};
} // namespace

namespace task_manager::execution
{
    Sweeper::Sweeper(storage::ITaskStore& store,
                     const registry::TaskRegistry& registry,
                     Executor& executor,
                     Options options,
                     std::shared_ptr<metrics::TaskMetrics> metrics)
        : m_store {store}
        , m_registry {registry}
        , m_executor {executor}
        , m_options {std::move(options)}
        , m_metrics {std::move(metrics)}
    {
    }

    bool Sweeper::reclaim(const storage::ClaimedRow& row)
    {
        const auto* descriptor {m_registry.find(row.taskType)};

        storage::RequeueRequest request;
        request.taskId = row.taskId;
        request.taskType = row.taskType;
        request.agentId = row.agentId;
        request.lastError = "reclaimed from a worker that is no longer running it";
        request.nextAttemptAt = nowSeconds();

        // Reclaimed EXACTLY as it was: the attempt is not charged to the row. A crashed worker is
        // not the task failing, and charging it would spend the task's budget on the process --
        // a manager crash-looping for an unrelated reason would dead-letter healthy work.
        request.attempts = row.attempts;
        request.deferCount = row.deferCount;

        // An unknown type is still reclaimed, with coalescing off because there is no descriptor
        // to ask. The retired implementation skipped these rows entirely, which left a claimed row
        // of a renamed type stuck forever: the sweep would not release it, so it never became
        // pending, so the orphaned-type reaper -- which only looks at pending rows -- never saw
        // it, and the ceiling cannot evict a non-terminal row. Releasing it here is what lets the
        // reaper retire it on the same pass.
        request.coalesce = descriptor != nullptr && descriptor->coalesceByAgent;

        try
        {
            m_store.requeue(request);
        }
        catch (const std::exception& exception)
        {
            LOGFN_ERROR(
                schedulerLogFn(), "Failed to reclaim manager task '%s': %s", row.taskId.c_str(), exception.what());
            return false;
        }

        if (descriptor != nullptr)
        {
            m_executor.notify(descriptor->name);
        }

        return true;
    }

    std::int64_t Sweeper::sweepPages(const std::string& owner)
    {
        std::int64_t reclaimed {0};
        std::string cursor;

        // Both of these were previously computed once PER ROW, inside the loop below, for values
        // that do not vary across a page:
        //
        //  - selfIdentity(0) opens and parses /proc/self/stat. Any worker's identity carries this
        //    process's pid and start time, so worker 0's is as good as any for deciding whether an
        //    owner string is ours, and none of it changes while we run.
        //  - the worker snapshot locks every worker's mutex and copies two strings out of each.
        //
        // At a hundred rows a page and eight workers that was a hundred file reads and eight hundred
        // lock acquisitions per page, on a sweep that runs every sixty seconds. Hoisted, it is one
        // of each. The snapshot going slightly stale across a page is harmless in the direction that
        // matters: isReclaimable() only ever uses it to REFUSE to reclaim a row a worker says it is
        // running, so a stale entry can delay a reclaim by one sweep, never cause one under a live
        // handler.
        const auto self {selfIdentity(0)};
        const auto workers {m_executor.snapshot()};

        while (true)
        {
            const auto rows {m_store.claimedRows(owner, cursor, SWEEP_PAGE_SIZE)};
            if (rows.empty())
            {
                break;
            }

            const auto pageStart {cursor};

            for (const auto& row : rows)
            {
                cursor = row.taskId;

                std::string inflight;
                for (const auto& worker : workers)
                {
                    if (worker.owner.toString() == row.owner)
                    {
                        inflight = worker.inflightTaskId;
                        break;
                    }
                }

                ReclaimQuery query;
                query.owner = row.owner;
                query.rowTaskId = row.taskId;
                query.workerInflightTaskId = inflight;
                query.claimTime = row.claimTime;
                query.now = nowSeconds();
                query.claimGrace = m_options.claimGrace;

                if (!isReclaimable(query, self))
                {
                    continue;
                }

                if (reclaim(row))
                {
                    ++reclaimed;
                }
            }

            // A page whose cursor did not advance would page forever.
            if (cursor == pageStart)
            {
                break;
            }
        }

        if (reclaimed > 0 && m_metrics)
        {
            m_metrics->tasksReclaimed(static_cast<std::uint64_t>(reclaimed));
        }

        return reclaimed;
    }

    std::int64_t Sweeper::sweepAll()
    {
        const auto reclaimed {sweepPages({})};

        if (reclaimed > 0)
        {
            LOGFN_INFO(schedulerLogFn(),
                       "Startup sweep returned %lld manager tasks left claimed by a previous run",
                       static_cast<long long>(reclaimed));
        }

        return reclaimed;
    }

    std::int64_t Sweeper::sweepOwn()
    {
        std::int64_t reclaimed {0};

        for (const auto& owner : m_executor.ownerStrings())
        {
            reclaimed += sweepPages(owner);
        }

        if (reclaimed > 0)
        {
            LOGFN_WARN(schedulerLogFn(),
                       "Reclaimed %lld manager tasks from workers that were no longer running them",
                       static_cast<long long>(reclaimed));
        }

        return reclaimed;
    }

    std::int64_t Sweeper::reapOrphanedTypes()
    {
        const auto known {m_registry.typeNames()};
        const std::set<std::string, std::less<>> knownSet {known.cbegin(), known.cend()};

        std::int64_t retired {0};

        for (const auto& taskType : m_store.distinctPendingTaskTypes())
        {
            if (knownSet.find(taskType) != knownSet.cend())
            {
                continue;
            }

            const auto affected {m_store.failPendingByType(taskType, "unknown task type", nowSeconds())};

            if (affected > 0)
            {
                LOGFN_ERROR(schedulerLogFn(),
                            "Retired %lld pending manager tasks of unknown type '%s'. This build has no "
                            "handler for it, so they could never have run.",
                            static_cast<long long>(affected),
                            taskType.c_str());
                retired += affected;
            }
        }

        return retired;
    }

    void Sweeper::runWatchdog()
    {
        const auto now {nowSeconds()};

        for (const auto& worker : m_executor.snapshot())
        {
            if (worker.inflightTaskId.empty() || worker.budget.count() <= 0)
            {
                continue;
            }

            const auto elapsed {now - worker.lastProgressAt};
            if (elapsed <= worker.budget.count() + m_options.watchdogMargin.count())
            {
                continue;
            }

            // Observation only. With no cancellation primitive available, making a hang visible
            // instead of silent is the whole of what is achievable here -- and this runs on the
            // scheduler's own cadence, so it is a periodic record rather than a live signal.
            // "Work", not "manager task": periodic actions publish themselves here too, and they
            // have no row -- for those, both names below are the action's own.
            LOGFN_WARN(schedulerLogFn(),
                       "Executor work '%s' of type '%s' has been running for %lld s, past its %lld s budget. "
                       "It cannot be interrupted; this is a report, not a recovery.",
                       worker.inflightTaskId.c_str(),
                       worker.inflightTaskType.c_str(),
                       static_cast<long long>(elapsed),
                       static_cast<long long>(worker.budget.count()));
        }
    }
} // namespace task_manager::execution
