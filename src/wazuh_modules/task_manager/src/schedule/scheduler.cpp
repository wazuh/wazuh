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

#include "scheduler.hpp"

#include "model/taskId.hpp"
#include "taskManagerLog.hpp"

#include <json.hpp>

#include <algorithm>
#include <ctime>
#include <limits>
#include <utility>

namespace
{
    using task_manager::Timestamp;

    Timestamp nowSeconds()
    {
        return static_cast<Timestamp>(std::time(nullptr));
    }

    /// @brief How far out to push a schedule row whose id this build does not recognise. Left
    ///        rather than reaped: a downgrade produces exactly this, and the behaviour is safe and
    ///        visible once a day, where a reaper would be more code than the noise justifies.
    constexpr Timestamp UNKNOWN_SCHEDULE_BACKOFF {86400};

    /// @brief A due time that never arrives, for a timer the configuration turned off. Chosen so
    ///        `now >= it` stays false and computeNextWake()'s future-only filter ignores it,
    ///        without either place needing to know which timers are optional.
    constexpr Timestamp NEVER_DUE {std::numeric_limits<Timestamp>::max()};
} // namespace

namespace task_manager::schedule
{
    Scheduler::Scheduler(storage::ITaskStore& store,
                         execution::Executor& executor,
                         execution::Sweeper& sweeper,
                         host::IHostOps& hostOps,
                         std::vector<Schedule> schedules,
                         Options options,
                         std::shared_ptr<metrics::TaskMetrics> metrics)
        : m_store {store}
        , m_executor {executor}
        , m_sweeper {sweeper}
        , m_hostOps {hostOps}
        , m_schedules {std::move(schedules)}
        , m_options {std::move(options)}
        , m_metrics {std::move(metrics)}
    {
    }

    Scheduler::~Scheduler()
    {
        stop();
    }

    void Scheduler::start()
    {
        runStartupSequence();

        const auto now {nowSeconds()};
        m_nextSweep = now + m_options.sweepInterval.count();
        m_nextCleanup = now + m_options.cleanupInterval.count();
        m_nextSizeRotate = m_options.sizeRotationEnabled ? now + m_options.sizeRotateInterval.count() : NEVER_DUE;

        // The vacuum interval survives a restart, so a manager that is restarted daily still
        // compacts. Without this it would vacuum on every boot, or never.
        if (const auto last {m_store.getMetadata("last_vacuum_time")}; last.has_value())
        {
            try
            {
                m_nextVacuum = std::stoll(*last) + m_options.vacuumInterval.count();
            }
            catch (const std::exception&)
            {
                m_nextVacuum = now + m_options.vacuumInterval.count();
            }
        }
        else
        {
            m_nextVacuum = now + m_options.vacuumInterval.count();
        }

        m_thread = std::thread(&Scheduler::loop, this);
    }

    void Scheduler::stop()
    {
        if (m_stopping.exchange(true))
        {
            return;
        }

        {
            std::lock_guard lock {m_mutex};
            m_condition.notify_all();
        }

        if (m_thread.joinable())
        {
            m_thread.join();
        }
    }

    void Scheduler::wake()
    {
        std::lock_guard lock {m_mutex};
        m_condition.notify_all();
    }

    void Scheduler::runStartupSequence()
    {
        try
        {
            m_sweeper.sweepAll();
            m_sweeper.reapOrphanedTypes();
        }
        catch (const std::exception& exception)
        {
            // Not fatal. A failed startup sweep means some rows stay claimed for now; the periodic
            // sweep will get them, and refusing to start over it would be worse.
            LOGFN_ERROR(schedulerLogFn(), "Startup sweep failed: %s", exception.what());
        }

        try
        {
            reconcileSchedules();
        }
        catch (const std::exception& exception)
        {
            LOGFN_ERROR(schedulerLogFn(), "Could not reconcile schedules: %s", exception.what());
        }

        m_executor.notifyFromStore();
    }

    void Scheduler::reconcileSchedules()
    {
        const auto now {nowSeconds()};

        for (const auto& schedule : m_schedules)
        {
            // Read the previous row FIRST: its ENABLED is the only way to detect a
            // disabled-to-enabled transition, and that transition can straddle a restart.
            const auto previous {m_store.upsertSchedule(schedule.definition.id, 0, schedule.enabled)};

            const auto nextRunAt {startupNextRun(schedule,
                                                 previous.has_value(),
                                                 previous.has_value() ? previous->nextRunAt : 0,
                                                 previous.has_value() && previous->enabled,
                                                 now)};

            m_store.setScheduleNextRun(schedule.definition.id, nextRunAt);

            LOGFN_DEBUG1(schedulerLogFn(),
                         "Schedule '%s' is %s; next run at %lld",
                         schedule.definition.id.c_str(),
                         schedule.enabled ? "enabled" : "disabled",
                         static_cast<long long>(nextRunAt));
        }
    }

    void Scheduler::spawnDueRuns(const Timestamp now)
    {
        // Cached for this pass. The cluster role is read through a host call that re-parses
        // ossec.conf, so it must not be asked once per schedule -- and it must never reach the
        // wake path, which runs far more often than this.
        int workerState {-1};
        bool workerStateRead {false};

        for (const auto& row : m_store.dueSchedules(now))
        {
            const auto match {std::find_if(m_schedules.cbegin(),
                                           m_schedules.cend(),
                                           [&row](const Schedule& schedule)
                                           { return schedule.definition.id == row.scheduleId; })};

            if (match == m_schedules.cend())
            {
                // A schedule id this build does not know -- a downgrade leaves these behind. Push
                // it a day out and say so, rather than reaping it.
                m_store.setScheduleNextRun(row.scheduleId, now + UNKNOWN_SCHEDULE_BACKOFF);
                LOGFN_WARN(schedulerLogFn(),
                           "Ignoring unknown schedule '%s'; this build has no definition for it.",
                           row.scheduleId.c_str());
                continue;
            }

            const auto& schedule {*match};
            const auto slot {row.nextRunAt};

            // Always advance, whatever happens below. A slot that is skipped is FORFEITED, not
            // queued: leaving NEXT_RUN_AT in the past would re-evaluate the same slot on every
            // wake, and the work it represents is periodic anyway -- the next slot is the right
            // time to try again.
            const auto advanceTo {nextRun(schedule, slot, now)};

            if (!schedule.enabled)
            {
                m_store.setScheduleNextRun(schedule.definition.id, advanceTo);
                continue;
            }

            if (schedule.definition.scope == NodeScope::Master)
            {
                if (!workerStateRead)
                {
                    workerState = m_hostOps.workerState();
                    workerStateRead = true;
                }

                if (!nodeAllows(schedule.definition.scope, workerState))
                {
                    m_store.setScheduleNextRun(schedule.definition.id, advanceTo);
                    continue;
                }
            }

            if (m_store.scheduleHasActiveRun(schedule.definition.id))
            {
                // Overlap-skip, and it interacts with Incomplete on purpose: a multi-batch
                // retention sweep holds a non-terminal instance for its whole duration, which
                // suppresses its own next scheduled run until it finishes. That is correct -- a
                // sweep should not start again while the previous one is still walking -- but it
                // means the effective interval under a large backlog is "however long the sweep
                // takes", not the configured one.
                LOGFN_DEBUG1(schedulerLogFn(),
                             "Schedule '%s' still has an active run; skipping this slot.",
                             schedule.definition.id.c_str());
                m_store.setScheduleNextRun(schedule.definition.id, advanceTo);
                continue;
            }

            storage::CreateManagerTaskRequest request;
            // Keyed on the SLOT, so a crash between this insert and the advance below re-derives
            // the same id and the primary-key collision makes the double-spawn a no-op. No
            // cross-table transaction is needed for that.
            request.taskId = taskId::forScheduledRun(schedule.definition.id, slot);
            request.taskType = schedule.definition.taskType;
            request.payload = nlohmann::json {{"scheduled_run_at", slot}}.dump();
            request.createTime = now;
            request.nextAttemptAt = now;
            request.scheduleId = schedule.definition.id;
            request.scheduledRunAt = slot;

            try
            {
                const auto outcome {m_store.createManagerTask(request)};

                if (m_metrics)
                {
                    m_metrics->taskCreated(schedule.definition.taskType, outcome.result);
                }

                if (outcome.result == CreateResult::Created)
                {
                    LOGFN_DEBUG1(schedulerLogFn(),
                                 "Spawned '%s' run for slot %lld as task '%s'",
                                 schedule.definition.id.c_str(),
                                 static_cast<long long>(slot),
                                 outcome.taskId.c_str());
                    m_executor.notify(schedule.definition.taskType);
                }
                else if (outcome.result == CreateResult::Collided)
                {
                    // The expected idempotent path after a crash between the insert and the
                    // advance. Debug, not an error.
                    LOGFN_DEBUG1(schedulerLogFn(),
                                 "Run for '%s' slot %lld already existed; nothing to do.",
                                 schedule.definition.id.c_str(),
                                 static_cast<long long>(slot));
                }
            }
            catch (const std::exception& exception)
            {
                LOGFN_ERROR(schedulerLogFn(),
                            "Could not spawn a run for schedule '%s': %s",
                            schedule.definition.id.c_str(),
                            exception.what());
            }

            m_store.setScheduleNextRun(schedule.definition.id, advanceTo);
        }
    }

    void Scheduler::runRetention(const Timestamp now)
    {
        // Agent tasks DO age out while pending, and manager tasks deliberately do not. Both live
        // in this database and nothing else prunes either.
        m_store.expireAgentTasks(now - m_options.agentTaskTtl.count());
        m_store.deleteOldAgentTasks(now - m_options.agentTaskGrace.count());

        storage::RetentionRules rules;
        rules.terminalBefore = now - static_cast<Timestamp>(m_options.retentionDays) * 86400;
        rules.deadLetterBefore = now - static_cast<Timestamp>(m_options.deadLetterRetentionDays) * 86400;
        rules.historyPerSchedule = m_options.historyPerSchedule;
        rules.maxRows = m_options.maxRows;

        const auto stats {m_store.applyRetention(rules)};

        if (m_options.maxRows != storage::UNBOUNDED && stats.remaining > m_options.maxRows)
        {
            // The ceiling could not be met, which means the excess is pending, claimed or
            // dead-lettered rows that no rule may remove. Worth saying out loud: reaching this
            // state with only dead letters left is a real problem, and silence would hide it.
            LOGFN_WARN(schedulerLogFn(),
                       "MANAGER_TASKS still holds %lld rows after retention, above the %d ceiling. The "
                       "excess is pending, claimed or dead-lettered work that retention may not remove.",
                       static_cast<long long>(stats.remaining),
                       m_options.maxRows);
        }
    }

    Timestamp Scheduler::computeNextWake(const Timestamp now)
    {
        auto next {now + m_options.wakeBackstop.count()};

        // STRICTLY FUTURE candidates only, and that qualifier is the whole correctness of this
        // function rather than a detail.
        //
        // Every candidate below that is already due has, by this point, either been handled by the
        // pass that just ran (the four timers advance themselves) or belongs to somebody else --
        // and minPendingNextAttemptAt() is routinely in the PAST for a reason that is normal rather
        // than exceptional: a type whose concurrency group is saturated leaves its remaining rows
        // pending and eligible. Deleting 5000 agents leaves ~4996 of them in exactly that state for
        // the whole drain, because agent_delete_indexer runs four at a time.
        //
        // Admitting a past timestamp here would set `next` to it, the sleep would compute to zero,
        // and this thread would spin -- re-running spawnDueRuns, four store queries and a
        // notify_all() with no delay, for as long as the backlog lasted, serialised against the
        // executor on the store's single mutex. Those rows need no wake from here: the executor
        // holds them in its ready set and releaseGroup() wakes a worker the instant a slot frees.
        const auto consider {[&next, now](const std::optional<Timestamp>& candidate)
                             {
                                 if (candidate.has_value() && *candidate > now && *candidate < next)
                                 {
                                     next = *candidate;
                                 }
                             }};

        // The whole point: sleep until the earliest backed-off row becomes eligible, rather than
        // polling for it.
        consider(m_store.minPendingNextAttemptAt());
        consider(m_store.minScheduleNextRun());
        consider(m_nextSweep);
        consider(m_nextCleanup);
        consider(m_nextVacuum);
        consider(m_nextSizeRotate);

        // Never the past, and never `now` either: a zero-length wait is the spin this guards
        // against, so the floor is one second.
        return std::max(next, now + 1);
    }

    void Scheduler::loop()
    {
        while (!m_stopping.load(std::memory_order_acquire))
        {
            const auto now {nowSeconds()};

            try
            {
                spawnDueRuns(now);

                if (now >= m_nextSweep)
                {
                    m_sweeper.sweepOwn();
                    m_sweeper.runWatchdog();
                    m_nextSweep = now + m_options.sweepInterval.count();
                }

                if (now >= m_nextCleanup)
                {
                    runRetention(now);
                    m_nextCleanup = now + m_options.cleanupInterval.count();
                }

                if (now >= m_nextSizeRotate)
                {
                    // Signalled, not run here: rotation gzips a file up to the size threshold
                    // inline, and this thread is also the sweeper and the retention pass.
                    m_executor.signalPeriodicAction("log_rotate_size");
                    m_nextSizeRotate = now + m_options.sizeRotateInterval.count();
                }

                if (now >= m_nextVacuum)
                {
                    m_store.vacuum();
                    m_store.setMetadata("last_vacuum_time", std::to_string(now));
                    m_nextVacuum = now + m_options.vacuumInterval.count();
                }

                // Rows whose backoff has just elapsed.
                m_executor.notifyFromStore();

                // Close the group-commit window. Everything batched by the executor since the last
                // tick becomes durable here at the latest.
                m_store.flushWrites();
            }
            catch (const std::exception& exception)
            {
                LOGFN_ERROR(schedulerLogFn(), "Scheduler pass failed: %s", exception.what());
            }

            Timestamp wakeAt {0};
            try
            {
                wakeAt = computeNextWake(nowSeconds());
            }
            catch (const std::exception& exception)
            {
                LOGFN_ERROR(schedulerLogFn(), "Could not compute the next wake time: %s", exception.what());

                // The backstop earns its keep here, and only here: with the store unreadable there
                // is no earliest-eligible instant to sleep until, and neither alternative is
                // acceptable -- looping without a delay would spin against a failing database,
                // and waiting to be signalled would strand every backed-off row until a producer
                // happened to create one. Measured from now rather than from the top of the pass,
                // which may be a whole pass old.
                wakeAt = nowSeconds() + m_options.wakeBackstop.count();
            }

            const auto sleepFor {std::max<Timestamp>(wakeAt - nowSeconds(), 0)};

            std::unique_lock lock {m_mutex};
            m_condition.wait_for(
                lock, std::chrono::seconds {sleepFor}, [this] { return m_stopping.load(std::memory_order_acquire); });
        }

        LOGFN_DEBUG1(schedulerLogFn(), "Scheduler finished");
    }
} // namespace task_manager::schedule
