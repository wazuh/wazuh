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

#include "executor.hpp"

#include "registry/retryPolicy.hpp"
#include "taskManagerLog.hpp"

#include <chrono>
#include <ctime>
#include <utility>

namespace
{
    using task_manager::Timestamp;

    Timestamp nowSeconds()
    {
        return static_cast<Timestamp>(std::time(nullptr));
    }

    /// @brief Consecutive-deferral thresholds at which the log escalates. The message names the
    ///        actual condition from LAST_ERROR rather than the counter, because DEFER_COUNT mixes
    ///        not_ready and busy on purpose.
    constexpr int DEFER_WARN_AT {3};
    constexpr int DEFER_ERROR_AT {20};
} // namespace

namespace task_manager::execution
{
    Executor::Executor(storage::ITaskStore& store,
                       const registry::TaskRegistry& registry,
                       Options options,
                       std::shared_ptr<metrics::TaskMetrics> metrics)
        : m_store {store}
        , m_registry {registry}
        , m_options {std::move(options)}
        , m_metrics {std::move(metrics)}
    {
        if (m_options.workerCount < 1)
        {
            m_options.workerCount = 1;
        }

        m_workers.reserve(static_cast<std::size_t>(m_options.workerCount));
        for (int index = 0; index < m_options.workerCount; ++index)
        {
            auto worker {std::make_unique<WorkerState>()};
            worker->owner = selfIdentity(index);
            worker->ownerString = worker->owner.toString();
            m_workers.push_back(std::move(worker));
        }
    }

    Executor::~Executor()
    {
        stop();
    }

    void Executor::start()
    {
        m_threads.reserve(m_workers.size());
        for (std::size_t index = 0; index < m_workers.size(); ++index)
        {
            m_threads.emplace_back(&Executor::workerLoop, this, static_cast<int>(index));
        }

        LOGFN_DEBUG1(executorLogFn(), "Executor started with %zu workers", m_workers.size());
    }

    void Executor::stop()
    {
        if (m_stopping.exchange(true))
        {
            return;
        }

        m_stopToken.requestStop();
        {
            std::lock_guard lock {m_mutex};
            m_condition.notify_all();
        }

        for (auto& thread : m_threads)
        {
            if (thread.joinable())
            {
                thread.join();
            }
        }
        m_threads.clear();
    }

    void Executor::notify(const std::string& taskType)
    {
        {
            std::lock_guard lock {m_mutex};
            m_ready[taskType] = m_nextToken++;
        }
        m_condition.notify_all();
    }

    void Executor::notifyTypes(const std::vector<std::string>& taskTypes)
    {
        if (taskTypes.empty())
        {
            return;
        }

        {
            std::lock_guard lock {m_mutex};
            for (const auto& taskType : taskTypes)
            {
                m_ready[taskType] = m_nextToken++;
            }
        }
        m_condition.notify_all();
    }

    void Executor::notifyFromStore()
    {
        const auto now {nowSeconds()};
        std::vector<std::string> due;

        for (const auto& entry : m_store.pendingTypes())
        {
            // Only types whose earliest row is actually eligible. Signalling a type that is still
            // backing off would spin a worker through a claim that cannot succeed.
            if (entry.minNextAttemptAt <= now)
            {
                due.push_back(entry.taskType);
            }
        }

        notifyTypes(due);
    }

    void Executor::registerPeriodicAction(std::shared_ptr<PeriodicAction> action)
    {
        if (action && action->run)
        {
            m_actions.push_back(std::move(action));
        }
    }

    void Executor::signalPeriodicAction(const std::string& name)
    {
        {
            std::lock_guard lock {m_mutex};
            // A set, so a rotation already owed is not owed twice.
            m_pendingActions.insert(name);
        }
        m_condition.notify_all();
    }

    bool Executor::groupHasRoomLocked(const std::string& group, const int cap) const
    {
        const auto inflight {m_groupInflight.find(group)};
        return (inflight == m_groupInflight.end() ? 0 : inflight->second) < cap;
    }

    bool Executor::hasEligibleLocked() const
    {
        const auto& limits {m_registry.groupLimits()};

        for (const auto& action : m_actions)
        {
            if (m_pendingActions.find(action->name) == m_pendingActions.end())
            {
                continue;
            }

            const auto limit {limits.find(action->concurrencyGroup)};
            const auto cap {limit == limits.end() ? 1 : limit->second};
            if (groupHasRoomLocked(action->concurrencyGroup, cap))
            {
                return true;
            }
        }

        for (const auto& descriptor : m_registry.all())
        {
            if (m_ready.find(descriptor.name) == m_ready.end())
            {
                continue;
            }

            const auto limit {limits.find(descriptor.concurrencyGroup)};
            const auto cap {limit == limits.end() ? descriptor.maxConcurrent : limit->second};
            if (groupHasRoomLocked(descriptor.concurrencyGroup, cap))
            {
                return true;
            }
        }

        return false;
    }

    std::optional<Executor::Selection> Executor::selectLocked()
    {
        const auto& limits {m_registry.groupLimits()};

        // Periodic actions first. They are rare, cheap and time-sensitive -- a size rotation that
        // waits behind a queue of scans is a log file growing past its threshold -- and taking
        // them first cannot starve tasks, because each runs at most once per signal.
        for (const auto& action : m_actions)
        {
            const auto pending {m_pendingActions.find(action->name)};
            if (pending == m_pendingActions.end())
            {
                continue;
            }

            const auto limit {limits.find(action->concurrencyGroup)};
            const auto cap {limit == limits.end() ? 1 : limit->second};
            if (!groupHasRoomLocked(action->concurrencyGroup, cap))
            {
                continue;
            }

            m_pendingActions.erase(pending);
            ++m_groupInflight[action->concurrencyGroup];

            Selection selection;
            selection.action = action.get();
            selection.group = action->concurrencyGroup;
            return selection;
        }

        const auto& descriptors {m_registry.all()};
        if (descriptors.empty())
        {
            return std::nullopt;
        }

        // Round-robin over the descriptor list rather than over the ready set, so a type that
        // became ready at the same moment as a busier sibling still gets its turn.
        for (std::size_t offset = 0; offset < descriptors.size(); ++offset)
        {
            const auto index {(m_rotation + offset) % descriptors.size()};
            const auto& descriptor {descriptors[index]};

            const auto ready {m_ready.find(descriptor.name)};
            if (ready == m_ready.end())
            {
                continue;
            }

            const auto limit {limits.find(descriptor.concurrencyGroup)};
            const auto cap {limit == limits.end() ? descriptor.maxConcurrent : limit->second};
            if (!groupHasRoomLocked(descriptor.concurrencyGroup, cap))
            {
                continue;
            }

            ++m_groupInflight[descriptor.concurrencyGroup];
            m_rotation = index + 1;

            Selection selection;
            selection.descriptor = &descriptor;
            selection.token = ready->second;
            selection.group = descriptor.concurrencyGroup;
            return selection;
        }

        return std::nullopt;
    }

    void Executor::releaseGroup(const std::string& group)
    {
        {
            std::lock_guard lock {m_mutex};
            if (auto it {m_groupInflight.find(group)}; it != m_groupInflight.end() && it->second > 0)
            {
                --it->second;
            }
        }
        m_condition.notify_all();
    }

    void Executor::retireType(const std::string& taskType, const std::uint64_t token)
    {
        std::lock_guard lock {m_mutex};

        // Only if nothing has signalled this type since we picked it up. A producer that inserted
        // a row between our empty claim and this line moved the token, and dropping the type here
        // would swallow that notification -- the row would then wait for the scheduler's backstop
        // instead of starting immediately, which is precisely the latency this design removes.
        if (const auto it {m_ready.find(taskType)}; it != m_ready.end() && it->second == token)
        {
            m_ready.erase(it);
        }
    }

    void Executor::publish(WorkerState& worker, const ClaimedTask& task, const std::chrono::seconds budget)
    {
        std::lock_guard lock {worker.mutex};
        worker.inflightTaskId = task.taskId;
        worker.inflightTaskType = task.taskType;
        worker.lastProgressAt = nowSeconds();
        worker.budget = budget;
    }

    void Executor::unpublish(WorkerState& worker)
    {
        std::lock_guard lock {worker.mutex};
        worker.inflightTaskId.clear();
        worker.inflightTaskType.clear();
        worker.budget = std::chrono::seconds {0};
    }

    void Executor::workerLoop(const int workerIndex)
    {
        auto& worker {*m_workers[static_cast<std::size_t>(workerIndex)]};

        while (!m_stopping.load(std::memory_order_acquire))
        {
            Selection selection;

            {
                std::unique_lock lock {m_mutex};

                // Eligibility, not merely "something is ready": when everything ready is already
                // at its group's cap, this worker sleeps until releaseGroup() notifies, rather
                // than waking to fail selection and poll.
                m_condition.wait(lock,
                                 [this] { return m_stopping.load(std::memory_order_acquire) || hasEligibleLocked(); });

                if (m_stopping.load(std::memory_order_acquire))
                {
                    break;
                }

                auto picked {selectLocked()};
                if (!picked.has_value())
                {
                    // Another worker took the last eligible slot between the predicate and here.
                    continue;
                }

                selection = std::move(*picked);
            }

            if (selection.action != nullptr)
            {
                runAction(worker, selection);
            }
            else
            {
                runTask(worker, selection);
            }

            releaseGroup(selection.group);
        }

        LOGFN_DEBUG1(executorLogFn(), "Executor worker %d finished", workerIndex);
    }

    void Executor::runAction(WorkerState& worker, const Selection& selection)
    {
        static_cast<void>(worker);

        if (m_stopping.load(std::memory_order_acquire))
        {
            return;
        }

        try
        {
            selection.action->run(m_stopToken);
        }
        catch (const std::exception& exception)
        {
            // A periodic action has no row to record a failure on, so the log line is the whole
            // record. It is retried on its own next signal regardless.
            LOGFN_ERROR(
                executorLogFn(), "Periodic action '%s' threw: %s", selection.action->name.c_str(), exception.what());
        }
    }

    void Executor::runTask(WorkerState& worker, const Selection& selection)
    {
        const auto& descriptor {*selection.descriptor};
        std::optional<ClaimedTask> claimed;

        try
        {
            claimed = m_store.claim(descriptor.name, worker.ownerString, nowSeconds());
        }
        catch (const std::exception& exception)
        {
            LOGFN_ERROR(executorLogFn(), "Failed to claim a '%s' task: %s", descriptor.name.c_str(), exception.what());
            return;
        }

        if (!claimed.has_value())
        {
            retireType(descriptor.name, selection.token);
            return;
        }

        // Between the claim and the handler. A task claimed as the daemon is stopping stays
        // claimed and is reclaimed by the next boot's startup sweep -- cheaper and safer than
        // starting work we cannot finish inside the shutdown budget.
        if (m_stopping.load(std::memory_order_acquire))
        {
            LOGFN_DEBUG1(
                executorLogFn(), "Leaving task '%s' claimed: shutting down before it started", claimed->taskId.c_str());
            return;
        }

        publish(worker, *claimed, descriptor.watchdogBudget);
        if (m_metrics)
        {
            m_metrics->setBusyWorkers(m_busyWorkers.fetch_add(1, std::memory_order_relaxed) + 1);
        }

        HandlerResult result {Outcome::Retryable, "handler threw"};
        const auto started {std::chrono::steady_clock::now()};

        try
        {
            result = descriptor.handler->run(*claimed, m_stopToken);
        }
        catch (const std::exception& exception)
        {
            // A handler that throws is a bug, but it must not take the worker with it or the whole
            // type stops being executed for the life of the process.
            result = HandlerResult::of(Outcome::Retryable, std::string {"handler threw: "} + exception.what());
            LOGFN_ERROR(executorLogFn(),
                        "Handler for '%s' threw on task '%s': %s",
                        descriptor.name.c_str(),
                        claimed->taskId.c_str(),
                        exception.what());
        }

        const auto micros {static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - started).count())};

        unpublish(worker);

        if (m_metrics)
        {
            m_metrics->setBusyWorkers(m_busyWorkers.fetch_sub(1, std::memory_order_relaxed) - 1);
            m_metrics->handlerRan(descriptor.name, result.outcome, micros);
        }

        // The outcome is ALWAYS written, even while stopping. It is one batched UPDATE flushed by
        // the shutdown path, and recording work that actually happened is worth far more than the
        // microseconds it costs; skipping it would leave the row claimed for a sweep to re-run
        // work that already succeeded.
        try
        {
            recordOutcome(descriptor, *claimed, result);
        }
        catch (const std::exception& exception)
        {
            // The one case where ATTEMPTS and LAST_ERROR cannot record what happened, so it is
            // logged loudly. The row stays claimed and the sweep will re-run it -- which is
            // exactly why every handler must be idempotent.
            LOGFN_ERROR(executorLogFn(),
                        "Failed to record the outcome of task '%s' (type '%s'): %s. The task will be "
                        "reclaimed and run again.",
                        claimed->taskId.c_str(),
                        descriptor.name.c_str(),
                        exception.what());
        }
    }

    void Executor::recordOutcome(const registry::TaskTypeDescriptor& descriptor,
                                 const ClaimedTask& task,
                                 const HandlerResult& result)
    {
        const auto now {nowSeconds()};
        const auto transition {registry::applyResult(
            descriptor, m_registry.policy(), result.outcome, task.attempts, task.deferCount, now)};

        const std::optional<std::string> lastError {result.error.empty() ? std::nullopt
                                                                         : std::optional<std::string> {result.error}};

        if (transition.terminalStatus.has_value())
        {
            m_store.setResult(
                task.taskId, *transition.terminalStatus, transition.attempts, transition.deferCount, lastError, now);

            if (m_metrics)
            {
                m_metrics->taskRetired(descriptor.name, *transition.terminalStatus);
            }

            if (*transition.terminalStatus == TaskStatus::DeadLetter)
            {
                // Both halves of discoverability matter: this line carries the id, and the id can
                // be looked up afterwards through the list and get endpoints. A record nobody can
                // find is not a record.
                LOGFN_ERROR(executorLogFn(),
                            "Manager task '%s' of type '%s' dead-lettered after %d attempts and %d "
                            "deferrals: %s",
                            task.taskId.c_str(),
                            descriptor.name.c_str(),
                            transition.attempts,
                            transition.deferCount,
                            result.error.empty() ? "no detail" : result.error.c_str());
            }
            else if (*transition.terminalStatus == TaskStatus::Failed)
            {
                LOGFN_WARN(executorLogFn(),
                           "Manager task '%s' of type '%s' failed: %s",
                           task.taskId.c_str(),
                           descriptor.name.c_str(),
                           result.error.empty() ? "no detail" : result.error.c_str());
            }
            return;
        }

        storage::RequeueRequest request;
        request.taskId = task.taskId;
        request.taskType = descriptor.name;
        request.agentId = task.agentId;
        request.lastError = lastError;
        request.nextAttemptAt = transition.nextAttemptAt;
        request.attempts = transition.attempts;
        request.deferCount = transition.deferCount;
        request.coalesce = descriptor.coalesceByAgent;

        const auto outcome {m_store.requeue(request)};

        if (outcome == storage::RequeueResult::Superseded)
        {
            LOGFN_DEBUG1(executorLogFn(),
                         "Manager task '%s' superseded: a newer pending '%s' row already holds its slot",
                         task.taskId.c_str(),
                         descriptor.name.c_str());
            if (m_metrics)
            {
                m_metrics->taskRetired(descriptor.name, TaskStatus::Superseded);
            }
            return;
        }

        // Escalate on CONSECUTIVE no-fault deferrals. The counter mixes not_ready and busy on
        // purpose, so the message names the actual condition from the error text rather than
        // claiming one of the two.
        if (isNoFault(result.outcome))
        {
            if (transition.deferCount == DEFER_ERROR_AT)
            {
                LOGFN_ERROR(executorLogFn(),
                            "Manager task '%s' of type '%s' has deferred %d times in a row: %s",
                            task.taskId.c_str(),
                            descriptor.name.c_str(),
                            transition.deferCount,
                            result.error.c_str());
            }
            else if (transition.deferCount == DEFER_WARN_AT)
            {
                LOGFN_WARN(executorLogFn(),
                           "Manager task '%s' of type '%s' has deferred %d times in a row: %s",
                           task.taskId.c_str(),
                           descriptor.name.c_str(),
                           transition.deferCount,
                           result.error.c_str());
            }
        }

        // A row that is eligible again right now must wake a worker, or an `incomplete` multi-batch
        // sweep would stall until the scheduler's next pass.
        if (transition.nextAttemptAt <= now)
        {
            notify(descriptor.name);
        }
    }

    std::vector<Executor::WorkerSnapshot> Executor::snapshot() const
    {
        std::vector<WorkerSnapshot> snapshots;
        snapshots.reserve(m_workers.size());

        for (const auto& worker : m_workers)
        {
            std::lock_guard lock {worker->mutex};
            snapshots.push_back({worker->owner,
                                 worker->inflightTaskId,
                                 worker->inflightTaskType,
                                 worker->lastProgressAt,
                                 worker->budget});
        }

        return snapshots;
    }

    std::vector<std::string> Executor::ownerStrings() const
    {
        std::vector<std::string> owners;
        owners.reserve(m_workers.size());
        for (const auto& worker : m_workers)
        {
            owners.push_back(worker->ownerString);
        }
        return owners;
    }
} // namespace task_manager::execution
