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

#ifndef _TASK_MANAGER_MODEL_TASK_HPP
#define _TASK_MANAGER_MODEL_TASK_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace task_manager
{
    /// @brief Seconds since the epoch. Wall clock, because it is persisted and compared across
    ///        process lifetimes -- a monotonic clock cannot survive a restart. Every *interval*
    ///        in this module uses std::chrono::steady_clock instead.
    using Timestamp = std::int64_t;

    /**
     * @brief The lifecycle of a manager task.
     *
     * These names are PERSISTED. The CHECK constraint on MANAGER_TASKS.STATUS mirrors this list
     * exactly, so adding a value here without adding it there writes rows the database rejects,
     * and removing one strands existing rows.
     *
     * Status is NOT forward-only: retry, deferral, hang recovery and the ownership sweep all
     * return rows to Pending. Only the four terminal states are one-way.
     */
    enum class TaskStatus
    {
        Pending,   ///< Waiting to be claimed. Eligible once NEXT_ATTEMPT_AT has passed.
        Claimed,   ///< A named executor worker is running it.
        Completed, ///< The consumer reported the work done.
        Failed,    ///< Declared impossible. Not "gave up after trying" -- that is DeadLetter.
        DeadLetter,///< Exhausted its attempt or deferral budget.
        Superseded ///< A newer pending row for the same agent took its place while it ran.
    };

    /**
     * @brief What a handler reports about one attempt.
     *
     * There is deliberately no Superseded here. Supersession is decided at re-queue time by
     * looking for a competing pending row; no handler can observe it, so no handler may return it.
     */
    enum class Outcome
    {
        Ok,        ///< -> Completed.
        Retryable, ///< -> Pending with backoff. Costs an attempt.
        Timeout,   ///< -> Pending with backoff. Costs an attempt.
        Terminal,  ///< -> Failed. Costs nothing: it is not being given up on, it is impossible.
        NotReady,  ///< Consumer has not bound its socket. -> Pending on the deferral ladder.
        Busy,      ///< Consumer is up but still running an earlier attempt at the same work.
        Incomplete ///< Self-bounded handler has more to do. -> Pending, eligible immediately.
    };

    /// @brief What create() did. Mirrors manager_task_create_result in shared/include/manager_task_op.h
    ///        so a producer sees the same vocabulary on the wire that it sees in C.
    enum class CreateResult
    {
        Created,  ///< A new row exists.
        Coalesced,///< An equivalent pending row already existed; its id is returned.
        Collided, ///< The id already exists. Normal for deterministic ids, a bug for random ones.
        QueueFull ///< The type's admission bound is reached.
    };

    /// @brief A manager task row, as stored.
    struct ManagerTask
    {
        std::string taskId;   ///< 64 lowercase hex characters.
        std::string taskType; ///< Opaque to storage; meaningful only to the registry.
        std::string payload;  ///< The consumer's request body, verbatim. Authored by the producer.
        std::optional<std::string> agentId; ///< Absent for tasks that are not about one agent.
        Timestamp createTime {0};
        TaskStatus status {TaskStatus::Pending};
        std::optional<std::string> owner;     ///< Set while Claimed. See execution/ownership.hpp.
        std::optional<Timestamp> claimTime;
        int attempts {0};    ///< Never decreases, except when a survivor inherits a larger value.
        int deferCount {0};  ///< CONSECUTIVE no-fault deferrals. Zeroed by any other outcome.
        std::optional<std::string> lastError;
        Timestamp nextAttemptAt {0}; ///< Never left at 0 -- see storage/schema.hpp for why.
        std::optional<std::string> scheduleId;     ///< Set on rows spawned by a schedule.
        std::optional<Timestamp> scheduledRunAt;   ///< The slot this run belongs to.
        std::optional<Timestamp> endTime;          ///< When it reached a terminal state.
    };

    /// @brief What a worker needs to run a task. A projection of ManagerTask, not the whole row:
    ///        the claim reads five columns, and widening it would put payloads on the hot path.
    struct ClaimedTask
    {
        std::string taskId;
        std::string taskType;
        std::string payload;
        std::optional<std::string> agentId;
        int attempts {0};
        int deferCount {0};
    };

    /// @brief An agent task row -- work handed to an agent, not executed by the manager.
    struct AgentTask
    {
        std::string taskId;   ///< UUID-shaped, 36 characters. See model/taskId.hpp.
        std::string agentId;
        std::string taskType;
        std::string payload;
        Timestamp createTime {0};
    };

    /// @brief One row of a manager-task listing. Deliberately narrow: enough to see WHAT failed
    ///        and why, without paging whole payloads.
    struct ManagerTaskSummary
    {
        std::string taskId;
        std::optional<std::string> agentId;
        TaskStatus status {TaskStatus::Pending};
        Timestamp createTime {0};
        std::optional<std::string> lastError;
    };

    std::string_view toString(TaskStatus status) noexcept;
    std::string_view toString(Outcome outcome) noexcept;
    std::string_view toString(CreateResult result) noexcept;

    /// @return The status, or nullopt for anything not in the CHECK list.
    std::optional<TaskStatus> taskStatusFromString(std::string_view text) noexcept;

    /// @brief Terminal states are one-way. Retention only ever removes these.
    constexpr bool isTerminal(TaskStatus status) noexcept
    {
        return status == TaskStatus::Completed || status == TaskStatus::Failed ||
               status == TaskStatus::DeadLetter || status == TaskStatus::Superseded;
    }

    /// @brief NotReady and Busy are the two no-fault outcomes: they cost a deferral, never an
    ///        attempt. Sharing one counter is why it is named DEFER_COUNT rather than for either
    ///        condition -- a task flapping between them would otherwise escalate a log line
    ///        naming the wrong one.
    constexpr bool isNoFault(Outcome outcome) noexcept
    {
        return outcome == Outcome::NotReady || outcome == Outcome::Busy;
    }

    /// @brief Retryable and Timeout are the outcomes that consume the attempt budget.
    constexpr bool consumesAttempt(Outcome outcome) noexcept
    {
        return outcome == Outcome::Retryable || outcome == Outcome::Timeout;
    }
} // namespace task_manager

#endif // _TASK_MANAGER_MODEL_TASK_HPP
