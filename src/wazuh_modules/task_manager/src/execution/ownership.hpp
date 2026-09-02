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

#ifndef _TASK_MANAGER_EXECUTION_OWNERSHIP_HPP
#define _TASK_MANAGER_EXECUTION_OWNERSHIP_HPP

#include "model/task.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace task_manager::execution
{
    /**
     * @brief Who holds a claimed row: `<pid>:<process start time>:w<worker index>`.
     *
     * The start time comes from field 22 of /proc/<pid>/stat, and it is what makes the identity
     * honest: a pid alone is reused by the kernel, so a crashed manager's rows could be judged
     * "still owned by a live process" purely because something else inherited the number.
     */
    struct OwnerIdentity
    {
        std::int32_t pid {0};
        std::uint64_t startTime {0};
        int workerIndex {0};

        std::string toString() const;
        bool sameProcess(const OwnerIdentity& other) const noexcept
        {
            return pid == other.pid && startTime == other.startTime;
        }
    };

    enum class OwnerKind
    {
        Dead,        ///< No such process, or the pid was recycled.
        Mine,        ///< This process instance.
        Foreign,     ///< A different, LIVE process. Another modulesd, or an overlapping restart.
        Unparseable  ///< Not an owner string this build can read.
    };

    /// @brief This process's identity for `workerIndex`.
    OwnerIdentity selfIdentity(int workerIndex);

    /// @return Field 22 of /proc/<pid>/stat, or 0 when the process does not exist.
    std::uint64_t processStartTime(std::int32_t pid);

    std::optional<OwnerIdentity> parseOwner(std::string_view owner);

    OwnerKind classifyOwner(std::string_view owner, const OwnerIdentity& self);

    /// @brief Everything the reclaim decision needs, gathered so the rule below stays pure.
    struct ReclaimQuery
    {
        std::string_view owner;
        std::string_view rowTaskId;
        /// @brief What the owning worker says it is running right now. Empty when that worker is
        ///        idle, or when the owner is not one of ours.
        std::string_view workerInflightTaskId;
        Timestamp claimTime {0};
        Timestamp now {0};
        std::chrono::seconds claimGrace {30};
    };

    /**
     * @brief May the sweep return this claimed row to pending?
     *
     * Four cases, and the asymmetry between them is the whole point:
     *
     *  - DEAD: yes, immediately. Strictly better than a lease timer -- after a crash mid-scan the
     *    row does not sit unusable for however long the lease was.
     *
     *  - UNPARSEABLE: yes. A row whose owner this build cannot read would be reclaimed by no other
     *    rule, and would sit unclaimable forever while counting against the row ceiling.
     *
     *  - FOREIGN: NEVER. Under a systemd restart with an overlapping old process, or an operator
     *    starting a second modulesd, those workers may still be mid-call. Inferring death from
     *    "not my pid" is what would cause two processes to rotate the same log file at once.
     *
     *  - MINE: only when BOTH hold -- the worker is not running this row, AND the claim is older
     *    than the grace.
     *
     * The grace term is not belt-and-braces. A worker cannot publish "I am running X" until the
     * claim returns X, so between the claim committing and that publish there is a window in which
     * the sweep sees "not the row this worker is running" for a row the worker is about to run,
     * and reclaims it -- double execution, produced by the very mechanism meant to prevent it. The
     * window is microseconds and the grace is thirty seconds, so the margin is enormous, and it
     * costs at most one extra sweep interval of reclaim latency.
     */
    bool isReclaimable(const ReclaimQuery& query, const OwnerIdentity& self);
} // namespace task_manager::execution

#endif // _TASK_MANAGER_EXECUTION_OWNERSHIP_HPP
