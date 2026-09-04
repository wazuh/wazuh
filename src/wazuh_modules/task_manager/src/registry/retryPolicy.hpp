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

#ifndef _TASK_MANAGER_REGISTRY_RETRY_POLICY_HPP
#define _TASK_MANAGER_REGISTRY_RETRY_POLICY_HPP

#include "taskTypeDescriptor.hpp"

namespace task_manager::registry
{
    /**
     * @brief Double `base` `steps` times, stopping at `cap`. Cannot overflow.
     *
     * @param steps Doublings from zero.
     * @param base  First delay. A non-positive base degenerates to the cap, so a misconfigured
     *              base can never produce a zero delay and a spin loop.
     */
    std::chrono::seconds ladder(int steps, std::chrono::seconds base, std::chrono::seconds cap) noexcept;

    /**
     * @brief Retry backoff for a row that has now made `attempts` attempts.
     *
     * The FIRST retry uses the base, so the doublings are one fewer than the attempt count. At the
     * defaults that is 30 + 60 + 120 + 240 + 480 + 900 + 900 = 2730 s, about 45 minutes across the
     * default budget of 8. Worth stating in full, because an attempt count hides its own
     * arithmetic: a budget of 5 is only about 7.5 minutes, shorter than a routine indexer restart
     * and short enough that the cap is never even reached.
     */
    std::chrono::seconds backoffFor(int attempts, const RetryPolicy& policy) noexcept;

    /**
     * @brief Deferral delay for a row that has now deferred `deferCount` times consecutively.
     *
     * Starts far lower than the retry ladder, and deliberately: the common cause of a deferral is
     * a boot race -- the executor starts before its in-process consumers bind their sockets -- and
     * starting at the cap would tax every restart with a fifteen-minute delay to price a failure
     * that resolves in seconds.
     */
    std::chrono::seconds deferDelayFor(int deferCount, const RetryPolicy& policy) noexcept;

    /// @brief The type's effective attempt budget: its own override, or the policy default.
    int effectiveMaxAttempts(const TaskTypeDescriptor& descriptor, const RetryPolicy& policy) noexcept;

    /// @brief The type's effective deferral budget.
    int effectiveMaxDefer(const TaskTypeDescriptor& descriptor, const RetryPolicy& policy) noexcept;

    /**
     * @brief Decide what an outcome does to a row. Pure: no clock, no I/O, no state.
     *
     * The whole state machine lives here, which is what makes it testable as a table:
     *
     *   ok         -> completed
     *   retryable  -> pending, attempts + 1, defer_count reset, backoff ladder
     *   timeout    -> as retryable
     *   terminal   -> failed, budget NOT consumed
     *   not_ready  -> pending, defer_count + 1, attempts unchanged, deferral ladder
     *   busy       -> as not_ready
     *   incomplete -> pending, eligible immediately, defer_count reset, attempts unchanged
     *
     * Either budget being exhausted converts the re-queue into dead_letter instead.
     *
     * @param now Injected rather than read, so the ladders can be tested without a clock.
     */
    Transition applyResult(const TaskTypeDescriptor& descriptor,
                           const RetryPolicy& policy,
                           Outcome outcome,
                           int attempts,
                           int deferCount,
                           Timestamp now) noexcept;
} // namespace task_manager::registry

#endif // _TASK_MANAGER_REGISTRY_RETRY_POLICY_HPP
