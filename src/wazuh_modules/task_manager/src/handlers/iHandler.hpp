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

#ifndef _TASK_MANAGER_HANDLERS_I_HANDLER_HPP
#define _TASK_MANAGER_HANDLERS_I_HANDLER_HPP

#include "model/task.hpp"

#include <atomic>
#include <string>

namespace task_manager
{
    /**
     * @brief Cooperative cancellation for a running handler.
     *
     * There is no cancellation primitive available in this daemon: pthread_cancel is not used
     * anywhere in the tree, and SIGALRM is wired to a TERMINATING handler, so arming a timer to
     * interrupt a handler would kill the process. What a handler gets instead is this flag, which
     * it checks between units of work.
     *
     * That bounds a handler at the granularity of its own loop, not at an arbitrary instant, so a
     * handler must keep its units small. The routed handlers do not need it -- libcurl enforces
     * their deadline -- but the local ones do: they are the only work that can outlive the 30 s
     * shutdown budget.
     */
    class StopToken
    {
    public:
        StopToken() = default;

        bool stopRequested() const noexcept
        {
            return m_stop.load(std::memory_order_acquire);
        }
        void requestStop() noexcept
        {
            m_stop.store(true, std::memory_order_release);
        }

        StopToken(const StopToken&) = delete;
        StopToken& operator=(const StopToken&) = delete;

    private:
        std::atomic<bool> m_stop {false};
    };

    /// @brief One attempt's result: what happened, and what to record in LAST_ERROR.
    struct HandlerResult
    {
        Outcome outcome {Outcome::Retryable};
        /// @brief Empty on Ok. Otherwise a short, operator-readable reason; it is the only thing a
        ///        dead-lettered row carries about why it failed.
        std::string error;

        static HandlerResult ok()
        {
            return {Outcome::Ok, {}};
        }
        static HandlerResult of(const Outcome outcome, std::string error)
        {
            return {outcome, std::move(error)};
        }
    };

    /**
     * @brief Executes one manager task type.
     *
     * IDEMPOTENCY IS MANDATORY, not advisory. An outcome write can fail after the work is done --
     * the process dies between the handler returning and the row being updated -- leaving the row
     * claimed for the next sweep to reclaim and re-run. There is no way to make those two atomic,
     * so the design absorbs the repeat instead, and a handler that cannot tolerate being run twice
     * is a bug in the handler.
     *
     * SELF-BOUNDING IS MANDATORY for handlers that do not delegate to a client with a deadline.
     * A handler that can run unbounded holds an executor slot forever; the watchdog will report it
     * but nothing can stop it.
     */
    class IHandler
    {
    public:
        virtual ~IHandler() = default;

        /// @param task The claimed row. `payload` is opaque to the dispatcher and meaningful only
        ///             to this handler and to whoever created the row.
        /// @param stop Checked between units of work by handlers that have units.
        virtual HandlerResult run(const ClaimedTask& task, const StopToken& stop) = 0;
    };
} // namespace task_manager

#endif // _TASK_MANAGER_HANDLERS_I_HANDLER_HPP
