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

#ifndef _TASK_MANAGER_HANDLERS_LOCAL_HANDLERS_HPP
#define _TASK_MANAGER_HANDLERS_LOCAL_HANDLERS_HPP

#include "host/iHostOps.hpp"
#include "iHandler.hpp"

#include <chrono>
#include <mutex>
#include <string>

/*
 * The three handlers ported from the retired monitord daemon, kept together because they are one
 * body of work: they share a configuration struct, they all reach the manager through the same
 * host-ops table, and they are the only handlers that must bound themselves.
 *
 * SELF-BOUNDING IS THE COMMON REQUIREMENT. A routed handler gets its deadline from libcurl. These
 * do not, and there is no cancellation primitive available, so each one limits its own work and
 * checks the stop token between units. A handler here that could run unbounded would hold an
 * executor slot forever, and the watchdog could only report it.
 */
namespace task_manager::handlers
{
    /// @brief Everything the three local handlers read. Resolved once at start.
    struct LocalConfig
    {
        /// @brief <global><agents_disconnection_time>. The sweep's INTERVAL and its WINDOW.
        std::chrono::seconds disconnectionTime {900};
        /// @brief Minutes past the disconnection window before an agent is deleted. 0 disables.
        int deleteOldAgents {0};
        /// @brief Silences the per-agent disconnection log lines. The transition runs regardless.
        bool monitorAgents {true};
        /// @brief Per-agent diagnostic lookups allowed in one sweep.
        int disconnectLogMax {200};
        /// @brief Wall-clock budget for those lookups, independent of the count.
        std::chrono::seconds disconnectLogBudget {30};

        bool compressRotatedLogs {true};
        int keepLogDays {31};
        int dailyRotations {12};
        long sizeRotateBytes {512L * 1024 * 1024};

        /// @brief Agents examined per agent_delete_old run.
        int deleteOldBatch {200};
        /// @brief Wall-clock occupancy budget per agent_delete_old run.
        std::chrono::seconds deleteOldBudget {30};

        std::chrono::seconds authdTimeout {10};
    };

    /**
     * @brief Has this agent been disconnected long enough to delete?
     *
     * The window is the disconnection time PLUS the retention minutes: an agent becomes
     * disconnected after the first, and is deleted only after the second on top of it.
     *
     * Pure, so the boundary is testable without a database.
     */
    bool deleteOldExpired(Timestamp lastKeepalive,
                          Timestamp now,
                          std::chrono::seconds disconnectionTime,
                          int deleteOldAgents);

    /**
     * @brief Map authd's answer for one agent onto an outcome for the whole sweep.
     *
     * Three of authd's refusals are NOT failures, and getting that wrong is what would make this
     * handler non-idempotent -- which the design requires it to be, because an outcome write can
     * be lost after the work is done.
     *
     * Pure, so every branch is testable without authd.
     */
    HandlerResult deleteOldOutcome(bool answered, int authdError);

    /**
     * @brief Transition agents past the disconnection window, then log what happened.
     *
     * The transition is ONE query and always completes. What follows is diagnostics -- one lookup
     * per agent, to turn an id into a name -- and that is the part that is bounded, by both a count
     * and a wall clock. A partition transitions tens of thousands of agents at once, and at one
     * round trip each that is minutes of occupancy for log lines nobody reads individually at that
     * volume.
     *
     * It DROPS the remainder rather than returning Incomplete, and the difference matters: the ids
     * exist only inside this call's return value, so a resumed attempt would have no list to
     * resume from and would re-run a transition that has nothing left to transition. The dropped
     * count is reported instead, so a mass disconnection is never silent.
     */
    class DisconnectSweepHandler final : public IHandler
    {
    public:
        DisconnectSweepHandler(host::IHostOps& hostOps, LocalConfig config);
        HandlerResult run(const ClaimedTask& task, const StopToken& stop) override;

    private:
        host::IHostOps& m_hostOps;
        LocalConfig m_config;
    };

    /**
     * @brief Delete agents that have been disconnected past the retention window.
     *
     * Bounded by a batch count AND an elapsed-time budget, returning Incomplete when candidates
     * remain. The time bound is the one that matters: what is being protected is how long this
     * holds its executor slot, measured in seconds, while the batch is counted in agents.
     *
     * The cursor is RESUMED IN THE QUERY, not by skipping rows client-side. The candidate list is
     * ordered by agent id over a `WHERE id > ?`, so handing it the cursor costs nothing; skipping
     * client-side instead would make a full walk quadratic in the number of disconnected agents.
     */
    class DeleteOldAgentsHandler final : public IHandler
    {
    public:
        DeleteOldAgentsHandler(host::IHostOps& hostOps, LocalConfig config);
        HandlerResult run(const ClaimedTask& task, const StopToken& stop) override;

    private:
        host::IHostOps& m_hostOps;
        LocalConfig m_config;

        /// @brief The run this cursor belongs to, taken from the row's scheduled slot. A different
        ///        slot is a different run and restarts the walk; equal slots are attempts at one
        ///        run, which is what the cursor is for.
        ///
        /// Guarded even though the type's concurrency cap is one: the cap is a registry value, and
        /// a future change to it should not silently introduce a data race here. The lock is
        /// uncontended, so it costs nothing.
        std::mutex m_mutex;
        Timestamp m_slot {0};
        int m_cursor {0};
    };

    /// @brief Daily log rotation. Idempotent and self-bounded by the host's own implementation.
    class LogRotateHandler final : public IHandler
    {
    public:
        LogRotateHandler(host::IHostOps& hostOps, LocalConfig config);
        HandlerResult run(const ClaimedTask& task, const StopToken& stop) override;

    private:
        host::IHostOps& m_hostOps;
        LocalConfig m_config;
    };
} // namespace task_manager::handlers

#endif // _TASK_MANAGER_HANDLERS_LOCAL_HANDLERS_HPP
