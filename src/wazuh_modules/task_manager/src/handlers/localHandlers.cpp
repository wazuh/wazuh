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

#include "localHandlers.hpp"

#include "host/agentRow.hpp"
#include "taskManagerLog.hpp"

#include <json.hpp>

#include <ctime>
#include <utility>

namespace
{
    using task_manager::Timestamp;

    /* The two sweeps below are the only work in this module that still reaches wazuh-db, and
     * wazuh-db is signalled to stop in the same pass of the init script that signals modulesd. It
     * therefore routinely dies while this module is still draining, and a sweep that started in
     * that gap would spend its whole budget failing to reach a socket nobody is listening on.
     *
     * NotReady, not Retryable: this is the same condition as the boot race the registry already
     * prices -- a consumer that is not there -- only at the other end of the process's life. It
     * costs a deferral rather than an attempt, so a stop never pushes a schedule toward its
     * dead-letter bound, and a single deferral is logged by nobody. */
    constexpr auto SHUTTING_DOWN {"the manager is shutting down"};

    Timestamp nowSeconds()
    {
        return static_cast<Timestamp>(std::time(nullptr));
    }

    /// @brief The scheduled slot a row was spawned for, which keys the delete-old cursor.
    Timestamp payloadSlot(const std::string& payload)
    {
        if (payload.empty())
        {
            return 0;
        }

        const auto parsed = nlohmann::json::parse(payload, nullptr, false);
        if (parsed.is_discarded() || !parsed.is_object())
        {
            return 0;
        }

        const auto it {parsed.find("scheduled_run_at")};
        if (it == parsed.end() || !it->is_number())
        {
            return 0;
        }

        return it->get<Timestamp>();
    }

    // agentRow() moved to host/agentRow.hpp when the upgrade subsystem needed to read the same
    // rows; a second private copy that forgot the array case would report every agent as missing
    // from the database rather than failing visibly.
    using task_manager::host::agentRow;
} // namespace

namespace task_manager::handlers
{
    bool deleteOldExpired(const Timestamp lastKeepalive,
                          const Timestamp now,
                          const std::chrono::seconds disconnectionTime,
                          const int deleteOldAgents)
    {
        return lastKeepalive < now - (disconnectionTime.count() + static_cast<Timestamp>(deleteOldAgents) * 60);
    }

    HandlerResult deleteOldOutcome(const bool answered, const int authdError)
    {
        if (!answered)
        {
            return HandlerResult::of(Outcome::Retryable, "authd did not answer the removal");
        }

        switch (authdError)
        {
            case 0:
            case host::AUTHD_NO_SUCH_ID:
            case host::AUTHD_ID_NOT_FOUND:
                // Already gone. The sweep wanted the agent removed and it is. Treating a second
                // delete of a deleted agent as a failure is exactly what would make this handler
                // non-idempotent, and it must tolerate being re-run after a lost outcome write.
                return HandlerResult::ok();

            case host::AUTHD_PENDING_PURGE:
                // Someone already asked and authd has journaled the intent, so the removal will
                // happen whether or not this sweep waits for it.
                return HandlerResult::ok();

            case host::AUTHD_DELETE_BACKLOG:
                // The refusal this mapping exists for. authd is holding as many journaled
                // deletions as its bound allows, so the agent is still there and the sweep must
                // come back. Retryable rather than Incomplete, deliberately: Incomplete re-claims
                // at once and would spin against a saturated authd, while Retryable takes the
                // backoff ladder.
                return HandlerResult::of(Outcome::Retryable, "authd's deletion backlog is full");

            case host::AUTHD_WORKER_NODE:
                // A master-scoped schedule spawned this row, so reaching here means the node was
                // demoted between the spawn and the run. No retry can help; the new master's own
                // schedule will.
                return HandlerResult::of(Outcome::Terminal, "this node is no longer the cluster master");

            default:
                return HandlerResult::of(Outcome::Retryable,
                                         "authd refused the removal with error " + std::to_string(authdError));
        }
    }

    // ---- disconnection sweep -------------------------------------------------------------------

    DisconnectSweepHandler::DisconnectSweepHandler(host::IHostOps& hostOps, LocalConfig config)
        : m_hostOps {hostOps}
        , m_config {std::move(config)}
    {
    }

    HandlerResult DisconnectSweepHandler::run(const ClaimedTask& task, const StopToken& stop)
    {
        static_cast<void>(task);

        if (stop.stopRequested())
        {
            return HandlerResult::of(Outcome::NotReady, SHUTTING_DOWN);
        }

        const auto started {nowSeconds()};

        // "synced" is the sync_status WRITTEN onto the transitioned rows, not a filter on which
        // agents are considered: the master marks agents in its own database and no cluster
        // synchronisation is involved, so the rows are already in their final state.
        const auto disconnected {
            m_hostOps.disconnectAgents(static_cast<long>(nowSeconds() - m_config.disconnectionTime.count()), "synced")};

        if (!disconnected.has_value())
        {
            return HandlerResult::of(Outcome::Retryable, "wazuh-db did not complete the disconnection sweep");
        }

        int logged {0};
        int dropped {0};

        // Decided ONCE, before the loop, rather than re-tested per agent. Both settings silence the
        // per-agent line and nothing else -- the database transition above already ran for every
        // agent -- so when neither will ever log there is nothing to walk the list for, and the
        // whole cost of this loop is one wazuh-db round trip per entry.
        //
        // A `disconnectLogMax` of zero is the documented way to transition silently, and it only
        // became reachable when zero stopped being swallowed by the ABI's sentinel (see
        // valueOrAllowingZero in taskManagerFacade.hpp). Turning it off is not the same event as
        // running out of budget, so it does not report agents as "dropped": there is nothing
        // surprising to tell an operator who asked for silence.
        const bool nameAgentsIndividually {m_config.monitorAgents && m_config.disconnectLogMax > 0};

        for (const auto agentId : *disconnected)
        {
            if (!nameAgentsIndividually)
            {
                break;
            }

            if (logged >= m_config.disconnectLogMax || nowSeconds() - started >= m_config.disconnectLogBudget.count() ||
                stop.stopRequested())
            {
                ++dropped;
                continue;
            }

            ++logged;

            const auto info {m_hostOps.agentInfo(agentId)};
            if (!info.has_value())
            {
                LOGFN_DEBUG2(
                    moduleLogFn(), "Cannot read agent '%d' data; its disconnection is not logged by name.", agentId);
                continue;
            }

            const auto* row {agentRow(*info)};
            if (row == nullptr)
            {
                continue;
            }

            const auto name {row->find("name")};
            if (name != row->end() && name->is_string())
            {
                LOGFN_DEBUG1(
                    moduleLogFn(), "Agent '%d' (%s) is disconnected.", agentId, name->get<std::string>().c_str());
            }
        }

        if (!disconnected->empty())
        {
            LOGFN_INFO(moduleLogFn(),
                       "Agent disconnection sweep transitioned %zu agent(s) to disconnected.",
                       disconnected->size());
        }

        if (dropped > 0)
        {
            // Said out loud, at INFO: every one of these agents WAS transitioned, and only its
            // individual log line was skipped. Silence here would read as a smaller outage than it
            // actually was.
            LOGFN_INFO(moduleLogFn(),
                       "%d of them were not logged individually; the per-agent lookup is bounded to %d per "
                       "sweep.",
                       dropped,
                       m_config.disconnectLogMax);
        }

        return HandlerResult::ok();
    }

    // ---- retention deletion --------------------------------------------------------------------

    DeleteOldAgentsHandler::DeleteOldAgentsHandler(host::IHostOps& hostOps, LocalConfig config)
        : m_hostOps {hostOps}
        , m_config {std::move(config)}
    {
    }

    HandlerResult DeleteOldAgentsHandler::run(const ClaimedTask& task, const StopToken& stop)
    {
        if (m_config.deleteOldAgents <= 0)
        {
            // Reachable only through a row that outlived the option being turned off. Completing
            // it is right: the work it asked for is no longer wanted, and failing it would
            // dead-letter a row over a configuration change.
            return HandlerResult::ok();
        }

        const auto slot {payloadSlot(task.payload)};
        int cursor {0};

        {
            std::lock_guard lock {m_mutex};
            if (slot != m_slot)
            {
                m_slot = slot;
                m_cursor = 0;
            }
            cursor = m_cursor;
        }

        if (stop.stopRequested())
        {
            return HandlerResult::of(Outcome::NotReady, SHUTTING_DOWN);
        }

        // Re-read from the cursor on every attempt rather than caching the list: agents removed by
        // the previous attempt are then simply no longer in it.
        const auto candidates {m_hostOps.agentsByStatusFrom(cursor, "disconnected")};
        if (!candidates.has_value())
        {
            return HandlerResult::of(Outcome::Retryable, "wazuh-db did not return the disconnected agents");
        }

        const auto started {nowSeconds()};
        int examined {0};
        int removed {0};
        bool exhausted {true};
        HandlerResult stopReason {HandlerResult::ok()};

        for (const auto agentId : *candidates)
        {
            if (examined >= m_config.deleteOldBatch || nowSeconds() - started >= m_config.deleteOldBudget.count())
            {
                // Bound reached with candidates left. Neither success nor failure: completing
                // would retire the row with the sweep half done, and consuming an attempt would
                // dead-letter a fleet that simply needs more batches than the budget allows.
                exhausted = false;
                break;
            }

            if (stop.stopRequested())
            {
                exhausted = false;
                break;
            }

            ++examined;

            const auto info {m_hostOps.agentInfo(agentId)};
            if (!info.has_value())
            {
                // Not fatal to the sweep and not retried for this agent: the next run reads it
                // again.
                LOGFN_DEBUG2(moduleLogFn(), "Cannot read agent '%d' data; skipping it this run.", agentId);
                std::lock_guard lock {m_mutex};
                m_cursor = agentId;
                continue;
            }

            const auto* row {agentRow(*info)};
            if (row == nullptr)
            {
                std::lock_guard lock {m_mutex};
                m_cursor = agentId;
                continue;
            }

            const auto keepalive {row->find("last_keepalive")};
            const auto expired {
                keepalive != row->end() && keepalive->is_number() &&
                deleteOldExpired(
                    keepalive->get<Timestamp>(), nowSeconds(), m_config.disconnectionTime, m_config.deleteOldAgents)};

            if (expired)
            {
                int authdError {0};
                const auto answered {
                    m_hostOps.removeAgent(agentId, static_cast<int>(m_config.authdTimeout.count()), authdError)};
                const auto outcome {deleteOldOutcome(answered, authdError)};

                if (outcome.outcome == Outcome::Ok)
                {
                    ++removed;
                    const auto name {row->find("name")};
                    if (name != row->end() && name->is_string())
                    {
                        LOGFN_DEBUG1(
                            moduleLogFn(), "Agent '%d' (%s) removed.", agentId, name->get<std::string>().c_str());
                    }
                }
                else
                {
                    // A refusal that is not "already gone" stops the sweep here rather than
                    // walking on. Both reachable causes -- a full deletion backlog and an
                    // unreachable authd -- are about authd's capacity, not about this agent, so
                    // the next candidate would answer the same way and each attempt costs a
                    // connect. The cursor stays where it is, so the retry resumes at this agent.
                    exhausted = false;
                    stopReason = outcome;
                    break;
                }
            }

            std::lock_guard lock {m_mutex};
            m_cursor = agentId;
        }

        if (removed > 0)
        {
            LOGFN_INFO(moduleLogFn(), "Agent retention sweep removed %d agent(s).", removed);
        }

        if (stopReason.outcome != Outcome::Ok)
        {
            return stopReason;
        }

        if (!exhausted)
        {
            return HandlerResult::of(Outcome::Incomplete, "more agents to examine");
        }

        // A completed walk resets the cursor, so the next run starts from the beginning.
        {
            std::lock_guard lock {m_mutex};
            m_cursor = 0;
        }

        return HandlerResult::ok();
    }

    // ---- daily log rotation --------------------------------------------------------------------

    LogRotateHandler::LogRotateHandler(host::IHostOps& hostOps, LocalConfig config)
        : m_hostOps {hostOps}
        , m_config {std::move(config)}
    {
    }

    HandlerResult LogRotateHandler::run(const ClaimedTask& task, const StopToken& stop)
    {
        static_cast<void>(task);

        if (stop.stopRequested())
        {
            return HandlerResult::of(Outcome::NotReady, "shutting down before the rotation started");
        }

        if (!m_hostOps.rotateLogDaily(m_config.compressRotatedLogs, m_config.keepLogDays, m_config.dailyRotations))
        {
            return HandlerResult::of(Outcome::Retryable, "the daily log rotation did not complete");
        }

        return HandlerResult::ok();
    }
} // namespace task_manager::handlers
