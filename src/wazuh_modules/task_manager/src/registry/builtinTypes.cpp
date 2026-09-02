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

#include "builtinTypes.hpp"

#include "handlers/httpHandler.hpp"
#include "taskManagerLog.hpp"

#include <stdexcept>

namespace
{
    /// @brief Resolve an int from the config POD, applying the sentinel rule: anything <= 0 means
    ///        "no opinion", so the default below is the one place a default lives.
    int valueOr(const int configured, const int fallback)
    {
        return configured > 0 ? configured : fallback;
    }

    constexpr int DEFAULT_MAX_ATTEMPTS {8};
    constexpr int DEFAULT_MAX_DEFER {48};
    constexpr int DEFAULT_BACKOFF_BASE {30};
    constexpr int DEFAULT_BACKOFF_CAP {900};
    constexpr int DEFAULT_DEFER_BASE {5};
    constexpr int DEFAULT_VD_SCAN_TIMEOUT {300};
    constexpr int DEFAULT_DELETE_TIMEOUT {600};
    constexpr int DEFAULT_MAX_PENDING_DELETES {20000};
    constexpr int DEFAULT_MAX_PENDING_SCANS {64};
    constexpr int DEFAULT_DISCONNECTION_TIME {900};
    constexpr int DEFAULT_DAY_WAIT {10};
    constexpr int DEFAULT_DELETE_OLD_BUDGET {30};

    /// @brief Connect deadline for the consumer calls. Deliberately not an operator knob: it
    ///        governs reaching a socket on the same host, where two seconds is already generous,
    ///        and a longer one would only slow down recognising that a consumer is absent.
    constexpr int CONNECT_TIMEOUT_MS {2000};

    /// @brief Watchdog budgets for the two rotations. Judgements rather than deadlines: nothing
    ///        enforces them, and rotation gzips a file up to the size threshold inline.
    constexpr int ROTATE_WATCHDOG_SECONDS {900};
    constexpr int DISCONNECT_SWEEP_WATCHDOG_SECONDS {300};
} // namespace

namespace task_manager::registry
{
    TaskRegistry buildBuiltinRegistry(const task_manager_config_t& config,
                                      host::IHostOps& hostOps,
                                      const handlers::LocalConfig& localConfig)
    {
        const auto vdScanTimeout {valueOr(config.vd_scan_timeout, DEFAULT_VD_SCAN_TIMEOUT)};
        const auto deleteTimeout {valueOr(config.delete_timeout, DEFAULT_DELETE_TIMEOUT)};

        if (deleteTimeout <= vdScanTimeout)
        {
            throw std::invalid_argument(
                "manager_task_delete_timeout (" + std::to_string(deleteTimeout) +
                "s) must exceed manager_task_vd_scan_timeout (" + std::to_string(vdScanTimeout) +
                "s): a scan holding an agent parks that agent's deletion behind it in the consumer's "
                "per-agent queue, so an equal or shorter deletion deadline would expire while parked");
        }

        RetryPolicy policy;
        policy.maxAttempts = valueOr(config.max_attempts, DEFAULT_MAX_ATTEMPTS);
        policy.maxDefer = valueOr(config.max_defer, DEFAULT_MAX_DEFER);
        policy.backoffBase = std::chrono::seconds {valueOr(config.backoff_base, DEFAULT_BACKOFF_BASE)};
        policy.backoffCap = std::chrono::seconds {valueOr(config.backoff_cap, DEFAULT_BACKOFF_CAP)};
        policy.deferBase = std::chrono::seconds {valueOr(config.defer_base, DEFAULT_DEFER_BASE)};

        if (policy.backoffBase > policy.backoffCap)
        {
            policy.backoffBase = policy.backoffCap;
        }
        if (policy.deferBase > policy.backoffCap)
        {
            policy.deferBase = policy.backoffCap;
        }

        const std::string consumerSocket {config.inventory_sync_socket};

        std::vector<TaskTypeDescriptor> descriptors;

        // ---- agent_delete_indexer ---------------------------------------------------------
        //
        // The only type that NEVER gives up: no attempt budget, no deferral budget, and a 4xx
        // re-queues instead of retiring the row. Once client.keys is written the agent is gone and
        // nobody will ask again, so this row is the only remaining record of the obligation.
        //
        // None of those three is an operator knob. A deployment that gave this lane a finite
        // budget, or re-enabled terminal failure on it, would silently reintroduce exactly the
        // orphaned indexer documents the queue exists to prevent.
        {
            handlers::HttpHandler::Options options;
            options.socketPath = consumerSocket;
            options.path = ROUTE_AGENT_DELETE;
            options.connectTimeout = std::chrono::milliseconds {CONNECT_TIMEOUT_MS};
            options.requestTimeout = std::chrono::seconds {deleteTimeout};
            options.allowTerminalFailure = false;

            TaskTypeDescriptor descriptor;
            descriptor.name = TYPE_AGENT_DELETE_INDEXER;
            descriptor.concurrencyGroup = TYPE_AGENT_DELETE_INDEXER;
            descriptor.maxConcurrent = 4;
            descriptor.maxAttempts = UNBOUNDED;
            descriptor.maxDefer = UNBOUNDED;
            descriptor.allowTerminalFailure = false;
            descriptor.coalesceByAgent = false;
            descriptor.maxPending = valueOr(config.max_pending_deletes, DEFAULT_MAX_PENDING_DELETES);
            descriptor.watchdogBudget = std::chrono::seconds {deleteTimeout};
            descriptor.handler = std::make_shared<handlers::HttpHandler>(std::move(options));
            descriptors.push_back(std::move(descriptor));
        }

        // ---- vd_scan ----------------------------------------------------------------------
        //
        // Coalescing, because a second scan request for an agent that already has one pending is
        // the same work. Deletions must NOT coalesce: two deletions of one agent are two distinct
        // obligations.
        {
            handlers::HttpHandler::Options options;
            options.socketPath = consumerSocket;
            options.path = ROUTE_VD_SCAN;
            options.connectTimeout = std::chrono::milliseconds {CONNECT_TIMEOUT_MS};
            options.requestTimeout = std::chrono::seconds {vdScanTimeout};
            options.allowTerminalFailure = true;

            TaskTypeDescriptor descriptor;
            descriptor.name = TYPE_VD_SCAN;
            descriptor.concurrencyGroup = TYPE_VD_SCAN;
            descriptor.maxConcurrent = 1;
            descriptor.coalesceByAgent = true;
            descriptor.maxPending = valueOr(config.max_pending_scans, DEFAULT_MAX_PENDING_SCANS);
            descriptor.watchdogBudget = std::chrono::seconds {vdScanTimeout};
            descriptor.handler = std::make_shared<handlers::HttpHandler>(std::move(options));
            descriptors.push_back(std::move(descriptor));
        }

        // ---- agent_disconnect_sweep -------------------------------------------------------
        {
            TaskTypeDescriptor descriptor;
            descriptor.name = TYPE_AGENT_DISCONNECT_SWEEP;
            descriptor.concurrencyGroup = TYPE_AGENT_DISCONNECT_SWEEP;
            descriptor.maxConcurrent = 1;
            descriptor.watchdogBudget = std::chrono::seconds {DISCONNECT_SWEEP_WATCHDOG_SECONDS};
            descriptor.handler = std::make_shared<handlers::DisconnectSweepHandler>(hostOps, localConfig);
            descriptors.push_back(std::move(descriptor));
        }

        // ---- agent_delete_old --------------------------------------------------------------
        //
        // Its watchdog budget is DERIVED from its occupancy budget rather than fixed, because that
        // budget is an operator knob: a handler that is allowed thirty seconds must not be
        // reported as stalled at thirty seconds.
        {
            TaskTypeDescriptor descriptor;
            descriptor.name = TYPE_AGENT_DELETE_OLD;
            descriptor.concurrencyGroup = TYPE_AGENT_DELETE_OLD;
            descriptor.maxConcurrent = 1;
            descriptor.watchdogBudget = std::chrono::seconds {
                valueOr(config.delete_old_budget, DEFAULT_DELETE_OLD_BUDGET) + 60};
            descriptor.handler = std::make_shared<handlers::DeleteOldAgentsHandler>(hostOps, localConfig);
            descriptors.push_back(std::move(descriptor));
        }

        // ---- log_rotate_daily --------------------------------------------------------------
        //
        // The only type in a shared concurrency group: it and the size-triggered rotation both
        // rewrite the same files, so they take turns.
        {
            TaskTypeDescriptor descriptor;
            descriptor.name = TYPE_LOG_ROTATE_DAILY;
            descriptor.concurrencyGroup = GROUP_ROTATION;
            descriptor.maxConcurrent = 1;
            descriptor.watchdogBudget = std::chrono::seconds {ROTATE_WATCHDOG_SECONDS};
            descriptor.handler = std::make_shared<handlers::LogRotateHandler>(hostOps, localConfig);
            descriptors.push_back(std::move(descriptor));
        }

        return TaskRegistry {std::move(policy), std::move(descriptors)};
    }

    std::vector<schedule::Schedule> buildBuiltinSchedules(const task_manager_config_t& config)
    {
        const auto disconnectionTime {
            std::chrono::seconds {valueOr(config.disconnection_time, DEFAULT_DISCONNECTION_TIME)}};

        std::vector<schedule::Schedule> schedules;

        // The sweep's interval IS agents_disconnection_time, which merely defaults to 900 -- it is
        // not a hardcoded fifteen minutes. remoted reads the same <global> value, which is why
        // that section had to survive monitord's removal.
        {
            schedule::Schedule sweep;
            sweep.definition = {SCHEDULE_AGENT_DISCONNECT_SWEEP,
                                TYPE_AGENT_DISCONNECT_SWEEP,
                                schedule::NodeScope::Master,
                                schedule::Cadence::Interval};
            sweep.interval = disconnectionTime;
            sweep.enabled = config.monitor_agents != 0;
            schedules.push_back(std::move(sweep));
        }

        // Disabled by default, and destructive when enabled. That is why re-enabling recomputes
        // the next run rather than honouring a stale slot: an operator flipping the switch and
        // getting an instant purge is a surprise worth not shipping.
        {
            schedule::Schedule retention;
            retention.definition = {SCHEDULE_AGENT_DELETE_OLD,
                                    TYPE_AGENT_DELETE_OLD,
                                    schedule::NodeScope::Master,
                                    schedule::Cadence::Interval};
            retention.interval = std::chrono::seconds {static_cast<long>(config.delete_old_agents) * 60};
            retention.enabled = config.delete_old_agents > 0;
            schedules.push_back(std::move(retention));
        }

        // ANY scope, unlike the two above: every node writes its own log files, so every node
        // rotates them.
        {
            schedule::Schedule rotation;
            rotation.definition = {SCHEDULE_LOG_ROTATE_DAILY,
                                   TYPE_LOG_ROTATE_DAILY,
                                   schedule::NodeScope::Any,
                                   schedule::Cadence::Daily};
            rotation.dayWait = std::chrono::seconds {valueOr(config.day_wait, DEFAULT_DAY_WAIT)};
            rotation.enabled = config.rotate_log != 0;
            schedules.push_back(std::move(rotation));
        }

        return schedules;
    }

    std::shared_ptr<execution::Executor::PeriodicAction> makeSizeRotationAction(
        host::IHostOps& hostOps, const handlers::LocalConfig& localConfig)
    {
        auto action {std::make_shared<execution::Executor::PeriodicAction>()};
        action->name = ACTION_LOG_ROTATE_SIZE;
        action->concurrencyGroup = GROUP_ROTATION;
        action->run = [&hostOps, localConfig](const StopToken& stop)
        {
            if (stop.stopRequested())
            {
                return;
            }

            // A no-op when the log is under the threshold, which is the common case at the
            // one-minute cadence this is signalled at. That is the whole reason this is not a task
            // row: about 1440 rows a day for work that is idempotent, instantaneous and harmless
            // to miss -- a skipped tick just rotates a minute later.
            if (hostOps.rotateLogBySize(localConfig.compressRotatedLogs,
                                        localConfig.keepLogDays,
                                        localConfig.dailyRotations,
                                        localConfig.sizeRotateBytes))
            {
                LOGFN_DEBUG1(moduleLogFn(), "Rotated the manager log after it passed its size threshold");
            }
        };

        return action;
    }
} // namespace task_manager::registry
