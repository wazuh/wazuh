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

#ifndef _TASK_MANAGER_HTTP_API_HANDLERS_HPP
#define _TASK_MANAGER_HTTP_API_HANDLERS_HPP

#include "cache/pendingCache.hpp"
#include "metrics/taskMetrics.hpp"
#include "registry/taskRegistry.hpp"
#include "storage/iTaskStore.hpp"

#include <json.hpp>

#include <functional>
#include <memory>
#include <string>

namespace task_manager::http
{
    /// @brief A status code and a JSON body, decoupled from the transport so every route's logic
    ///        can be tested without starting a server.
    struct ApiResponse
    {
        int status {200};
        nlohmann::json body;

        static ApiResponse ok(nlohmann::json body)
        {
            return {200, std::move(body)};
        }
        static ApiResponse error(int status, const std::string& code, const std::string& message);
    };

    /**
     * @brief Every route's logic, in one place, with no transport dependency.
     *
     * WHAT THE HTTP SURFACE REPLACED. The retired module spoke a bespoke JSON dialect framed with
     * a four-byte length prefix, served by a hand-rolled dealer thread and eight workers over an
     * epoll wrapper. Everything below the JSON is now shared_modules/uds_http_server -- the same
     * transport wazuh-db and inventory-sync use -- so this class is only the mapping between a
     * request body and the store.
     *
     * WHAT DISAPPEARED ENTIRELY. Twelve manager-task operations that used to be wazuh-db
     * sub-commands -- claim, requeue, set result, poll, sweep paging, retention, and the four
     * schedule calls -- are gone from every wire. They existed only because storage lived in
     * another process; they are now ITaskStore method calls.
     */
    class ApiHandlers
    {
    public:
        /**
         * @brief Called after a manager task is created, so the executor claims it and the
         *        scheduler recomputes its sleep immediately rather than at the next backstop wake.
         *
         * MANAGER TASKS ONLY. There is deliberately no agent-task equivalent: an agent task is not
         * executed by this module at all -- it sits in TASKS until the agent polls for it -- so
         * there is nothing to wake. The parameter used to exist and was wired to an empty lambda,
         * which read as though agent creates fed the executor too.
         */
        using NotifyFn = std::function<void(const std::string& taskType)>;

        ApiHandlers(storage::ITaskStore& store,
                    const registry::TaskRegistry& registry,
                    cache::PendingCache& cache,
                    NotifyFn notifyManagerTask,
                    std::shared_ptr<metrics::TaskMetrics> metrics,
                    int maxPayloadBytes,
                    int maxTasksPerPoll);

        // ---- agent tasks ---------------------------------------------------------------------
        ApiResponse createAgentTask(const nlohmann::json& body);
        ApiResponse createAgentTasksBulk(const nlohmann::json& body);
        ApiResponse takePendingAgentTasks(const nlohmann::json& body);

        // ---- manager tasks -------------------------------------------------------------------
        ApiResponse createManagerTask(const nlohmann::json& body);
        ApiResponse getManagerTask(const nlohmann::json& body);
        ApiResponse getManagerTaskByAgent(const nlohmann::json& body);
        ApiResponse listManagerTasks(const nlohmann::json& body);
        ApiResponse countManagerTasks(const nlohmann::json& body);

    private:
        /// @brief Validate and normalise one agent-task create request into a row.
        /// @return An error response when the request is malformed, otherwise nullopt and `task`
        ///         is filled.
        std::optional<ApiResponse> parseAgentTask(const nlohmann::json& body, AgentTask& task);

        storage::ITaskStore& m_store;
        const registry::TaskRegistry& m_registry;
        cache::PendingCache& m_cache;
        NotifyFn m_notifyManagerTask;
        std::shared_ptr<metrics::TaskMetrics> m_metrics;
        int m_maxPayloadBytes;
        int m_maxTasksPerPoll;
    };

    /// @brief Render a manager task as the full row an operator gets from the by-id lookup.
    nlohmann::json toJson(const ManagerTask& task);

    /// @brief Render a listing row. Deliberately narrow -- enough to see WHAT failed and why,
    ///        without paging whole payloads.
    nlohmann::json toJson(const ManagerTaskSummary& summary);
} // namespace task_manager::http

#endif // _TASK_MANAGER_HTTP_API_HANDLERS_HPP
