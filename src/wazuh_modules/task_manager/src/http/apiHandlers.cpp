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

#include "apiHandlers.hpp"

#include "model/taskId.hpp"
#include "taskManagerLog.hpp"

#include <cstddef>
#include <ctime>
#include <utility>

namespace
{
    using task_manager::Timestamp;

    Timestamp nowSeconds()
    {
        return static_cast<Timestamp>(std::time(nullptr));
    }

    // MAX_FUTURE_SKEW and MAX_AGE now live in model/task.hpp so the upgrade routes admit agent tasks
    // through exactly the same window this one does.
    using task_manager::MAX_AGE;
    using task_manager::MAX_FUTURE_SKEW;

    std::optional<std::string> optionalString(const nlohmann::json& body, const char* key)
    {
        const auto it {body.find(key)};
        if (it == body.end() || !it->is_string())
        {
            return std::nullopt;
        }
        return it->get<std::string>();
    }

    std::optional<Timestamp> optionalTime(const nlohmann::json& body, const char* key)
    {
        const auto it {body.find(key)};
        if (it == body.end() || !it->is_number())
        {
            return std::nullopt;
        }
        return it->get<Timestamp>();
    }

    bool optionalBool(const nlohmann::json& body, const char* key, const bool fallback)
    {
        const auto it {body.find(key)};
        if (it == body.end() || !it->is_boolean())
        {
            return fallback;
        }
        return it->get<bool>();
    }

    int optionalInt(const nlohmann::json& body, const char* key, const int fallback)
    {
        const auto it {body.find(key)};
        if (it == body.end() || !it->is_number_integer())
        {
            return fallback;
        }
        return it->get<int>();
    }
} // namespace

namespace task_manager::http
{
    ApiResponse ApiResponse::error(const int status, const std::string& code, const std::string& message)
    {
        return {status, nlohmann::json {{"error", code}, {"message", message}}};
    }

    nlohmann::json toJson(const ManagerTask& task)
    {
        // Absent rather than null for every optional column, matching the retired representation
        // so an operator's existing expectations still hold.
        nlohmann::json out {{"task_id", task.taskId},
                            {"task_type", task.taskType},
                            {"payload", task.payload},
                            {"create_time", task.createTime},
                            {"status", toString(task.status)},
                            {"attempts", task.attempts},
                            {"defer_count", task.deferCount},
                            {"next_attempt_at", task.nextAttemptAt}};

        if (task.agentId.has_value())
        {
            out["agent_id"] = *task.agentId;
        }
        if (task.owner.has_value())
        {
            out["owner"] = *task.owner;
        }
        if (task.claimTime.has_value())
        {
            out["claim_time"] = *task.claimTime;
        }
        if (task.lastError.has_value())
        {
            out["last_error"] = *task.lastError;
        }
        if (task.scheduleId.has_value())
        {
            out["schedule_id"] = *task.scheduleId;
        }
        if (task.scheduledRunAt.has_value())
        {
            out["scheduled_run_at"] = *task.scheduledRunAt;
        }
        if (task.endTime.has_value())
        {
            out["end_time"] = *task.endTime;
        }

        return out;
    }

    nlohmann::json toJson(const ManagerTaskSummary& summary)
    {
        nlohmann::json out {
            {"task_id", summary.taskId}, {"status", toString(summary.status)}, {"create_time", summary.createTime}};

        if (summary.agentId.has_value())
        {
            out["agent_id"] = *summary.agentId;
        }
        if (summary.lastError.has_value())
        {
            out["last_error"] = *summary.lastError;
        }

        return out;
    }

    ApiHandlers::ApiHandlers(storage::ITaskStore& store,
                             const registry::TaskRegistry& registry,
                             cache::PendingCache& cache,
                             NotifyFn notifyManagerTask,
                             NotifyFn notifyAgentTask,
                             std::shared_ptr<metrics::TaskMetrics> metrics,
                             const int maxPayloadBytes,
                             const int maxTasksPerPoll)
        : m_store {store}
        , m_registry {registry}
        , m_cache {cache}
        , m_notifyManagerTask {std::move(notifyManagerTask)}
        , m_notifyAgentTask {std::move(notifyAgentTask)}
        , m_metrics {std::move(metrics)}
        , m_maxPayloadBytes {maxPayloadBytes}
        , m_maxTasksPerPoll {maxTasksPerPoll}
    {
    }

    std::optional<ApiResponse> ApiHandlers::parseAgentTask(const nlohmann::json& body, AgentTask& task)
    {
        const auto agentId {optionalString(body, "agent_id")};
        if (!agentId.has_value() || agentId->empty())
        {
            return ApiResponse::error(400, "parsing_error", "agent_id is required");
        }

        const auto taskType {optionalString(body, "task_type")};
        if (!taskType.has_value() || taskType->empty())
        {
            return ApiResponse::error(400, "parsing_error", "task_type is required");
        }

        const auto createTime {optionalTime(body, "create_time")};
        if (!createTime.has_value())
        {
            return ApiResponse::error(400, "parsing_error", "create_time is required");
        }

        const auto now {nowSeconds()};
        if (*createTime > now + MAX_FUTURE_SKEW)
        {
            return ApiResponse::error(400, "parsing_error", "Timestamp is in the future");
        }
        if (*createTime < now - MAX_AGE)
        {
            return ApiResponse::error(400, "parsing_error", "Timestamp is too old (>1 year)");
        }

        const auto payload {body.find("payload")};
        if (payload == body.end())
        {
            return ApiResponse::error(400, "parsing_error", "payload is required");
        }

        auto serialized {payload->dump()};
        if (m_maxPayloadBytes > 0 && serialized.size() > static_cast<std::size_t>(m_maxPayloadBytes))
        {
            return ApiResponse::error(413,
                                      "payload_too_large",
                                      "payload exceeds max_payload_bytes (" + std::to_string(m_maxPayloadBytes) + ")");
        }

        // An absent source_id and an empty one produce the SAME id. That aliasing is pre-existing
        // on a shipping path and is reproduced deliberately -- see model/taskId.hpp.
        const auto sourceId {optionalString(body, "source_id").value_or(std::string {})};

        task.taskId = taskId::forAgentTask(sourceId, *agentId, *taskType, *createTime);
        task.agentId = *agentId;
        task.taskType = *taskType;
        task.payload = std::move(serialized);
        task.createTime = *createTime;

        return std::nullopt;
    }

    ApiResponse ApiHandlers::createAgentTask(const nlohmann::json& body)
    {
        AgentTask task;
        if (auto error {parseAgentTask(body, task)}; error.has_value())
        {
            return *error;
        }

        if (!m_store.createAgentTask(task))
        {
            return ApiResponse::error(500, "create_failed", "Failed to create task");
        }

        // Evicting BEFORE answering. A poll that raced this create must not be told "nothing
        // pending" from a cache entry this task has already invalidated.
        m_cache.invalidate(task.agentId);

        if (m_metrics)
        {
            m_metrics->agentTaskCreated();
        }

        if (m_notifyAgentTask)
        {
            m_notifyAgentTask(task.taskType);
        }

        return ApiResponse::ok(nlohmann::json {{"task_id", task.taskId}});
    }

    ApiResponse ApiHandlers::createAgentTasksBulk(const nlohmann::json& body)
    {
        const auto tasks {body.find("tasks")};
        if (tasks == body.end() || !tasks->is_array())
        {
            return ApiResponse::error(400, "parsing_error", "tasks must be an array");
        }

        // Parse every entry BEFORE writing any of them, so a malformed entry cannot leave half a
        // fleet's restart written and the other half rejected.
        std::vector<AgentTask> rows;
        rows.reserve(tasks->size());
        nlohmann::json results = nlohmann::json::array();

        for (const auto& entry : *tasks)
        {
            AgentTask task;
            if (auto error {parseAgentTask(entry, task)}; error.has_value())
            {
                return *error;
            }
            rows.push_back(std::move(task));
        }

        // ONE transaction for the whole batch. The framework restarts a fleet in chunks of 500,
        // which used to be 500 separate socket connections.
        const auto flags {m_store.createAgentTasks(rows)};

        for (std::size_t index = 0; index < rows.size(); ++index)
        {
            m_cache.invalidate(rows[index].agentId);
            results.push_back(nlohmann::json {{"agent_id", rows[index].agentId},
                                              {"task_id", rows[index].taskId},
                                              {"created", index < flags.size() && flags[index]}});
        }

        if (m_metrics)
        {
            for (std::size_t index = 0; index < flags.size(); ++index)
            {
                if (flags[index])
                {
                    m_metrics->agentTaskCreated();
                }
            }
        }

        return ApiResponse::ok(nlohmann::json {{"results", std::move(results)}});
    }

    ApiResponse ApiHandlers::takePendingAgentTasks(const nlohmann::json& body)
    {
        const auto agentId {optionalString(body, "agent_id")};
        if (!agentId.has_value() || agentId->empty())
        {
            return ApiResponse::error(400, "parsing_error", "agent_id is required");
        }

        // The cache only ever records ABSENCE, so a hit means "nothing to hand over" and can be
        // answered without touching the store. This is the branch that keeps a fleet's idle polls
        // off the write path entirely.
        if (m_cache.knownEmpty(*agentId))
        {
            return ApiResponse::ok(nlohmann::json {{"tasks", nlohmann::json::array()}});
        }

        const auto tasks {m_store.takePendingAgentTasks(*agentId, m_maxTasksPerPoll)};

        if (tasks.empty())
        {
            m_cache.markEmpty(*agentId);
            return ApiResponse::ok(nlohmann::json {{"tasks", nlohmann::json::array()}});
        }

        nlohmann::json out = nlohmann::json::array();
        for (const auto& task : tasks)
        {
            // The payload is stored as text and handed back as JSON, so a consumer sees the object
            // it created rather than a string containing one.
            auto payload = nlohmann::json::parse(task.payload, nullptr, false);
            out.push_back(
                nlohmann::json {{"task_id", task.taskId},
                                {"task_type", task.taskType},
                                {"payload", payload.is_discarded() ? nlohmann::json::object() : std::move(payload)}});
        }

        if (m_metrics)
        {
            m_metrics->agentTasksDelivered(tasks.size());
        }

        return ApiResponse::ok(nlohmann::json {{"tasks", std::move(out)}});
    }

    ApiResponse ApiHandlers::createManagerTask(const nlohmann::json& body)
    {
        const auto taskId {optionalString(body, "task_id")};
        const auto taskType {optionalString(body, "task_type")};

        if (!taskId.has_value() || taskId->empty())
        {
            return ApiResponse::error(400, "parsing_error", "task_id is required");
        }
        if (!taskType.has_value() || taskType->empty())
        {
            return ApiResponse::error(400, "parsing_error", "task_type is required");
        }

        const auto payload {body.find("payload")};
        if (payload == body.end())
        {
            return ApiResponse::error(400, "parsing_error", "payload is required");
        }

        auto serialized {payload->is_string() ? payload->get<std::string>() : payload->dump()};
        if (m_maxPayloadBytes > 0 && serialized.size() > static_cast<std::size_t>(m_maxPayloadBytes))
        {
            return ApiResponse::error(413, "payload_too_large", "payload exceeds max_payload_bytes");
        }

        storage::CreateManagerTaskRequest request;
        request.taskId = *taskId;
        request.taskType = *taskType;
        request.payload = std::move(serialized);
        request.agentId = optionalString(body, "agent_id");
        request.scheduleId = optionalString(body, "schedule_id");
        request.scheduledRunAt = optionalTime(body, "scheduled_run_at");
        request.createTime = optionalTime(body, "create_time").value_or(nowSeconds());
        request.nextAttemptAt = optionalTime(body, "next_attempt_at");

        // The descriptor is the authority on coalescing and admission, not the request. A producer
        // that could choose either would be able to bypass the bound that protects the queue --
        // and, for the deletion type, to silently reintroduce the orphaned documents the whole
        // design exists to prevent. Both are still accepted from the body as an override ONLY for
        // types this build does not know, which is how a test fixture registers a synthetic type.
        if (const auto* descriptor {m_registry.find(*taskType)}; descriptor != nullptr)
        {
            request.coalesce = descriptor->coalesceByAgent;
            request.maxPending = descriptor->maxPending;
        }
        else
        {
            request.coalesce = optionalBool(body, "coalesce", false);
            request.maxPending = optionalInt(body, "max_pending", storage::UNBOUNDED);
        }

        const auto outcome {m_store.createManagerTask(request)};

        if (m_metrics)
        {
            m_metrics->taskCreated(*taskType, outcome.result);
        }

        if (outcome.result == CreateResult::QueueFull)
        {
            // 503 rather than 429: the queue is full, which is a capacity condition the producer
            // is expected to retry through, and the admission bound is what protects the manager
            // from an unbounded backlog.
            return {503,
                    nlohmann::json {{"result", toString(outcome.result)},
                                    {"error", "queue_full"},
                                    {"message", "the admission bound for this task type is reached"}}};
        }

        if (outcome.result == CreateResult::Created && m_notifyManagerTask)
        {
            // Start it now. This is why a manager task created through this endpoint does not wait
            // for a poll interval: there is no poll interval.
            m_notifyManagerTask(*taskType);
        }

        return ApiResponse::ok(nlohmann::json {{"result", toString(outcome.result)}, {"task_id", outcome.taskId}});
    }

    ApiResponse ApiHandlers::getManagerTask(const nlohmann::json& body)
    {
        const auto taskId {optionalString(body, "task_id")};
        if (!taskId.has_value() || taskId->empty())
        {
            return ApiResponse::error(400, "parsing_error", "task_id is required");
        }

        const auto task {m_store.getManagerTask(*taskId)};
        if (!task.has_value())
        {
            return ApiResponse::error(404, "not_found", "no manager task with that id");
        }

        return ApiResponse::ok(nlohmann::json {{"task", toJson(*task)}});
    }

    ApiResponse ApiHandlers::getManagerTaskByAgent(const nlohmann::json& body)
    {
        const auto agentId {optionalString(body, "agent_id")};
        const auto taskType {optionalString(body, "task_type")};

        if (!agentId.has_value() || !taskType.has_value())
        {
            return ApiResponse::error(400, "parsing_error", "agent_id and task_type are required");
        }

        const auto task {m_store.getManagerTaskByAgent(*agentId, *taskType)};
        if (!task.has_value())
        {
            // Not an error: "this agent has no such task" is the answer authd's pending-purge
            // check is actually asking for.
            return ApiResponse::ok(nlohmann::json::object());
        }

        return ApiResponse::ok(nlohmann::json {{"task", toJson(*task)}});
    }

    ApiResponse ApiHandlers::listManagerTasks(const nlohmann::json& body)
    {
        const auto taskType {optionalString(body, "task_type")};
        if (!taskType.has_value() || taskType->empty())
        {
            return ApiResponse::error(400, "parsing_error", "task_type is required");
        }

        std::optional<TaskStatus> status;
        if (const auto text {optionalString(body, "status")}; text.has_value())
        {
            status = taskStatusFromString(*text);
            if (!status.has_value())
            {
                return ApiResponse::error(400, "parsing_error", "unknown status '" + *text + "'");
            }
        }

        const auto after {optionalString(body, "last_task_id").value_or(std::string {})};
        const auto limit {optionalInt(body, "limit", storage::DEFAULT_PAGE_SIZE)};

        const auto rows {m_store.listManagerTasks(*taskType, status, after, limit)};

        nlohmann::json out = nlohmann::json::array();
        for (const auto& row : rows)
        {
            out.push_back(toJson(row));
        }

        // Paged on task id, so the caller passes the last one back as last_task_id until a page
        // comes back empty.
        return ApiResponse::ok(nlohmann::json {{"tasks", std::move(out)}});
    }

    ApiResponse ApiHandlers::countManagerTasks(const nlohmann::json& body)
    {
        const auto taskType {optionalString(body, "task_type")};
        const auto statusText {optionalString(body, "status")};

        if (!taskType.has_value() || !statusText.has_value())
        {
            return ApiResponse::error(400, "parsing_error", "task_type and status are required");
        }

        const auto status {taskStatusFromString(*statusText)};
        if (!status.has_value())
        {
            return ApiResponse::error(400, "parsing_error", "unknown status '" + *statusText + "'");
        }

        return ApiResponse::ok(nlohmann::json {{"count", m_store.countManagerTasks(*taskType, *status)}});
    }
} // namespace task_manager::http
