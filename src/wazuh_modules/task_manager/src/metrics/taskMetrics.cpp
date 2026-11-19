/*
 * Wazuh task manager module
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "taskMetrics.hpp"

#include "metricNames.hpp"

#include <stdexcept>
#include <utility>

namespace task_manager::metrics
{
    namespace
    {
        constexpr std::array CREATE_RESULTS {
            CreateResult::Created, CreateResult::Coalesced, CreateResult::Collided, CreateResult::QueueFull};

        /// @brief The statuses a row can be retired with; only these have a `retired` counter.
        constexpr std::array TERMINAL_STATUSES {
            TaskStatus::Completed, TaskStatus::Failed, TaskStatus::DeadLetter, TaskStatus::Superseded};

        constexpr std::array OUTCOMES {Outcome::Ok,
                                       Outcome::Retryable,
                                       Outcome::Timeout,
                                       Outcome::Terminal,
                                       Outcome::NotReady,
                                       Outcome::Busy,
                                       Outcome::Incomplete};

        /// @brief Position of `status` in TERMINAL_STATUSES, or the array's size if it is not there.
        constexpr std::size_t terminalIndex(const TaskStatus status) noexcept
        {
            std::size_t index {0};
            while (index < TERMINAL_STATUSES.size() && TERMINAL_STATUSES[index] != status)
            {
                ++index;
            }
            return index;
        }

        /// @brief `<prefix><taskType>.<member>`, the shape of every per-type family.
        std::string familyName(const char* prefix, const std::string_view taskType, const std::string_view member)
        {
            std::string name {prefix};
            name.append(taskType).append(".").append(member);
            return name;
        }
    } // namespace

    TaskMetrics::TaskMetrics(std::shared_ptr<wazuh::metrics::IManager> manager,
                             const std::vector<std::string>& registeredTypes)
        : m_manager {std::move(manager)}
    {
        for (const auto& taskType : registeredTypes)
        {
            if (taskType == names::UNKNOWN_TASK_TYPE)
            {
                // Its counters would be the bucket's, mixing a real type with every misspelt one.
                throw std::invalid_argument("task type name '" + taskType + "' is reserved for the metrics bucket");
            }
            m_byType.emplace(taskType, createTypeCounters(taskType));
        }
        m_unknownType = createTypeCounters(names::UNKNOWN_TASK_TYPE);

        m_handlerDuration = m_manager->getOrCreateHistogram(
            names::HANDLER_DURATION, "Manager task handler execution time", "microseconds");
        m_busyWorkers = m_manager->getOrCreateGaugeInt(
            names::EXECUTOR_BUSY_WORKERS, "Executor workers currently running a handler", "workers");
        m_agentTasksCreated = m_manager->getOrCreateCounter(names::AGENT_TASKS_CREATED, "Agent tasks stored", "count");
        m_agentTasksDelivered =
            m_manager->getOrCreateCounter(names::AGENT_TASKS_DELIVERED, "Agent tasks handed to a poller", "count");
        m_tasksReclaimed = m_manager->getOrCreateCounter(
            names::MANAGER_TASKS_RECLAIMED, "Claimed rows the ownership sweep returned to pending", "count");
    }

    TaskMetrics::TypeCounters TaskMetrics::createTypeCounters(const std::string_view taskType)
    {
        TypeCounters counters;

        static_assert(std::tuple_size_v<decltype(counters.created)> == CREATE_RESULTS.size());
        static_assert(static_cast<std::size_t>(CreateResult::QueueFull) == CREATE_RESULTS.size() - 1);
        for (const auto result : CREATE_RESULTS)
        {
            counters.created[static_cast<std::size_t>(result)] = m_manager->getOrCreateCounter(
                familyName(names::MANAGER_TASKS_CREATED_PREFIX, taskType, toString(result)),
                "Manager task create requests by outcome",
                "count");
        }

        static_assert(std::tuple_size_v<decltype(counters.retired)> == TERMINAL_STATUSES.size());
        for (std::size_t index {0}; index < TERMINAL_STATUSES.size(); ++index)
        {
            counters.retired[index] = m_manager->getOrCreateCounter(
                familyName(names::MANAGER_TASKS_RETIRED_PREFIX, taskType, toString(TERMINAL_STATUSES[index])),
                "Manager task outcomes",
                "count");
        }

        static_assert(std::tuple_size_v<decltype(counters.outcome)> == OUTCOMES.size());
        static_assert(static_cast<std::size_t>(Outcome::Incomplete) == OUTCOMES.size() - 1);
        for (const auto outcome : OUTCOMES)
        {
            counters.outcome[static_cast<std::size_t>(outcome)] =
                m_manager->getOrCreateCounter(familyName(names::HANDLER_OUTCOME_PREFIX, taskType, toString(outcome)),
                                              "Manager task outcomes",
                                              "count");
        }

        return counters;
    }

    const TaskMetrics::TypeCounters& TaskMetrics::countersFor(const std::string_view taskType) const
    {
        const auto it {m_byType.find(taskType)};
        return it != m_byType.end() ? it->second : m_unknownType;
    }

    void TaskMetrics::taskRetired(const std::string& taskType, const TaskStatus status)
    {
        // Only the executor retires rows, and only rows of a registered type with a terminal
        // status; anything else lands in the `unknown` bucket or is dropped, never named.
        if (const auto index {terminalIndex(status)}; index < TERMINAL_STATUSES.size())
        {
            countersFor(taskType).retired[index]->add();
        }
    }

    void TaskMetrics::handlerRan(const std::string& taskType, const Outcome outcome, const std::uint64_t micros)
    {
        m_handlerDuration->observe(micros);
        countersFor(taskType).outcome[static_cast<std::size_t>(outcome)]->add();
    }

    void TaskMetrics::taskCreated(const std::string& taskType, const CreateResult result)
    {
        countersFor(taskType).created[static_cast<std::size_t>(result)]->add();
    }

    void TaskMetrics::agentTaskCreated()
    {
        m_agentTasksCreated->add();
    }

    void TaskMetrics::agentTasksDelivered(const std::uint64_t count)
    {
        m_agentTasksDelivered->add(count);
    }

    void TaskMetrics::setBusyWorkers(const std::int64_t count)
    {
        m_busyWorkers->set(count);
    }

    void TaskMetrics::tasksReclaimed(const std::uint64_t count)
    {
        m_tasksReclaimed->add(count);
    }

    void TaskMetrics::registerPull(const std::string& name,
                                   std::function<std::uint64_t()> getter,
                                   const std::string& description,
                                   const std::string& unit)
    {
        m_manager->registerPullMetric(name, std::move(getter), description, unit);
    }
} // namespace task_manager::metrics
