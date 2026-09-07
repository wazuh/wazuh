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

#include "taskMetrics.hpp"

#include <utility>

namespace task_manager::metrics
{
    TaskMetrics::TaskMetrics(std::shared_ptr<wazuh::metrics::IManager> manager)
        : m_manager {std::move(manager)}
    {
        m_handlerDuration = m_manager->getOrCreateHistogram(
            "task_manager.handler.duration", "Manager task handler execution time", "microseconds");
        m_busyWorkers = m_manager->getOrCreateGaugeInt(
            "task_manager.executor.busy_workers", "Executor workers currently running a handler", "workers");
        m_agentTasksCreated =
            m_manager->getOrCreateCounter("task_manager.agent_tasks.created", "Agent tasks stored", "count");
        m_agentTasksDelivered = m_manager->getOrCreateCounter(
            "task_manager.agent_tasks.delivered", "Agent tasks handed to a poller", "count");
        m_tasksReclaimed = m_manager->getOrCreateCounter(
            "task_manager.manager_tasks.reclaimed", "Claimed rows the ownership sweep returned to pending", "count");
    }

    std::shared_ptr<wazuh::metrics::ICounter> TaskMetrics::counterFor(const std::string& name)
    {
        std::lock_guard lock {m_mutex};

        if (const auto it {m_counters.find(name)}; it != m_counters.end())
        {
            return it->second;
        }

        auto counter {m_manager->getOrCreateCounter(name, "Manager task outcomes", "count")};
        m_counters.emplace(name, counter);
        return counter;
    }

    void TaskMetrics::taskRetired(const std::string& taskType, const TaskStatus status)
    {
        counterFor("task_manager.manager_tasks.retired." + taskType + "." + std::string {toString(status)})->add();
    }

    void TaskMetrics::handlerRan(const std::string& taskType, const Outcome outcome, const std::uint64_t micros)
    {
        m_handlerDuration->observe(micros);
        counterFor("task_manager.handler.outcome." + taskType + "." + std::string {toString(outcome)})->add();
    }

    void TaskMetrics::taskCreated(const std::string& taskType, const CreateResult result)
    {
        counterFor("task_manager.manager_tasks.created." + taskType + "." + std::string {toString(result)})->add();
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
