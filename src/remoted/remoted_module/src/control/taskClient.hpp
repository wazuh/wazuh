/*
 * Wazuh remoted module - Task client
 * Copyright (C) 2015, Wazuh Inc.
 * July 31, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_CONTROL_TASK_CLIENT_HPP
#define _REMOTED_CONTROL_TASK_CLIENT_HPP

#include "controlConfig.hpp"
#include "controlTypes.hpp"
#include "metrics.hpp"
#include <functional>
#include <memory>

namespace remoted::control
{
    class TaskClient
    {
    public:
        TaskClient(const std::string& taskSocketPath,
                   uint32_t concurrency,
                   uint32_t deadlineMs,
                   uint32_t maxQueueSize,
                   ControlMetrics& metrics);
        ~TaskClient();

        void getPendingTasks(AgentId id, std::function<void(SocketError, std::vector<Task>)> callback);

    private:
        class Impl;
        std::unique_ptr<Impl> m_impl;
    };

} // namespace remoted::control

#endif // _REMOTED_CONTROL_TASK_CLIENT_HPP
