/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 28, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HC_TASK_ID_STORE_ADAPTER_HPP
#define _HC_TASK_ID_STORE_ADAPTER_HPP

#include "https_client.h"
#include "taskIdStore.hpp"

/**
 * @brief Production ITaskIdStore: forwards to the C bridge's
 *        check_and_record_task callback (hc_callbacks_t), which performs the
 *        actual IPC round-trip to agent-info's durable registry.
 *
 * A thin adapter, deliberately: the module's C/C++ boundary is always
 * crossed through hc_callbacks_t (see https_client.h), so the concrete IPC
 * mechanics (Unix socket on Linux/macOS, in-process on Windows) live in
 * client-agent's bridge, not here. This class only maps the callback's
 * tri-state return (1 new / 0 duplicate / -1 error) onto the interface's
 * fail-closed boolean.
 */
class TaskIdStoreAdapter final : public ITaskIdStore
{
    public:
        TaskIdStoreAdapter(hc_check_and_record_task_fn callback, void* userData)
            : m_callback(callback)
            , m_userData(userData)
        {
        }

        bool checkAndRecord(const std::string& taskId) override
        {
            if (m_callback == nullptr)
            {
                // No bridge wired (e.g. a test double harness): fail closed
                // rather than silently treating everything as new.
                return false;
            }

            return m_callback(taskId.c_str(), m_userData) == 1;
        }

    private:
        hc_check_and_record_task_fn m_callback;
        void* m_userData;
};

#endif // _HC_TASK_ID_STORE_ADAPTER_HPP
