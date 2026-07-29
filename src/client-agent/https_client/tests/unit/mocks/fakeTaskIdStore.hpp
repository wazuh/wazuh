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

#ifndef _HC_FAKE_TASK_ID_STORE_HPP
#define _HC_FAKE_TASK_ID_STORE_HPP

#include "taskIdStore.hpp"

#include <unordered_set>
#include <vector>

/**
 * @brief In-memory ITaskIdStore double for ControlStream tests.
 *
 * Mirrors the real durable registry's contract (checkAndRecord: true once
 * per id, false thereafter) without any IPC/persistence, so tests can drive
 * "restart" or "TTL expiry" scenarios explicitly via forget()/forceDuplicate
 * rather than depending on the real registry's timing.
 */
class FakeTaskIdStore final : public ITaskIdStore
{
    public:
        bool checkAndRecord(const std::string& taskId) override
        {
            m_calls.push_back(taskId);

            if (m_forcedDuplicates.count(taskId) != 0)
            {
                return false;
            }

            return m_seen.insert(taskId).second; // true only the first time.
        }

        /// Simulates a restart/TTL expiry: the next checkAndRecord(taskId)
        /// reports it as new again.
        void forget(const std::string& taskId)
        {
            m_seen.erase(taskId);
        }

        /// Simulates the registry being unreachable/erroring for this id: the
        /// fail-closed contract (checkAndRecord returns false) applies even
        /// though the id was never actually seen before.
        void forceDuplicate(const std::string& taskId)
        {
            m_forcedDuplicates.insert(taskId);
        }

        const std::vector<std::string>& calls() const
        {
            return m_calls;
        }

    private:
        std::unordered_set<std::string> m_seen;
        std::unordered_set<std::string> m_forcedDuplicates;
        std::vector<std::string> m_calls;
};

#endif // _HC_FAKE_TASK_ID_STORE_HPP
