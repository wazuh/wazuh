/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HC_TASK_DEDUPER_HPP
#define _HC_TASK_DEDUPER_HPP

#include <cstddef>
#include <deque>
#include <string>
#include <unordered_set>

/**
 * @brief Bounded LRU set of seen task ids. Task delivery is at-least-once
 *        (#37733), so the client must ignore duplicates. The bound keeps the
 *        memory flat; once an id ages out, a re-delivery is accepted again
 *        (acceptable under at-least-once).
 */
class TaskDeduper final
{
    public:
        explicit TaskDeduper(size_t capacity = 4096)
            : m_capacity(capacity == 0 ? 1 : capacity)
        {
        }

        /// Records the id. Returns true if it is new (should be dispatched),
        /// false if it was already seen (drop).
        bool markIfNew(const std::string& taskId)
        {
            if (m_seen.count(taskId) != 0)
            {
                return false;
            }

            if (m_order.size() >= m_capacity)
            {
                m_seen.erase(m_order.front());
                m_order.pop_front();
            }

            m_seen.insert(taskId);
            m_order.push_back(taskId);
            return true;
        }

    private:
        size_t m_capacity;
        std::unordered_set<std::string> m_seen;
        std::deque<std::string> m_order;
};

#endif // _HC_TASK_DEDUPER_HPP
