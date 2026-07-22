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

#include <chrono>
#include <cstddef>
#include <deque>
#include <string>
#include <unordered_set>

/**
 * @brief Bounded, TTL-aged set of seen task ids. Task delivery is
 *        at-least-once (#37733), so the client ignores duplicates; the bound
 *        keeps memory flat and the TTL lets a much-later re-delivery through
 *        (acceptable under at-least-once).
 *
 * TODO(#37833): INTERIM. This in-memory record is lost on restart, so a
 *        duplicate that straddles a restart (notably a remote_upgrade, which
 *        restarts the agent) can re-execute. Issue #37833 replaces it with a
 *        durable, restart-surviving task_id table owned by the agent-info
 *        module, reached over IPC; this class is retired then.
 */
class TaskDeduper final
{
    public:
        explicit TaskDeduper(size_t capacity = 4096,
                             std::chrono::seconds ttl = std::chrono::seconds {3600})
            : m_capacity(capacity == 0 ? 1 : capacity)
            , m_ttl(ttl)
        {
        }

        /// Records the id at time `now`. Returns true if it is new (dispatch),
        /// false if already seen and unexpired (drop). Insertion-time TTL: an
        /// id re-delivered after the TTL is treated as new.
        bool markIfNew(const std::string& taskId, std::chrono::steady_clock::time_point now)
        {
            pruneExpired(now);

            if (m_seen.count(taskId) != 0)
            {
                return false;
            }

            if (m_order.size() >= m_capacity)
            {
                m_seen.erase(m_order.front().id);
                m_order.pop_front();
            }

            m_seen.insert(taskId);
            m_order.push_back({taskId, now});
            return true;
        }

    private:
        struct Entry
        {
            std::string id;
            std::chrono::steady_clock::time_point seenAt;
        };

        /// Insertion-time TTL means m_order is sorted by seenAt, so expired
        /// entries are always a front prefix: pop them, amortized O(expired).
        void pruneExpired(std::chrono::steady_clock::time_point now)
        {
            while (!m_order.empty() && now - m_order.front().seenAt >= m_ttl)
            {
                m_seen.erase(m_order.front().id);
                m_order.pop_front();
            }
        }

        size_t m_capacity;
        std::chrono::seconds m_ttl;
        std::unordered_set<std::string> m_seen;
        std::deque<Entry> m_order;
};

#endif // _HC_TASK_DEDUPER_HPP
