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

#ifndef _TASK_MANAGER_CACHE_PENDING_CACHE_HPP
#define _TASK_MANAGER_CACHE_PENDING_CACHE_HPP

#include <cstddef>
#include <mutex>
#include <set>
#include <string>

namespace task_manager::cache
{
    /**
     * @brief Remembers which agents are known to have NO pending tasks.
     *
     * Ported from the retired module, and load-bearing for exactly one reason: the pending-tasks
     * route is the only high-frequency one -- remoted polls it per agent -- and it is a WRITE,
     * because it marks what it returns as delivered. Every idle poll that this cache answers is a
     * write transaction that never happens, which is what keeps the single store connection from
     * being the bottleneck at fleet scale.
     *
     * IT ONLY EVER CACHES ABSENCE. Tasks themselves are never cached, so a task cannot be handed
     * out twice from memory; the worst a stale entry can do is delay a task by one poll, and it
     * cannot do even that, because creating a task for an agent evicts its entry.
     *
     * Its size grows with the number of distinct agents that have no work, which is the whole
     * fleet in the steady state -- one short string each.
     */
    class PendingCache
    {
    public:
        /// @return true when this agent is known to have nothing pending.
        bool knownEmpty(const std::string& agentId) const;

        /// @brief Record that a read found nothing for this agent.
        void markEmpty(const std::string& agentId);

        /// @brief Forget this agent, because it now has work. MUST be called on every create, or
        ///        a task would sit invisible until something else evicted the entry.
        void invalidate(const std::string& agentId);

        void clear();

        std::size_t size() const;

    private:
        mutable std::mutex m_mutex;
        std::set<std::string, std::less<>> m_empty;
    };
} // namespace task_manager::cache

#endif // _TASK_MANAGER_CACHE_PENDING_CACHE_HPP
