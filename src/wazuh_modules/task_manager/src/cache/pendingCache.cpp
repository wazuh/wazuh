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

#include "pendingCache.hpp"

namespace task_manager::cache
{
    bool PendingCache::knownEmpty(const std::string& agentId) const
    {
        std::lock_guard lock {m_mutex};
        return m_empty.find(agentId) != m_empty.cend();
    }

    void PendingCache::markEmpty(const std::string& agentId)
    {
        std::lock_guard lock {m_mutex};
        m_empty.insert(agentId);
    }

    void PendingCache::invalidate(const std::string& agentId)
    {
        std::lock_guard lock {m_mutex};
        m_empty.erase(agentId);
    }

    void PendingCache::clear()
    {
        std::lock_guard lock {m_mutex};
        m_empty.clear();
    }

    std::size_t PendingCache::size() const
    {
        std::lock_guard lock {m_mutex};
        return m_empty.size();
    }
} // namespace task_manager::cache
