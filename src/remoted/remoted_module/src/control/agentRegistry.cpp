/*
 * Wazuh remoted module - Agent registry
 * Copyright (C) 2015, Wazuh Inc.
 * July 30, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "agentRegistry.hpp"
#include <ctime>
#include <mutex>

namespace remoted::control
{
    std::shared_ptr<const AgentEntry> AgentRegistry::get(AgentId id) const
    {
        auto& shard = getShard(id);
        std::shared_lock lock(shard.mtx);

        auto it = shard.map.find(id);
        return (it != shard.map.end()) ? it->second : nullptr;
    }

    std::shared_ptr<const AgentEntry>
    AgentRegistry::update(AgentId id,
                          std::function<std::shared_ptr<AgentEntry>(std::shared_ptr<const AgentEntry>)> updater)
    {
        auto& shard = getShard(id);
        std::unique_lock lock(shard.mtx);

        auto it = shard.map.find(id);
        auto current = (it != shard.map.end()) ? it->second : nullptr;

        auto updated = updater(current);
        if (!updated)
        {
            return current;
        }

        shard.map[id] = updated;
        return updated;
    }

    void AgentRegistry::evictExpiredEntries(uint64_t ttlSec)
    {
        const auto now = static_cast<uint64_t>(std::time(nullptr));

        for (auto& shard : m_shards)
        {
            // Two-phase eviction: first collect expired ids under a shared
            // (read) lock so concurrent get()/update() calls on this shard are
            // not blocked for the whole scan; then reacquire exclusively and
            // erase only those still-expired entries. Under contention this
            // trades a slightly larger critical-section footprint for much
            // shorter blocking windows on hot shards.
            std::vector<AgentId> expired;
            {
                std::shared_lock lock(shard.mtx);
                expired.reserve(shard.map.size());
                for (const auto& [id, entry] : shard.map)
                {
                    // Use the most recent between activity and creation
                    // timestamps so entries that were inserted but never
                    // touched (lastActivitySec == 0) still age out and don't
                    // leak forever.
                    const uint64_t reference =
                        entry->lastActivitySec > entry->createdAtSec ? entry->lastActivitySec : entry->createdAtSec;

                    if (reference > 0 && now >= reference && (now - reference) > ttlSec)
                    {
                        expired.push_back(id);
                    }
                }
            }

            if (expired.empty())
            {
                continue;
            }

            std::unique_lock lock(shard.mtx);
            for (AgentId id : expired)
            {
                auto it = shard.map.find(id);
                if (it == shard.map.end())
                {
                    continue;
                }
                // Re-check under the write lock: a concurrent update() may
                // have refreshed lastActivitySec between phases.
                const auto& entry = it->second;
                const uint64_t reference =
                    entry->lastActivitySec > entry->createdAtSec ? entry->lastActivitySec : entry->createdAtSec;
                if (reference > 0 && now >= reference && (now - reference) > ttlSec)
                {
                    shard.map.erase(it);
                }
            }
        }
    }

} // namespace remoted::control
