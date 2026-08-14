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

#ifndef _REMOTED_CONTROL_AGENT_REGISTRY_HPP
#define _REMOTED_CONTROL_AGENT_REGISTRY_HPP

#include "controlTypes.hpp"
#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace remoted::control
{
    struct AgentEntry
    {
        std::vector<std::string> groups;
        uint64_t groupsRefreshedAtSec = 0;
        uint64_t lastKeepaliveUpdateSec = 0;
        uint64_t lastActivitySec = 0;
        uint64_t createdAtSec = 0;
    };

    class AgentRegistry
    {
    public:
        std::shared_ptr<const AgentEntry> get(AgentId id) const;

        std::shared_ptr<const AgentEntry>
        update(AgentId id, std::function<std::shared_ptr<AgentEntry>(std::shared_ptr<const AgentEntry>)> updater);

        void evictExpiredEntries(uint64_t ttlSec);

    private:
        struct Shard
        {
            mutable std::shared_mutex mtx;
            std::unordered_map<AgentId, std::shared_ptr<const AgentEntry>> map;
        };

        std::array<Shard, 8> m_shards;

        Shard& getShard(AgentId id)
        {
            return m_shards[id % m_shards.size()];
        }
        const Shard& getShard(AgentId id) const
        {
            return m_shards[id % m_shards.size()];
        }
    };

} // namespace remoted::control

#endif // _REMOTED_CONTROL_AGENT_REGISTRY_HPP
