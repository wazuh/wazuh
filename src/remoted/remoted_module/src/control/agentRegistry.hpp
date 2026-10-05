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
#include <atomic>
#include <cstddef>
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
        bool hostPersisted = false;
        /// Stamp of the last write to `groups`/`groupsRefreshedAtSec`, from the registry-wide
        /// counter (AgentRegistry::nextGroupsSeq()); 0 = never written. It orders every writer of
        /// the membership: a wazuh-db answer read before a newer write must not overwrite it.
        uint64_t groupsSeq = 0;
    };

    /// @brief Whether `entry`'s groups came from wazuh-db less than `intervalSec` ago (only a
    /// wazuh-db read establishes a membership; a membership push only withdraws one). A
    /// never-established entry (groupsRefreshedAtSec == 0) is not fresh; a wall clock stepping back
    /// makes the difference wrap, which reads as "expired" (one extra lookup, never a stale
    /// authorization).
    inline bool groupsFresh(const AgentEntry& entry, uint64_t nowSec, uint64_t intervalSec)
    {
        return entry.groupsRefreshedAtSec != 0 && nowSec - entry.groupsRefreshedAtSec < intervalSec;
    }

    class AgentRegistry
    {
    public:
        std::shared_ptr<const AgentEntry> get(AgentId id) const;

        std::shared_ptr<const AgentEntry>
        update(AgentId id, std::function<std::shared_ptr<AgentEntry>(std::shared_ptr<const AgentEntry>)> updater);

        /// @brief Erases the entries idle for more than `ttlSec`. An erased entry's groups stamp
        /// leaves the eviction mark mayStoreLookup() reads, as a skipped push leaves its own.
        void evictExpiredEntries(uint64_t ttlSec);

        /// Outcome of a membership push for one agent.
        enum class PushOutcome
        {
            Invalidated, ///< An existing entry is no longer an established membership.
            Skipped      ///< No entry for the agent: nothing is created (the fallback covers it).
        };

        /// @brief The one write of a membership push: marks an existing entry's membership as not
        /// established (groupsRefreshedAtSec = 0, groups kept), stamping it, so the next reader
        /// looks it up. A push never establishes groups: it describes the database as it was when
        /// the cluster daemon wrote it, which a later read may already have overtaken. Activity,
        /// keepalive and host fields are left as they are. An absent agent is skipped and leaves
        /// the skip mark mayStoreLookup() reads.
        PushOutcome invalidateGroups(AgentId id);

        /// @brief The counter as it is now. A caller about to query wazuh-db takes it BEFORE the
        /// query and hands it to mayStoreLookup() when the answer arrives.
        uint64_t groupsTicket() const;

        /// @brief A new stamp, strictly larger than every ticket handed out so far. Call it only
        /// from inside an update() updater, when the updater writes groups.
        uint64_t nextGroupsSeq();

        /// @brief Whether a wazuh-db answer whose query was issued at `ticket` may be written over
        /// `current` (the value an update() updater receives). False when a newer groups write
        /// stamped `current` after the ticket, and, while `current` holds no established membership,
        /// when a push skipped some absent agent after the ticket (the push may have been this
        /// agent's, and nothing recorded it) or when eviction erased an entry whose groups were
        /// written after the ticket (it may have been this agent's, taking that write's stamp
        /// with it).
        bool mayStoreLookup(const std::shared_ptr<const AgentEntry>& current, uint64_t ticket) const;

        /// @brief Number of agents currently tracked, summed across the shards (each under its
        /// shared lock, so concurrent updates make this a best-effort snapshot, not a fence).
        /// Feeds the remoted.control.registry.agents pull metric -- dump-cadence only.
        std::size_t size() const;

    private:
        struct Shard
        {
            mutable std::shared_mutex mtx;
            std::unordered_map<AgentId, std::shared_ptr<const AgentEntry>> map;
        };

        std::array<Shard, 8> m_shards;
        std::atomic<uint64_t> m_groupsSeq {0};
        std::atomic<uint64_t> m_lastSkipSeq {0};
        /// The largest groups stamp an evicted entry held (0 = none yet).
        std::atomic<uint64_t> m_lastEvictSeq {0};

        /// Records that a push skipped an absent agent, as the new stamp it takes.
        void markSkipped();

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
