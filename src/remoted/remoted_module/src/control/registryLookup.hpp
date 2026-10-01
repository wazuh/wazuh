/*
 * Wazuh remoted module - Registry lookup (the /download fallback)
 * Copyright (C) 2015, Wazuh Inc.
 * September 28, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_CONTROL_REGISTRY_LOOKUP_HPP
#define _REMOTED_CONTROL_REGISTRY_LOOKUP_HPP

#include "agentRegistry.hpp"
#include "controlConfig.hpp"
#include "controlTypes.hpp"
#include "metrics.hpp"

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace remoted::control
{
    class WazuhDBClient;

    /// What a lookup established about an agent's membership in the local wazuh-db.
    struct LookupOutcome
    {
        enum class Kind
        {
            Groups,     ///< The agent's groups, wazuh-db order (empty = a row with no groups).
            NoRow,      ///< The local replica has no row for the agent. Never a membership: retry.
            Unavailable ///< wazuh-db did not answer in time, refused, or the lookup was refused.
        };
        Kind kind {Kind::Unavailable};
        std::vector<std::string> groups;
    };

    /// Bounds on the requests waiting for lookups. Defaults are the S18 constants; tests override them.
    struct LookupLimits
    {
        uint32_t maxWaitersPerAgent = kLookupMaxWaitersPerAgent;
        uint32_t maxWaiters = kLookupMaxWaiters;
    };

    /**
     * @brief Asynchronous, coalesced lookups of agent memberships in the local wazuh-db, for a
     * requester whose AgentRegistry entry is missing or expired.
     *
     * Concurrent lookups for one agent share a single query; the requests waiting on lookups are
     * bounded per agent and in total, and one over a bound is answered Unavailable at once. What a
     * query reads is written into the registry under its ordering rule (the ticket is taken when
     * the query is issued): a newer write wins, a read that may be older than a skipped push is
     * answered but not written, and a row with no groups is stored as {"default"}. "No row" is never
     * a membership and never creates an entry; it invalidates the membership an existing entry
     * holds, under the same rule.
     *
     * Waiters are called with no lock held: on a client worker thread, or inline on the caller's
     * thread when the lookup is refused. A waiter may call lookup() again; it must never call
     * stop() (that joins the client's workers, one of which may be running the waiter).
     *
     * Lifetime: stop() may run while other threads call lookup() (they are answered Unavailable),
     * but the object may only be destroyed once no thread can still be inside lookup() -- callers
     * that can race the owner's teardown hold it by shared_ptr.
     */
    class RegistryLookup
    {
    public:
        using Waiter = std::function<void(LookupOutcome)>;

        struct Stats
        {
            uint64_t queries = 0;   ///< wazuh-db queries issued.
            uint64_t coalesced = 0; ///< Lookups that joined a query already in flight.
            uint64_t rejected = 0;  ///< Lookups refused by a bound or by stop().
        };

        RegistryLookup(std::shared_ptr<AgentRegistry> registry,
                       const Config& config,
                       ControlMetrics& metrics,
                       LookupLimits limits = {});
        ~RegistryLookup();

        RegistryLookup(const RegistryLookup&) = delete;
        RegistryLookup& operator=(const RegistryLookup&) = delete;

        /// @brief Looks agent @p id up; @p done is called exactly once. @p issueSec is the wall
        /// clock at the request, the time an established answer is stamped with.
        void lookup(AgentId id, uint64_t issueSec, Waiter done);

        /// @brief Refuses new lookups and answers every waiter (in-flight queries complete or time
        /// out; queued ones are failed). Idempotent; the destructor calls it.
        void stop();

        Stats stats() const;

    private:
        struct Pending
        {
            uint64_t ticket = 0;
            uint64_t issueSec = 0;
            std::vector<Waiter> waiters;
        };

        void complete(AgentId id, SocketError err, AgentGroupsResult result);
        LookupOutcome store(AgentId id, const Pending& pending, std::vector<std::string> groups);
        LookupOutcome storeNoRow(AgentId id, const Pending& pending);

        std::shared_ptr<AgentRegistry> m_registry;
        const LookupLimits m_limits;

        mutable std::mutex m_mutex; ///< Guards m_pending, m_totalWaiters, m_stopping.
        std::unordered_map<AgentId, Pending> m_pending;
        uint32_t m_totalWaiters = 0;
        bool m_stopping = false;

        std::shared_mutex m_clientMutex; ///< Shared to issue a query, unique to destroy the client.
        std::unique_ptr<WazuhDBClient> m_client;

        std::atomic<uint64_t> m_queries {0};
        std::atomic<uint64_t> m_coalesced {0};
        std::atomic<uint64_t> m_rejected {0};
    };

} // namespace remoted::control

#endif // _REMOTED_CONTROL_REGISTRY_LOOKUP_HPP
