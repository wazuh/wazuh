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

#include "registryLookup.hpp"
#include "wazuhDBClient.hpp"

#include <optional>
#include <thread>
#include <utility>

namespace remoted::control
{
    namespace
    {
        void answerAll(std::vector<RegistryLookup::Waiter>& waiters, const LookupOutcome& outcome)
        {
            for (auto& waiter : waiters)
            {
                waiter(outcome);
            }
        }
    } // namespace

    RegistryLookup::RegistryLookup(std::shared_ptr<AgentRegistry> registry,
                                   const Config& config,
                                   ControlMetrics& metrics,
                                   LookupLimits limits)
        : m_registry(std::move(registry))
        , m_limits(limits)
        , m_client(std::make_unique<WazuhDBClient>(config.wdbSocketPath,
                                                   kLookupConnections,
                                                   config.wdbRoundtripDeadlineMs,
                                                   limits.maxWaiters,
                                                   metrics,
                                                   config.wdbRequestDeadlineMs))
    {
    }

    RegistryLookup::~RegistryLookup()
    {
        stop();
    }

    void RegistryLookup::lookup(AgentId id, uint64_t issueSec, Waiter done)
    {
        {
            std::unique_lock lock(m_mutex);
            auto it = m_pending.find(id);
            const bool overAgent = it != m_pending.end() && it->second.waiters.size() >= m_limits.maxWaitersPerAgent;
            if (m_stopping || overAgent || m_totalWaiters >= m_limits.maxWaiters)
            {
                lock.unlock();
                ++m_rejected;
                done(LookupOutcome {LookupOutcome::Kind::Unavailable, {}});
                return;
            }
            ++m_totalWaiters;
            if (it != m_pending.end())
            {
                it->second.waiters.push_back(std::move(done));
                ++m_coalesced;
                return;
            }
            // Taken before the query is issued: an answer read before a newer write to this
            // agent's membership (a push) must not overwrite it.
            Pending pending;
            pending.ticket = m_registry->groupsTicket();
            pending.issueSec = issueSec;
            pending.waiters.push_back(std::move(done));
            m_pending.emplace(id, std::move(pending));
        }

        // The client may call back inline, on this thread, from inside getAgentGroups()
        // (QueueFull). That completion must not run while the client lock is held -- a waiter may
        // call lookup() again -- so it is parked and run once the lock is released. "Inline" is
        // this thread while still issuing: a later callback may also land on this thread when it
        // is a client worker running a re-entrant waiter, and that one completes normally.
        struct Issue
        {
            const std::thread::id thread = std::this_thread::get_id();
            std::atomic<bool> issuing {true};
            std::optional<std::pair<SocketError, AgentGroupsResult>> inlineResult;
        };
        auto state = std::make_shared<Issue>();
        {
            std::shared_lock clientLock(m_clientMutex);
            if (m_client)
            {
                ++m_queries;
                m_client->getAgentGroups(id,
                                         [this, id, state](SocketError err, AgentGroupsResult result)
                                         {
                                             if (std::this_thread::get_id() == state->thread && state->issuing.load())
                                             {
                                                 state->inlineResult.emplace(err, std::move(result));
                                                 return;
                                             }
                                             complete(id, err, std::move(result));
                                         });
            }
            else
            {
                state->inlineResult.emplace(SocketError::Stopping, AgentGroupsResult {});
            }
            state->issuing = false;
        }
        if (state->inlineResult)
        {
            complete(id, state->inlineResult->first, std::move(state->inlineResult->second));
        }
    }

    void RegistryLookup::complete(AgentId id, SocketError err, AgentGroupsResult result)
    {
        Pending pending;
        {
            std::lock_guard lock(m_mutex);
            auto it = m_pending.find(id);
            if (it == m_pending.end())
            {
                return; // Exactly-once by the client; nothing else takes a Pending out.
            }
            pending = std::move(it->second);
            m_pending.erase(it);
            m_totalWaiters -= static_cast<uint32_t>(pending.waiters.size());
        }

        LookupOutcome outcome;
        if (err != SocketError::None)
        {
            outcome.kind = LookupOutcome::Kind::Unavailable;
        }
        else if (result.noRow)
        {
            // Never a membership, and never cached (S7, S15): the next request looks it up again.
            outcome.kind = LookupOutcome::Kind::NoRow;
        }
        else
        {
            outcome = store(id, pending, std::move(result.groups));
        }
        answerAll(pending.waiters, outcome);
    }

    LookupOutcome RegistryLookup::store(AgentId id, const Pending& pending, std::vector<std::string> groups)
    {
        LookupOutcome outcome {LookupOutcome::Kind::Groups, groups};
        m_registry->update(id,
                           [&](std::shared_ptr<const AgentEntry> old) -> std::shared_ptr<AgentEntry>
                           {
                               if (old && old->groupsSeq > pending.ticket)
                               {
                                   // A newer write landed while the query was in flight. An
                                   // established one (a push) is the fresher answer; an
                                   // invalidation leaves this read as the best one available.
                                   if (old->groupsRefreshedAtSec != 0)
                                   {
                                       outcome.groups = old->groups;
                                   }
                                   return nullptr;
                               }
                               if (!m_registry->mayStoreLookup(old, pending.ticket))
                               {
                                   return nullptr; // Answered, not cached.
                               }
                               auto e = old ? std::make_shared<AgentEntry>(*old) : std::make_shared<AgentEntry>();
                               e->groups = std::move(groups);
                               e->groupsRefreshedAtSec = pending.issueSec;
                               e->groupsSeq = m_registry->nextGroupsSeq();
                               if (e->createdAtSec == 0)
                               {
                                   e->createdAtSec = pending.issueSec;
                               }
                               return e;
                           });
        return outcome;
    }

    void RegistryLookup::stop()
    {
        {
            std::lock_guard lock(m_mutex);
            m_stopping = true;
        }
        // Destroying the client joins its workers (an in-flight query completes or times out) and
        // fails whatever is still queued with Stopping: every Pending is answered through
        // complete() before this returns.
        std::unique_ptr<WazuhDBClient> client;
        {
            std::unique_lock clientLock(m_clientMutex);
            client = std::move(m_client);
        }
        client.reset();
    }

    RegistryLookup::Stats RegistryLookup::stats() const
    {
        return Stats {m_queries.load(), m_coalesced.load(), m_rejected.load()};
    }

} // namespace remoted::control
