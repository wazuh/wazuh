/*
 * Wazuh remoted module - Agent group source backed by the agent registry
 * Copyright (C) 2015, Wazuh Inc.
 * September 7, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "registryAgentGroupSource.hpp"
#include "controlTypes.hpp"
#include "groupSelector.hpp"

#include <charconv>
#include <ctime>
#include <string_view>
#include <utility>

namespace remoted::control
{
    namespace
    {
        // Non-negative integer, fully consuming the string. Rejects a leading '-'
        // (from_chars<uint32_t> already does) and any trailing garbage. Same policy
        // /control applies to the agent id it parses out of a request.
        bool parseAgentId(std::string_view s, AgentId& out)
        {
            AgentId value = 0;
            const auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), value);
            if (s.empty() || ec != std::errc {} || ptr != s.data() + s.size())
            {
                return false;
            }
            out = value;
            return true;
        }
    } // namespace

    RegistryAgentGroupSource::RegistryAgentGroupSource(std::shared_ptr<const AgentRegistry> registry,
                                                       std::shared_ptr<RegistryLookup> lookup,
                                                       uint32_t freshnessSec)
        : m_registry(std::move(registry))
        , m_lookup(std::move(lookup))
        , m_freshnessSec(freshnessSec)
    {
    }

    void RegistryAgentGroupSource::resolveSelector(const std::string& agentId,
                                                   std::function<void(remoted::endpoints::GroupVerdict)> done) const
    {
        using remoted::endpoints::GroupVerdict;
        using remoted::endpoints::GroupVerdictKind;

        AgentId id = 0;
        if (m_registry == nullptr || !parseAgentId(agentId, id))
        {
            done(GroupVerdict {GroupVerdictKind::Deny, {}});
            return;
        }

        const auto now = static_cast<uint64_t>(std::time(nullptr));

        // An entry is not the same thing as a known membership: /control/shutdown mints one with no
        // groups, an invalidation or a "no row" answer leaves groupsRefreshedAtSec at 0, and an old
        // one may no longer be true. Only a fresh, established entry answers without asking
        // wazuh-db -- and then it is the same two steps /control runs before a notify, from the same
        // entry, so it matches the config_token it handed out. (An agent whose groups really are
        // empty still gets "default": that membership WAS established.)
        if (const auto entry = m_registry->get(id); entry && groupsFresh(*entry, now, m_freshnessSec))
        {
            done(GroupVerdict {GroupVerdictKind::Selector, makeConfigToken(toGroupsCsv(entry->groups))});
            return;
        }

        if (m_lookup == nullptr)
        {
            done(GroupVerdict {GroupVerdictKind::Deny, {}});
            return;
        }

        m_lookup->lookup(
            id,
            now,
            [done = std::move(done)](LookupOutcome outcome)
            {
                switch (outcome.kind)
                {
                    case LookupOutcome::Kind::Groups:
                        done(GroupVerdict {GroupVerdictKind::Selector, makeConfigToken(toGroupsCsv(outcome.groups))});
                        return;
                    case LookupOutcome::Kind::NoRow:
                        // No local row is never membership of "default": the agent retries until
                        // its row reaches this node's database.
                        done(GroupVerdict {GroupVerdictKind::NoRow, {}});
                        return;
                    case LookupOutcome::Kind::Unavailable:
                    default: done(GroupVerdict {GroupVerdictKind::Unavailable, {}}); return;
                }
            });
    }
} // namespace remoted::control
