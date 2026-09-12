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

    RegistryAgentGroupSource::RegistryAgentGroupSource(std::shared_ptr<const AgentRegistry> registry)
        : m_registry(std::move(registry))
    {
    }

    std::optional<std::string> RegistryAgentGroupSource::expectedSelectorFor(const std::string& agentId) const
    {
        if (m_registry == nullptr)
        {
            return std::nullopt;
        }

        AgentId id = 0;
        if (!parseAgentId(agentId, id))
        {
            return std::nullopt;
        }

        const auto entry = m_registry->get(id);
        if (entry == nullptr)
        {
            return std::nullopt;
        }

        // An entry is not the same thing as a known membership. /control/shutdown creates one with
        // no groups at all when it has never seen the agent (controlHandler.cpp handleShutdown),
        // and groupsRefreshedAtSec is written ONLY by the two wazuh-db-backed paths -- startup and
        // the notify refresh. Without this guard an agent could mint itself an empty entry with a
        // shutdown and then be handed the "default" selector by makeConfigToken(""), which is
        // exactly the fail-open this check exists to prevent. Note the distinction: an agent whose
        // wdb groups really are empty still gets "default", because that refresh DID happen.
        if (entry->groupsRefreshedAtSec == 0)
        {
            return std::nullopt;
        }

        // Same two steps /control runs before answering a notify, in the same order, from the same
        // entry: whatever it handed the agent as config_token is what this reproduces.
        return makeConfigToken(toGroupsCsv(entry->groups));
    }
} // namespace remoted::control
