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

#ifndef _REMOTED_CONTROL_REGISTRY_AGENT_GROUP_SOURCE_HPP
#define _REMOTED_CONTROL_REGISTRY_AGENT_GROUP_SOURCE_HPP

#include "agentRegistry.hpp"
#include "endpoints/iAgentGroupSource.hpp"
#include "registryLookup.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <string>

namespace remoted::control
{
    /**
     * @brief Answers "which selector may this agent download?" from the in-memory agent registry,
     * falling back to the local wazuh-db when the registry cannot vouch for the agent.
     *
     * A fresh entry (established less than `freshnessSec` ago -- the /control refresh interval) is
     * answered inline, before resolveSelector() returns, with no wazuh-db round trip: exactly the
     * `config_token` /control hands out. A missing, expired or invalidated entry (a node the agent
     * never sent /control to, a remoted restart, a membership a push or a "no row" answer
     * invalidated) is looked up asynchronously through RegistryLookup: a row is the answer (and is
     * cached), no row is NoRow, a failed lookup is Unavailable -- both of those retry, neither
     * authorizes.
     *
     * Lives in control/ (which owns the registry) and is consumed through
     * remoted::endpoints::IAgentGroupSource, so the dependency runs endpoints -> interface <-
     * control and never the other way.
     */
    class RegistryAgentGroupSource : public remoted::endpoints::IAgentGroupSource
    {
    public:
        /// @param lookup May be null: then anything not fresh is Deny (fail closed).
        RegistryAgentGroupSource(std::shared_ptr<const AgentRegistry> registry,
                                 std::shared_ptr<RegistryLookup> lookup,
                                 uint32_t freshnessSec);

        /// @copydoc remoted::endpoints::IAgentGroupSource::resolveSelector
        ///
        /// Deny, inline, when the id is not a well-formed AgentId or no registry is held.
        void resolveSelector(const std::string& agentId,
                             std::function<void(remoted::endpoints::GroupVerdict)> done) const override;

    private:
        std::shared_ptr<const AgentRegistry> m_registry;
        std::shared_ptr<RegistryLookup> m_lookup;
        uint32_t m_freshnessSec;
    };
} // namespace remoted::control

#endif // _REMOTED_CONTROL_REGISTRY_AGENT_GROUP_SOURCE_HPP
