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

#include <memory>
#include <optional>
#include <string>

namespace remoted::control
{
    /**
     * @brief Answers "which selector may this agent download?" from the in-memory agent registry.
     *
     * The registry is the same cache /control fills on startup and refreshes on notify, so the
     * answer is exactly the `config_token` that agent was last handed -- no wazuh-db round trip on
     * the download path, which is the property that let the group lookup be dropped there in the
     * first place. The cost is one sharded shared-lock read plus a shared_ptr copy.
     *
     * Lives in control/ (which owns the registry) and is consumed through
     * remoted::endpoints::IAgentGroupSource, so the dependency runs endpoints -> interface <-
     * control and never the other way.
     */
    class RegistryAgentGroupSource : public remoted::endpoints::IAgentGroupSource
    {
    public:
        explicit RegistryAgentGroupSource(std::shared_ptr<const AgentRegistry> registry);

        /// @copydoc remoted::endpoints::IAgentGroupSource::expectedSelectorFor
        ///
        /// Returns std::nullopt -- deny -- when the id is not a well-formed AgentId, when no
        /// registry is held, or when the agent has no entry (never completed /control/startup, or
        /// evicted after its inactivity TTL).
        std::optional<std::string> expectedSelectorFor(const std::string& agentId) const override;

    private:
        std::shared_ptr<const AgentRegistry> m_registry;
    };
} // namespace remoted::control

#endif // _REMOTED_CONTROL_REGISTRY_AGENT_GROUP_SOURCE_HPP
