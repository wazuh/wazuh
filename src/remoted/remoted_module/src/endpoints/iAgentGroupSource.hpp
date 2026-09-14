/*
 * Wazuh remoted module - Agent group source interface
 * Copyright (C) 2015, Wazuh Inc.
 * September 7, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_ENDPOINTS_I_AGENT_GROUP_SOURCE_HPP
#define _REMOTED_ENDPOINTS_I_AGENT_GROUP_SOURCE_HPP

#include <optional>
#include <string>

namespace remoted::endpoints
{
    /**
     * @brief Tells an endpoint which shared-configuration resource an authenticated agent may ask
     *        for.
     *
     * The answer is the selector /control already handed that agent as `config_token`, so an
     * endpoint can authorize a download by string comparison instead of repeating the group
     * lookup. Kept as an interface (rather than a direct dependency on the agent registry) so the
     * endpoint layer never sees where the groups are cached, and so its tests need no control-plane
     * collaborator.
     */
    class IAgentGroupSource
    {
    public:
        virtual ~IAgentGroupSource() = default;

        /**
         * @brief The selector this agent is entitled to download.
         *
         * @param agentId Verified agent id, exactly as it reaches a handler on
         *                remoted::auth::AuthenticatedRequest (canonical, never the raw header).
         *
         * @return The agent's own selector (e.g. "default", "web,db"), or std::nullopt when the
         *         source cannot vouch for the agent -- it is unknown to the cache, or the id is not
         *         a well-formed agent id.
         *
         * @note std::nullopt means DENY, never "allow by default": an agent that never completed
         *       /control/startup, or whose entry has been evicted, has no established group
         *       membership, and the manager has nothing to authorize it against. Do not "fix" a
         *       caller that refuses on std::nullopt into falling through to the request's own
         *       claim -- that is precisely the defect this interface exists to close.
         */
        virtual std::optional<std::string> expectedSelectorFor(const std::string& agentId) const = 0;
    };
} // namespace remoted::endpoints

#endif // _REMOTED_ENDPOINTS_I_AGENT_GROUP_SOURCE_HPP
