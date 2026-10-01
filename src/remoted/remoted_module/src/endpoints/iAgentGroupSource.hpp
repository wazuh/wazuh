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

#include <functional>
#include <string>

namespace remoted::endpoints
{
    /// What a group source could establish about the agent a request came from.
    enum class GroupVerdictKind
    {
        Selector,   ///< The agent's own selector (e.g. "default", "web,db") is in `selector`.
        Deny,       ///< The source cannot vouch for the agent (no local row, malformed id, no source).
        Unavailable ///< The membership could not be established now (its store did not answer).
    };

    struct GroupVerdict
    {
        GroupVerdictKind kind {GroupVerdictKind::Deny};
        std::string selector;
    };

    /**
     * @brief Tells an endpoint which shared-configuration resource an authenticated agent may ask
     *        for.
     *
     * The answer is the selector /control hands that agent as `config_token`, so an endpoint can
     * authorize a download by string comparison. Kept as an interface (rather than a direct
     * dependency on the agent registry) so the endpoint layer never sees where the groups come
     * from, and so its tests need no control-plane collaborator.
     */
    class IAgentGroupSource
    {
    public:
        virtual ~IAgentGroupSource() = default;

        /**
         * @brief Resolves the selector this agent is entitled to download.
         *
         * @param agentId Verified agent id, exactly as it reaches a handler on
         *                remoted::auth::AuthenticatedRequest (canonical, never the raw header).
         * @param done    Called exactly once with the verdict -- inline, before this returns, when
         *                the answer is at hand, or later from another thread. The caller must not
         *                hold anything `done` needs beyond what it captures.
         *
         * @note Deny means DENY, never "allow by default": an agent whose membership the source
         *       cannot establish has nothing to authorize it against. Do not "fix" a caller that
         *       refuses on Deny into falling through to the request's own claim -- that is
         *       precisely the defect this interface exists to close. Unavailable is not a Deny
         *       either: it says "retry", and it never authorizes.
         */
        virtual void resolveSelector(const std::string& agentId, std::function<void(GroupVerdict)> done) const = 0;
    };
} // namespace remoted::endpoints

#endif // _REMOTED_ENDPOINTS_I_AGENT_GROUP_SOURCE_HPP
