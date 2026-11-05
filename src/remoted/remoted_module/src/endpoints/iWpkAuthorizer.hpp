/*
 * Wazuh remoted module - WPK download authorizer interface
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_ENDPOINTS_I_WPK_AUTHORIZER_HPP
#define _REMOTED_ENDPOINTS_I_WPK_AUTHORIZER_HPP

#include <functional>
#include <string>

namespace remoted::endpoints
{
    /// The answer to "may this agent download this WPK now".
    enum class WpkAuthorization
    {
        Granted,    ///< The agent has an open upgrade task for exactly this file.
        Denied,     ///< It has none. Answered like a missing file, so existence is not revealed.
        Unavailable ///< No answer could be obtained. Never served: a 503, which a 5.0.0 agent tries
                    ///< agent.https_download_attempts times in total before abandoning the upgrade.
    };

    /**
     * @brief Decides whether an authenticated agent may download a WPK.
     *
     * A WPK's authority is the agent's own open upgrade task, which lives in the task manager, so
     * the answer is asynchronous. Kept as an interface so the endpoint never sees the transport
     * and its tests need no socket.
     */
    class IWpkAuthorizer
    {
    public:
        virtual ~IWpkAuthorizer() = default;

        /**
         * @brief Ask for one decision.
         *
         * @param agentId Verified agent id, exactly as it reaches a handler on
         *                remoted::auth::AuthenticatedRequest (canonical, "001").
         * @param wpkFile The requested file name, already accepted by the WPK grammar.
         * @param done    Called once with the decision, on any thread, possibly before authorize()
         *                returns. Once the implementation is stopped a pending request may be dropped
         *                without a call, so stop it only when nothing can still be waiting on one.
         */
        virtual void authorize(const std::string& agentId,
                               const std::string& wpkFile,
                               std::function<void(WpkAuthorization)> done) const = 0;
    };
} // namespace remoted::endpoints

#endif // _REMOTED_ENDPOINTS_I_WPK_AUTHORIZER_HPP
