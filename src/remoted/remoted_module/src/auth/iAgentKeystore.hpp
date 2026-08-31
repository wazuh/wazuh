/*
 * Wazuh auth middleware (framework-agnostic)
 * Copyright (C) 2015, Wazuh Inc.
 * July 20, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

#include "authTypes.hpp" // remoted::auth::AgentId

namespace remoted::auth
{

    /**
     * @brief Everything one client.keys entry contributes to authenticating a request.
     */
    struct AgentLookup
    {
        /// The agent's HS256 key: exactly the 32 bytes the 64-hex client.keys secret decodes to.
        /// Empty when the entry exists but its on-disk key column is not that (wrong length, not
        /// lowercase hex), which is what lets a caller answer the more precise "unusable key"
        /// instead of "unknown agent".
        std::vector<std::uint8_t> key;

        /// Whether the peer address passed to lookup() satisfies the entry's `ip` column.
        bool addressAllowed {false};
    };

    /**
     * @brief Relates agent ids to their pre-shared key and to the addresses they may connect from.
     */
    class IAgentKeystore
    {
    public:
        virtual ~IAgentKeystore() = default;

        /**
         * @brief Resolve an agent's key and evaluate its address restriction in one step.
         *
         * The `ip` column is enforced here, the same restriction the legacy remoted applies via
         * OS_IsAllowedDynamicID(): an agent registered with a fixed address (or a range) may only
         * reach the manager from it, while `any` accepts every peer.
         *
         * Both answers come from a single pass over the implementation's table, under whatever lock it
         * holds, so a concurrent reload cannot leave a caller pairing one entry's key with another
         * entry's address. Only values are returned -- no reference into the table escapes.
         *
         * @param agentId Agent id parsed from the request's Authorization header (numeric --
         *                a non-numeric agent-id token never reaches this call, see AuthMiddleware).
         * @param peerIp  Textual peer address as observed on the socket.
         * @return std::nullopt for an unknown agent, which grants nothing. Otherwise the entry's key
         *         and whether @p peerIp satisfies its address restriction.
         */
        virtual std::optional<AgentLookup> lookup(AgentId agentId, std::string_view peerIp) const = 0;
    };

} // namespace remoted::auth
