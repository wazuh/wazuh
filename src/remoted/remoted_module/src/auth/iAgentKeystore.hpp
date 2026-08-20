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
#include <string>
#include <vector>

#include "authTypes.hpp" // remoted::auth::AgentId

namespace remoted::auth
{

    /**
     * @brief Relates agent ids to their pre-shared AES key.
     */
    class IAgentKeystore
    {
    public:
        virtual ~IAgentKeystore() = default;

        /**
         * @brief Look up an agent's key.
         *
         * @param agentId Agent id parsed from the request's Authorization header (numeric --
         *                a non-numeric agent-id token never reaches this call, see AuthMiddleware).
         * @return std::nullopt for an unknown agent. Otherwise the agent's
         *         pre-shared AES key (16, 24 or 32 bytes); empty if the agent
         *         is known but its on-disk key could not be used as-is.
         */
        virtual std::optional<std::vector<std::uint8_t>> keyFor(AgentId agentId) const = 0;

        /**
         * @brief The agent's `client.keys` source-address column; nullopt if absent (unrestricted).
         *
         * Pure virtual like keyFor(): a security control must not inherit a silent "unrestricted" default.
         */
        virtual std::optional<std::string> allowedAddressFor(AgentId agentId) const = 0;
    };

} // namespace remoted::auth
