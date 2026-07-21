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

namespace wazuh_auth
{

    /**
     * @brief Resolves an agent id to its pre-shared AES key.
     *
     * Kept as its own interface so a client.keys-backed resolver can later be
     * swapped for whatever the manager actually uses (agent registry,
     * database, cache) without touching AuthMiddleware or any transport
     * implementation.
     */
    class IAgentKeyResolver
    {
    public:
        virtual ~IAgentKeyResolver() = default;

        /**
         * @brief Look up an agent's key.
         *
         * @param agentId Agent id parsed from the request's Authorization header.
         * @return std::nullopt for an unknown agent. Otherwise the agent's
         *         pre-shared AES key (16, 24 or 32 bytes); empty if the agent
         *         is known but its on-disk key could not be used as-is.
         */
        virtual std::optional<std::vector<std::uint8_t>> resolve(const std::string& agentId) const = 0;
    };

} // namespace wazuh_auth
