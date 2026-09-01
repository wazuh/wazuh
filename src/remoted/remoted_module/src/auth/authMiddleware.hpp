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
#include <memory>
#include <string_view>
#include <variant>

#include "authTypes.hpp"
#include "iAgentKeystore.hpp"

namespace remoted::auth
{

    /**
     * @brief Framework-agnostic implementation of the agent<->manager authentication: the
     *        `wazuh-agent+jwt` bearer profile (shared_modules/utils/jwt).
     *
     * Header-only authentication: the transport supplies the protocol-version and Authorization
     * header values and the peer address, and gets back the verified agent identity. The request
     * body plays no part (TLS protects the channel; the token authenticates identity), so there is
     * no per-request session and nothing to stream.
     *
     * Order, fail-closed (steps of the profile's validation procedure):
     *   1. protocol-version present and supported; exactly one `Bearer <token>`.
     *   2. peekKid(): size, compact grammar, exact JOSE header, canonical `kid` -- the candidate
     *      identity, used ONLY to fetch the candidate key.
     *   3. Keystore lookup + client.keys ip column (the address gates authorization, it is not part
     *      of what the agent signs, and it is checked before any HMAC is computed).
     *   4. JwtRequestTokenVerifier::verify(): HS256 signature with that key, exact claims, identity
     *      equality (kid == sub == iss suffix), time policy, canonical jti.
     * The identity handed back is the token's verified `sub`, never the raw header text.
     */
    class AuthMiddleware
    {
    public:
        /**
         * @param config   Auth-protocol tunables (protocol version, time policy, max body size).
         * @param keystore Used to look up an agent's pre-shared key; must outlive this object.
         */
        AuthMiddleware(AuthConfig config, std::shared_ptr<IAgentKeystore> keystore);

        /**
         * @brief Authenticate one request from its headers.
         *
         * @param protocolVersionHeader  Value of the protocol-version header; empty means absent or duplicated.
         * @param authorizationHeader    Value of the Authorization header; empty means absent.
         * @param peerIp                 Textual peer address observed on the socket, matched against the
         *                               agent's client.keys ip column (AuthError::AddressNotAllowed on a
         *                               mismatch). Never part of the token.
         * @param currentUnixTimeSeconds Current time, for the token's time policy. Read once per request
         *                               by the caller so every rule sees the same instant.
         * @return The verified agent, or the AuthError that rejected the request. Never throws for a
         *         malformed or hostile token; a keystore failure may propagate (the gateway's
         *         catch-all answers 500).
         */
        std::variant<VerifiedAgent, AuthError> authenticate(std::string_view protocolVersionHeader,
                                                            std::string_view authorizationHeader,
                                                            std::string_view peerIp,
                                                            std::int64_t currentUnixTimeSeconds) const;

        /// @return The auth-protocol configuration this middleware was constructed with.
        const AuthConfig& config() const
        {
            return m_config;
        }

    private:
        AuthConfig m_config;
        std::shared_ptr<IAgentKeystore> m_keystore;
    };

} // namespace remoted::auth
