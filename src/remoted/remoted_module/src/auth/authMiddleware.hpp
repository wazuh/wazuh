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

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <variant>

#include "authTypes.hpp"
#include "cmac.hpp"
#include "iAgentKeystore.hpp"

namespace remoted::auth
{

    /**
     * @brief Framework-agnostic implementation of the agent<->manager auth protocol.
     *
     * Handles canonical request construction, incremental AES-CMAC, the
     * timestamp window and constant-time comparison. A transport supplies
     * the raw method/target/headers and streams body bytes through
     * Session::update().
     */
    class AuthMiddleware
    {
    public:
        /**
         * @param config   Auth-protocol tunables (protocol version, timestamp window, max body size).
         * @param keystore Used to look up an agent's pre-shared key; must outlive this object.
         */
        AuthMiddleware(AuthConfig config, std::shared_ptr<IAgentKeystore> keystore);

        /**
         * @brief Per-request auth state, from a resolved key up to a verified MAC.
         *
         * One instance per in-flight request, returned only once steps 1-5 of
         * the manager-side procedure already succeeded (protocol-version and
         * Authorization parsed, timestamp window checked, agent key resolved,
         * AES-CMAC initialized with the canonical prefix). Not thread-safe;
         * the transport must confine a Session to the connection/strand
         * handling that request.
         */
        class Session
        {
        public:
            Session(Session&&) = default;
            Session& operator=(Session&&) = default;

            /**
             * @brief Step 6: feed one body chunk into the running MAC.
             *
             * Streams each chunk straight into the incremental AES-CMAC; the body
             * is NOT buffered here. Enforces the configured max body size as bytes
             * arrive (via a running counter), independent of any buffering.
             *
             * @param data Pointer to the chunk's bytes.
             * @param len  Number of bytes in this chunk.
             * @return AuthError::None on success, or AuthError::BodyTooLarge
             *         once the cumulative body size exceeds AuthConfig::maxBodySize.
             */
            AuthError update(const std::uint8_t* data, std::size_t len);

            /**
             * @brief Step 7: finalize AES-CMAC and compare it against the
             *        expected MAC parsed during beginSession().
             *
             * Steps 8-9 (parsing the endpoint payload and matching its
             * embedded agent id against agentId() below) are the caller's job
             * once it holds the returned AuthenticatedRequest. Consumes the
             * session; call at most once.
             *
             * @return The AuthenticatedRequest on a MAC match, or AuthError::InvalidMac otherwise.
             */
            std::variant<AuthenticatedRequest, AuthError> finish();

            /// @return The agent id resolved for this session, in canonical form, valid even before
            /// finish(). Not the text the agent signed: see m_signedAgentId.
            const std::string& agentId() const
            {
                return m_agentId;
            }

        private:
            friend class AuthMiddleware;
            Session() = default;

            /// The identity every consumer downstream sees, canonicalized (authTypes.hpp's AgentId is
            /// the numeric truth; client.keys spells it zero-padded to three digits). The wire form is
            /// NOT canonical: the key lookup resolves numerically, so "1", "001" and "0001" all
            /// authenticate as agent 1. Propagating the wire form would make three identities out of
            /// one -- and `POST /stats` uses this value as the id of the agent's document.
            std::string m_agentId;
            /// The agent id exactly as it appeared in the Authorization header. Only the MAC may use
            /// it: the agent signed those bytes, so canonicalizing before hashing would break every
            /// request from an agent that pads differently.
            std::string m_signedAgentId;
            std::string m_protocolVersion;
            std::string m_method;
            std::string m_requestTarget;
            std::array<std::uint8_t, Cmac::kMacSize> m_expectedMac {};
            std::size_t m_maxBodySize = 0;
            std::size_t m_bodySizeSoFar = 0;
            std::unique_ptr<Cmac> m_cmac;
        };

        /**
         * @brief Steps 1-5 of the manager-side procedure: validate the
         *        protocol version and Authorization header, check the
         *        timestamp window, resolve the agent key and initialize the
         *        running AES-CMAC with the canonical prefix.
         *
         * @param protocolVersionHeader  Value of the protocol-version header; empty means absent or duplicated.
         * @param authorizationHeader    Value of the Authorization header; empty means absent.
         * @param method                 Raw HTTP method, as received (case-insensitive; uppercased internally).
         * @param requestTarget          Raw path + query, exactly as received from the HTTP parser.
         * @param currentUnixTimeSeconds Current time, for the timestamp-window check.
         * @return A Session ready for body bytes, or the AuthError that rejected the request.
         */
        std::variant<Session, AuthError> beginSession(std::string_view protocolVersionHeader,
                                                      std::string_view authorizationHeader,
                                                      std::string_view method,
                                                      std::string_view requestTarget,
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
