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
#include <string>
#include <vector>

namespace wazuh_auth
{

    /**
     * @brief Identity + payload an endpoint handler receives once the MAC has
     *        been verified.
     *
     * This struct is the contract between the transport (Beast, RESTinio,
     * whatever comes next) and endpoint-specific code, so it must never carry
     * a library-specific type.
     */
    struct AuthenticatedRequest
    {
        std::string agentId;            ///< Agent id parsed from the Authorization header.
        std::string protocolVersion;    ///< Value of the protocol-version header.
        std::string method;             ///< Uppercase HTTP method, e.g. "POST".
        std::string requestTarget;      ///< Raw path + query, exactly as received.
        std::vector<std::uint8_t> body; ///< Raw request body, exactly as received.
    };

    /**
     * @brief Internal auth failure reason, safe to log.
     *
     * The public HTTP status/message must never distinguish between the
     * credential-related reasons -- those all collapse to a single generic 401
     * (see publicErrorFor()). Protocol-version and payload-agent-mismatch are
     * called out as their own 400s, so they keep distinct public messages.
     */
    enum class AuthError
    {
        None = 0,
        MissingProtocolVersion,
        UnsupportedProtocolVersion,
        MissingAuthorization,
        MalformedAuthorization,
        UnknownAgent,
        MissingKey,
        ExpiredRequest,
        FutureRequest,
        InvalidMac,
        PayloadAgentMismatch,
        BodyTooLarge,
    };

    /**
     * @brief Render an AuthError as a lowercase_snake_case tag, for logging.
     *
     * @param err Error to render.
     * @return Static string; never null.
     */
    const char* toString(AuthError err);

    /**
     * @brief Client-visible HTTP status + message for a rejected request.
     */
    struct PublicError
    {
        int status;          ///< HTTP status code to send back to the client.
        const char* message; ///< Static, human-readable message; never null.
    };

    /**
     * @brief Single source of truth for the client-visible status/message.
     *
     * Shared by every transport so a Beast server and a RESTinio server answer
     * identically instead of each re-deriving the error-response mapping.
     *
     * @param err Internal failure reason returned by AuthMiddleware.
     * @return The status/message pair the transport must send to the client.
     */
    PublicError publicErrorFor(AuthError err);

    /**
     * @brief Auth-protocol tunables shared by every transport.
     *
     * A Beast implementation and a RESTinio implementation must configure the
     * exact same knobs the same way.
     */
    struct AuthConfig
    {
        std::string supportedProtocolVersion = "1"; ///< Expected value of the protocol-version header.
        std::int64_t maxRequestAgeSeconds = 300;    ///< How far in the past a request timestamp may be.
        std::int64_t maxFutureSkewSeconds = 30;     ///< How far in the future a request timestamp may be.
        std::size_t maxBodySize = 10 * 1024 * 1024; ///< Hard cap on the authenticated body size (10 MiB).
    };

} // namespace wazuh_auth
