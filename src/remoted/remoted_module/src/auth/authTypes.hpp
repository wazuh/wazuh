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

#include "remoted_module.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

namespace remoted::auth
{

    /// @brief Canonical numeric form of an agent id -- an agent id is always numeric by design
    /// (assigned sequentially by authd), even though it travels as text on the wire (Authorization
    /// header, client.keys, the /stateless payload's wazuh.agent.id).
    using AgentId = std::uint32_t;

    /**
     * @brief Zero-copy view of the verified request body, with explicit release.
     *
     * The bytes are NOT owned here: they live in a single transport-owned buffer
     * that this holder keeps alive via an opaque keep-alive (a shared_ptr to the
     * transport's request context, which also carries the in-flight byte
     * reservation). So there is exactly one physical copy of the payload.
     *
     * Lifetime contract: bytes() is valid until the payload is released -- either
     * by destroying the owning AuthenticatedRequest (RAII) or by calling release()
     * explicitly (e.g. once the handler has forwarded the body downstream and only
     * needs the responder afterwards). Releasing drops the keep-alive, freeing the
     * buffer and restoring the byte budget. Confine a payload to one thread.
     */
    class Payload
    {
    public:
        Payload() = default;

        Payload(std::string_view view, std::shared_ptr<const void> keepAlive)
            : m_keepAlive {std::move(keepAlive)}
            , m_view {view}
        {
        }

        /// @return The body bytes, or an empty view once released.
        std::string_view bytes() const noexcept
        {
            return m_keepAlive ? m_view : std::string_view {};
        }

        std::size_t size() const noexcept
        {
            return bytes().size();
        }

        bool empty() const noexcept
        {
            return bytes().empty();
        }

        /**
         * @brief Release the underlying buffer and the in-flight byte reservation now.
         *
         * Idempotent. After this, bytes() is empty. Const because it manages the
         * payload's lifetime, not the (const) identity of the request that owns it.
         */
        void release() const noexcept
        {
            m_keepAlive.reset();
            m_view = {};
        }

    private:
        mutable std::shared_ptr<const void> m_keepAlive; ///< Pins the transport buffer + byte reservation.
        mutable std::string_view m_view;                 ///< View into that buffer; empty once released.
    };

    /**
     * @brief Identity + payload an endpoint handler receives once the MAC has
     *        been verified.
     *
     * This struct is the contract between the transport and endpoint-specific
     * code, so it must never carry a transport-specific type. The small identity
     * fields are owned (they outlive an early payload release); the body is a
     * zero-copy Payload view (see above).
     */
    struct AuthenticatedRequest
    {
        std::string agentId;         ///< Agent id parsed from the Authorization header.
        std::string protocolVersion; ///< Value of the protocol-version header.
        std::string method;          ///< Uppercase HTTP method, e.g. "POST".
        std::string requestTarget;   ///< Raw path + query, exactly as received.
        Payload payload;             ///< Verified request body (a view into the single transport buffer).
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
        PayloadAgentMismatch, ///< Raised by POST /stateless's pre-forward check (statelessEndpoint.cpp):
                              ///< the H-line JSON is missing/malformed, or wazuh.agent.id is
                              ///< missing/not-a-string/not-numeric, or doesn't match the authenticated
                              ///< agent id.
        BodyTooLarge,
        UnsupportedContentEncoding, ///< Content-Encoding present but not (case-insensitively) "zstd".
        MalformedContentEncoding,   ///< Content-Encoding: zstd, but the body isn't a valid/complete
                                    ///< zstd frame (bad magic, truncated, oversized window, ...).
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
     * Shared by every transport so they all answer identically instead of
     * each re-deriving the error-response mapping.
     *
     * @param err Internal failure reason returned by AuthMiddleware.
     * @return The status/message pair the transport must send to the client.
     */
    PublicError publicErrorFor(AuthError err);

    /**
     * @brief Auth-protocol tunables shared by every transport.
     *
     * Every transport implementation must configure the exact same knobs the
     * same way.
     */
    struct AuthConfig
    {
        std::string supportedProtocolVersion = "1"; ///< Expected value of the protocol-version header.
        std::int64_t maxRequestAgeSeconds = 300;    ///< How far in the past a request timestamp may be.
        std::int64_t maxFutureSkewSeconds = 30;     ///< How far in the future a request timestamp may be.
        std::size_t maxBodySize = 10 * 1024 * 1024; ///< Hard cap on the authenticated body size (10 MiB).
    };

    /**
     * @brief Translate the module's C-ABI config into an AuthConfig.
     *
     * Every field resolves as **caller value (C-ABI struct) -> built-in default**, same pattern as
     * remoted::http::buildHttpServerConfig(). `supportedProtocolVersion` is not C-ABI driven --
     * it's a protocol constant, not an ops tuning knob.
     *
     * @param config Configuration handed by remoted.
     * @return Resolved AuthConfig.
     */
    AuthConfig buildAuthConfig(const remoted_module_config_t& config);

} // namespace remoted::auth
