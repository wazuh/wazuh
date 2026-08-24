/*
 * Wazuh remoted module - agent enrollment authenticator
 * Copyright (C) 2015, Wazuh Inc.
 * August 19, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include "auth/authTypes.hpp" // remoted::auth::AuthError
#include "auth/passwordKeySource.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace remoted::enrollment
{

    struct EnrollmentAuthConfig
    {
        /// Whether the WazuhEnroll CMAC header is required, mirroring authd's own <use_password>.
        /// Deliberately independent of whatever client-certificate requirement the TLS listener
        /// separately enforces (HttpServerConfig::verificationMode) -- legacy authd already treats
        /// its own <ssl_verify_host> (cert) and <use_password> checks as two independent gates on
        /// the same connection (main-server.c: check_x509_cert() at the TLS handshake, the `PASS:`
        /// line separately while parsing the enrollment message), so an operator who configures
        /// both today already gets both enforced. Modeling this as a single mutually-exclusive
        /// "mode" (mTLS XOR Password) would have silently dropped the password check whenever a
        /// client certificate was also required -- this flag exists so that can't happen.
        bool requirePassword {false};
        std::int64_t maxRequestAgeSeconds {300};
        std::int64_t maxFutureSkewSeconds {30};

        /// Same `auth_max_body_size` internal option (and the same 10 MiB default) the
        /// agent<->manager AES-CMAC scheme's AuthConfig enforces (authTypes.cpp) -- checked BEFORE
        /// the CMAC runs, in BOTH Open and Password mode, so an unauthenticated peer can't make
        /// this endpoint hash an arbitrarily large body (up to the transport's own cap) and hold
        /// that many in-flight bytes reserved, and so an oversized body gets the same 413 every
        /// other endpoint returns instead of falling through to parseAndValidateBody()'s 400.
        std::size_t maxBodySize {10U * 1024U * 1024U};

        /// The accepted `protocol-version` header value, shared with the agent<->manager scheme via
        /// remoted::auth::kSupportedProtocolVersion so the two can never accept different versions.
        /// Validated in EVERY mode (including Open), for the reasons in authenticate()'s comment.
        std::string supportedProtocolVersion {remoted::auth::kSupportedProtocolVersion};
    };

    /**
     * @brief Authenticates POST /enroll requests.
     *
     * /enroll is registered directly on IHttpServer, bypassing AuthGateway/AuthMiddleware: an
     * enrolling agent has no client.keys entry yet, so the agent<->manager AES-CMAC protocol
     * (keyed by an agent id) structurally cannot apply here. When requirePassword is set, this
     * class runs a deliberately similar but distinct scheme -- same Cmac primitive, same
     * freshness-window check, same remoted::auth::AuthError taxonomy (so it collapses through the
     * same publicErrorFor()/errorResponseFor() as every other endpoint) -- but with no agent-id
     * field, since the agent doesn't have one yet.
     *
     * A client-certificate requirement is NOT this class's concern at all: the TLS listener
     * enforces it (or doesn't) entirely on its own, before any handler -- including this one --
     * ever runs. That's why requirePassword=false passes unconditionally regardless of whether
     * the listener also requires mTLS: from here, "mTLS-only" and "Open" are indistinguishable,
     * and correctly so.
     */
    class EnrollmentAuthenticator
    {
    public:
        /**
         * @param config    requirePassword + freshness window (same defaults as the agent<->manager
         *                  scheme: 300s max age, 30s max future skew).
         * @param keySource Password signing key; ignored (may be null) when requirePassword is false.
         */
        EnrollmentAuthenticator(EnrollmentAuthConfig config,
                                std::shared_ptr<remoted::auth::PasswordKeySource> keySource);

        /**
         * @brief Authenticate one /enroll request.
         *
         * @param protocolVersionHeader  Value of the protocol-version header (empty if absent or
         *                               duplicated -- the transport collapses both). Validated
         *                               FIRST, in every mode including Open, exactly as
         *                               AuthMiddleware::beginSession() does for every other route.
         * @param authorizationHeader    Value of the Authorization header (empty if absent).
         *                               Ignored when requirePassword is false.
         * @param method                 Raw HTTP method, as received (case-insensitive).
         * @param requestTarget          Raw path + query, exactly as received.
         * @param body                   Raw request body bytes, exactly as sent on the wire.
         *                               Checked against maxBodySize once the version is accepted,
         *                               in every mode -- see the field's own doc comment.
         * @param currentUnixTimeSeconds Current time, for the timestamp-window check.
         * @return std::nullopt on success, or the AuthError that rejected the request.
         */
        std::optional<remoted::auth::AuthError> authenticate(std::string_view protocolVersionHeader,
                                                             std::string_view authorizationHeader,
                                                             std::string_view method,
                                                             std::string_view requestTarget,
                                                             std::string_view body,
                                                             std::int64_t currentUnixTimeSeconds) const;

    private:
        std::optional<remoted::auth::AuthError> authenticatePassword(std::string_view protocolVersionHeader,
                                                                     std::string_view authorizationHeader,
                                                                     std::string_view method,
                                                                     std::string_view requestTarget,
                                                                     std::string_view body,
                                                                     std::int64_t currentUnixTimeSeconds) const;

        EnrollmentAuthConfig m_config;
        std::shared_ptr<remoted::auth::PasswordKeySource> m_keySource;
    };

} // namespace remoted::enrollment
