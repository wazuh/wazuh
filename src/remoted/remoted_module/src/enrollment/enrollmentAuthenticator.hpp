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

#include "auth/authTypes.hpp" // remoted::auth::AuthError, kSupportedProtocolVersion
#include "auth/passwordKeySource.hpp"
#include "jwt/jwtProfileV1.hpp"

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
        /// Whether the `wazuh-enroll+jwt` bearer is required, mirroring authd's own <use_password>.
        /// Deliberately independent of whatever client-certificate requirement the TLS listener
        /// separately enforces (HttpServerConfig::verificationMode) -- legacy authd already treats
        /// its own <ssl_verify_host> (cert) and <use_password> checks as two independent gates on
        /// the same connection (main-server.c: check_x509_cert() at the TLS handshake, the `PASS:`
        /// line separately while parsing the enrollment message), so an operator who configures
        /// both today already gets both enforced. Modeling this as a single mutually-exclusive
        /// "mode" (mTLS XOR Password) would have silently dropped the password check whenever a
        /// client certificate was also required -- this flag exists so that can't happen.
        bool requirePassword {false};

        /// Accepted token age / clock skew of the bearer: the same `remoted.jwt_max_age` /
        /// `remoted.jwt_clock_skew` policy the agent<->manager profile uses (enrollmentConfig.hpp).
        jwt_profile::v1::TimePolicy timePolicy {};

        /// Same `auth_max_body_size` internal option (and the same 10 MiB default) the
        /// agent<->manager AuthConfig enforces (authTypes.cpp) -- checked BEFORE the credential, in
        /// BOTH Open and Password mode, so an unauthenticated peer can't hold an arbitrarily large
        /// body (up to the transport's own cap) in the in-flight budget, and so an oversized body
        /// gets the same 413 every other endpoint returns instead of falling through to
        /// parseAndValidateBody()'s 400.
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
     * enrolling agent has no client.keys entry yet, so the agent<->manager `wazuh-agent+jwt`
     * bearer (keyed by an agent id) structurally cannot apply here. When requirePassword is set,
     * this class requires the sibling profile `wazuh-enroll+jwt` (jwt/jwtEnrollProfileV1.hpp): the
     * same HS256 core, keyed by the HKDF of authd's enrollment password (PasswordKeySource), with
     * no `kid`/`sub`/`iss` since there is no identity to name yet. Failures collapse through the
     * same remoted::auth::AuthError taxonomy -- and the same publicErrorFor()/errorResponseFor()
     * uniform 401 -- as every other endpoint.
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
         * @param config    requirePassword + time policy + body cap.
         * @param keySource Enrollment key; ignored (may be null) when requirePassword is false.
         */
        EnrollmentAuthenticator(EnrollmentAuthConfig config,
                                std::shared_ptr<remoted::auth::PasswordKeySource> keySource);

        /**
         * @brief Authenticate one /enroll request.
         *
         * @param protocolVersionHeader  Value of the protocol-version header (empty if absent or
         *                               duplicated -- the transport collapses both). Validated
         *                               FIRST, in every mode including Open, exactly as
         *                               AuthMiddleware::authenticate() does for every other route.
         * @param authorizationHeader    Value of the Authorization header (empty if absent or
         *                               duplicated). Must be `Bearer <wazuh-enroll+jwt>` when
         *                               requirePassword is set; ignored otherwise.
         * @param bodySize               Size of the raw request body, checked against maxBodySize
         *                               once the version is accepted, in every mode. The bearer does
         *                               not cover the body (TLS protects it), so the bytes themselves
         *                               are never needed here.
         * @param currentUnixTimeSeconds Current time, for the token's time rules.
         * @return std::nullopt on success, or the AuthError that rejected the request.
         */
        std::optional<remoted::auth::AuthError> authenticate(std::string_view protocolVersionHeader,
                                                             std::string_view authorizationHeader,
                                                             std::size_t bodySize,
                                                             std::int64_t currentUnixTimeSeconds) const;

    private:
        std::optional<remoted::auth::AuthError> authenticatePassword(std::string_view authorizationHeader,
                                                                     std::int64_t currentUnixTimeSeconds) const;

        EnrollmentAuthConfig m_config;
        std::shared_ptr<remoted::auth::PasswordKeySource> m_keySource;
    };

} // namespace remoted::enrollment
