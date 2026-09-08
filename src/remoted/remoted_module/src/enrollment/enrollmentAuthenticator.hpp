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
#include "auth/tokenKeySource.hpp"
#include "jwt/jwtProfileV1.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <variant>

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
        ///
        /// An enrollment-token bearer (a `kid` naming a token id, issue #38993) is verified whether
        /// or not this is set: a credential the agent presents is never ignored. This flag only
        /// decides what happens to a request that presents NO token credential.
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
     * @brief What authenticate() hands back on success: which credential, if any, the request
     *        enrolled with -- the one fact the endpoint must forward to authd.
     */
    struct EnrollmentGranted
    {
        /// The enrollment token id (the bearer's verified `kid`) when the request authenticated with
        /// an enrollment token; nullopt for the password bearer and for the credential-less (Open /
        /// mTLS-only) paths. The endpoint forwards it as authd's `token_id` so the use is consumed.
        std::optional<std::string> tokenId;
    };

    /// Granted (with what credential) or rejected (why).
    using EnrollmentDecision = std::variant<EnrollmentGranted, remoted::auth::AuthError>;

    /**
     * @brief Authenticates POST /enroll requests.
     *
     * /enroll is registered directly on IHttpServer, bypassing AuthGateway/AuthMiddleware: an
     * enrolling agent has no client.keys entry yet, so the agent<->manager `wazuh-agent+jwt`
     * bearer (keyed by an agent id) structurally cannot apply here. Three credentials are
     * understood, all of them `wazuh-enroll+jwt` tokens (jwt/jwtEnrollProfileV1.hpp) told apart by
     * the header alone (JwtEnrollTokenVerifier::peekKid()), before any signature work:
     *
     *   - no `kid`: the shared password key (PasswordKeySource, HKDF of authd's enrollment
     *     password). Required when requirePassword is set; ignored otherwise (Open mode, or a
     *     listener that requires a client certificate instead).
     *   - `kid` = enrollment token id (issue #38993): the key derived from that token's secret, from
     *     TokenKeySource's replica of authd's store. Verified ALWAYS, in every mode -- a presented
     *     credential is never ignored -- then the token's own state (expired / revoked) is checked,
     *     in this order: lookup, signature, expiry, revocation, so only a caller that holds the
     *     token's secret learns anything about its status (ids are 128-bit random values, so an
     *     "unknown" answer for a guessed id leaks nothing either). On success the token id travels
     *     to authd (EnrollmentGranted::tokenId), which consumes one use.
     *   - `kid` = canonical agent id (re-enrollment): recognised by shape and rejected as
     *     InvalidToken until the re-enrollment secret lands (issue #38993, later stage).
     *
     * Failures collapse through the same remoted::auth::AuthError taxonomy -- and the same
     * publicErrorFor()/errorResponseFor() uniform 401 -- as every other endpoint; the token-specific
     * causes (TokenUnknown/TokenExpired/TokenRevoked) keep their own metric cells.
     *
     * A client-certificate requirement is NOT this class's concern at all: the TLS listener
     * enforces it (or doesn't) entirely on its own, before any handler -- including this one --
     * ever runs. That's why requirePassword=false passes a credential-less request unconditionally
     * regardless of whether the listener also requires mTLS: from here, "mTLS-only" and "Open" are
     * indistinguishable, and correctly so.
     */
    class EnrollmentAuthenticator
    {
    public:
        /**
         * @param config      requirePassword + time policy + body cap.
         * @param keySource   Enrollment password key; ignored (may be null) when requirePassword is false.
         * @param tokenSource Replica of the enrollment token store; may be null, in which case every
         *                    enrollment-token bearer is rejected as TokenUnknown (fail closed).
         */
        EnrollmentAuthenticator(EnrollmentAuthConfig config,
                                std::shared_ptr<remoted::auth::PasswordKeySource> keySource,
                                std::shared_ptr<remoted::auth::TokenKeySource> tokenSource = nullptr);

        /**
         * @brief Authenticate one /enroll request.
         *
         * @param protocolVersionHeader  Value of the protocol-version header (empty if absent or
         *                               duplicated -- the transport collapses both). Validated
         *                               FIRST, in every mode including Open, exactly as
         *                               AuthMiddleware::authenticate() does for every other route.
         * @param authorizationHeader    Value of the Authorization header (empty if absent or
         *                               duplicated). `Bearer <wazuh-enroll+jwt>`: an enrollment-token
         *                               bearer is verified in every mode; the password bearer is
         *                               required when requirePassword is set and ignored otherwise.
         * @param bodySize               Size of the raw request body, checked against maxBodySize
         *                               once the version is accepted, in every mode. The bearer does
         *                               not cover the body (TLS protects it), so the bytes themselves
         *                               are never needed here.
         * @param currentUnixTimeSeconds Current time, for the token's time rules and the enrollment
         *                               token's expiry.
         * @return EnrollmentGranted on success (with the token id when a token was used), or the
         *         AuthError that rejected the request.
         */
        EnrollmentDecision authenticate(std::string_view protocolVersionHeader,
                                        std::string_view authorizationHeader,
                                        std::size_t bodySize,
                                        std::int64_t currentUnixTimeSeconds) const;

    private:
        EnrollmentDecision authenticatePassword(std::string_view authorizationHeader,
                                                std::int64_t currentUnixTimeSeconds) const;
        EnrollmentDecision
        authenticateToken(std::string_view kid, std::string_view token, std::int64_t currentUnixTimeSeconds) const;

        EnrollmentAuthConfig m_config;
        std::shared_ptr<remoted::auth::PasswordKeySource> m_keySource;
        std::shared_ptr<remoted::auth::TokenKeySource> m_tokenSource;
    };

} // namespace remoted::enrollment
