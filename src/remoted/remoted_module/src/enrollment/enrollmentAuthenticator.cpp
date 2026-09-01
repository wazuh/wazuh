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

#include "enrollmentAuthenticator.hpp"

#include "jwt/jwtEnrollTokenVerifier.hpp"

#include <chrono>
#include <utility>

namespace remoted::enrollment
{
    namespace
    {
        constexpr std::string_view kBearerScheme {"Bearer "};
    }

    EnrollmentAuthenticator::EnrollmentAuthenticator(EnrollmentAuthConfig config,
                                                     std::shared_ptr<remoted::auth::PasswordKeySource> keySource)
        : m_config(std::move(config))
        , m_keySource(std::move(keySource))
    {
    }

    std::optional<remoted::auth::AuthError>
    EnrollmentAuthenticator::authenticate(std::string_view protocolVersionHeader,
                                          std::string_view authorizationHeader,
                                          std::size_t bodySize,
                                          std::int64_t currentUnixTimeSeconds) const
    {
        // Step 1, exactly as AuthMiddleware::authenticate() does for every other authenticated
        // route: a request naming a protocol version this manager does not implement is not one it
        // can process at all, so nothing else is worth looking at. Enforced in EVERY mode,
        // including Open -- the version is a property of the protocol, not of the credential, so
        // whether a password is configured has no bearing on it.
        //
        // An empty value means absent (or present but empty) -- the caller reads the header through
        // the same case-insensitive headerValue() the AuthGateway uses, so /enroll sees exactly what
        // every other route sees, including how the transport's header map treats a repeated field.
        if (protocolVersionHeader.empty())
        {
            return remoted::auth::AuthError::MissingProtocolVersion;
        }
        if (protocolVersionHeader != m_config.supportedProtocolVersion)
        {
            return remoted::auth::AuthError::UnsupportedProtocolVersion;
        }

        // Checked next, in EVERY mode (including Open): otherwise an unauthenticated peer could
        // make this endpoint hold an arbitrarily large body -- up to the transport's own cap, not
        // this class's -- in the in-flight budget shared with every other route, for however long
        // parseAndValidateBody() takes to notice and reject it. Checking here also means an
        // oversized body gets the same 413 every other endpoint returns, instead of falling
        // through to parseAndValidateBody()'s own (much smaller) cap and a 400.
        if (bodySize > m_config.maxBodySize)
        {
            return remoted::auth::AuthError::BodyTooLarge;
        }

        if (!m_config.requirePassword)
        {
            return std::nullopt;
        }
        return authenticatePassword(authorizationHeader, currentUnixTimeSeconds);
    }

    std::optional<remoted::auth::AuthError>
    EnrollmentAuthenticator::authenticatePassword(std::string_view authorizationHeader,
                                                  std::int64_t currentUnixTimeSeconds) const
    {
        if (authorizationHeader.empty())
        {
            return remoted::auth::AuthError::MissingAuthorization;
        }

        // Exactly `Bearer <token>` (same scheme parsing as AuthMiddleware). Anything about the token
        // itself is the verifier's call below.
        if (authorizationHeader.size() <= kBearerScheme.size() ||
            authorizationHeader.substr(0, kBearerScheme.size()) != kBearerScheme)
        {
            return remoted::auth::AuthError::MalformedAuthorization;
        }
        const std::string_view token = authorizationHeader.substr(kBearerScheme.size());

        // Fail-closed: Password mode active but the key is unavailable (file missing/unreadable/
        // invalid, not yet synced from the master to a worker, or HKDF unavailable) -- never fall
        // back to Open mode. See PasswordKeySource's class comment for why conflating the two would
        // be a security bug. EnrollmentKeyUnavailable, deliberately NOT MissingKey: MissingKey means
        // an already-enrolled agent's client.keys entry doesn't decode, and logRejection() tells the
        // operator to "re-enroll" for that -- nonsensical advice here, where there is no agent and
        // no client.keys entry yet at all.
        const auto key = m_keySource ? m_keySource->currentKey() : std::nullopt;
        if (!key)
        {
            return remoted::auth::AuthError::EnrollmentKeyUnavailable;
        }

        const auto now = std::chrono::system_clock::time_point {std::chrono::seconds {currentUnixTimeSeconds}};
        const auto verdict =
            jwt_profile::v1::enroll::JwtEnrollTokenVerifier::verify(token, *key, m_config.timePolicy, now);
        if (verdict != jwt_profile::v1::VerifyError::None)
        {
            return remoted::auth::toAuthError(verdict);
        }
        return std::nullopt;
    }

} // namespace remoted::enrollment
