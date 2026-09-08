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

        using jwt_profile::v1::enroll::JwtEnrollTokenVerifier;

        /// The token after `Bearer `, or nullopt when the header is not exactly that framing (same
        /// scheme parsing as AuthMiddleware; anything about the token itself is the verifier's call).
        std::optional<std::string_view> bearerToken(std::string_view authorizationHeader)
        {
            if (authorizationHeader.size() <= kBearerScheme.size() ||
                authorizationHeader.substr(0, kBearerScheme.size()) != kBearerScheme)
            {
                return std::nullopt;
            }
            return authorizationHeader.substr(kBearerScheme.size());
        }

        std::chrono::system_clock::time_point at(std::int64_t unixSeconds)
        {
            return std::chrono::system_clock::time_point {std::chrono::seconds {unixSeconds}};
        }
    } // namespace

    EnrollmentAuthenticator::EnrollmentAuthenticator(EnrollmentAuthConfig config,
                                                     std::shared_ptr<remoted::auth::PasswordKeySource> keySource,
                                                     std::shared_ptr<remoted::auth::TokenKeySource> tokenSource)
        : m_config(std::move(config))
        , m_keySource(std::move(keySource))
        , m_tokenSource(std::move(tokenSource))
    {
    }

    EnrollmentDecision EnrollmentAuthenticator::authenticate(std::string_view protocolVersionHeader,
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

        // Step 2: which credential is this? A well-framed bearer whose header carries a `kid` is
        // classified by shape alone, before any signature work (peekKid() trusts nothing). An
        // enrollment-token bearer takes its own path in EVERY mode, Open included: a credential the
        // agent presents is never ignored, and an operator who minted a token with a credential
        // expects it to be checked. An agent `kid` (re-enrollment) is recognised by shape and handed
        // to the endpoint UNVERIFIED, in every mode too: the secret it is signed with is the master's
        // alone, so authd there is the verifier (see ReenrollmentRequested). Everything else -- no
        // header, a non-bearer scheme, a shared-key token, garbage -- is the mode's own business
        // below, exactly as before tokens.
        if (!authorizationHeader.empty())
        {
            if (const auto token = bearerToken(authorizationHeader))
            {
                if (const auto peeked = JwtEnrollTokenVerifier::peekKid(*token))
                {
                    switch (peeked->kind)
                    {
                        case JwtEnrollTokenVerifier::KidKind::Token:
                            return authenticateToken(peeked->text, *token, currentUnixTimeSeconds);
                        case JwtEnrollTokenVerifier::KidKind::Agent:
                            return ReenrollmentRequested {std::string {peeked->text}, std::string {*token}};
                        case JwtEnrollTokenVerifier::KidKind::None: break;
                    }
                }
            }
        }

        if (!m_config.requirePassword)
        {
            return EnrollmentGranted {};
        }
        return authenticatePassword(authorizationHeader, currentUnixTimeSeconds);
    }

    EnrollmentDecision EnrollmentAuthenticator::authenticatePassword(std::string_view authorizationHeader,
                                                                     std::int64_t currentUnixTimeSeconds) const
    {
        if (authorizationHeader.empty())
        {
            return remoted::auth::AuthError::MissingAuthorization;
        }

        const auto token = bearerToken(authorizationHeader);
        if (!token)
        {
            return remoted::auth::AuthError::MalformedAuthorization;
        }

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

        const auto verdict =
            JwtEnrollTokenVerifier::verify(*token, *key, m_config.timePolicy, at(currentUnixTimeSeconds));
        if (verdict != jwt_profile::v1::VerifyError::None)
        {
            return remoted::auth::toAuthError(verdict);
        }
        return EnrollmentGranted {};
    }

    EnrollmentDecision EnrollmentAuthenticator::authenticateToken(std::string_view kid,
                                                                  std::string_view token,
                                                                  std::int64_t currentUnixTimeSeconds) const
    {
        // No replica at all (the facade only builds one when enrollment is enabled, and a test may
        // pass none): fail closed, every token is unknown.
        if (!m_tokenSource)
        {
            return remoted::auth::AuthError::TokenUnknown;
        }

        // Lookup, then the P35b mitigation: a token minted on the master moments ago may not have
        // reached this node's copy of the store yet, so an unknown `kid` forces ONE re-read (rate-
        // limited inside TokenKeySource) before the request is refused.
        auto entry = m_tokenSource->lookup(kid);
        if (!entry && m_tokenSource->reloadIfMissing(kid))
        {
            entry = m_tokenSource->lookup(kid);
        }
        if (!entry)
        {
            return remoted::auth::AuthError::TokenUnknown;
        }

        // Signature BEFORE status: an expired or revoked answer is only ever given to a caller that
        // proved it holds the token's secret. verifyWithKid() also re-checks that the header names
        // exactly this `kid`, so a token can never be verified against a key it did not ask for.
        const auto verdict = JwtEnrollTokenVerifier::verifyWithKid(
            token, kid, entry->key, m_config.timePolicy, at(currentUnixTimeSeconds));
        if (verdict != jwt_profile::v1::VerifyError::None)
        {
            return remoted::auth::toAuthError(verdict);
        }

        // Same rule authd applies when it consumes the use (etoken_store_consume(): `now >= expires`
        // is expired), so remoted and authd agree on the boundary second.
        if (currentUnixTimeSeconds >= entry->expires)
        {
            return remoted::auth::AuthError::TokenExpired;
        }
        if (entry->revoked)
        {
            return remoted::auth::AuthError::TokenRevoked;
        }
        return EnrollmentGranted {std::string {kid}};
    }

} // namespace remoted::enrollment
