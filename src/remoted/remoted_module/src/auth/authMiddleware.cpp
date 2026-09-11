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

#include "authMiddleware.hpp"

#include "common/logThrottle.hpp"
#include "jwt/canonicalAgentId.hpp"
#include "jwt/jwtProfileV1.hpp"
#include "jwt/jwtRequestTokenVerifier.hpp"
#include "jwt/secureBytes.hpp"
#include "loggerHelper.h"

#include <openssl/crypto.h>

#include <chrono>
#include <cstddef>
#include <string>

namespace remoted::auth
{
    namespace
    {
        constexpr auto AUTH_MIDDLEWARE_LOGTAG {"wazuh-manager-remoted:auth"};

        // Function-local statics rather than members: loggerHelper.h must stay out of
        // authMiddleware.hpp (the tests include it, and Log::GLOBAL_LOG_FUNCTION is DSO-hidden),
        // and this is a process-wide condition anyway.
        const LogFn& logFn()
        {
            static const LogFn instance {AUTH_MIDDLEWARE_LOGTAG};
            return instance;
        }

        // An agent whose address stopped matching retries on its own schedule, indefinitely. Reported
        // from here, rather than from the endpoints' rejection funnel, because this is the only scope
        // that knows both the resolved agent id and the peer address.
        remoted::common::LogThrottle& addressNotAllowedThrottle()
        {
            static remoted::common::LogThrottle instance;
            return instance;
        }

        // The only credential scheme the request path accepts. Exact, case-sensitive spelling: RFC 7235
        // lets schemes be case-insensitive, but the profile is closed and a client that spells it
        // differently is not this profile's client. Anything else is malformed, never "unsupported".
        constexpr std::string_view kBearerScheme {"Bearer "};

    } // namespace

    const char* toString(AuthError err)
    {
        switch (err)
        {
            case AuthError::None: return "none";
            case AuthError::MissingProtocolVersion: return "missing_protocol_version";
            case AuthError::UnsupportedProtocolVersion: return "unsupported_protocol_version";
            case AuthError::MissingAuthorization: return "missing_authorization";
            case AuthError::MalformedAuthorization: return "malformed_authorization";
            case AuthError::UnknownAgent: return "unknown_agent";
            case AuthError::MissingKey: return "missing_key";
            case AuthError::AddressNotAllowed: return "address_not_allowed";
            case AuthError::InvalidToken: return "invalid_token";
            case AuthError::InvalidSignature: return "invalid_signature";
            case AuthError::StaleToken: return "stale_token";
            case AuthError::IdentityMismatch: return "identity_mismatch";
            case AuthError::PayloadAgentMismatch: return "payload_agent_mismatch";
            case AuthError::BodyTooLarge: return "body_too_large";
            case AuthError::UnsupportedContentEncoding: return "unsupported_content_encoding";
            case AuthError::MalformedContentEncoding: return "malformed_content_encoding";
            case AuthError::EnrollmentKeyUnavailable: return "enrollment_key_unavailable";
            case AuthError::TokenUnknown: return "token_unknown";
            case AuthError::TokenExpired: return "token_expired";
            case AuthError::TokenRevoked: return "token_revoked";
        }
        return "unknown";
    }

    namespace
    {
        // The 401 classes and their RFC 6750 §3 challenges (issue #38993, T10). One literal per class:
        // errorResponseFor() renders them on every rejected request and must stay allocation-free.
        constexpr const char* kAuthMessage = "Invalid client authentication";
        constexpr const char* kUnknownAgent = "unknown_agent";
        constexpr const char* kStaleToken = "stale_token";
        constexpr const char* kInvalidSignature = "invalid_signature";
        constexpr const char* kInvalidRequest = "invalid_request";
        constexpr const char* kEnrollmentKeyUnavailable = "enrollment_key_unavailable";
        constexpr const char* kTokenExpired = "token_expired";
        constexpr const char* kTokenRevoked = "token_revoked";
        constexpr const char* kChallengeUnknownAgent =
            R"(Bearer error="invalid_token", error_description="unknown_agent")";
        constexpr const char* kChallengeStaleToken = R"(Bearer error="invalid_token", error_description="stale_token")";
        constexpr const char* kChallengeInvalidSignature =
            R"(Bearer error="invalid_token", error_description="invalid_signature")";
        constexpr const char* kChallengeInvalidRequest = R"(Bearer error="invalid_request")";
        // The server could not judge the credential at all (no enrollment key to judge it with): RFC
        // 6750 §3.1 has no error code for that and `invalid_token` would be a lie about the agent's
        // credential, so the challenge is bare and only the body's `code` names the condition.
        constexpr const char* kChallengeBare = "Bearer";
        constexpr const char* kChallengeTokenExpired =
            R"(Bearer error="invalid_token", error_description="token_expired")";
        constexpr const char* kChallengeTokenRevoked =
            R"(Bearer error="invalid_token", error_description="token_revoked")";
    } // namespace

    PublicError publicErrorFor(AuthError err)
    {
        // Exhaustive on purpose (no default, like toString()): a reason added to AuthError must pick
        // its public class here, or the build says so.
        switch (err)
        {
            case AuthError::None: return {200, "", nullptr, nullptr};
            case AuthError::MissingProtocolVersion:
                return {400, "Missing required header: protocol-version", nullptr, nullptr};
            case AuthError::UnsupportedProtocolVersion: return {400, "Unsupported protocol-version", nullptr, nullptr};
            case AuthError::PayloadAgentMismatch: return {400, "Invalid event batch", nullptr, nullptr};
            case AuthError::BodyTooLarge: return {413, "Request payload is too large", nullptr, nullptr};
            case AuthError::MalformedContentEncoding: return {400, "Malformed compressed body", nullptr, nullptr};
            case AuthError::UnsupportedContentEncoding: return {415, "Unsupported Content-Encoding", nullptr, nullptr};

            // No usable credential was presented: nothing was judged.
            case AuthError::MissingAuthorization:
            case AuthError::MalformedAuthorization:
                return {401, kAuthMessage, kInvalidRequest, kChallengeInvalidRequest};

            // The three agent-actionable classes of the document's §2.10.
            case AuthError::UnknownAgent: return {401, kAuthMessage, kUnknownAgent, kChallengeUnknownAgent};
            case AuthError::StaleToken: return {401, kAuthMessage, kStaleToken, kChallengeStaleToken};
            // Everything that says "this credential does not work for this identity": a bad MAC, a
            // token that is not a wazuh-agent+jwt, a `sub`/`iss` naming another agent, a peer address
            // the entry does not allow, an entry whose key does not decode. None of them is fixed by
            // re-enrolling, so they share the class that tells the agent not to (T10).
            //
            // TokenUnknown joins them, and deliberately does NOT get a class of its own: it is the one
            // /enroll token verdict a caller can reach WITHOUT proving it holds the token's secret
            // (the `kid` must be looked up before there is a key to check the signature with), so
            // naming it would answer "does this token id exist here?" for free -- exactly the oracle
            // authd refuses to be when it folds an unknown id into a revoked one
            // (etoken_store_consume(), enrollment_token_store.c). With it folded, the two layers state
            // ONE invariant: a token's state is named only to a caller that proved it holds the secret
            // (TokenExpired / TokenRevoked below, reachable only after verifyWithKid() succeeds).
            // Operators keep the distinction where it belongs -- remoted.auth.reject.token_unknown and
            // remoted.enroll.token.rejected_unknown, plus the DEBUG line -- since it is their
            // diagnostic, not the caller's.
            case AuthError::InvalidSignature:
            case AuthError::InvalidToken:
            case AuthError::IdentityMismatch:
            case AuthError::AddressNotAllowed:
            case AuthError::TokenUnknown:
            case AuthError::MissingKey: return {401, kAuthMessage, kInvalidSignature, kChallengeInvalidSignature};

            case AuthError::EnrollmentKeyUnavailable:
                return {401, kAuthMessage, kEnrollmentKeyUnavailable, kChallengeBare};

            // /enroll's enrollment-token states (issue #38993), both proof-gated: only a caller whose
            // bearer verified against the token's own key is told the token has lapsed or been revoked.
            case AuthError::TokenExpired: return {401, kAuthMessage, kTokenExpired, kChallengeTokenExpired};
            case AuthError::TokenRevoked: return {401, kAuthMessage, kTokenRevoked, kChallengeTokenRevoked};
        }
        return {401, kAuthMessage, kInvalidSignature, kChallengeInvalidSignature};
    }

    AuthMiddleware::AuthMiddleware(AuthConfig config, std::shared_ptr<IAgentKeystore> keystore)
        : m_config(std::move(config))
        , m_keystore(std::move(keystore))
    {
    }

    std::variant<VerifiedAgent, AuthError> AuthMiddleware::authenticate(std::string_view protocolVersionHeader,
                                                                        std::string_view authorizationHeader,
                                                                        std::string_view peerIp,
                                                                        std::int64_t currentUnixTimeSeconds) const
    {
        using jwt_profile::v1::JwtRequestTokenVerifier;

        // Step 1: protocol version. An empty value here must mean "absent or duplicated" -- the
        // transport collapses both cases before calling in, since the header must be present exactly
        // once.
        if (protocolVersionHeader.empty())
        {
            return AuthError::MissingProtocolVersion;
        }
        if (protocolVersionHeader != m_config.supportedProtocolVersion)
        {
            return AuthError::UnsupportedProtocolVersion;
        }

        // Step 1 (cont.): exactly `Bearer <token>`. Anything about the token itself (length, grammar,
        // content) is the verifier's call and reports as InvalidToken; only the credential framing is
        // "malformed" here.
        if (authorizationHeader.empty())
        {
            return AuthError::MissingAuthorization;
        }
        if (authorizationHeader.size() <= kBearerScheme.size() ||
            authorizationHeader.substr(0, kBearerScheme.size()) != kBearerScheme)
        {
            return AuthError::MalformedAuthorization;
        }
        const std::string_view token = authorizationHeader.substr(kBearerScheme.size());

        // Step 2: the bounded, pre-signature peek. Nothing here is trusted: `kid` only names the
        // candidate key. A token that fails the profile's grammar/header rules never reaches the
        // keystore, so a hostile peer cannot probe agent ids with garbage.
        const auto kid = JwtRequestTokenVerifier::peekKid(token);
        if (!kid)
        {
            return AuthError::InvalidToken;
        }

        // Step 3: one lookup resolves the key AND evaluates the client.keys ip column against the
        // peer, so both answers always describe the same entry even if the file is reloaded
        // mid-request. The address check happens before any HMAC, so a peer that cannot use this
        // identity costs no crypto. The address is NOT part of the token and must not be: a NAT
        // rewrite would then invalidate every token. It gates authorization, not authentication.
        auto agent = m_keystore->lookup(kid->numeric(), peerIp);
        if (!agent)
        {
            return AuthError::UnknownAgent;
        }
        if (agent->key.size() != jwt_profile::v1::kKeyBytes)
        {
            // Empty (the key column did not decode to exactly 32 bytes) or -- defensively -- any
            // other size a keystore implementation might hand back. Reported to the operator,
            // throttled, from errorResponseFor()'s MissingKey branch; nothing extra is logged here.
            return AuthError::MissingKey;
        }
        if (!agent->addressAllowed)
        {
            // INFO, not WARN: the condition is a property of the agent's registration, not a fault in
            // the manager. Arguments stay allocation-free -- an integer and a view printed with "%.*s".
            if (const auto d = addressNotAllowedThrottle().record())
            {
                LOGFN_INFO(logFn(),
                           "Rejected %llu request(s) in the last %d s coming from an address the agent is not "
                           "registered with (most recently agent %u from '%.*s'). client.keys restricts that agent to "
                           "a fixed address; re-enroll it with the address it actually connects from, or with 'any' if "
                           "that address changes or the agent reaches the manager through a load balancer.",
                           static_cast<unsigned long long>(d.total),
                           remoted::common::LogThrottle::kDefaultWindowSeconds,
                           kid->numeric(),
                           static_cast<int>(peerIp.size()),
                           peerIp.data());
            }
            return AuthError::AddressNotAllowed;
        }

        // Step 4: the token against that key. The key moves into a wiped buffer for the duration of
        // the check; the copy the keystore handed us is cleansed as soon as it has been consumed.
        const jwt_profile::v1::SecureBytes key {agent->key.data(), agent->key.size()};
        OPENSSL_cleanse(agent->key.data(), agent->key.size());

        const auto now = std::chrono::system_clock::time_point {std::chrono::seconds {currentUnixTimeSeconds}};
        const auto result = JwtRequestTokenVerifier::verify(token, key, m_config.timePolicy, now);
        if (!result.ok())
        {
            return toAuthError(result.error());
        }

        // The identity every consumer downstream sees is the VERIFIED one: the token's `sub`, which
        // the verifier already proved equal to `kid` and to the `iss` suffix, in client.keys' canonical
        // spelling (zero-padded to three digits) -- the form the API's agent list and `POST /stats`'
        // document id use.
        return VerifiedAgent {result.agent().text()};
    }

} // namespace remoted::auth
