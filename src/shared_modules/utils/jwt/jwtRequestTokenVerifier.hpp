/*
 * Wazuh shared modules utils - JWT agent authentication profile
 * Copyright (C) 2015, Wazuh Inc.
 * August 26, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/// @file jwtRequestTokenVerifier.hpp
/// Verifies `wazuh-agent+jwt` tokens (issue #38582; profile in jwtProfileV1.hpp) -- steps 2-10 and
/// 12-13 of the profile's validation order. Fail-closed and stateless: the caller (remoted's auth
/// middleware) owns TLS/HTTP framing, the key lookup by `kid`, the "agent still active" check and
/// the uniform 401. Nothing from the token is trusted before the signature except the bounded `kid`
/// that peekKid() exposes for the lookup; the algorithm is fixed to HS256 and never read from the
/// token. No exception leaves these functions.

#pragma once

#include "jwt/base64Url.hpp"
#include "jwt/canonicalAgentId.hpp"
#include "jwt/hmacSha256.hpp"
#include "jwt/jwtCompactGrammar.hpp"
#include "jwt/jwtProfileV1.hpp"
#include "jwt/jwtVerifyError.hpp"
#include "jwt/secureBytes.hpp"
#include "jwt/strictJsonObject.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace jwt_profile::v1
{
    class VerifyResult final
    {
    public:
        static VerifyResult success(CanonicalAgentId agent) noexcept
        {
            VerifyResult r;
            r.m_agent = std::move(agent);
            return r;
        }
        static VerifyResult failure(VerifyError error) noexcept
        {
            VerifyResult r;
            r.m_error = error;
            return r;
        }

        bool ok() const noexcept
        {
            return m_agent.has_value();
        }
        /// The verified identity; only meaningful when ok().
        const CanonicalAgentId& agent() const noexcept
        {
            return *m_agent;
        }
        VerifyError error() const noexcept
        {
            return m_error;
        }

    private:
        std::optional<CanonicalAgentId> m_agent;
        VerifyError m_error {VerifyError::None};
    };

    class JwtRequestTokenVerifier final
    {
    public:
        /// @brief Pre-signature peek: size limit, compact grammar, canonical base64url header, exact
        /// header {alg, kid, typ} with alg == HS256 and typ == wazuh-agent+jwt, canonical kid. Returns
        /// the agent named by `kid` so the caller can fetch the CANDIDATE key -- it authenticates nothing.
        static std::optional<CanonicalAgentId> peekKid(std::string_view token) noexcept
        {
            try
            {
                Parsed parsed;
                if (parseUpToHeader(token, parsed) != VerifyError::None)
                {
                    return std::nullopt;
                }
                return parsed.kid;
            }
            catch (...)
            {
                return std::nullopt;
            }
        }

        /// @brief Full verification with the key the caller resolved for peekKid()'s agent.
        /// @param now Clock reading supplied by the caller (testable; read once per request).
        static VerifyResult verify(std::string_view token,
                                   const SecureBytes& key,
                                   const TimePolicy& policy,
                                   std::chrono::system_clock::time_point now) noexcept
        {
            try
            {
                return verifyImpl(token, key, policy, now);
            }
            catch (...)
            {
                return VerifyResult::failure(VerifyError::InvalidToken);
            }
        }

    private:
        static constexpr std::array<JsonField, 3> kHeaderFields {{{"alg", false}, {"kid", false}, {"typ", false}}};
        enum HeaderIndex : std::size_t
        {
            hAlg = 0,
            hKid = 1,
            hTyp = 2
        };
        static constexpr std::array<JsonField, 6> kPayloadFields {
            {{"exp", true}, {"iat", true}, {"iss", false}, {"jti", false}, {"nbf", true}, {"sub", false}}};
        enum PayloadIndex : std::size_t
        {
            pExp = 0,
            pIat = 1,
            pIss = 2,
            pJti = 3,
            pNbf = 4,
            pSub = 5
        };

        struct Parsed
        {
            CompactParts parts;
            std::optional<CanonicalAgentId> kid;
        };

        static VerifyError parseUpToHeader(std::string_view token, Parsed& out)
        {
            // Grammar of every segment before decoding anything (shared with the enroll profile).
            if (!splitCompact(token, out.parts))
            {
                return VerifyError::InvalidToken;
            }
            const auto headerJson = base64UrlDecodeCanonical(out.parts.header64);
            if (!headerJson)
            {
                return VerifyError::InvalidToken;
            }
            StrictJsonObject<3> header;
            if (!StrictJsonObject<3>::parse(kHeaderFields, *headerJson, header))
            {
                return VerifyError::InvalidToken;
            }
            if (header.str(hAlg) != kAlg || header.str(hTyp) != kTyp)
            {
                return VerifyError::InvalidToken;
            }
            out.kid = CanonicalAgentId::parseCanonical(header.str(hKid));
            return out.kid ? VerifyError::None : VerifyError::InvalidToken;
        }

        static VerifyResult verifyImpl(std::string_view token,
                                       const SecureBytes& key,
                                       const TimePolicy& policy,
                                       std::chrono::system_clock::time_point now)
        {
            Parsed parsed;
            if (const auto err = parseUpToHeader(token, parsed); err != VerifyError::None)
            {
                return VerifyResult::failure(err);
            }

            // Signature first: nothing below is looked at on an unauthenticated payload.
            if (!verifyHs256(parsed.parts, key))
            {
                return VerifyResult::failure(VerifyError::InvalidSignature);
            }
            // Exact claim set and types.
            const auto payloadJson = base64UrlDecodeCanonical(parsed.parts.payload64);
            StrictJsonObject<6> claims;
            if (!payloadJson || !StrictJsonObject<6>::parse(kPayloadFields, *payloadJson, claims))
            {
                return VerifyResult::failure(VerifyError::InvalidToken);
            }

            // Identity: kid == sub == iss minus prefix.
            const CanonicalAgentId& agent = *parsed.kid;
            const std::string_view iss = claims.str(pIss);
            if (claims.str(pSub) != agent.text() || iss.size() != kIssuerPrefix.size() + agent.text().size() ||
                iss.substr(0, kIssuerPrefix.size()) != kIssuerPrefix ||
                iss.substr(kIssuerPrefix.size()) != agent.text())
            {
                return VerifyResult::failure(VerifyError::IdentityMismatch);
            }

            // Time rules, structural then clock-relative (shared with the enroll profile).
            if (const auto err = checkTimeRules(claims.num(pIat), claims.num(pNbf), claims.num(pExp), policy, now);
                err != VerifyError::None)
            {
                return VerifyResult::failure(err);
            }
            // jti: 22 canonical chars for 16 bytes.
            if (!isCanonicalBase64UrlOf(claims.str(pJti), kJtiBytes))
            {
                return VerifyResult::failure(VerifyError::InvalidToken);
            }

            return VerifyResult::success(agent);
        }
    };
} // namespace jwt_profile::v1
