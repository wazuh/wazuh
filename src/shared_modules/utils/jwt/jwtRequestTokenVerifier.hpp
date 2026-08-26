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
#include "jwt/jwtProfileV1.hpp"
#include "jwt/secureBytes.hpp"
#include "jwt/strictJsonObject.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace jwt_profile::v1
{
    /// Low-cardinality failure classes (for metrics; the HTTP answer is the same 401 for all).
    enum class VerifyError
    {
        None,
        InvalidToken,     ///< size, grammar, base64url, JSON, header/claim sets or types, jti, structural time rules
        InvalidSignature, ///< HMAC mismatch (also a key of the wrong size)
        StaleToken,       ///< clock-relative rules: future iat, expired, older than the accepted age
        IdentityMismatch, ///< sub or iss do not name the kid agent
    };

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
            std::string_view header64;
            std::string_view payload64;
            std::string_view signature64;
            std::string_view signingInput;
            std::optional<CanonicalAgentId> kid;
        };

        static VerifyError parseUpToHeader(std::string_view token, Parsed& out)
        {
            if (token.empty() || token.size() > kMaxTokenBytes)
            {
                return VerifyError::InvalidToken;
            }
            const auto dot1 = token.find('.');
            if (dot1 == std::string_view::npos)
            {
                return VerifyError::InvalidToken;
            }
            const auto dot2 = token.find('.', dot1 + 1);
            if (dot2 == std::string_view::npos || token.find('.', dot2 + 1) != std::string_view::npos)
            {
                return VerifyError::InvalidToken; // exactly three segments
            }
            out.header64 = token.substr(0, dot1);
            out.payload64 = token.substr(dot1 + 1, dot2 - dot1 - 1);
            out.signature64 = token.substr(dot2 + 1);
            out.signingInput = token.substr(0, dot2);

            // Grammar of every segment before decoding anything: canonical base64url, non-empty
            // header/payload, signature of exactly 32 bytes.
            if (out.header64.empty() || out.payload64.empty() || !isCanonicalBase64Url(out.header64) ||
                !isCanonicalBase64Url(out.payload64) || !isCanonicalBase64UrlOf(out.signature64, kHmacSha256Bytes))
            {
                return VerifyError::InvalidToken;
            }

            const auto headerJson = base64UrlDecodeCanonical(out.header64);
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
            if (key.size() != kKeyBytes)
            {
                return VerifyResult::failure(VerifyError::InvalidSignature);
            }
            const auto signature = base64UrlDecodeCanonical(parsed.signature64);
            HmacSha256Digest expected {};
            if (!signature || !hmacSha256(key, parsed.signingInput, expected) ||
                !hmacSha256Equal(expected, reinterpret_cast<const std::uint8_t*>(signature->data()), signature->size()))
            {
                return VerifyResult::failure(VerifyError::InvalidSignature);
            }

            // Exact claim set and types.
            const auto payloadJson = base64UrlDecodeCanonical(parsed.payload64);
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

            // Structural time rules (independent of the clock). All values are non-negative int64
            // (the parser rejects anything else), so the differences below cannot overflow.
            const std::int64_t iat = claims.num(pIat);
            const std::int64_t nbf = claims.num(pNbf);
            const std::int64_t exp = claims.num(pExp);
            if (nbf != iat || exp <= iat || exp - iat > kLifetimeSec)
            {
                return VerifyResult::failure(VerifyError::InvalidToken);
            }

            // Clock-relative rules. `iat <= nowSec + skew` is checked first, which bounds every later
            // sum (exp <= iat + 60 <= nowSec + skew + 60) away from overflow.
            const auto nowSec = static_cast<std::int64_t>(
                std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count());
            if (nowSec < 0 || nowSec > INT64_MAX - kMaxClockSkewSec - kLifetimeSec)
            {
                return VerifyResult::failure(VerifyError::StaleToken);
            }
            const std::int64_t skew = policy.skewSec();
            if (iat > nowSec + skew)
            {
                return VerifyResult::failure(VerifyError::StaleToken); // issued in the future
            }
            if (nowSec > exp + skew)
            {
                return VerifyResult::failure(VerifyError::StaleToken); // expired
            }
            if (nowSec >= iat && nowSec - iat > policy.maxAgeSec() + skew)
            {
                return VerifyResult::failure(VerifyError::StaleToken); // older than the accepted age
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
