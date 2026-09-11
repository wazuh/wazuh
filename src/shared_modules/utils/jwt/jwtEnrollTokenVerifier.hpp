/*
 * Wazuh shared modules - JWT profile library
 * Copyright (C) 2015, Wazuh Inc.
 * August 26, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/// @file jwtEnrollTokenVerifier.hpp
/// Verifies `wazuh-enroll+jwt` tokens (jwtEnrollProfileV1.hpp) with the single HKDF-derived key
/// the manager holds. Fail-closed, stateless, no exception leaves verify(). The caller owns TLS/HTTP
/// framing, the "password required" decision, the key's availability and the uniform 401.

#pragma once

#include "jwt/base64Url.hpp"
#include "jwt/jwtCompactGrammar.hpp"
#include "jwt/jwtEnrollProfileV1.hpp"
#include "jwt/jwtProfileV1.hpp"
#include "jwt/jwtVerifyError.hpp"
#include "jwt/secureBytes.hpp"
#include "jwt/strictJsonObject.hpp"

#include <array>
#include <chrono>
#include <string_view>

namespace jwt_profile::v1::enroll
{
    class JwtEnrollTokenVerifier final
    {
    public:
        /// @return VerifyError::None when the token is a valid `wazuh-enroll+jwt` for `key` at `now`.
        static VerifyError verify(std::string_view token,
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
                return VerifyError::InvalidToken;
            }
        }

    private:
        static constexpr std::array<JsonField, 2> kHeaderFields {{{"alg", false}, {"typ", false}}};
        enum HeaderIndex : std::size_t
        {
            hAlg = 0,
            hTyp = 1
        };
        static constexpr std::array<JsonField, 4> kPayloadFields {
            {{"exp", true}, {"iat", true}, {"jti", false}, {"nbf", true}}};
        enum PayloadIndex : std::size_t
        {
            pExp = 0,
            pIat = 1,
            pJti = 2,
            pNbf = 3
        };

        static VerifyError verifyImpl(std::string_view token,
                                      const SecureBytes& key,
                                      const TimePolicy& policy,
                                      std::chrono::system_clock::time_point now)
        {
            CompactParts parts;
            if (!splitCompact(token, parts))
            {
                return VerifyError::InvalidToken;
            }
            // Exact header {alg, typ}: a `kid` (agent profile) or anything else is rejected here.
            const auto headerJson = base64UrlDecodeCanonical(parts.header64);
            StrictJsonObject<2> header;
            if (!headerJson || !StrictJsonObject<2>::parse(kHeaderFields, *headerJson, header) ||
                header.str(hAlg) != kAlg || header.str(hTyp) != kTyp)
            {
                return VerifyError::InvalidToken;
            }
            // Signature before anything in the payload is looked at.
            if (!verifyHs256(parts, key))
            {
                return VerifyError::InvalidSignature;
            }
            const auto payloadJson = base64UrlDecodeCanonical(parts.payload64);
            StrictJsonObject<4> claims;
            if (!payloadJson || !StrictJsonObject<4>::parse(kPayloadFields, *payloadJson, claims))
            {
                return VerifyError::InvalidToken;
            }
            if (const auto err = checkTimeRules(claims.num(pIat), claims.num(pNbf), claims.num(pExp), policy, now);
                err != VerifyError::None)
            {
                return err;
            }
            if (!isCanonicalBase64UrlOf(claims.str(pJti), kJtiBytes))
            {
                return VerifyError::InvalidToken;
            }
            return VerifyError::None;
        }
    };
} // namespace jwt_profile::v1::enroll
