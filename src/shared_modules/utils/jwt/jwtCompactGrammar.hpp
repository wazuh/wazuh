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

/// @file jwtCompactGrammar.hpp
/// The parts of token validation both closed profiles share (issue #38582): the compact JWS
/// grammar checked before anything is decoded, the HS256 signature check over the signing input,
/// and the time rules (structural + clock-relative) every token obeys with the same TimePolicy.
/// Profile-specific work -- exact header/claim sets, identity -- stays in each verifier.

#pragma once

#include "jwt/base64Url.hpp"
#include "jwt/hmacSha256.hpp"
#include "jwt/jwtProfileV1.hpp"
#include "jwt/jwtVerifyError.hpp"
#include "jwt/secureBytes.hpp"

#include <chrono>
#include <cstdint>
#include <string_view>

namespace jwt_profile::v1
{
    /// Views into the token text (no decoding yet).
    struct CompactParts
    {
        std::string_view header64;
        std::string_view payload64;
        std::string_view signature64;
        std::string_view signingInput; ///< `<header64>.<payload64>`
    };

    /// @brief Compact grammar: non-empty, at most kMaxTokenBytes, exactly three segments, canonical
    /// base64url everywhere, non-empty header and payload, signature of exactly 32 bytes.
    inline bool splitCompact(std::string_view token, CompactParts& out) noexcept
    {
        if (token.empty() || token.size() > kMaxTokenBytes)
        {
            return false;
        }
        const auto dot1 = token.find('.');
        if (dot1 == std::string_view::npos)
        {
            return false;
        }
        const auto dot2 = token.find('.', dot1 + 1);
        if (dot2 == std::string_view::npos || token.find('.', dot2 + 1) != std::string_view::npos)
        {
            return false; // exactly three segments
        }
        out.header64 = token.substr(0, dot1);
        out.payload64 = token.substr(dot1 + 1, dot2 - dot1 - 1);
        out.signature64 = token.substr(dot2 + 1);
        out.signingInput = token.substr(0, dot2);
        return !out.header64.empty() && !out.payload64.empty() && isCanonicalBase64Url(out.header64) &&
               isCanonicalBase64Url(out.payload64) && isCanonicalBase64UrlOf(out.signature64, kHmacSha256Bytes);
    }

    /// @brief HS256 over the signing input with a 32-byte key, compared in constant time.
    inline bool verifyHs256(const CompactParts& parts, const SecureBytes& key) noexcept
    {
        if (key.size() != kKeyBytes)
        {
            return false;
        }
        const auto signature = base64UrlDecodeCanonical(parts.signature64);
        HmacSha256Digest expected {};
        return signature && hmacSha256(key, parts.signingInput, expected) &&
               hmacSha256Equal(expected, reinterpret_cast<const std::uint8_t*>(signature->data()), signature->size());
    }

    /// @brief Time rules shared by both profiles. Structural first (independent of the clock):
    /// `nbf == iat`, `iat < exp <= iat + kLifetimeSec`. Then clock-relative, in an order that keeps
    /// every sum away from overflow: not issued in the future (`iat <= now + skew`), not expired
    /// (`now <= exp + skew`), not older than the accepted age (`now - iat <= maxAge + skew`).
    /// All claim values are non-negative (the strict parser guarantees it).
    inline VerifyError checkTimeRules(std::int64_t iat,
                                      std::int64_t nbf,
                                      std::int64_t exp,
                                      const TimePolicy& policy,
                                      std::chrono::system_clock::time_point now) noexcept
    {
        if (nbf != iat || exp <= iat || exp - iat > kLifetimeSec)
        {
            return VerifyError::InvalidToken;
        }
        const auto nowSec =
            static_cast<std::int64_t>(std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count());
        if (nowSec < 0 || nowSec > INT64_MAX - kMaxClockSkewSec - kLifetimeSec)
        {
            return VerifyError::StaleToken;
        }
        const std::int64_t skew = policy.skewSec();
        if (iat > nowSec + skew)
        {
            return VerifyError::StaleToken; // issued in the future
        }
        if (nowSec > exp + skew)
        {
            return VerifyError::StaleToken; // expired
        }
        if (nowSec >= iat && nowSec - iat > policy.maxAgeSec() + skew)
        {
            return VerifyError::StaleToken; // older than the accepted age
        }
        return VerifyError::None;
    }
} // namespace jwt_profile::v1
