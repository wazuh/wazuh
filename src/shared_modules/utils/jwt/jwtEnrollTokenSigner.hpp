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

/// @file jwtEnrollTokenSigner.hpp
/// Mints `wazuh-enroll+jwt` tokens (jwtEnrollProfileV1.hpp). Header and payload are serialized by
/// hand in the canonical form the verifier expects and the frozen vectors pin (keys in ASCII
/// order, no whitespace), so agent, manager tests and the Python tools agree byte for byte.

#pragma once

#include "jwt/base64Url.hpp"
#include "jwt/hmacSha256.hpp"
#include "jwt/jwtEnrollProfileV1.hpp"
#include "jwt/jwtProfileV1.hpp"
#include "jwt/jwtRequestTokenSigner.hpp" // randomJti / isCanonicalJti
#include "jwt/secureBytes.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace jwt_profile::v1::enroll
{
    class JwtEnrollTokenSigner final
    {
    public:
        /// @param key         The HKDF-derived 32-byte key (deriveEnrollKey()).
        /// @param now         Wall clock of this attempt: `iat = nbf = now`, `exp = now + kLifetimeSec`.
        /// @param jtiOverride Tests only: a fixed canonical jti instead of 16 CSPRNG bytes.
        /// @return The compact JWS, or nullopt (wrong key size, clock out of range, CSPRNG failure).
        static std::optional<std::string>
        sign(const SecureBytes& key, std::chrono::system_clock::time_point now, std::string_view jtiOverride = {})
        {
            if (key.size() != kKeyBytes)
            {
                return std::nullopt;
            }
            const auto iat = static_cast<std::int64_t>(
                std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count());
            if (iat < 0 || iat > INT64_MAX - kLifetimeSec)
            {
                return std::nullopt;
            }

            std::string jti;
            if (jtiOverride.empty())
            {
                auto fresh = JwtRequestTokenSigner::randomJti();
                if (!fresh)
                {
                    return std::nullopt;
                }
                jti = std::move(*fresh);
            }
            else
            {
                if (!JwtRequestTokenSigner::isCanonicalJti(jtiOverride))
                {
                    return std::nullopt;
                }
                jti = std::string(jtiOverride);
            }

            std::string signingInput = base64UrlEncode(headerJson());
            signingInput += '.';
            signingInput += base64UrlEncode(payloadJson(iat, jti));

            HmacSha256Digest mac {};
            if (!hmacSha256(key, signingInput, mac))
            {
                return std::nullopt;
            }
            signingInput += '.';
            signingInput += base64UrlEncode(mac.data(), mac.size());
            return signingInput;
        }

        static std::string headerJson()
        {
            std::string out = R"({"alg":")";
            out += kAlg;
            out += R"(","typ":")";
            out += kTyp;
            out += R"("})";
            return out;
        }

        static std::string payloadJson(std::int64_t iat, std::string_view jti)
        {
            std::string out = R"({"exp":)";
            out += std::to_string(iat + kLifetimeSec);
            out += R"(,"iat":)";
            out += std::to_string(iat);
            out += R"(,"jti":")";
            out += jti;
            out += R"(","nbf":)";
            out += std::to_string(iat);
            out += '}';
            return out;
        }
    };
} // namespace jwt_profile::v1::enroll
