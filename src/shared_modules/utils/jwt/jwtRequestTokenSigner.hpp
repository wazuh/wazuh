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

/// @file jwtRequestTokenSigner.hpp
/// Emits `wazuh-agent+jwt` tokens (issue #38582, profile in jwtProfileV1.hpp). Typed API: it takes an
/// agent id, a key and a clock reading and always produces exactly the profile -- no claim map, no
/// algorithm choice, nothing an unwary caller could widen. Serialisation is by hand (the profile is
/// six fixed claims), compact and alphabetically ordered, which is byte-identical to what a
/// nlohmann-backed jwt-cpp builder emits (pinned by jwtCppSpike_test.cpp).

#pragma once

#include "jwt/base64Url.hpp"
#include "jwt/canonicalAgentId.hpp"
#include "jwt/hmacSha256.hpp"
#include "jwt/jwtProfileV1.hpp"
#include "jwt/secureBytes.hpp"

#include <openssl/rand.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace jwt_profile::v1
{
    class JwtRequestTokenSigner final
    {
    public:
        /// @brief Signs one token for `agentId` with `key` as of `now`.
        /// @param jtiOverride Test/vector hook only: a canonical 22-char `jti` to use instead of a
        ///        fresh CSPRNG one. Production callers leave it empty.
        /// @return The compact JWS, or nullopt if the key is not 32 bytes, `now` is before the epoch,
        ///         the override is not a canonical jti, or the CSPRNG / HMAC failed. Never a weaker token.
        static std::optional<std::string> sign(const CanonicalAgentId& agentId,
                                               const SecureBytes& key,
                                               std::chrono::system_clock::time_point now,
                                               std::string_view jtiOverride = {})
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
                auto fresh = randomJti();
                if (!fresh)
                {
                    return std::nullopt;
                }
                jti = std::move(*fresh);
            }
            else
            {
                if (!isCanonicalJti(jtiOverride))
                {
                    return std::nullopt;
                }
                jti = std::string(jtiOverride);
            }

            std::string signingInput = base64UrlEncode(headerJson(agentId));
            signingInput += '.';
            signingInput += base64UrlEncode(payloadJson(agentId, iat, jti));

            HmacSha256Digest mac {};
            if (!hmacSha256(key, signingInput, mac))
            {
                return std::nullopt;
            }
            signingInput += '.';
            signingInput += base64UrlEncode(mac.data(), mac.size());
            return signingInput;
        }

        /// Exact JOSE header text of the profile for `agentId`.
        static std::string headerJson(const CanonicalAgentId& agentId)
        {
            std::string out = R"({"alg":")";
            out += kAlg;
            out += R"(","kid":")";
            out += agentId.text();
            out += R"(","typ":")";
            out += kTyp;
            out += R"("})";
            return out;
        }

        /// Exact payload text: the six claims, alphabetically, `nbf == iat`, `exp == iat + 60`.
        static std::string payloadJson(const CanonicalAgentId& agentId, std::int64_t iat, std::string_view jti)
        {
            std::string out = R"({"exp":)";
            out += std::to_string(iat + kLifetimeSec);
            out += R"(,"iat":)";
            out += std::to_string(iat);
            out += R"(,"iss":")";
            out += kIssuerPrefix;
            out += agentId.text();
            out += R"(","jti":")";
            out += jti;
            out += R"(","nbf":)";
            out += std::to_string(iat);
            out += R"(,"sub":")";
            out += agentId.text();
            out += R"("})";
            return out;
        }

        /// 16 bytes from RAND_bytes as 22 canonical base64url chars; nullopt if the CSPRNG fails
        /// (never degrades to a weaker source).
        static std::optional<std::string> randomJti()
        {
            std::array<unsigned char, kJtiBytes> bytes {};
            if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1)
            {
                return std::nullopt;
            }
            return base64UrlEncode(bytes.data(), bytes.size());
        }

        /// 22 chars of base64url that decode to exactly 16 bytes (trailing bits zero).
        static bool isCanonicalJti(std::string_view jti) noexcept
        {
            return jti.size() == kJtiChars && isCanonicalBase64UrlOf(jti, kJtiBytes);
        }
    };
} // namespace jwt_profile::v1
