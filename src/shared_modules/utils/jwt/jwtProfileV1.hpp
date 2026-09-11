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

/// @file jwtProfileV1.hpp
/// Constants and time policy of the closed `wazuh-agent+jwt` profile (issue #38582): the bearer
/// token an agent self-signs with its client.keys secret (HS256) to authenticate to remoted over
/// TLS. Shared by the manager (verifier), the agent (signer) and every test. Nothing here is
/// negotiable on the wire: a token is either exactly this profile or it is rejected.
/// The JSON text of the header and of the claims is ASCII (every value the profile carries is);
/// a non-ASCII byte anywhere in either segment is an invalid token (strictJsonObject.hpp).

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string_view>

namespace jwt_profile::v1
{
    /// JOSE `typ`: fixes the domain of the token (there is no `aud` claim by design).
    constexpr std::string_view kTyp = "wazuh-agent+jwt";
    /// The only accepted algorithm; the verifier never takes it from the token.
    constexpr std::string_view kAlg = "HS256";
    /// `iss` is `kIssuerPrefix + <canonical agent id>`.
    constexpr std::string_view kIssuerPrefix = "wazuh-agent/";

    /// The HS256 key is exactly the 32 bytes obtained by hex-decoding the 64-char client.keys secret
    /// -- never the ASCII text.
    constexpr std::size_t kKeyBytes = 32;
    constexpr std::size_t kKeyHexChars = 2 * kKeyBytes;

    /// `jti`: 16 CSPRNG bytes, base64url without padding -> 22 chars.
    constexpr std::size_t kJtiBytes = 16;
    constexpr std::size_t kJtiChars = 22;

    /// Upper bound on the bearer token text, enforced before any decoding.
    constexpr std::size_t kMaxTokenBytes = 4096;

    /// Declared lifetime of every token: the agent always emits `exp = iat + kLifetimeSec` and the
    /// verifier requires `exp - iat <= kLifetimeSec`. A profile constant, not a knob (J12).
    constexpr std::int64_t kLifetimeSec = 60;

    /// Bounds of the two operator knobs (remoted internals `jwt_max_age` / `jwt_clock_skew`):
    /// the maximum accepted token AGE (`now - iat <= maxAge + skew`) and the tolerated clock skew.
    /// Both default to the profile's original maxima (60 s / 30 s); the ceiling is raised to 12h to
    /// let a deployment tolerate real manager/agent clock drift larger than 90 s combined. This does
    /// NOT widen a token's own declared lifetime (`kLifetimeSec`, still fixed at 60 s) -- only how
    /// old a token is still allowed to be when the manager sees it. A captured token's replay window
    /// grows with `skewSec`; this profile relies on the TLS-authenticated channel, not a replay
    /// store, so that tradeoff is accepted (issue: API key format + jwt_max_age ceiling).
    constexpr std::int64_t kMinAgeSec = 1;
    constexpr std::int64_t kMaxAgeSec = 43200;
    constexpr std::int64_t kMinClockSkewSec = 0;
    constexpr std::int64_t kMaxClockSkewSec = 43200;
    constexpr std::int64_t kDefaultAgeSec = 60;
    constexpr std::int64_t kDefaultClockSkewSec = 30;

    /// @brief Effective time policy of a verifier: the profile defaults, optionally changed by
    /// configuration within [kMinAgeSec, kMaxAgeSec] / [kMinClockSkewSec, kMaxClockSkewSec].
    /// Construction is fail-fast: out-of-range values throw, so a bad configuration can never
    /// silently widen (or zero) the window beyond what the profile allows.
    class TimePolicy final
    {
    public:
        /// Profile defaults (60 s accepted age, 30 s skew).
        constexpr TimePolicy() noexcept = default;

        /// @throw std::invalid_argument if `maxAgeSec` is outside [1, 43200] or `skewSec` outside
        /// [0, 43200].
        TimePolicy(std::int64_t maxAgeSec, std::int64_t skewSec)
            : m_maxAgeSec(maxAgeSec)
            , m_skewSec(skewSec)
        {
            if (!isValid(maxAgeSec, skewSec))
            {
                throw std::invalid_argument("jwt TimePolicy out of range: maxAge in [1,43200], skew in [0,43200]");
            }
        }

        /// Non-throwing variant for configuration code that wants to report instead of unwind.
        static std::optional<TimePolicy> tryMake(std::int64_t maxAgeSec, std::int64_t skewSec) noexcept
        {
            if (!isValid(maxAgeSec, skewSec))
            {
                return std::nullopt;
            }
            TimePolicy policy;
            policy.m_maxAgeSec = maxAgeSec;
            policy.m_skewSec = skewSec;
            return policy;
        }

        static constexpr bool isValid(std::int64_t maxAgeSec, std::int64_t skewSec) noexcept
        {
            return maxAgeSec >= kMinAgeSec && maxAgeSec <= kMaxAgeSec && skewSec >= kMinClockSkewSec &&
                   skewSec <= kMaxClockSkewSec;
        }

        constexpr std::int64_t maxAgeSec() const noexcept
        {
            return m_maxAgeSec;
        }
        constexpr std::int64_t skewSec() const noexcept
        {
            return m_skewSec;
        }

    private:
        std::int64_t m_maxAgeSec {kDefaultAgeSec};
        std::int64_t m_skewSec {kDefaultClockSkewSec};
    };
} // namespace jwt_profile::v1
