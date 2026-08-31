/*
 * Wazuh auth middleware (framework-agnostic)
 * Copyright (C) 2015, Wazuh Inc.
 * July 27, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "authTypes.hpp"

namespace
{
    constexpr std::size_t DEFAULT_MAX_BODY_SIZE {10U * 1024U * 1024U};
} // namespace

namespace remoted::auth
{
    AuthError toAuthError(jwt_profile::v1::VerifyError error)
    {
        using jwt_profile::v1::VerifyError;
        switch (error)
        {
            case VerifyError::InvalidSignature: return AuthError::InvalidSignature;
            case VerifyError::StaleToken: return AuthError::StaleToken;
            case VerifyError::IdentityMismatch: return AuthError::IdentityMismatch;
            case VerifyError::InvalidToken:
            case VerifyError::None: break; // None never comes back on the failure path
        }
        return AuthError::InvalidToken;
    }

    jwt_profile::v1::TimePolicy buildTimePolicy(int jwtMaxAge, int jwtClockSkew, bool jwtClockSkewSet)
    {
        // jwt_max_age: <= 0 is "unset" (the C-ABI's zeroed struct, or a garbage negative) -> profile
        // default; 0 is outside its 1..43200 range anyway. jwt_clock_skew: 0 is a VALID setting ("no
        // tolerance", the bottom of its 0..43200 range), so "unset" is signalled by the explicit
        // jwt_clock_skew_set flag instead -- a zeroed struct (no flag) still yields the module default.
        // Configured values are validated by TimePolicy itself, which throws outside the range.
        const std::int64_t maxAge = jwtMaxAge > 0 ? jwtMaxAge : jwt_profile::v1::kDefaultAgeSec;
        const std::int64_t skew = jwtClockSkewSet ? jwtClockSkew : jwt_profile::v1::kDefaultClockSkewSec;
        return jwt_profile::v1::TimePolicy {maxAge, skew};
    }

    AuthConfig buildAuthConfig(const remoted_module_config_t& config)
    {
        AuthConfig result; // keeps supportedProtocolVersion's built-in default ("1")

        result.timePolicy = buildTimePolicy(config.jwt_max_age, config.jwt_clock_skew, config.jwt_clock_skew_set != 0);
        result.maxBodySize =
            config.auth_max_body_size > 0 ? static_cast<std::size_t>(config.auth_max_body_size) : DEFAULT_MAX_BODY_SIZE;

        return result;
    }

} // namespace remoted::auth
