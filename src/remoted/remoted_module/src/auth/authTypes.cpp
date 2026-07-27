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
    constexpr std::int64_t DEFAULT_MAX_REQUEST_AGE_SECONDS {300};
    constexpr std::int64_t DEFAULT_MAX_FUTURE_SKEW_SECONDS {30};
    constexpr std::size_t DEFAULT_MAX_BODY_SIZE {10U * 1024U * 1024U};
} // namespace

namespace remoted::auth
{

    AuthConfig buildAuthConfig(const remoted_module_config_t& config)
    {
        AuthConfig result; // keeps supportedProtocolVersion's built-in default ("1")

        result.maxRequestAgeSeconds =
            config.auth_max_request_age > 0 ? config.auth_max_request_age : DEFAULT_MAX_REQUEST_AGE_SECONDS;
        result.maxFutureSkewSeconds =
            config.auth_max_future_skew > 0 ? config.auth_max_future_skew : DEFAULT_MAX_FUTURE_SKEW_SECONDS;
        result.maxBodySize =
            config.auth_max_body_size > 0 ? static_cast<std::size_t>(config.auth_max_body_size) : DEFAULT_MAX_BODY_SIZE;

        return result;
    }

} // namespace remoted::auth
