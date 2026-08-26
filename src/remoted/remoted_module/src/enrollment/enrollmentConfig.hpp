/*
 * Wazuh remoted module - Enrollment endpoint configuration
 * Copyright (C) 2015, Wazuh Inc.
 * August 19, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include "remoted_module.h"

#include "jwt/jwtProfileV1.hpp"

#include <cstddef>
#include <cstdint>
#include <string>

namespace remoted::enrollment
{

    /**
     * @brief Resolved /enroll configuration, translated from the C ABI.
     *
     * The behavioral flags (enrollmentEnabled/usePassword/useSourceIp/allowHigherVersions) are
     * copied verbatim from authd's own <auth> block (see remoted_module.h's comment on the ABI
     * fields this reads) -- they are not remoted-owned tuning knobs, so /enroll and legacy port
     * 1515 can never disagree on whether password auth is required or which agent versions are
     * acceptable.
     */
    struct Config
    {
        bool enrollmentEnabled {false};
        bool usePassword {false};
        bool useSourceIp {false};
        bool allowHigherVersions {false};
        std::string managerVersion;
        bool isWorkerNode {false};

        /// The SAME time policy the agent<->manager bearer scheme's AuthConfig resolves from the
        /// `jwt_max_age` / `jwt_clock_skew` ABI fields (authTypes.cpp's buildTimePolicy()): /enroll's
        /// freshness window (maxAgeSec back, skewSec either way) must never silently diverge from the
        /// two documented, tunable internal options: the `wazuh-enroll+jwt` bearer is verified with
        /// exactly this policy (EnrollmentAuthConfig::timePolicy).
        jwt_profile::v1::TimePolicy timePolicy {};

        /// Same `auth_max_body_size` ABI field (and the same 10 MiB default) authTypes.cpp
        /// resolves for the agent<->manager scheme's AuthConfig -- see EnrollmentAuthConfig's own
        /// field comment for why /enroll must not silently exempt itself from this cap.
        std::size_t maxBodySize {10U * 1024U * 1024U};

        /// Seconds between etc/authd.pass change checks. Passed straight to PasswordKeySource,
        /// which itself treats <=0 as "use its own built-in default" -- no resolution needed here.
        int passwordRefreshIntervalSec {0};

        /// Milliseconds, already converted from the ABI's seconds-denominated fields. 0 means "let
        /// AuthdClient apply its own built-in default" -- the same sentinel AuthdClient's
        /// constructor itself documents, so this is a unit conversion, not a default resolution.
        std::uint32_t authdConnectTimeoutMs {0};
        std::uint32_t authdResponseTimeoutMs {0};
        std::uint32_t authdMaxQueueSize {0};

        /// Number of concurrent AuthdClient workers bridging to authd's local socket. 0 -> let
        /// AuthdClient apply its own built-in default. See authdClient.hpp's class comment for why
        /// more than one is worth having even though authd's own accept loop is single-threaded.
        std::uint32_t authdWorkerThreads {0};
    };

    Config buildEnrollmentConfig(const remoted_module_config_t& c);

} // namespace remoted::enrollment
