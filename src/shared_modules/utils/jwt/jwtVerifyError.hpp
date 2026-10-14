/*
 * Wazuh shared modules - JWT profile library
 * Copyright (C) 2015, Wazuh Inc.
 * August 26, 2026.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

/// @file jwtVerifyError.hpp
/// Failure classes shared by every verifier of this library (`wazuh-agent+jwt`,
/// `wazuh-enroll+jwt`): low-cardinality on purpose -- they feed metrics, while the HTTP answer
/// is the same uniform 401 for all of them.

#pragma once

namespace jwt_profile::v1
{
    enum class VerifyError
    {
        None,
        InvalidToken,     ///< size, grammar, base64url, JSON, header/claim sets or types, jti, structural time rules
        InvalidSignature, ///< HMAC mismatch (also a key of the wrong size)
        StaleToken,       ///< clock-relative rules: future iat, expired, older than the accepted age
        IdentityMismatch, ///< sub or iss do not name the kid agent (agent profile only)
    };
} // namespace jwt_profile::v1
