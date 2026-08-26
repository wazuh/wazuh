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

/// @file jwtEnrollProfileV1.hpp
/// Constants of the closed `wazuh-enroll+jwt` profile (issue #38582): the bearer an agent that has
/// no client.keys entry yet presents to POST /enroll when the manager requires the enrollment
/// password. Same core as `wazuh-agent+jwt` (jwtProfileV1.hpp: HS256, 32-byte key, compact grammar,
/// TimePolicy, kLifetimeSec, 4096-byte cap, jti), different domain:
///   header  exactly {alg: "HS256", typ: "wazuh-enroll+jwt"}   -- no `kid`: one shared key
///   claims  exactly {exp, iat, jti, nbf}                        -- no `iss`/`sub`: no identity to assert
///   key     HKDF-SHA256(IKM = password, salt = 32 x 0x00, info = "WAZUH-ENROLL-JWT-KEY" || 0x01, L = 32)
/// A token of either profile presented to the other's verifier fails on `typ` (exact header set).

#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace jwt_profile::v1::enroll
{
    constexpr std::string_view kTyp = "wazuh-enroll+jwt";
    /// HKDF `info` = this label followed by the single version byte kHkdfInfoVersion. The label is
    /// the domain separator from the historical AES-CMAC key ("WAZUH-ENROLL-CMAC-KEY"): the same
    /// password yields an unrelated key here.
    constexpr std::string_view kHkdfInfoLabel = "WAZUH-ENROLL-JWT-KEY";
    constexpr std::uint8_t kHkdfInfoVersion = 0x01;
    /// RFC 5869: an omitted salt is HashLen zero bytes; spelled explicitly so no provider default
    /// is relied upon.
    constexpr std::size_t kHkdfSaltBytes = 32;
} // namespace jwt_profile::v1::enroll
