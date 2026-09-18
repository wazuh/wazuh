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
///   header  exactly {alg: "HS256", typ: "wazuh-enroll+jwt"}, plus an OPTIONAL `kid` (below)
///   claims  exactly {exp, iat, jti, nbf}                        -- no `iss`/`sub`: no identity to assert
///   key     without `kid` (the only form up to 5.0, unchanged): the one shared key,
///             HKDF-SHA256(IKM = password, salt = 32 x 0x00, info = "WAZUH-ENROLL-JWT-KEY" || 0x01, L = 32)
///           with `kid` (issue #38993): the `kid` names the key. Two forms, disjoint by shape:
///             - enrollment token: `kid` = the 16-byte token id as 22 canonical base64url chars,
///               key = HKDF-SHA256(IKM = 16-byte token secret, same salt, info = "WAZUH-ENROLL-TOKEN-KEY" || 0x01)
///             - re-enrollment:    `kid` = the canonical agent id ("001", canonicalAgentId.hpp),
///               key = HKDF-SHA256(IKM = 32-byte reenroll_secret, same salt, info = "WAZUH-REENROLL-KEY" || 0x01)
///           JwtEnrollTokenVerifier::peekKid() tells the three cases apart before any signature work;
///           verify() (shared key) keeps rejecting every header that carries a `kid`.
/// A token of either profile presented to the other's verifier fails on `typ` (exact header set).
/// Like the agent profile, the JSON text of both segments is ASCII; anything else is an invalid token.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace jwt_profile::v1::enroll
{
    constexpr std::string_view kTyp = "wazuh-enroll+jwt";
    /// HKDF `info` = this label followed by the single version byte kHkdfInfoVersion: the domain
    /// separator of this key (the same password fed to any other construction yields an unrelated key).
    constexpr std::string_view kHkdfInfoLabel = "WAZUH-ENROLL-JWT-KEY";
    constexpr std::uint8_t kHkdfInfoVersion = 0x01;
    /// RFC 5869: an omitted salt is HashLen zero bytes; spelled explicitly so no provider default
    /// is relied upon.
    constexpr std::size_t kHkdfSaltBytes = 32;

    /// `kid` = enrollment token (issue #38993): HKDF `info` label of the key derived from the token secret.
    constexpr std::string_view kHkdfTokenInfoLabel = "WAZUH-ENROLL-TOKEN-KEY";
    /// `kid` = re-enrolling agent: HKDF `info` label of the key derived from its reenroll_secret.
    constexpr std::string_view kHkdfReenrollInfoLabel = "WAZUH-REENROLL-KEY";
    /// Enrollment token id and secret; the token's `key` field is id || secret (32 bytes, 43 base64url chars).
    constexpr std::size_t kTokenIdBytes = 16;
    constexpr std::size_t kTokenSecretBytes = 16;
    /// The token id as it travels in `kid`: 16 bytes = 22 canonical base64url chars.
    constexpr std::size_t kTokenKidChars = 22;
    /// Per-agent re-enrollment secret (global.db `reenroll_secret`; 64 hex chars in the /enroll response).
    constexpr std::size_t kReenrollSecretBytes = 32;
} // namespace jwt_profile::v1::enroll
