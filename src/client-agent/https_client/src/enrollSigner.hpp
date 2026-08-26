/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * August 19, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HC_ENROLL_SIGNER_HPP
#define _HC_ENROLL_SIGNER_HPP

#include <cstddef>
#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <vector>

/// The two headers of one password-mode /enroll attempt (#38438):
///   protocol-version: 1
///   Authorization: WazuhEnroll <unix-ts>:<mac>
struct EnrollSignedHeaders
{
    std::string protocolVersion;
    std::string authorization;
};

/// Derives and applies the password-mode enrollment signature (#38438).
///
/// Recipe: HKDF-SHA256(IKM=password, salt=32 zero bytes [RFC 5869's default
/// for an omitted salt], info="WAZUH-ENROLL-CMAC-KEY"+0x01, L=32) once to get
/// a 32-byte key, then AES-256-CBC-CMAC(that key, canonical string) for the
/// mac. Stateless (no per-agent identity): unlike JwtSigner, which mints the
/// agent's bearer with its own client.keys secret, this signs with a secret
/// derived from the authd password, since an enrolling agent has no key yet.
///
/// Uses cmacPrimitive.hpp for the CMAC step. Transitional: the only remaining
/// CMAC in the module, until /enroll moves to its own JWT profile.
class EnrollSigner
{
public:
    /// @return nullopt if the HKDF or CMAC step fails (not observed in
    ///         practice for a non-empty password and a 32-byte derived key).
    static std::optional<EnrollSignedHeaders> sign(const std::string& password,
                                                   const std::string& method,
                                                   const std::string& target,
                                                   const uint8_t* body,
                                                   size_t bodyLength,
                                                   std::time_t timestamp);

    /// HKDF-SHA256 key derivation alone, exposed so tests can pin the
    /// #38438 known-answer vector directly.
    /// @return nullopt on a provider/allocation failure.
    static std::optional<std::vector<uint8_t>> deriveKey(const std::string& password);
};

#endif // _HC_ENROLL_SIGNER_HPP
