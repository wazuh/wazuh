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

#include "jwt/secureBytes.hpp"

#include <ctime>
#include <optional>
#include <string>

/// The two headers of one password-mode /enroll attempt (#38582):
///   protocol-version: 1
///   Authorization: Bearer <wazuh-enroll+jwt>
struct EnrollSignedHeaders
{
    std::string protocolVersion;
    std::string authorization;
};

/// Mints the password-mode enrollment credential: the `wazuh-enroll+jwt`
/// bearer (shared_modules/utils/jwt/jwtEnrollProfileV1.hpp), HS256 over a key
/// derived once per call from the authd password with the shared HKDF
/// (jwt/enrollKeyDerivation.hpp -- the manager's PasswordKeySource runs the
/// exact same construction). Stateless and identity-free: unlike JwtSigner,
/// which mints the agent's own bearer with its client.keys secret, an
/// enrolling agent has no key yet. The token binds nothing but time (iat/exp)
/// and a fresh jti -- TLS protects the request; the body is not signed.
class EnrollSigner
{
    public:
        /// One fresh token per attempt (new jti, iat = timestamp, exp = iat + 60).
        /// @return nullopt for an empty password or an HKDF/CSPRNG failure.
        static std::optional<EnrollSignedHeaders> sign(const std::string& password, std::time_t timestamp);

        /// HKDF-SHA256 key derivation alone, exposed so tests can pin the frozen
        /// known-answer vector directly.
        static std::optional<jwt_profile::v1::SecureBytes> deriveKey(const std::string& password);
};

#endif // _HC_ENROLL_SIGNER_HPP
