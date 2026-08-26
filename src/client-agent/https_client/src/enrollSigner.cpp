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

#include "enrollSigner.hpp"

#include "jwt/enrollKeyDerivation.hpp"
#include "jwt/jwtEnrollTokenSigner.hpp"

#include <chrono>

std::optional<jwt_profile::v1::SecureBytes> EnrollSigner::deriveKey(const std::string& password)
{
    return jwt_profile::v1::enroll::deriveEnrollKey(password);
}

std::optional<EnrollSignedHeaders> EnrollSigner::sign(const std::string& password, std::time_t timestamp)
{
    const auto key = deriveKey(password);

    if (!key)
    {
        return std::nullopt;
    }

    const auto token = jwt_profile::v1::enroll::JwtEnrollTokenSigner::sign(
                           *key, std::chrono::system_clock::time_point {std::chrono::seconds {timestamp}});

    if (!token)
    {
        return std::nullopt; // LCOV_EXCL_LINE: CSPRNG failure or clock out of range only.
    }

    EnrollSignedHeaders headers;
    headers.protocolVersion = "protocol-version: 1";
    headers.authorization = "Authorization: Bearer " + *token;
    return headers;
}
