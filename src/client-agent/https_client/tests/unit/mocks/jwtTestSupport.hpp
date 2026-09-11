/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * August 26, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HC_TEST_JWT_SUPPORT_HPP
#define _HC_TEST_JWT_SUPPORT_HPP

#include "external/nlohmann/json.hpp"
#include "jwt/base64Url.hpp"
#include "jwt/hmacSha256.hpp"
#include "jwt/jwtKeyDecoder.hpp"

#include <optional>
#include <string>

/// A minimal test-side view of a `Authorization: Bearer <jws>` header: the decoded claims and
/// whether the HS256 signature verifies with the agent's 64-hex secret. Stands in for the manager
/// so the unit tests can check what the RetrySender actually put on the wire without depending on
/// the token's random jti.
struct DecodedBearer
{
    bool signatureValid {false};
    nlohmann::json header;
    nlohmann::json claims;
};

inline std::optional<DecodedBearer> decodeBearer(const std::string& authorizationHeader, const std::string& keyHex)
{
    static const std::string prefix = "Authorization: Bearer ";

    if (authorizationHeader.rfind(prefix, 0) != 0)
    {
        return std::nullopt;
    }

    const std::string token = authorizationHeader.substr(prefix.size());
    const auto dot1 = token.find('.');
    const auto dot2 = token.find('.', dot1 + 1);

    if (dot1 == std::string::npos || dot2 == std::string::npos)
    {
        return std::nullopt;
    }

    const auto header = jwt_profile::v1::base64UrlDecodeCanonical(token.substr(0, dot1));
    const auto claims = jwt_profile::v1::base64UrlDecodeCanonical(token.substr(dot1 + 1, dot2 - dot1 - 1));
    const auto signature = jwt_profile::v1::base64UrlDecodeCanonical(token.substr(dot2 + 1));
    const auto key = jwt_profile::v1::JwtKeyDecoder::decode(keyHex);

    if (!header || !claims || !signature || !key)
    {
        return std::nullopt;
    }

    DecodedBearer decoded;
    decoded.header = nlohmann::json::parse(*header, nullptr, false);
    decoded.claims = nlohmann::json::parse(*claims, nullptr, false);

    jwt_profile::v1::HmacSha256Digest mac {};
    decoded.signatureValid =
        jwt_profile::v1::hmacSha256(*key, token.substr(0, dot2), mac) &&
        jwt_profile::v1::hmacSha256Equal(mac, reinterpret_cast<const uint8_t*>(signature->data()), signature->size());
    return decoded;
}

/// The 64-hex secret the unit-test fixtures register for agent 001.
inline const char* testAgentKeyHex()
{
    return "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
}

#endif // _HC_TEST_JWT_SUPPORT_HPP
