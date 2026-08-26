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

#include "jwtSigner.hpp"

#include "jwt/canonicalAgentId.hpp"
#include "jwt/jwtRequestTokenSigner.hpp"
#include "jwt/secureBytes.hpp"

#include <chrono>

JwtSigner::JwtSigner(std::string agentId, const IKeyProvider& keyProvider)
    : m_agentId(std::move(agentId))
    , m_keyProvider(keyProvider)
{
}

void JwtSigner::setAgentId(std::string agentId)
{
    std::lock_guard<std::mutex> lock(m_agentIdMutex);
    m_agentId = std::move(agentId);
}

std::string JwtSigner::agentId() const
{
    std::lock_guard<std::mutex> lock(m_agentIdMutex);
    return m_agentId;
}

std::optional<SignedHeaders> JwtSigner::sign(std::time_t timestamp) const
{
    const auto key = m_keyProvider.signingKey();

    if (!key)
    {
        return std::nullopt;
    }

    // Snapshot once: kid, sub and iss below must all carry the SAME id, even
    // if setAgentId() runs concurrently on another thread mid-call. The
    // configured spelling ("1", "001") is canonicalised by the shared signer.
    const auto agent = jwt_profile::v1::CanonicalAgentId::parse(agentId());

    if (!agent)
    {
        return std::nullopt;
    }

    const jwt_profile::v1::SecureBytes secret {key->data(), key->size()};
    const auto token = jwt_profile::v1::JwtRequestTokenSigner::sign(
                           *agent, secret, std::chrono::system_clock::time_point {std::chrono::seconds {timestamp}});

    if (!token)
    {
        return std::nullopt;
    }

    SignedHeaders headers;
    headers.protocolVersion = "protocol-version: 1";
    headers.authorization = "Authorization: Bearer " + *token;
    return headers;
}
