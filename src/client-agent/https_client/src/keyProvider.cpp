/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "keyProvider.hpp"

#include "jwt/jwtKeyDecoder.hpp"

namespace
{
    /// 64 lowercase hex chars -> 32 bytes, through the shared profile decoder
    /// (the manager's keystore uses the same one), copied into a vector for the
    /// IKeyProvider contract; the SecureBytes wipes itself on return.
    std::optional<std::vector<uint8_t>> decodeKeyHex(const std::string& keyHex)
    {
        const auto key = jwt_profile::v1::JwtKeyDecoder::decode(keyHex);

        if (!key)
        {
            return std::nullopt;
        }

        return std::vector<uint8_t>(key->data(), key->data() + key->size());
    }
} // namespace

ConfigKeyProvider::ConfigKeyProvider(std::string keyHex)
    : m_keyHex(std::move(keyHex))
{
}

std::optional<std::vector<uint8_t>> ConfigKeyProvider::signingKey() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return decodeKeyHex(m_keyHex);
}

bool ConfigKeyProvider::setKey(const std::string& keyHex)
{
    if (!decodeKeyHex(keyHex))
    {
        return false; // Invalid material: keep the previous key.
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    m_keyHex = keyHex;
    return true;
}
