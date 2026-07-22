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

namespace
{
    /// AES-CMAC key sizes, cipher chosen by length (AES-128/192/256) exactly
    /// like the manager-side resolver. A real client.keys entry is 64 hex
    /// chars = 32 bytes = AES-256.
    bool validKeyLength(size_t bytes)
    {
        return bytes == 16 || bytes == 24 || bytes == 32;
    }

    int hexNibble(char character)
    {
        if (character >= '0' && character <= '9')
        {
            return character - '0';
        }

        if (character >= 'a' && character <= 'f')
        {
            return character - 'a' + 10;
        }

        if (character >= 'A' && character <= 'F')
        {
            return character - 'A' + 10;
        }

        return -1;
    }

    std::optional<std::vector<uint8_t>> decodeKeyHex(const std::string& keyHex)
    {
        if (keyHex.size() % 2 != 0 || !validKeyLength(keyHex.size() / 2))
        {
            return std::nullopt;
        }

        const size_t keyBytes = keyHex.size() / 2;
        std::vector<uint8_t> key(keyBytes);

        for (size_t index = 0; index < keyBytes; index++)
        {
            const int high = hexNibble(keyHex[2 * index]);
            const int low = hexNibble(keyHex[2 * index + 1]);

            if (high < 0 || low < 0)
            {
                return std::nullopt;
            }

            key[index] = static_cast<uint8_t>((high << 4) | low);
        }

        return key;
    }
} // namespace

ConfigKeyProvider::ConfigKeyProvider(std::string keyHex)
    : m_keyHex(std::move(keyHex))
{
}

std::optional<std::vector<uint8_t>> ConfigKeyProvider::cmacKey() const
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
