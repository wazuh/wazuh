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
    constexpr size_t KEY_BYTES = 16; // AES-128.

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
} // namespace

ConfigKeyProvider::ConfigKeyProvider(std::string keyHex)
    : m_keyHex(std::move(keyHex))
{
}

std::optional<std::vector<uint8_t>> ConfigKeyProvider::cmacKey() const
{
    if (m_keyHex.size() != KEY_BYTES * 2)
    {
        return std::nullopt;
    }
    std::vector<uint8_t> key(KEY_BYTES);
    for (size_t index = 0; index < KEY_BYTES; index++)
    {
        const int high = hexNibble(m_keyHex[2 * index]);
        const int low = hexNibble(m_keyHex[2 * index + 1]);
        if (high < 0 || low < 0)
        {
            return std::nullopt;
        }
        key[index] = static_cast<uint8_t>((high << 4) | low);
    }
    return key;
}
