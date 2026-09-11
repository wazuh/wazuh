/*
 * Wazuh shared modules utils - JWT agent authentication profile
 * Copyright (C) 2015, Wazuh Inc.
 * August 26, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/// @file jwtKeyDecoder.hpp
/// client.keys secret (64 lowercase hex chars) -> the 32-byte HS256 key. Exactly that and nothing
/// else: no other length, no uppercase, no whitespace, no hashing, no padding. The ASCII text is
/// never a key (signing with it is the classic interoperability mistake the vectors pin).

#pragma once

#include "jwt/jwtProfileV1.hpp"
#include "jwt/secureBytes.hpp"

#include <cstdint>
#include <optional>
#include <string_view>

namespace jwt_profile::v1
{
    class JwtKeyDecoder final
    {
    public:
        static std::optional<SecureBytes> decode(std::string_view hex) noexcept
        {
            if (hex.size() != kKeyHexChars)
            {
                return std::nullopt;
            }
            SecureBytes key {kKeyBytes};
            for (std::size_t i = 0; i < kKeyBytes; ++i)
            {
                const int hi = nibble(hex[2 * i]);
                const int lo = nibble(hex[2 * i + 1]);
                if (hi < 0 || lo < 0)
                {
                    return std::nullopt; // `key` wipes itself on the way out
                }
                key.data()[i] = static_cast<std::uint8_t>((hi << 4) | lo);
            }
            return key;
        }

    private:
        static int nibble(char c) noexcept
        {
            if (c >= '0' && c <= '9')
            {
                return c - '0';
            }
            if (c >= 'a' && c <= 'f')
            {
                return c - 'a' + 10;
            }
            return -1;
        }
    };
} // namespace jwt_profile::v1
