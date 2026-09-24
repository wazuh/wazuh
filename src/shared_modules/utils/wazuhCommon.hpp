/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * September 22, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _WAZUH_COMMON_HPP
#define _WAZUH_COMMON_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace wazuh
{
    inline constexpr std::string_view HEX_DIGITS {"0123456789abcdef"};

    /// `size` bytes at `data` as 2*size lowercase hex chars. One allocation,
    /// no stream and no per-byte snprintf.
    [[nodiscard]] inline std::string hex_encode(const void* data, std::size_t size)
    {
        const auto* bytes {static_cast<const std::uint8_t*>(data)};
        std::string hex(2 * size, '\0');

        for (std::size_t i = 0; i < size; ++i)
        {
            hex[2 * i] = HEX_DIGITS[bytes[i] >> 4];
            hex[2 * i + 1] = HEX_DIGITS[bytes[i] & 0x0f];
        }

        return hex;
    }

    /// hex_encode() with `separator` between bytes: MAC addresses and any
    /// other grouped dump.
    [[nodiscard]] inline std::string hex_encode_delimited(const void* data, std::size_t size, char separator)
    {
        const auto* bytes {static_cast<const std::uint8_t*>(data)};
        std::string hex;
        hex.reserve(3 * size);

        for (std::size_t i = 0; i < size; ++i)
        {
            if (i != 0)
            {
                hex.push_back(separator);
            }

            hex.push_back(HEX_DIGITS[bytes[i] >> 4]);
            hex.push_back(HEX_DIGITS[bytes[i] & 0x0f]);
        }

        return hex;
    }
} // namespace wazuh

#endif // _WAZUH_COMMON_HPP
