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

/// @file base64Url.hpp
/// base64url without padding (RFC 7515 §2 / RFC 4648 §5), the only encoding the profile uses. The
/// encoder delegates to jwt-cpp's `jwt::base` (header-only, no OpenSSL or JSON dependency). Canonical
/// decoding for the verifier lives here too so both directions share one definition of the alphabet.

#pragma once

#include <jwt-cpp/base.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace jwt_profile::v1
{
    inline std::string base64UrlEncode(const std::uint8_t* data, std::size_t len)
    {
        const std::string raw(reinterpret_cast<const char*>(data), len);
        return jwt::base::trim<jwt::alphabet::base64url>(jwt::base::encode<jwt::alphabet::base64url>(raw));
    }

    inline std::string base64UrlEncode(std::string_view text)
    {
        return base64UrlEncode(reinterpret_cast<const std::uint8_t*>(text.data()), text.size());
    }

    /// True iff every char is in the base64url alphabet (A-Z a-z 0-9 - _). No padding chars.
    inline bool isBase64UrlAlphabet(std::string_view text) noexcept
    {
        for (const char c : text)
        {
            const bool ok =
                (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
            if (!ok)
            {
                return false;
            }
        }
        return true;
    }

    /// True iff `text` is the canonical unpadded base64url encoding of exactly `bytes` bytes:
    /// right alphabet, right length, and the trailing bits of the last char are zero (so no two
    /// different texts decode to the same bytes).
    inline bool isCanonicalBase64UrlOf(std::string_view text, std::size_t bytes) noexcept
    {
        const std::size_t fullGroups = bytes / 3;
        const std::size_t rest = bytes % 3;
        const std::size_t expectedLen = fullGroups * 4 + (rest == 0 ? 0 : rest + 1);
        if (text.size() != expectedLen || !isBase64UrlAlphabet(text))
        {
            return false;
        }
        if (rest == 0)
        {
            return true;
        }
        const auto sextet = [](char c) -> int
        {
            if (c >= 'A' && c <= 'Z')
            {
                return c - 'A';
            }
            if (c >= 'a' && c <= 'z')
            {
                return c - 'a' + 26;
            }
            if (c >= '0' && c <= '9')
            {
                return c - '0' + 52;
            }
            return c == '-' ? 62 : 63;
        };
        // 1 leftover byte -> 2 chars, last carries 2 bits (4 must be zero); 2 bytes -> 3 chars,
        // last carries 4 bits (2 must be zero).
        const int last = sextet(text.back());
        const int zeroBits = rest == 1 ? 4 : 2;
        return (last & ((1 << zeroBits) - 1)) == 0;
    }
} // namespace jwt_profile::v1
