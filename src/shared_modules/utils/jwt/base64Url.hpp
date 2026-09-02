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
#include <optional>
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

    /// Sextet value of a base64url char; -1 outside the alphabet.
    inline int base64UrlSextet(char c) noexcept
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
        if (c == '-')
        {
            return 62;
        }
        if (c == '_')
        {
            return 63;
        }
        return -1;
    }

    /// True iff `text` is a canonical unpadded base64url encoding of SOME byte string: right
    /// alphabet, `len % 4 != 1`, and the unused trailing bits of the last char are zero (so no two
    /// different texts decode to the same bytes -- RFC 7515 §2, RFC 8725 §3.12). Empty is canonical
    /// for zero bytes.
    inline bool isCanonicalBase64Url(std::string_view text) noexcept
    {
        const std::size_t rest = text.size() % 4;
        if (rest == 1 || !isBase64UrlAlphabet(text))
        {
            return false;
        }
        if (rest == 0)
        {
            return true;
        }
        // 2 chars -> 1 byte, last char carries 2 bits (low 4 must be zero); 3 chars -> 2 bytes,
        // last char carries 4 bits (low 2 must be zero).
        const int zeroBits = rest == 2 ? 4 : 2;
        return (base64UrlSextet(text.back()) & ((1 << zeroBits) - 1)) == 0;
    }

    /// Number of bytes a canonical base64url text of `len` chars decodes to (len % 4 != 1 assumed).
    constexpr std::size_t base64UrlDecodedSize(std::size_t len) noexcept
    {
        return (len / 4) * 3 + (len % 4 == 0 ? 0 : len % 4 - 1);
    }

    /// True iff `text` is the canonical encoding of exactly `bytes` bytes.
    inline bool isCanonicalBase64UrlOf(std::string_view text, std::size_t bytes) noexcept
    {
        return text.size() % 4 != 1 && base64UrlDecodedSize(text.size()) == bytes && isCanonicalBase64Url(text);
    }

    /// Strict decoder: nullopt unless `text` is canonical (see isCanonicalBase64Url). Never pads,
    /// never accepts '=' or percent-encoded fill, never ignores dirty trailing bits.
    inline std::optional<std::string> base64UrlDecodeCanonical(std::string_view text)
    {
        if (!isCanonicalBase64Url(text))
        {
            return std::nullopt;
        }
        std::string out;
        out.reserve(base64UrlDecodedSize(text.size()));
        std::size_t i = 0;
        for (; i + 4 <= text.size(); i += 4)
        {
            const std::uint32_t triple = (static_cast<std::uint32_t>(base64UrlSextet(text[i])) << 18) |
                                         (static_cast<std::uint32_t>(base64UrlSextet(text[i + 1])) << 12) |
                                         (static_cast<std::uint32_t>(base64UrlSextet(text[i + 2])) << 6) |
                                         static_cast<std::uint32_t>(base64UrlSextet(text[i + 3]));
            out += static_cast<char>((triple >> 16) & 0xff);
            out += static_cast<char>((triple >> 8) & 0xff);
            out += static_cast<char>(triple & 0xff);
        }
        const std::size_t rest = text.size() - i;
        if (rest == 2)
        {
            const std::uint32_t pair = (static_cast<std::uint32_t>(base64UrlSextet(text[i])) << 6) |
                                       static_cast<std::uint32_t>(base64UrlSextet(text[i + 1]));
            out += static_cast<char>((pair >> 4) & 0xff);
        }
        else if (rest == 3)
        {
            const std::uint32_t triple = (static_cast<std::uint32_t>(base64UrlSextet(text[i])) << 12) |
                                         (static_cast<std::uint32_t>(base64UrlSextet(text[i + 1])) << 6) |
                                         static_cast<std::uint32_t>(base64UrlSextet(text[i + 2]));
            out += static_cast<char>((triple >> 10) & 0xff);
            out += static_cast<char>((triple >> 2) & 0xff);
        }
        return out;
    }
} // namespace jwt_profile::v1
