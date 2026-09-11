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

/// @file hmacSha256.hpp
/// HMAC-SHA256 over a SecureBytes key with OpenSSL's one-shot EVP_Q_mac (OpenSSL 3). Used instead of
/// jwt-cpp's `jwt::algorithm::hs256`, which copies the key into a std::string it never wipes (J13).
/// The key bytes are read in place and never leave the SecureBytes.

#pragma once

#include "jwt/secureBytes.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace jwt_profile::v1
{
    constexpr std::size_t kHmacSha256Bytes = 32;
    using HmacSha256Digest = std::array<std::uint8_t, kHmacSha256Bytes>;

    /// @return false on an empty key or an OpenSSL failure (`out` is then unspecified).
    inline bool hmacSha256(const SecureBytes& key, std::string_view data, HmacSha256Digest& out) noexcept
    {
        if (key.empty())
        {
            return false;
        }
        std::size_t outLen = 0;
        const auto* result = EVP_Q_mac(nullptr,
                                       "HMAC",
                                       nullptr,
                                       "SHA256",
                                       nullptr,
                                       key.data(),
                                       key.size(),
                                       reinterpret_cast<const unsigned char*>(data.data()),
                                       data.size(),
                                       out.data(),
                                       out.size(),
                                       &outLen);
        return result != nullptr && outLen == kHmacSha256Bytes;
    }

    /// Constant-time comparison of a computed digest against `len` bytes of a received one.
    inline bool
    hmacSha256Equal(const HmacSha256Digest& expected, const std::uint8_t* received, std::size_t len) noexcept
    {
        return len == kHmacSha256Bytes && CRYPTO_memcmp(expected.data(), received, kHmacSha256Bytes) == 0;
    }
} // namespace jwt_profile::v1
