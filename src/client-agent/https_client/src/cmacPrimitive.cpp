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

#include "cmacPrimitive.hpp"

#include <openssl/evp.h>
#include <openssl/params.h>

#include <array>
#include <cstdio>
#include <memory>

namespace
{
    using MacPtr = std::unique_ptr<EVP_MAC, decltype(&EVP_MAC_free)>;
    using MacCtxPtr = std::unique_ptr<EVP_MAC_CTX, decltype(&EVP_MAC_CTX_free)>;

    constexpr size_t MAC_BYTES = 16;

    std::string toHex(const std::array<uint8_t, MAC_BYTES>& tag)
    {
        static const char* digits = "0123456789abcdef";
        std::string hex;
        hex.reserve(2 * tag.size());

        for (const auto byte : tag)
        {
            hex.push_back(digits[byte >> 4]);
            hex.push_back(digits[byte & 0x0f]);
        }

        return hex;
    }

    /// Cipher by key length, mirroring the manager's enrollment resolver.
    const char* cipherFor(size_t keyLength)
    {
        if (keyLength == 24)
        {
            return "AES-192-CBC";
        }

        if (keyLength == 32)
        {
            return "AES-256-CBC";
        }

        return "AES-128-CBC";
    }

    MacCtxPtr makeCmacContext(const std::vector<uint8_t>& key)
    {
        const MacPtr mac {EVP_MAC_fetch(nullptr, "CMAC", nullptr), EVP_MAC_free};

        if (!mac)
        {
            return {nullptr, EVP_MAC_CTX_free}; // LCOV_EXCL_LINE: vendored provider always has CMAC.
        }

        MacCtxPtr context {EVP_MAC_CTX_new(mac.get()), EVP_MAC_CTX_free};

        if (!context)
        {
            return {nullptr, EVP_MAC_CTX_free}; // LCOV_EXCL_LINE: allocation failure only.
        }

        char cipher[12] = {};
        std::snprintf(cipher, sizeof cipher, "%s", cipherFor(key.size()));
        const OSSL_PARAM params[] = {OSSL_PARAM_utf8_string("cipher", cipher, 0), OSSL_PARAM_END};

        if (EVP_MAC_init(context.get(), key.data(), key.size(), params) != 1)
        {
            return {nullptr, EVP_MAC_CTX_free}; // Wrong key size (the provider validates).
        }

        return context;
    }
} // namespace

std::optional<std::string> cmacHex(const std::vector<uint8_t>& key, const uint8_t* message, size_t messageLength)
{
    auto context = makeCmacContext(key);

    if (!context)
    {
        return std::nullopt;
    }

    if (EVP_MAC_update(context.get(), message, messageLength) != 1)
    {
        return std::nullopt; // LCOV_EXCL_LINE: update on a valid context cannot fail.
    }

    std::array<uint8_t, MAC_BYTES> tag {};
    size_t tagLength = 0;

    if (EVP_MAC_final(context.get(), tag.data(), &tagLength, tag.size()) != 1 || tagLength != tag.size())
    {
        return std::nullopt; // LCOV_EXCL_LINE: cannot fail after a successful init.
    }

    return toHex(tag);
}
