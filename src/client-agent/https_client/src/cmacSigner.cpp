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

#include "cmacSigner.hpp"
#include "canonicalRequest.hpp"

#include <openssl/evp.h>
#include <openssl/params.h>

#include <array>
#include <cstdio>
#include <memory>

namespace
{
    using MacPtr = std::unique_ptr<EVP_MAC, decltype(&EVP_MAC_free)>;
    using MacCtxPtr = std::unique_ptr<EVP_MAC_CTX, decltype(&EVP_MAC_CTX_free)>;
    using FilePtr = std::unique_ptr<std::FILE, decltype(&std::fclose)>;

    constexpr size_t MAC_BYTES = 16;
    constexpr size_t FILE_CHUNK = 64 * 1024;

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

    /// Cipher by key length, mirroring the manager's resolver: agent and
    /// server must land on the same AES variant for the MACs to match.
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

    std::optional<std::string> finalizeMac(MacCtxPtr context)
    {
        std::array<uint8_t, MAC_BYTES> tag {};
        size_t tagLength = 0;

        if (EVP_MAC_final(context.get(), tag.data(), &tagLength, tag.size()) != 1 ||
                tagLength != tag.size())
        {
            return std::nullopt; // LCOV_EXCL_LINE: cannot fail after a successful init.
        }

        return toHex(tag);
    }
} // namespace

CmacSigner::CmacSigner(std::string agentId, const IKeyProvider& keyProvider)
    : m_agentId(std::move(agentId))
    , m_keyProvider(keyProvider)
{
}

std::optional<std::string> CmacSigner::macHex(const std::vector<uint8_t>& key,
                                              const uint8_t* message, size_t messageLength)
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

    return finalizeMac(std::move(context));
}

std::optional<SignedHeaders> CmacSigner::sign(const std::string& method, const std::string& target,
                                              const uint8_t* body, size_t bodyLength,
                                              std::time_t timestamp) const
{
    const auto key = m_keyProvider.cmacKey();

    if (!key)
    {
        return std::nullopt;
    }

    const auto canonical =
        buildCanonicalRequest(method, target, m_agentId, timestamp, body, bodyLength);
    const auto digest = macHex(*key, canonical.data(), canonical.size());

    if (!digest)
    {
        return std::nullopt; // LCOV_EXCL_LINE: CMAC cannot fail for a validated 16-byte key.
    }

    return makeHeaders(timestamp, *digest);
}

std::optional<SignedHeaders> CmacSigner::signFile(const std::string& method,
                                                  const std::string& target,
                                                  const std::string& bodyFilePath,
                                                  std::time_t timestamp) const
{
    const auto key = m_keyProvider.cmacKey();

    if (!key)
    {
        return std::nullopt;
    }

    const FilePtr file {std::fopen(bodyFilePath.c_str(), "rb"), std::fclose};

    if (!file)
    {
        return std::nullopt;
    }

    auto context = makeCmacContext(*key);

    if (!context)
    {
        return std::nullopt; // LCOV_EXCL_LINE: init cannot fail for a validated 16-byte key.
    }

    const std::string head = canonicalRequestHead(method, target, m_agentId, timestamp);

    if (EVP_MAC_update(context.get(), reinterpret_cast<const uint8_t*>(head.data()), head.size()) != 1)
    {
        return std::nullopt; // LCOV_EXCL_LINE: update on a valid context cannot fail.
    }

    std::array<uint8_t, FILE_CHUNK> chunk {};
    size_t bytesRead = 0;

    while ((bytesRead = std::fread(chunk.data(), 1, chunk.size(), file.get())) > 0)
    {
        if (EVP_MAC_update(context.get(), chunk.data(), bytesRead) != 1)
        {
            return std::nullopt; // LCOV_EXCL_LINE: update on a valid context cannot fail.
        }
    }

    const auto digest = finalizeMac(std::move(context));

    if (!digest)
    {
        return std::nullopt; // LCOV_EXCL_LINE: cannot fail after a successful init.
    }

    return makeHeaders(timestamp, *digest);
}

SignedHeaders CmacSigner::makeHeaders(std::time_t timestamp, const std::string& macHexDigest) const
{
    SignedHeaders headers;
    headers.protocolVersion = "protocol-version: 1";
    headers.authorization =
        "Authorization: Wazuh " + m_agentId + ":" + std::to_string(timestamp) + ":" + macHexDigest;
    return headers;
}
