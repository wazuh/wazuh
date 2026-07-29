/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 21, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "digest.hpp"

#include <openssl/evp.h>

#include <array>
#include <cstdio>
#include <memory>

namespace
{
    using MdCtxPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

    std::string toHex(const unsigned char* bytes, size_t length)
    {
        static const char digits[] = "0123456789abcdef";
        std::string hex;
        hex.reserve(2 * length);

        for (size_t i = 0; i < length; i++)
        {
            hex.push_back(digits[bytes[i] >> 4]);
            hex.push_back(digits[bytes[i] & 0x0f]);
        }

        return hex;
    }
} // namespace

std::string sha256Hex(const void* data, size_t length)
{
    const MdCtxPtr context {EVP_MD_CTX_new(), EVP_MD_CTX_free};
    std::array<unsigned char, EVP_MAX_MD_SIZE> hash {};
    unsigned int hashLength = 0;

    if (!context || EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1 ||
            EVP_DigestUpdate(context.get(), data, length) != 1 ||
            EVP_DigestFinal_ex(context.get(), hash.data(), &hashLength) != 1)
    {
        return {}; // LCOV_EXCL_LINE: EVP failures are not reproducible here.
    }

    return toHex(hash.data(), hashLength);
}

std::string sha1Hex(const void* data, size_t length)
{
    const MdCtxPtr context {EVP_MD_CTX_new(), EVP_MD_CTX_free};
    std::array<unsigned char, EVP_MAX_MD_SIZE> hash {};
    unsigned int hashLength = 0;

    if (!context || EVP_DigestInit_ex(context.get(), EVP_sha1(), nullptr) != 1 ||
            EVP_DigestUpdate(context.get(), data, length) != 1 ||
            EVP_DigestFinal_ex(context.get(), hash.data(), &hashLength) != 1)
    {
        return {}; // LCOV_EXCL_LINE: EVP failures are not reproducible here.
    }

    return toHex(hash.data(), hashLength);
}

std::optional<std::string> sha256FileHex(const std::string& path)
{
    const std::unique_ptr<std::FILE, decltype(&std::fclose)> file
    {
        std::fopen(path.c_str(), "rb"), std::fclose};

    if (!file)
    {
        return std::nullopt;
    }

    const MdCtxPtr context {EVP_MD_CTX_new(), EVP_MD_CTX_free};

    if (!context || EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1)
    {
        return std::nullopt; // LCOV_EXCL_LINE: EVP failures are not reproducible.
    }

    std::array<unsigned char, 64 * 1024> chunk {};
    size_t bytesRead = 0;

    while ((bytesRead = std::fread(chunk.data(), 1, chunk.size(), file.get())) > 0)
    {
        if (EVP_DigestUpdate(context.get(), chunk.data(), bytesRead) != 1)
        {
            return std::nullopt; // LCOV_EXCL_LINE: not reproducible.
        }
    }

    std::array<unsigned char, EVP_MAX_MD_SIZE> hash {};
    unsigned int hashLength = 0;

    if (EVP_DigestFinal_ex(context.get(), hash.data(), &hashLength) != 1)
    {
        return std::nullopt; // LCOV_EXCL_LINE: not reproducible.
    }

    return toHex(hash.data(), hashLength);
}

std::optional<std::string> sha1FileHex(const std::string& path)
{
    const std::unique_ptr<std::FILE, decltype(&std::fclose)> file
    {
        std::fopen(path.c_str(), "rb"), std::fclose};

    if (!file)
    {
        return std::nullopt;
    }

    const MdCtxPtr context {EVP_MD_CTX_new(), EVP_MD_CTX_free};

    if (!context || EVP_DigestInit_ex(context.get(), EVP_sha1(), nullptr) != 1)
    {
        return std::nullopt; // LCOV_EXCL_LINE: EVP failures are not reproducible.
    }

    std::array<unsigned char, 64 * 1024> chunk {};
    size_t bytesRead = 0;

    while ((bytesRead = std::fread(chunk.data(), 1, chunk.size(), file.get())) > 0)
    {
        if (EVP_DigestUpdate(context.get(), chunk.data(), bytesRead) != 1)
        {
            return std::nullopt; // LCOV_EXCL_LINE: not reproducible.
        }
    }

    std::array<unsigned char, EVP_MAX_MD_SIZE> hash {};
    unsigned int hashLength = 0;

    if (EVP_DigestFinal_ex(context.get(), hash.data(), &hashLength) != 1)
    {
        return std::nullopt; // LCOV_EXCL_LINE: not reproducible.
    }

    return toHex(hash.data(), hashLength);
}
