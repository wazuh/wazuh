/*
 * Copyright (C) 2015, Wazuh Inc.
 * November 6, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "fs/hashHelper.hpp"

namespace fs
{
HashData::HashData(const HashType hashType)
    : m_spCtx {createContext()}
{
    initializeContext(hashType, m_spCtx);
}

void HashData::update(const void* data, const size_t size)
{
    const auto ret {EVP_DigestUpdate(m_spCtx.get(), data, size)};

    // LCOV_EXCL_START
    if (!ret)
    {
        throw std::runtime_error {"Error getting digest final."};
    }
    // LCOV_EXCL_STOP
}

std::vector<unsigned char> HashData::hash()
{
    unsigned char digest[EVP_MAX_MD_SIZE] {0};
    unsigned int digestSize {0};
    const auto ret {EVP_DigestFinal_ex(m_spCtx.get(), digest, &digestSize)};

    // LCOV_EXCL_START
    if (!ret)
    {
        throw std::runtime_error {"Error getting digest final."};
    }

    // LCOV_EXCL_STOP
    return {digest, digest + digestSize};
}

EVP_MD_CTX* HashData::createContext()
{
    auto ctx {EVP_MD_CTX_create()};

    // LCOV_EXCL_START
    if (!ctx)
    {
        throw std::runtime_error {"Error creating EVP_MD_CTX."};
    }

    // LCOV_EXCL_STOP
    return ctx;
}

void HashData::initializeContext(const HashType hashType, std::unique_ptr<EVP_MD_CTX, EvpContextDeleter>& spCtx)
{
    auto ret {0};

    switch (hashType)
    {
        case HashType::Sha1: ret = EVP_DigestInit(spCtx.get(), EVP_sha1()); break;

        case HashType::Sha256: ret = EVP_DigestInit(spCtx.get(), EVP_sha256()); break;
    }

    if (!ret)
    {
        throw std::runtime_error {"Error initializing EVP_MD_CTX."};
    }
}

std::vector<unsigned char> hashFile(const std::string& filepath)
{
    std::ifstream inputFile(filepath, std::fstream::in);
    if (inputFile.good())
    {
        constexpr int BUFFER_SIZE {4096};
        std::array<char, BUFFER_SIZE> buffer {};

        HashData hash;
        while (inputFile.read(buffer.data(), buffer.size()))
        {
            hash.update(buffer.data(), inputFile.gcount());
        }
        hash.update(buffer.data(), inputFile.gcount());

        return hash.hash();
    }

    throw std::runtime_error {"Unable to open '" + filepath + "' for hashing."};
}
} // namespace fs
