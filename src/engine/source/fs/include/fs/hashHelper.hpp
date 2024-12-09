/*
 * Copyright (C) 2015, Wazuh Inc.
 * Sep 8, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _FS_HASH_HELPER_HPP
#define _FS_HASH_HELPER_HPP

#include <array>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include <openssl/evp.h>
#include <openssl/sha.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

namespace fs
{
/**
 * @brief Function to calculate the hash of a file.
 *
 * @param filepath Path to the file.
 * @return std::vector<unsigned char> Digest vector.
 */
std::vector<unsigned char> hashFile(const std::string& filepath);

enum class HashType
{
    Sha1,
    Sha256,
};
class HashData final
{
public:
    HashData(const HashType hashType = HashType::Sha1);

    // LCOV_EXCL_START
    ~HashData() = default;
    // LCOV_EXCL_STOP

    void update(const void* data, const size_t size);
    std::vector<unsigned char> hash();

private:
    struct EvpContextDeleter final
    {
        void operator()(EVP_MD_CTX* ctx) { EVP_MD_CTX_destroy(ctx); }
    };

    static EVP_MD_CTX* createContext();
    static void initializeContext(const HashType hashType, std::unique_ptr<EVP_MD_CTX, EvpContextDeleter>& spCtx);
    std::unique_ptr<EVP_MD_CTX, EvpContextDeleter> m_spCtx;
};
} // namespace fs

#pragma GCC diagnostic pop

#endif // _FS_HASH_HELPER_HPP
