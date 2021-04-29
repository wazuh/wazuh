/*
 * Wazuh shared modules utils
 * Copyright (C) 2015-2021, Wazuh Inc.
 * Sep 8, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HASH_HELPER_H
#define _HASH_HELPER_H

#include <vector>
#include <memory>
#include "openssl/evp.h"

namespace Utils
{
    enum class HashType
    {
        Sha1,
        Sha256,
    };
    class HashData final
    {
    public:
        HashData(const HashType hashType = HashType::Sha1)
        : m_spCtx{createContext()}
        {
            initializeContext(hashType, m_spCtx);
        }
        // LCOV_EXCL_START
        ~HashData() = default;
        // LCOV_EXCL_STOP
        void update(const void* data, const size_t size)
        {
            const auto ret
            {
                EVP_DigestUpdate(m_spCtx.get(), data, size)
            };
            // LCOV_EXCL_START
            if (!ret)
            {
                throw std::runtime_error
                {
                    "Error getting digest final."
                };
            }
            // LCOV_EXCL_STOP
        }
        std::vector<unsigned char> hash()
        {
            unsigned char digest[EVP_MAX_MD_SIZE]{0};
            unsigned int digestSize{0};
            const auto ret
            {
                EVP_DigestFinal_ex(m_spCtx.get(), digest, &digestSize)
            };
            // LCOV_EXCL_START
            if (!ret)
            {
                throw std::runtime_error
                {
                    "Error getting digest final."
                };
            }
            // LCOV_EXCL_STOP
            return {digest, digest+digestSize};
        }
    private:
        struct EvpContextDeleter final
        {
            void operator()(EVP_MD_CTX* ctx)
            {
                EVP_MD_CTX_destroy(ctx);
            }
        };

        static EVP_MD_CTX* createContext()
        {
            auto ctx{ EVP_MD_CTX_create() };
            // LCOV_EXCL_START
            if (!ctx)
            {
                throw std::runtime_error
                {
                    "Error creating EVP_MD_CTX."
                };
            }
            // LCOV_EXCL_STOP
            return ctx;
        }
        static void initializeContext(const HashType hashType, std::unique_ptr<EVP_MD_CTX, EvpContextDeleter>& spCtx)
        {
            auto ret{0};
            switch(hashType)
            {
                case HashType::Sha1:
                    ret = EVP_DigestInit(spCtx.get(), EVP_sha1());
                    break;
                case HashType::Sha256:
                    ret = EVP_DigestInit(spCtx.get(), EVP_sha256());
                    break;
            }
            if (!ret)
            {
                throw std::runtime_error
                {
                    "Error initializing EVP_MD_CTX."
                };
            }
        }
        std::unique_ptr<EVP_MD_CTX, EvpContextDeleter> m_spCtx;
    };


}

#endif // _HASH_HELPER_H