/*
 * Wazuh auth middleware (framework-agnostic)
 * Copyright (C) 2015, Wazuh Inc.
 * July 20, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "cmac.hpp"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include <stdexcept>

namespace remoted::auth
{

    namespace
    {
        const char* cipherNameFor(std::size_t keyLen)
        {
            switch (keyLen)
            {
                case 16: return "AES-128-CBC";
                case 24: return "AES-192-CBC";
                case 32: return "AES-256-CBC";
                default: throw CmacKeyError("AES-CMAC key must be 16, 24 or 32 bytes");
            }
        }
    } // namespace

    struct Cmac::Impl
    {
        EVP_MAC* mac = nullptr;
        EVP_MAC_CTX* ctx = nullptr;
        bool finalized = false;
    };

    Cmac::Cmac(const std::vector<std::uint8_t>& key)
    {
        // Validate BEFORE allocating m_impl. cipherNameFor() throws CmacKeyError for a bad key
        // length; if that happened after `m_impl = new Impl()` (as it used to, via a member
        // initializer), construction would abort without ever running ~Cmac() -- m_impl leaks,
        // since nothing else owns it. Caught by LeakSanitizer via the CmacKeyError unit test.
        const char* cipherName = cipherNameFor(key.size());

        m_impl = new Impl();
        m_impl->mac = EVP_MAC_fetch(nullptr, "CMAC", nullptr);
        if (!m_impl->mac)
        {
            delete m_impl;
            throw CmacProviderError("EVP_MAC_fetch(CMAC) failed");
        }

        m_impl->ctx = EVP_MAC_CTX_new(m_impl->mac);
        if (!m_impl->ctx)
        {
            EVP_MAC_free(m_impl->mac);
            delete m_impl;
            throw CmacProviderError("EVP_MAC_CTX_new failed");
        }

        OSSL_PARAM params[2];
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, const_cast<char*>(cipherName), 0);
        params[1] = OSSL_PARAM_construct_end();

        if (EVP_MAC_init(m_impl->ctx, key.data(), key.size(), params) != 1)
        {
            EVP_MAC_CTX_free(m_impl->ctx);
            EVP_MAC_free(m_impl->mac);
            delete m_impl;
            throw CmacProviderError("EVP_MAC_init failed");
        }
    }

    Cmac::~Cmac()
    {
        if (m_impl)
        {
            if (m_impl->ctx)
            {
                EVP_MAC_CTX_free(m_impl->ctx);
            }
            if (m_impl->mac)
            {
                EVP_MAC_free(m_impl->mac);
            }
            delete m_impl;
        }
    }

    void Cmac::update(const std::uint8_t* data, std::size_t len)
    {
        if (m_impl->finalized)
        {
            throw std::logic_error("Cmac::update called after finalize()");
        }
        if (EVP_MAC_update(m_impl->ctx, data, len) != 1)
        {
            throw std::runtime_error("EVP_MAC_update failed");
        }
    }

    void Cmac::update(std::string_view data)
    {
        update(reinterpret_cast<const std::uint8_t*>(data.data()), data.size());
    }

    std::array<std::uint8_t, Cmac::kMacSize> Cmac::finalize()
    {
        if (m_impl->finalized)
        {
            throw std::logic_error("Cmac::finalize called twice");
        }
        m_impl->finalized = true;

        std::array<std::uint8_t, kMacSize> out {};
        std::size_t outLen = 0;
        if (EVP_MAC_final(m_impl->ctx, out.data(), &outLen, out.size()) != 1 || outLen != kMacSize)
        {
            throw std::runtime_error("EVP_MAC_final failed");
        }
        return out;
    }

    std::string toLowerHex(const std::uint8_t* data, std::size_t len)
    {
        static const char* digits = "0123456789abcdef";
        std::string out;
        out.resize(len * 2);
        for (std::size_t i = 0; i < len; ++i)
        {
            out[2 * i] = digits[(data[i] >> 4) & 0x0F];
            out[2 * i + 1] = digits[data[i] & 0x0F];
        }
        return out;
    }

    namespace
    {
        int hexNibble(char c)
        {
            if (c >= '0' && c <= '9')
                return c - '0';
            if (c >= 'a' && c <= 'f')
                return 10 + (c - 'a');
            return -1;
        }
    } // namespace

    bool fromLowerHex(std::string_view hex, std::uint8_t* out, std::size_t outLen)
    {
        if (hex.size() != outLen * 2)
        {
            return false;
        }
        for (std::size_t i = 0; i < outLen; ++i)
        {
            int hi = hexNibble(hex[2 * i]);
            int lo = hexNibble(hex[2 * i + 1]);
            if (hi < 0 || lo < 0)
            {
                return false;
            }
            out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
        }
        return true;
    }

    bool constantTimeEquals(const std::uint8_t* a, const std::uint8_t* b, std::size_t len)
    {
        unsigned char diff = 0;
        for (std::size_t i = 0; i < len; ++i)
        {
            diff |= static_cast<unsigned char>(a[i] ^ b[i]);
        }
        return diff == 0;
    }

} // namespace remoted::auth
