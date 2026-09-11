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

/// @file secureBytes.hpp
/// Owning buffer for key material: move-only, wiped with OPENSSL_cleanse before its memory is
/// released, and deliberately without any conversion to text. The HS256 key lives here from the
/// moment the client.keys secret is decoded until the signer/verifier is done with it.

#pragma once

#include <openssl/crypto.h>

#include <cstddef>
#include <cstdint>
#include <vector>

namespace jwt_profile::v1
{
    class SecureBytes final
    {
    public:
        SecureBytes() = default;

        /// Zero-initialised buffer of `size` bytes, to be filled in place through data().
        explicit SecureBytes(std::size_t size)
            : m_bytes(size, 0)
        {
        }

        /// Copies `size` bytes from `data`; the caller remains responsible for wiping its own copy.
        SecureBytes(const std::uint8_t* data, std::size_t size)
            : m_bytes(data, data + size)
        {
        }

        SecureBytes(const SecureBytes&) = delete;
        SecureBytes& operator=(const SecureBytes&) = delete;

        SecureBytes(SecureBytes&& other) noexcept
            : m_bytes(std::move(other.m_bytes))
        {
            other.m_bytes.clear();
        }

        SecureBytes& operator=(SecureBytes&& other) noexcept
        {
            if (this != &other)
            {
                wipe();
                m_bytes = std::move(other.m_bytes);
                other.m_bytes.clear();
            }
            return *this;
        }

        ~SecureBytes()
        {
            wipe();
        }

        /// Overwrites the content and releases it. Safe to call more than once.
        void wipe() noexcept
        {
            if (!m_bytes.empty())
            {
                OPENSSL_cleanse(m_bytes.data(), m_bytes.size());
            }
            m_bytes.clear();
            m_bytes.shrink_to_fit();
        }

        /// Constant-time equality (CRYPTO_memcmp): sizes must match too.
        bool operator==(const SecureBytes& other) const noexcept
        {
            return m_bytes.size() == other.m_bytes.size() &&
                   (m_bytes.empty() || CRYPTO_memcmp(m_bytes.data(), other.m_bytes.data(), m_bytes.size()) == 0);
        }
        bool operator!=(const SecureBytes& other) const noexcept
        {
            return !(*this == other);
        }

        std::uint8_t* data() noexcept
        {
            return m_bytes.data();
        }
        const std::uint8_t* data() const noexcept
        {
            return m_bytes.data();
        }
        std::size_t size() const noexcept
        {
            return m_bytes.size();
        }
        bool empty() const noexcept
        {
            return m_bytes.empty();
        }

    private:
        std::vector<std::uint8_t> m_bytes;
    };
} // namespace jwt_profile::v1
